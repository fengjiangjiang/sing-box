//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/ws"
)

var wsAcceptGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

func (i *Inbound) handleBastionStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext) {
	destination, err := resolveBastionDestination(request)
	if err != nil {
		respWriter.WriteResponse(err, nil)
		return
	}

	targetConn, cleanup, err := i.dialRouterTCP(ctx, M.ParseSocksaddr(destination))
	if err != nil {
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()

	err = respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusSwitchingProtocols, websocketResponseHeaders(request)))
	if err != nil {
		i.logger.ErrorContext(ctx, "write bastion websocket response: ", err)
		return
	}

	wsConn := v2raywebsocket.NewConn(newStreamConn(stream), nil, ws.StateServerSide)
	defer wsConn.Close()
	_ = bufio.CopyConn(ctx, wsConn, targetConn)
}

func (i *Inbound) handleSocksProxyStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext) {
	err := respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusSwitchingProtocols, websocketResponseHeaders(request)))
	if err != nil {
		i.logger.ErrorContext(ctx, "write socks-proxy websocket response: ", err)
		return
	}

	wsConn := v2raywebsocket.NewConn(newStreamConn(stream), nil, ws.StateServerSide)
	defer wsConn.Close()
	if err := i.serveSocksProxy(ctx, wsConn); err != nil && !E.IsClosedOrCanceled(err) {
		i.logger.DebugContext(ctx, "socks-proxy stream closed: ", err)
	}
}

func resolveBastionDestination(request *ConnectRequest) (string, error) {
	headerValue := requestHeaderValue(request, "Cf-Access-Jump-Destination")
	if headerValue == "" {
		return "", E.New("missing Cf-Access-Jump-Destination header")
	}
	if parsed, err := url.Parse(headerValue); err == nil && parsed.Host != "" {
		headerValue = parsed.Host
	}
	return strings.SplitN(headerValue, "/", 2)[0], nil
}

func websocketResponseHeaders(request *ConnectRequest) http.Header {
	header := http.Header{}
	header.Set("Connection", "Upgrade")
	header.Set("Upgrade", "websocket")
	secKey := requestHeaderValue(request, "Sec-WebSocket-Key")
	if secKey != "" {
		sum := sha1.Sum(append([]byte(secKey), wsAcceptGUID...))
		header.Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(sum[:]))
	}
	return header
}

func requestHeaderValue(request *ConnectRequest, headerName string) string {
	for _, entry := range request.Metadata {
		if !strings.HasPrefix(entry.Key, metadataHTTPHeader+":") {
			continue
		}
		name := strings.TrimPrefix(entry.Key, metadataHTTPHeader+":")
		if strings.EqualFold(name, headerName) {
			return entry.Val
		}
	}
	return ""
}

func (i *Inbound) dialRouterTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, func(), error) {
	input, output := pipe.Pipe()
	done := make(chan struct{})
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkTCP,
		Destination: destination,
	}
	go i.router.RouteConnectionEx(ctx, output, metadata, N.OnceClose(func(it error) {
		common.Close(input, output)
		close(done)
	}))
	return input, func() {
		common.Close(input, output)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}, nil
}

func (i *Inbound) serveSocksProxy(ctx context.Context, conn net.Conn) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 5 {
		return E.New("unsupported SOCKS version: ", version[0])
	}

	methodCount := make([]byte, 1)
	if _, err := io.ReadFull(conn, methodCount); err != nil {
		return err
	}
	methods := make([]byte, int(methodCount[0]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}

	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return err
	}
	if requestHeader[0] != 5 {
		return E.New("unsupported SOCKS request version: ", requestHeader[0])
	}
	if requestHeader[1] != 1 {
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return E.New("unsupported SOCKS command: ", requestHeader[1])
	}

	destination, err := readSocksDestination(conn, requestHeader[3])
	if err != nil {
		return err
	}
	targetConn, cleanup, err := i.dialRouterTCP(ctx, destination)
	if err != nil {
		_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer cleanup()

	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	return bufio.CopyConn(ctx, conn, targetConn)
}

func readSocksDestination(conn net.Conn, addressType byte) (M.Socksaddr, error) {
	switch addressType {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return M.Socksaddr{}, err
		}
		port, err := readSocksPort(conn)
		if err != nil {
			return M.Socksaddr{}, err
		}
		ipAddr, ok := netip.AddrFromSlice(addr)
		if !ok {
			return M.Socksaddr{}, E.New("invalid IPv4 SOCKS destination")
		}
		return M.SocksaddrFrom(ipAddr, port), nil
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return M.Socksaddr{}, err
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, host); err != nil {
			return M.Socksaddr{}, err
		}
		port, err := readSocksPort(conn)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return M.ParseSocksaddr(net.JoinHostPort(string(host), strconv.Itoa(int(port)))), nil
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return M.Socksaddr{}, err
		}
		port, err := readSocksPort(conn)
		if err != nil {
			return M.Socksaddr{}, err
		}
		ipAddr, ok := netip.AddrFromSlice(addr)
		if !ok {
			return M.Socksaddr{}, E.New("invalid IPv6 SOCKS destination")
		}
		return M.SocksaddrFrom(ipAddr, port), nil
	default:
		return M.Socksaddr{}, E.New("unsupported SOCKS address type: ", addressType)
	}
}

func readSocksPort(conn net.Conn) (uint16, error) {
	port := make([]byte, 2)
	if _, err := io.ReadFull(conn, port); err != nil {
		return 0, err
	}
	return uint16(port[0])<<8 | uint16(port[1]), nil
}
