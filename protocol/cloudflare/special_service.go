//go:build with_cloudflared

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

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/v2raywebsocket"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
)

var wsAcceptGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

const (
	socksReplySuccess             = 0
	socksReplyRuleFailure         = 2
	socksReplyHostUnreachable     = 4
	socksReplyCommandNotSupported = 7
)

func (i *Inbound) handleBastionStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	destination, err := resolveBastionDestination(request)
	if err != nil {
		respWriter.WriteResponse(err, nil)
		return
	}
	i.handleRouterBackedStream(ctx, stream, respWriter, request, M.ParseSocksaddr(destination), service.OriginRequest.ProxyType)
}

func (i *Inbound) handleStreamService(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	i.handleRouterBackedStream(ctx, stream, respWriter, request, service.Destination, service.OriginRequest.ProxyType)
}

func (i *Inbound) handleRouterBackedStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, destination M.Socksaddr, proxyType string) {
	targetConn, cleanup, err := i.dialRouterTCP(ctx, destination)
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
	if isSocksProxyType(proxyType) {
		if err := serveFixedSocksStream(ctx, wsConn, targetConn); err != nil && !E.IsClosedOrCanceled(err) {
			i.logger.DebugContext(ctx, "socks-over-websocket stream closed: ", err)
		}
		return
	}
	_ = bufio.CopyConn(ctx, wsConn, targetConn)
}

func (i *Inbound) handleSocksProxyStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	err := respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusSwitchingProtocols, websocketResponseHeaders(request)))
	if err != nil {
		i.logger.ErrorContext(ctx, "write socks-proxy websocket response: ", err)
		return
	}

	wsConn := v2raywebsocket.NewConn(newStreamConn(stream), nil, ws.StateServerSide)
	defer wsConn.Close()
	if err := i.serveSocksProxy(ctx, wsConn, service.SocksPolicy); err != nil && !E.IsClosedOrCanceled(err) {
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

func isSocksProxyType(proxyType string) bool {
	lower := strings.ToLower(strings.TrimSpace(proxyType))
	return lower == "socks" || lower == "socks5"
}

func serveFixedSocksStream(ctx context.Context, conn net.Conn, targetConn net.Conn) error {
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

	var supportsNoAuth bool
	for _, method := range methods {
		if method == 0 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, err := conn.Write([]byte{5, 255})
		if err != nil {
			return err
		}
		return E.New("unknown authentication type")
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
		_ = writeSocksReply(conn, socksReplyCommandNotSupported)
		return E.New("unsupported SOCKS command: ", requestHeader[1])
	}
	if _, err := readSocksDestination(conn, requestHeader[3]); err != nil {
		return err
	}
	if err := writeSocksReply(conn, socksReplySuccess); err != nil {
		return err
	}
	return bufio.CopyConn(ctx, conn, targetConn)
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
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkTCP,
		Destination: destination,
	}
	return i.dialRouterTCPWithMetadata(ctx, metadata, routedPipeTCPOptions{})
}

func (i *Inbound) serveSocksProxy(ctx context.Context, conn net.Conn, policy *ipRulePolicy) error {
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
		_ = writeSocksReply(conn, socksReplyCommandNotSupported)
		return E.New("unsupported SOCKS command: ", requestHeader[1])
	}

	destination, err := readSocksDestination(conn, requestHeader[3])
	if err != nil {
		return err
	}
	allowed, err := policy.Allow(ctx, destination)
	if err != nil {
		_ = writeSocksReply(conn, socksReplyRuleFailure)
		return err
	}
	if !allowed {
		_ = writeSocksReply(conn, socksReplyRuleFailure)
		return E.New("connect to ", destination, " denied by ip_rules")
	}
	targetConn, cleanup, err := i.dialRouterTCP(ctx, destination)
	if err != nil {
		_ = writeSocksReply(conn, socksReplyHostUnreachable)
		return err
	}
	defer cleanup()

	if err := writeSocksReply(conn, socksReplySuccess); err != nil {
		return err
	}
	return bufio.CopyConn(ctx, conn, targetConn)
}

func writeSocksReply(conn net.Conn, reply byte) error {
	_, err := conn.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
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
