//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

const (
	metadataHTTPMethod = "HttpMethod"
	metadataHTTPHost   = "HttpHost"
	metadataHTTPHeader = "HttpHeader"
	metadataHTTPStatus = "HttpStatus"
)

// ConnectResponseWriter abstracts the response writing for both QUIC and HTTP/2.
type ConnectResponseWriter interface {
	// WriteResponse sends the connect response (ack or error) with optional metadata.
	WriteResponse(responseError error, metadata []Metadata) error
}

// quicResponseWriter writes ConnectResponse in QUIC data stream format (signature + capnp).
type quicResponseWriter struct {
	stream io.Writer
}

func (w *quicResponseWriter) WriteResponse(responseError error, metadata []Metadata) error {
	return WriteConnectResponse(w.stream, responseError, metadata...)
}

// HandleDataStream dispatches an incoming edge data stream (QUIC path).
func (i *Inbound) HandleDataStream(ctx context.Context, stream io.ReadWriteCloser, request *ConnectRequest, connIndex uint8) {
	ctx = log.ContextWithNewID(ctx)
	respWriter := &quicResponseWriter{stream: stream}
	i.dispatchRequest(ctx, stream, respWriter, request)
}

// HandleRPCStream handles an incoming edge RPC stream (session management, configuration).
func (i *Inbound) HandleRPCStream(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8) {
	i.logger.DebugContext(ctx, "received RPC stream on connection ", connIndex)
	// V2 RPC streams are handled here - the edge calls RegisterUdpSession/UnregisterUdpSession
	// We need the sender (DatagramSender) to find the muxer - but HandleRPCStream doesn't have it.
	// The V2 muxer is looked up via GetOrCreateV2Muxer in HandleDatagram when first datagram arrives.
	// For RPC, we need a different approach - see handleRPCStreamWithSender below.
}

// HandleRPCStreamWithSender handles an RPC stream with access to the DatagramSender for V2 muxer lookup.
func (i *Inbound) HandleRPCStreamWithSender(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8, sender DatagramSender) {
	muxer := i.getOrCreateV2Muxer(sender)
	ServeRPCStream(ctx, stream, i, muxer, i.logger)
}

// HandleDatagram handles an incoming QUIC datagram.
func (i *Inbound) HandleDatagram(ctx context.Context, datagram []byte, sender DatagramSender) {
	switch i.datagramVersion {
	case "v3":
		muxer := i.getOrCreateV3Muxer(sender)
		muxer.HandleDatagram(ctx, datagram)
	default:
		muxer := i.getOrCreateV2Muxer(sender)
		muxer.HandleDatagram(ctx, datagram)
	}
}

func (i *Inbound) getOrCreateV2Muxer(sender DatagramSender) *DatagramV2Muxer {
	i.datagramMuxerAccess.Lock()
	defer i.datagramMuxerAccess.Unlock()
	muxer, exists := i.datagramV2Muxers[sender]
	if !exists {
		muxer = NewDatagramV2Muxer(i, sender, i.logger)
		i.datagramV2Muxers[sender] = muxer
	}
	return muxer
}

func (i *Inbound) getOrCreateV3Muxer(sender DatagramSender) *DatagramV3Muxer {
	i.datagramMuxerAccess.Lock()
	defer i.datagramMuxerAccess.Unlock()
	muxer, exists := i.datagramV3Muxers[sender]
	if !exists {
		muxer = NewDatagramV3Muxer(i, sender, i.logger)
		i.datagramV3Muxers[sender] = muxer
	}
	return muxer
}

// RemoveDatagramMuxer cleans up muxers when a connection closes.
func (i *Inbound) RemoveDatagramMuxer(sender DatagramSender) {
	i.datagramMuxerAccess.Lock()
	if muxer, exists := i.datagramV2Muxers[sender]; exists {
		muxer.Close()
		delete(i.datagramV2Muxers, sender)
	}
	if muxer, exists := i.datagramV3Muxers[sender]; exists {
		muxer.Close()
		delete(i.datagramV3Muxers, sender)
	}
	i.datagramMuxerAccess.Unlock()
}

func (i *Inbound) dispatchRequest(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
	}

	switch request.Type {
	case ConnectionTypeTCP:
		metadata.Destination = M.ParseSocksaddr(request.Dest)
		i.handleTCPStream(ctx, stream, respWriter, metadata)
	case ConnectionTypeHTTP, ConnectionTypeWebsocket:
		originURL := i.ResolveOriginURL(request.Dest)
		request.Dest = originURL
		metadata.Destination = parseHTTPDestination(originURL)
		if request.Type == ConnectionTypeHTTP {
			i.handleHTTPStream(ctx, stream, respWriter, request, metadata)
		} else {
			i.handleWebSocketStream(ctx, stream, respWriter, request, metadata)
		}
	default:
		i.logger.ErrorContext(ctx, "unknown connection type: ", request.Type)
	}
}

func parseHTTPDestination(dest string) M.Socksaddr {
	parsed, err := url.Parse(dest)
	if err != nil {
		return M.ParseSocksaddr(dest)
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https", "wss":
			port = "443"
		default:
			port = "80"
		}
	}
	return M.ParseSocksaddr(net.JoinHostPort(host, port))
}

func (i *Inbound) handleTCPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, metadata adapter.InboundContext) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound TCP connection to ", metadata.Destination)

	err := respWriter.WriteResponse(nil, nil)
	if err != nil {
		i.logger.ErrorContext(ctx, "write connect response: ", err)
		return
	}

	done := make(chan struct{})
	i.router.RouteConnectionEx(ctx, newStreamConn(stream), metadata, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
}

func (i *Inbound) handleHTTPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound HTTP connection to ", metadata.Destination)

	httpRequest, err := buildHTTPRequestFromMetadata(ctx, request, stream)
	if err != nil {
		i.logger.ErrorContext(ctx, "build HTTP request: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}

	input, output := pipe.Pipe()
	var innerError error

	done := make(chan struct{})
	go i.router.RouteConnectionEx(ctx, output, metadata, N.OnceClose(func(it error) {
		innerError = it
		common.Close(input, output)
		close(done)
	}))

	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return input, nil
			},
		},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer httpClient.CloseIdleConnections()

	response, err := httpClient.Do(httpRequest)
	if err != nil {
		<-done
		i.logger.ErrorContext(ctx, "HTTP request: ", E.Errors(innerError, err))
		respWriter.WriteResponse(err, nil)
		return
	}

	responseMetadata := encodeResponseHeaders(response.StatusCode, response.Header)
	err = respWriter.WriteResponse(nil, responseMetadata)
	if err != nil {
		response.Body.Close()
		i.logger.ErrorContext(ctx, "write HTTP response headers: ", err)
		<-done
		return
	}

	_, err = io.Copy(stream, response.Body)
	response.Body.Close()
	common.Close(input, output)
	if err != nil && !E.IsClosedOrCanceled(err) {
		i.logger.DebugContext(ctx, "copy HTTP response body: ", err)
	}
	<-done
}

func (i *Inbound) handleWebSocketStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound WebSocket connection to ", metadata.Destination)

	httpRequest, err := buildHTTPRequestFromMetadata(ctx, request, stream)
	if err != nil {
		i.logger.ErrorContext(ctx, "build WebSocket request: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}

	input, output := pipe.Pipe()
	var innerError error

	done := make(chan struct{})
	go i.router.RouteConnectionEx(ctx, output, metadata, N.OnceClose(func(it error) {
		innerError = it
		common.Close(input, output)
		close(done)
	}))

	httpClient := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return input, nil
			},
		},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer httpClient.CloseIdleConnections()

	response, err := httpClient.Do(httpRequest)
	if err != nil {
		<-done
		i.logger.ErrorContext(ctx, "WebSocket request: ", E.Errors(innerError, err))
		respWriter.WriteResponse(err, nil)
		return
	}

	responseMetadata := encodeResponseHeaders(response.StatusCode, response.Header)
	err = respWriter.WriteResponse(nil, responseMetadata)
	if err != nil {
		response.Body.Close()
		i.logger.ErrorContext(ctx, "write WebSocket response headers: ", err)
		<-done
		return
	}

	_, err = io.Copy(stream, response.Body)
	response.Body.Close()
	common.Close(input, output)
	if err != nil && !E.IsClosedOrCanceled(err) {
		i.logger.DebugContext(ctx, "copy WebSocket response body: ", err)
	}
	<-done
}

func buildHTTPRequestFromMetadata(ctx context.Context, connectRequest *ConnectRequest, body io.Reader) (*http.Request, error) {
	metadataMap := connectRequest.MetadataMap()
	method := metadataMap[metadataHTTPMethod]
	host := metadataMap[metadataHTTPHost]

	request, err := http.NewRequestWithContext(ctx, method, connectRequest.Dest, body)
	if err != nil {
		return nil, E.Cause(err, "create HTTP request")
	}
	request.Host = host

	for _, entry := range connectRequest.Metadata {
		if !strings.Contains(entry.Key, metadataHTTPHeader) {
			continue
		}
		parts := strings.SplitN(entry.Key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		request.Header.Add(parts[1], entry.Val)
	}

	contentLengthStr := request.Header.Get("Content-Length")
	if contentLengthStr != "" {
		request.ContentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return nil, E.Cause(err, "parse content-length")
		}
	}

	if connectRequest.Type != ConnectionTypeWebsocket && !isTransferEncodingChunked(request) && request.ContentLength == 0 {
		request.Body = http.NoBody
	}

	request.Header.Del("Cf-Cloudflared-Proxy-Connection-Upgrade")

	return request, nil
}

func isTransferEncodingChunked(request *http.Request) bool {
	for _, encoding := range request.TransferEncoding {
		if strings.EqualFold(encoding, "chunked") {
			return true
		}
	}
	return false
}

func encodeResponseHeaders(statusCode int, header http.Header) []Metadata {
	metadata := make([]Metadata, 0, len(header)+1)
	metadata = append(metadata, Metadata{
		Key: metadataHTTPStatus,
		Val: strconv.Itoa(statusCode),
	})
	for name, values := range header {
		for _, value := range values {
			metadata = append(metadata, Metadata{
				Key: metadataHTTPHeader + ":" + name,
				Val: value,
			})
		}
	}
	return metadata
}

// streamConn wraps an io.ReadWriteCloser as a net.Conn.
type streamConn struct {
	io.ReadWriteCloser
}

func newStreamConn(stream io.ReadWriteCloser) *streamConn {
	return &streamConn{ReadWriteCloser: stream}
}

func (c *streamConn) LocalAddr() net.Addr                { return nil }
func (c *streamConn) RemoteAddr() net.Addr               { return nil }
func (c *streamConn) SetDeadline(_ time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(_ time.Time) error { return nil }
