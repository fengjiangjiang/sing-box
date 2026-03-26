//go:build with_cloudflared

package cloudflare

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	metadataHTTPMethod = "HttpMethod"
	metadataHTTPHost   = "HttpHost"
	metadataHTTPHeader = "HttpHeader"
	metadataHTTPStatus = "HttpStatus"
)

var (
	loadOriginCABasePool = cloudflareRootCertPool
	readOriginCAFile     = os.ReadFile
	proxyFromEnvironment = http.ProxyFromEnvironment
)

// ConnectResponseWriter abstracts the response writing for both QUIC and HTTP/2.
type ConnectResponseWriter interface {
	// WriteResponse sends the connect response (ack or error) with optional metadata.
	WriteResponse(responseError error, metadata []Metadata) error
}

type connectResponseTrailerWriter interface {
	AddTrailer(name, value string)
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
	switch datagramVersionForSender(sender) {
	case "v3":
		ServeV3RPCStream(ctx, stream, i, i.logger)
	default:
		muxer := i.getOrCreateV2Muxer(sender)
		ServeRPCStream(ctx, stream, i, muxer, i.logger)
	}
}

// HandleDatagram handles an incoming QUIC datagram.
func (i *Inbound) HandleDatagram(ctx context.Context, datagram []byte, sender DatagramSender) {
	switch datagramVersionForSender(sender) {
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
		service, originURL, err := i.resolveHTTPService(request.Dest)
		if err != nil {
			i.logger.ErrorContext(ctx, "resolve origin service: ", err)
			respWriter.WriteResponse(err, nil)
			return
		}
		request.Dest = originURL
		i.handleHTTPService(ctx, stream, respWriter, request, metadata, service)
	default:
		i.logger.ErrorContext(ctx, "unknown connection type: ", request.Type)
	}
}

func (i *Inbound) resolveHTTPService(requestURL string) (ResolvedService, string, error) {
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return ResolvedService{}, "", E.Cause(err, "parse request URL")
	}
	service, loaded := i.configManager.Resolve(parsedURL.Hostname(), parsedURL.Path)
	if !loaded {
		return ResolvedService{}, "", E.New("no ingress rule matched request host/path")
	}
	originURL, err := service.BuildRequestURL(requestURL)
	if err != nil {
		return ResolvedService{}, "", E.Cause(err, "build origin request URL")
	}
	return service, originURL, nil
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
	limit := i.maxActiveFlows()
	if !i.flowLimiter.Acquire(limit) {
		err := E.New("too many active flows")
		i.logger.ErrorContext(ctx, err)
		respWriter.WriteResponse(err, flowConnectRateLimitedMetadata())
		return
	}
	defer i.flowLimiter.Release(limit)

	warpRouting := i.configManager.Snapshot().WarpRouting
	targetConn, cleanup, err := i.dialRouterTCPWithMetadata(ctx, metadata, routedPipeTCPOptions{
		timeout: warpRouting.ConnectTimeout,
		onHandshake: func(conn net.Conn) {
			_ = applyTCPKeepAlive(conn, warpRouting.TCPKeepAlive)
		},
	})
	if err != nil {
		i.logger.ErrorContext(ctx, "dial tcp origin: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()

	// Cloudflare expects an optimistic ACK here so the routed TCP path can sniff
	// the real input stream before the outbound connection is fully established.
	err = respWriter.WriteResponse(nil, nil)
	if err != nil {
		i.logger.ErrorContext(ctx, "write connect response: ", err)
		return
	}

	err = bufio.CopyConn(ctx, newStreamConn(stream), targetConn)
	if err != nil && !E.IsClosedOrCanceled(err) {
		i.logger.DebugContext(ctx, "copy TCP stream: ", err)
	}
}

func (i *Inbound) handleHTTPService(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	validationRequest, err := buildMetadataOnlyHTTPRequest(ctx, request)
	if err != nil {
		i.logger.ErrorContext(ctx, "build request for access validation: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	validationRequest = applyOriginRequest(validationRequest, service.OriginRequest)
	if service.OriginRequest.Access.Required {
		validator, err := i.accessCache.Get(service.OriginRequest.Access)
		if err != nil {
			i.logger.ErrorContext(ctx, "create access validator: ", err)
			respWriter.WriteResponse(err, nil)
			return
		}
		if err := validator.Validate(validationRequest.Context(), validationRequest); err != nil {
			respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusForbidden, http.Header{}))
			return
		}
	}

	switch service.Kind {
	case ResolvedServiceStatus:
		err = respWriter.WriteResponse(nil, encodeResponseHeaders(service.StatusCode, http.Header{}))
		if err != nil {
			i.logger.ErrorContext(ctx, "write status service response: ", err)
		}
		return
	case ResolvedServiceHTTP:
		metadata.Destination = service.Destination
		if request.Type == ConnectionTypeHTTP {
			i.handleHTTPStream(ctx, stream, respWriter, request, metadata, service)
		} else {
			i.handleWebSocketStream(ctx, stream, respWriter, request, metadata, service)
		}
	case ResolvedServiceStream:
		if request.Type != ConnectionTypeWebsocket {
			err := E.New("stream service requires websocket request type")
			i.logger.ErrorContext(ctx, err)
			respWriter.WriteResponse(err, nil)
			return
		}
		i.handleStreamService(ctx, stream, respWriter, request, metadata, service)
	case ResolvedServiceUnix, ResolvedServiceUnixTLS:
		if request.Type == ConnectionTypeHTTP {
			i.handleDirectHTTPStream(ctx, stream, respWriter, request, metadata, service)
		} else {
			i.handleDirectWebSocketStream(ctx, stream, respWriter, request, metadata, service)
		}
	case ResolvedServiceBastion:
		if request.Type != ConnectionTypeWebsocket {
			err := E.New("bastion service requires websocket request type")
			i.logger.ErrorContext(ctx, err)
			respWriter.WriteResponse(err, nil)
			return
		}
		i.handleBastionStream(ctx, stream, respWriter, request, metadata, service)
	case ResolvedServiceSocksProxy:
		if request.Type != ConnectionTypeWebsocket {
			err := E.New("socks-proxy service requires websocket request type")
			i.logger.ErrorContext(ctx, err)
			respWriter.WriteResponse(err, nil)
			return
		}
		i.handleSocksProxyStream(ctx, stream, respWriter, request, metadata, service)
	default:
		err := E.New("unsupported service kind for HTTP/WebSocket request")
		i.logger.ErrorContext(ctx, err)
		respWriter.WriteResponse(err, nil)
	}
}

func (i *Inbound) handleHTTPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound HTTP connection to ", metadata.Destination)

	transport, cleanup, err := i.newRouterOriginTransport(ctx, metadata, service.OriginRequest, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		i.logger.ErrorContext(ctx, "build origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	i.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (i *Inbound) handleWebSocketStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound WebSocket connection to ", metadata.Destination)

	transport, cleanup, err := i.newRouterOriginTransport(ctx, metadata, service.OriginRequest, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		i.logger.ErrorContext(ctx, "build origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	i.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (i *Inbound) handleDirectHTTPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound HTTP connection to ", request.Dest)

	transport, cleanup, err := i.newDirectOriginTransport(service, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		i.logger.ErrorContext(ctx, "build direct origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	i.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (i *Inbound) handleDirectWebSocketStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, metadata adapter.InboundContext, service ResolvedService) {
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound WebSocket connection to ", request.Dest)

	transport, cleanup, err := i.newDirectOriginTransport(service, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		i.logger.ErrorContext(ctx, "build direct origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	i.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (i *Inbound) roundTripHTTP(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, service ResolvedService, transport *http.Transport) {
	httpRequest, err := buildHTTPRequestFromMetadata(ctx, request, stream)
	if err != nil {
		i.logger.ErrorContext(ctx, "build HTTP request: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}

	httpRequest = normalizeOriginRequest(request.Type, httpRequest, service.OriginRequest)
	requestCtx := httpRequest.Context()
	if service.OriginRequest.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(requestCtx, service.OriginRequest.ConnectTimeout)
		defer cancel()
		httpRequest = httpRequest.WithContext(requestCtx)
	}

	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer httpClient.CloseIdleConnections()

	response, err := httpClient.Do(httpRequest)
	if err != nil {
		i.logger.ErrorContext(ctx, "origin request: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer response.Body.Close()

	responseMetadata := encodeResponseHeaders(response.StatusCode, response.Header)
	err = respWriter.WriteResponse(nil, responseMetadata)
	if err != nil {
		i.logger.ErrorContext(ctx, "write origin response headers: ", err)
		return
	}

	if request.Type == ConnectionTypeWebsocket && response.StatusCode == http.StatusSwitchingProtocols {
		rwc, ok := response.Body.(io.ReadWriteCloser)
		if !ok {
			i.logger.ErrorContext(ctx, "websocket origin response body is not duplex")
			return
		}
		bidirectionalCopy(stream, rwc)
		return
	}

	_, err = io.Copy(stream, response.Body)
	if err != nil && !E.IsClosedOrCanceled(err) {
		i.logger.DebugContext(ctx, "copy HTTP response body: ", err)
	}
	if trailerWriter, ok := respWriter.(connectResponseTrailerWriter); ok {
		for name, values := range response.Trailer {
			for _, value := range values {
				trailerWriter.AddTrailer(name, value)
			}
		}
	}
}

func (i *Inbound) newRouterOriginTransport(ctx context.Context, metadata adapter.InboundContext, originRequest OriginRequestConfig, requestHost string) (*http.Transport, func(), error) {
	tlsConfig, err := newOriginTLSConfig(originRequest, effectiveOriginHost(originRequest, requestHost))
	if err != nil {
		return nil, nil, err
	}
	input, cleanup, _ := i.dialRouterTCPWithMetadata(ctx, metadata, routedPipeTCPOptions{})

	transport := &http.Transport{
		DisableCompression:  true,
		ForceAttemptHTTP2:   originRequest.HTTP2Origin,
		TLSHandshakeTimeout: originRequest.TLSTimeout,
		IdleConnTimeout:     originRequest.KeepAliveTimeout,
		MaxIdleConns:        originRequest.KeepAliveConnections,
		MaxIdleConnsPerHost: originRequest.KeepAliveConnections,
		Proxy:               proxyFromEnvironment,
		TLSClientConfig:     tlsConfig,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return input, nil
		},
	}
	return transport, cleanup, nil
}

func (i *Inbound) newDirectOriginTransport(service ResolvedService, requestHost string) (*http.Transport, func(), error) {
	dialer := &net.Dialer{
		Timeout:   service.OriginRequest.ConnectTimeout,
		KeepAlive: service.OriginRequest.TCPKeepAlive,
	}
	if service.OriginRequest.NoHappyEyeballs {
		dialer.FallbackDelay = -1
	}
	tlsConfig, err := newOriginTLSConfig(service.OriginRequest, effectiveOriginHost(service.OriginRequest, requestHost))
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		DisableCompression:  true,
		ForceAttemptHTTP2:   service.OriginRequest.HTTP2Origin,
		TLSHandshakeTimeout: service.OriginRequest.TLSTimeout,
		IdleConnTimeout:     service.OriginRequest.KeepAliveTimeout,
		MaxIdleConns:        service.OriginRequest.KeepAliveConnections,
		MaxIdleConnsPerHost: service.OriginRequest.KeepAliveConnections,
		Proxy:               proxyFromEnvironment,
		TLSClientConfig:     tlsConfig,
	}
	switch service.Kind {
	case ResolvedServiceUnix, ResolvedServiceUnixTLS:
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", service.UnixPath)
		}
	default:
		return nil, nil, E.New("unsupported direct origin service")
	}
	return transport, func() {}, nil
}

func effectiveOriginHost(originRequest OriginRequestConfig, requestHost string) string {
	if originRequest.HTTPHostHeader != "" {
		return originRequest.HTTPHostHeader
	}
	return requestHost
}

func newOriginTLSConfig(originRequest OriginRequestConfig, requestHost string) (*tls.Config, error) {
	rootCAs, err := loadOriginCABasePool()
	if err != nil {
		return nil, E.Cause(err, "load origin root CAs")
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: originRequest.NoTLSVerify, //nolint:gosec
		ServerName:         originTLSServerName(originRequest, requestHost),
		RootCAs:            rootCAs,
	}
	if originRequest.CAPool == "" {
		return tlsConfig, nil
	}
	pemData, err := readOriginCAFile(originRequest.CAPool)
	if err != nil {
		return nil, E.Cause(err, "read origin ca pool")
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(pemData) {
		return nil, E.New("parse origin ca pool")
	}
	return tlsConfig, nil
}

func originTLSServerName(originRequest OriginRequestConfig, requestHost string) string {
	if originRequest.OriginServerName != "" {
		return originRequest.OriginServerName
	}
	if !originRequest.MatchSNIToHost {
		return ""
	}
	if host, _, err := net.SplitHostPort(requestHost); err == nil {
		return host
	}
	return requestHost
}

func applyOriginRequest(request *http.Request, originRequest OriginRequestConfig) *http.Request {
	request = request.Clone(request.Context())
	if originRequest.HTTPHostHeader != "" {
		request.Header.Set("X-Forwarded-Host", request.Host)
		request.Host = originRequest.HTTPHostHeader
	}
	return request
}

func normalizeOriginRequest(connectType ConnectionType, request *http.Request, originRequest OriginRequestConfig) *http.Request {
	request = applyOriginRequest(request, originRequest)

	switch connectType {
	case ConnectionTypeWebsocket:
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-Websocket-Version", "13")
		request.ContentLength = 0
		request.Body = nil
	default:
		if originRequest.DisableChunkedEncoding {
			request.TransferEncoding = []string{"gzip", "deflate"}
			if contentLength, err := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64); err == nil {
				request.ContentLength = contentLength
			}
		}
		request.Header.Set("Connection", "keep-alive")
	}

	if _, exists := request.Header["User-Agent"]; !exists {
		request.Header.Set("User-Agent", "")
	}

	return request
}

func buildMetadataOnlyHTTPRequest(ctx context.Context, connectRequest *ConnectRequest) (*http.Request, error) {
	return buildHTTPRequestFromMetadata(ctx, &ConnectRequest{
		Dest:     connectRequest.Dest,
		Type:     connectRequest.Type,
		Metadata: append([]Metadata(nil), connectRequest.Metadata...),
	}, http.NoBody)
}

func bidirectionalCopy(left, right io.ReadWriteCloser) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			common.Close(left, right)
		})
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(left, right)
		closeBoth()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(right, left)
		closeBoth()
		done <- struct{}{}
	}()
	<-done
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
		if strings.Contains(strings.ToLower(encoding), "chunked") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(request.Header.Get("Transfer-Encoding")), "chunked")
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

type datagramVersionedSender interface {
	DatagramVersion() string
}

func datagramVersionForSender(sender DatagramSender) string {
	versioned, ok := sender.(datagramVersionedSender)
	if !ok {
		return defaultDatagramVersion
	}
	version := versioned.DatagramVersion()
	if version == "" {
		return defaultDatagramVersion
	}
	return version
}
