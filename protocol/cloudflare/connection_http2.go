//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"crypto/tls"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/google/uuid"
	"golang.org/x/net/http2"
)

const (
	h2EdgeSNI = "h2.cftunnel.com"
)

// HTTP2Connection manages a single HTTP/2 connection to the Cloudflare edge.
// Uses role reversal: we dial the edge as a TLS client but serve HTTP/2 as server.
type HTTP2Connection struct {
	conn        net.Conn
	server      *http2.Server
	logger      log.ContextLogger
	edgeAddr    *EdgeAddr
	connIndex   uint8
	credentials Credentials
	connectorID uuid.UUID
	features    []string
	gracePeriod time.Duration
	inbound     *Inbound

	numPreviousAttempts uint8
	registrationClient  *RegistrationClient
	registrationResult  *RegistrationResult
	controlStreamErr    error

	activeRequests sync.WaitGroup
	closeOnce      sync.Once
}

// NewHTTP2Connection dials the edge and establishes an HTTP/2 connection with role reversal.
func NewHTTP2Connection(
	ctx context.Context,
	edgeAddr *EdgeAddr,
	connIndex uint8,
	credentials Credentials,
	connectorID uuid.UUID,
	features []string,
	numPreviousAttempts uint8,
	gracePeriod time.Duration,
	inbound *Inbound,
	logger log.ContextLogger,
) (*HTTP2Connection, error) {
	rootCAs, err := cloudflareRootCertPool()
	if err != nil {
		return nil, E.Cause(err, "load Cloudflare root CAs")
	}

	tlsConfig := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: h2EdgeSNI,
	}

	tcpConn, err := inbound.controlDialer.DialContext(ctx, "tcp", M.SocksaddrFrom(edgeAddr.TCP.AddrPort().Addr(), edgeAddr.TCP.AddrPort().Port()))
	if err != nil {
		return nil, E.Cause(err, "dial edge TCP")
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		return nil, E.Cause(err, "TLS handshake")
	}

	return &HTTP2Connection{
		conn: tlsConn,
		server: &http2.Server{
			MaxConcurrentStreams: math.MaxUint32,
		},
		logger:              logger,
		edgeAddr:            edgeAddr,
		connIndex:           connIndex,
		credentials:         credentials,
		connectorID:         connectorID,
		features:            features,
		numPreviousAttempts: numPreviousAttempts,
		gracePeriod:         gracePeriod,
		inbound:             inbound,
	}, nil
}

// Serve runs the HTTP/2 server. Blocks until the context is cancelled or the connection ends.
func (c *HTTP2Connection) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		c.close()
	}()

	c.server.ServeConn(c.conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: c,
	})

	if c.controlStreamErr != nil {
		return c.controlStreamErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.registrationResult == nil {
		return E.New("edge connection closed before registration")
	}
	return E.New("edge connection closed")
}

func (c *HTTP2Connection) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.activeRequests.Add(1)
	defer c.activeRequests.Done()

	switch {
	case r.Header.Get(h2HeaderUpgrade) == h2UpgradeControlStream:
		c.handleControlStream(r.Context(), r, w)
	case r.Header.Get(h2HeaderUpgrade) == h2UpgradeWebsocket:
		c.handleH2DataStream(r.Context(), r, w, ConnectionTypeWebsocket)
	case r.Header.Get(h2HeaderTCPSrc) != "":
		c.handleH2DataStream(r.Context(), r, w, ConnectionTypeTCP)
	case r.Header.Get(h2HeaderUpgrade) == h2UpgradeConfiguration:
		c.handleConfigurationUpdate(r, w)
	default:
		c.handleH2DataStream(r.Context(), r, w, ConnectionTypeHTTP)
	}
}

func (c *HTTP2Connection) handleControlStream(ctx context.Context, r *http.Request, w http.ResponseWriter) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		c.logger.Error("response writer does not support flushing")
		return
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	stream := newHTTP2Stream(r.Body, &http2FlushWriter{w: w, flusher: flusher})

	c.registrationClient = NewRegistrationClient(ctx, stream)

	host, _, _ := net.SplitHostPort(c.conn.LocalAddr().String())
	originLocalIP := net.ParseIP(host)
	options := BuildConnectionOptions(c.connectorID, c.features, c.numPreviousAttempts, originLocalIP)
	result, err := c.registrationClient.RegisterConnection(
		ctx, c.credentials.Auth(), c.credentials.TunnelID, c.connIndex, options,
	)
	if err != nil {
		c.controlStreamErr = err
		c.logger.Error("register connection: ", err)
		if c.registrationClient != nil {
			c.registrationClient.Close()
		}
		go c.close()
		return
	}
	if err := validateRegistrationResult(result); err != nil {
		c.controlStreamErr = err
		c.logger.Error("register connection: ", err)
		c.registrationClient.Close()
		go c.close()
		return
	}
	c.registrationResult = result
	c.inbound.notifyConnected(c.connIndex)

	c.logger.Info("connected to ", result.Location,
		" (connection ", result.ConnectionID, ")")

	<-ctx.Done()
	unregisterCtx, cancel := context.WithTimeout(context.Background(), c.gracePeriod)
	defer cancel()
	err = c.registrationClient.Unregister(unregisterCtx)
	if err != nil {
		c.logger.Debug("failed to unregister: ", err)
	}
	c.registrationClient.Close()
}

func (c *HTTP2Connection) handleH2DataStream(ctx context.Context, r *http.Request, w http.ResponseWriter, connectionType ConnectionType) {
	r.Header.Del(h2HeaderUpgrade)
	r.Header.Del(h2HeaderTCPSrc)

	flusher, ok := w.(http.Flusher)
	if !ok {
		c.logger.Error("response writer does not support flushing")
		return
	}

	var destination string
	if connectionType == ConnectionTypeTCP {
		destination = r.Host
		if destination == "" && r.URL != nil {
			destination = r.URL.Host
		}
	} else {
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
		}
		if r.URL.Host == "" {
			r.URL.Host = r.Host
		}
		destination = r.URL.String()
	}

	request := &ConnectRequest{
		Dest: destination,
		Type: connectionType,
	}
	request.Metadata = append(request.Metadata, Metadata{
		Key: metadataHTTPMethod,
		Val: r.Method,
	})
	request.Metadata = append(request.Metadata, Metadata{
		Key: metadataHTTPHost,
		Val: r.Host,
	})
	for name, values := range r.Header {
		for _, value := range values {
			request.Metadata = append(request.Metadata, Metadata{
				Key: metadataHTTPHeader + ":" + name,
				Val: value,
			})
		}
	}

	stream := &http2DataStream{
		reader:  r.Body,
		writer:  w,
		flusher: flusher,
	}
	respWriter := &http2ResponseWriter{
		writer:  w,
		flusher: flusher,
	}

	c.inbound.dispatchRequest(ctx, stream, respWriter, request)
}

type h2ConfigurationUpdateBody struct {
	Version int32           `json:"version"`
	Config  json.RawMessage `json:"config"`
}

func (c *HTTP2Connection) handleConfigurationUpdate(r *http.Request, w http.ResponseWriter) {
	var body h2ConfigurationUpdateBody
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		c.logger.Error("decode configuration update: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result := c.inbound.ApplyConfig(body.Version, body.Config)
	w.WriteHeader(http.StatusOK)
	if result.Err != nil {
		w.Write([]byte(`{"lastAppliedVersion":` + strconv.FormatInt(int64(result.LastAppliedVersion), 10) + `,"err":` + strconv.Quote(result.Err.Error()) + `}`))
		return
	}
	w.Write([]byte(`{"lastAppliedVersion":` + strconv.FormatInt(int64(result.LastAppliedVersion), 10) + `,"err":null}`))
}

func (c *HTTP2Connection) close() {
	c.closeOnce.Do(func() {
		c.conn.Close()
		c.activeRequests.Wait()
	})
}

// Close closes the HTTP/2 connection.
func (c *HTTP2Connection) Close() error {
	c.close()
	return nil
}

// http2Stream wraps an HTTP/2 request body (reader) and a flush-writer (writer) as an io.ReadWriteCloser.
// Used for the control stream.
type http2Stream struct {
	reader io.ReadCloser
	writer io.Writer
}

func newHTTP2Stream(reader io.ReadCloser, writer io.Writer) *http2Stream {
	return &http2Stream{reader: reader, writer: writer}
}

func (s *http2Stream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *http2Stream) Write(p []byte) (int, error) { return s.writer.Write(p) }
func (s *http2Stream) Close() error                { return s.reader.Close() }

// http2FlushWriter wraps an http.ResponseWriter and flushes after every write.
type http2FlushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (w *http2FlushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil {
		w.flusher.Flush()
	}
	return n, err
}

// http2DataStream wraps an HTTP/2 request/response pair as io.ReadWriteCloser for data streams.
type http2DataStream struct {
	reader  io.ReadCloser
	writer  http.ResponseWriter
	flusher http.Flusher
}

func (s *http2DataStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *http2DataStream) Write(p []byte) (int, error) {
	n, err := s.writer.Write(p)
	if err == nil {
		s.flusher.Flush()
	}
	return n, err
}

func (s *http2DataStream) Close() error {
	return s.reader.Close()
}

// http2ResponseWriter translates ConnectResponse metadata to HTTP/2 response headers.
type http2ResponseWriter struct {
	writer      http.ResponseWriter
	flusher     http.Flusher
	headersSent bool
}

func (w *http2ResponseWriter) WriteResponse(responseError error, metadata []Metadata) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true

	if responseError != nil {
		w.writer.Header().Set(h2HeaderResponseMeta, `{"src":"cloudflared"}`)
		w.writer.WriteHeader(http.StatusBadGateway)
		w.flusher.Flush()
		return nil
	}

	statusCode := http.StatusOK
	userHeaders := make(http.Header)

	for _, entry := range metadata {
		if entry.Key == metadataHTTPStatus {
			code, err := strconv.Atoi(entry.Val)
			if err == nil {
				statusCode = code
			}
			continue
		}
		if strings.HasPrefix(entry.Key, metadataHTTPHeader+":") {
			headerName := strings.TrimPrefix(entry.Key, metadataHTTPHeader+":")
			lower := strings.ToLower(headerName)

			if lower == "content-length" {
				w.writer.Header().Set(headerName, entry.Val)
			}

			if !isControlResponseHeader(lower) || isWebsocketClientHeader(lower) {
				userHeaders.Add(headerName, entry.Val)
			}
		}
	}

	w.writer.Header().Set(h2HeaderResponseUser, SerializeHeaders(userHeaders))
	w.writer.Header().Set(h2HeaderResponseMeta, h2ResponseMetaOrigin)

	if statusCode == http.StatusSwitchingProtocols {
		statusCode = http.StatusOK
	}

	w.writer.WriteHeader(statusCode)
	w.flusher.Flush()
	return nil
}
