//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/uuid"
)

const (
	quicEdgeSNI  = "quic.cftunnel.com"
	quicEdgeALPN = "argotunnel"

	quicHandshakeIdleTimeout = 5 * time.Second
	quicMaxIdleTimeout       = 5 * time.Second
	quicKeepAlivePeriod      = 1 * time.Second
)

func quicInitialPacketSize(ipVersion int) uint16 {
	initialPacketSize := uint16(1252)
	if ipVersion == 4 {
		initialPacketSize = 1232
	}
	return initialPacketSize
}

// QUICConnection manages a single QUIC connection to the Cloudflare edge.
type QUICConnection struct {
	conn                *quic.Conn
	logger              log.ContextLogger
	edgeAddr            *EdgeAddr
	connIndex           uint8
	credentials         Credentials
	connectorID         uuid.UUID
	features            []string
	numPreviousAttempts uint8
	gracePeriod         time.Duration
	registrationClient  *RegistrationClient
	registrationResult  *RegistrationResult

	closeOnce sync.Once
}

// NewQUICConnection dials the edge and establishes a QUIC connection.
func NewQUICConnection(
	ctx context.Context,
	edgeAddr *EdgeAddr,
	connIndex uint8,
	credentials Credentials,
	connectorID uuid.UUID,
	features []string,
	numPreviousAttempts uint8,
	gracePeriod time.Duration,
	logger log.ContextLogger,
) (*QUICConnection, error) {
	rootCAs, err := cloudflareRootCertPool()
	if err != nil {
		return nil, E.Cause(err, "load Cloudflare root CAs")
	}

	tlsConfig := &tls.Config{
		RootCAs:          rootCAs,
		ServerName:       quicEdgeSNI,
		NextProtos:       []string{quicEdgeALPN},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}

	quicConfig := &quic.Config{
		HandshakeIdleTimeout:  quicHandshakeIdleTimeout,
		MaxIdleTimeout:        quicMaxIdleTimeout,
		KeepAlivePeriod:       quicKeepAlivePeriod,
		MaxIncomingStreams:    1 << 60,
		MaxIncomingUniStreams: 1 << 60,
		EnableDatagrams:       true,
		InitialPacketSize:     quicInitialPacketSize(edgeAddr.IPVersion),
	}

	conn, err := quic.DialAddr(ctx, edgeAddr.UDP.String(), tlsConfig, quicConfig)
	if err != nil {
		return nil, E.Cause(err, "dial QUIC edge")
	}

	return &QUICConnection{
		conn:                conn,
		logger:              logger,
		edgeAddr:            edgeAddr,
		connIndex:           connIndex,
		credentials:         credentials,
		connectorID:         connectorID,
		features:            features,
		numPreviousAttempts: numPreviousAttempts,
		gracePeriod:         gracePeriod,
	}, nil
}

// Serve runs the QUIC connection: registers, accepts streams, handles datagrams.
// Blocks until the context is cancelled or a fatal error occurs.
func (q *QUICConnection) Serve(ctx context.Context, handler StreamHandler) error {
	controlStream, err := q.conn.OpenStream()
	if err != nil {
		return E.Cause(err, "open control stream")
	}

	err = q.register(ctx, controlStream)
	if err != nil {
		controlStream.Close()
		return err
	}

	q.logger.Info("connected to ", q.registrationResult.Location,
		" (connection ", q.registrationResult.ConnectionID, ")")

	errChan := make(chan error, 2)

	go func() {
		errChan <- q.acceptStreams(ctx, handler)
	}()

	go func() {
		errChan <- q.handleDatagrams(ctx, handler)
	}()

	select {
	case <-ctx.Done():
		q.gracefulShutdown()
		return ctx.Err()
	case err = <-errChan:
		q.gracefulShutdown()
		return err
	}
}

func (q *QUICConnection) register(ctx context.Context, stream *quic.Stream) error {
	q.registrationClient = NewRegistrationClient(ctx, newStreamReadWriteCloser(stream))

	host, _, _ := net.SplitHostPort(q.conn.LocalAddr().String())
	originLocalIP := net.ParseIP(host)
	options := BuildConnectionOptions(q.connectorID, q.features, q.numPreviousAttempts, originLocalIP)
	result, err := q.registrationClient.RegisterConnection(
		ctx, q.credentials.Auth(), q.credentials.TunnelID, q.connIndex, options,
	)
	if err != nil {
		return E.Cause(err, "register connection")
	}
	q.registrationResult = result
	return nil
}

func (q *QUICConnection) acceptStreams(ctx context.Context, handler StreamHandler) error {
	for {
		stream, err := q.conn.AcceptStream(ctx)
		if err != nil {
			return E.Cause(err, "accept stream")
		}
		go q.handleStream(ctx, stream, handler)
	}
}

func (q *QUICConnection) handleStream(ctx context.Context, stream *quic.Stream, handler StreamHandler) {
	rwc := newStreamReadWriteCloser(stream)
	defer rwc.Close()

	streamType, err := ReadStreamSignature(rwc)
	if err != nil {
		q.logger.Debug("failed to read stream signature: ", err)
		return
	}

	switch streamType {
	case StreamTypeData:
		request, err := ReadConnectRequest(rwc)
		if err != nil {
			q.logger.Debug("failed to read connect request: ", err)
			return
		}
		handler.HandleDataStream(ctx, rwc, request, q.connIndex)

	case StreamTypeRPC:
		handler.HandleRPCStreamWithSender(ctx, rwc, q.connIndex, q)
	}
}

func (q *QUICConnection) handleDatagrams(ctx context.Context, handler StreamHandler) error {
	for {
		datagram, err := q.conn.ReceiveDatagram(ctx)
		if err != nil {
			return E.Cause(err, "receive datagram")
		}
		handler.HandleDatagram(ctx, datagram, q)
	}
}

// SendDatagram sends a QUIC datagram to the edge.
func (q *QUICConnection) SendDatagram(data []byte) error {
	return q.conn.SendDatagram(data)
}

func (q *QUICConnection) gracefulShutdown() {
	q.closeOnce.Do(func() {
		if q.registrationClient != nil {
			ctx, cancel := context.WithTimeout(context.Background(), q.gracePeriod)
			defer cancel()
			err := q.registrationClient.Unregister(ctx)
			if err != nil {
				q.logger.Debug("failed to unregister: ", err)
			}
			q.registrationClient.Close()
		}
		q.conn.CloseWithError(0, "graceful shutdown")
	})
}

// Close closes the QUIC connection immediately.
func (q *QUICConnection) Close() error {
	q.gracefulShutdown()
	return nil
}

// StreamHandler handles incoming edge streams and datagrams.
type StreamHandler interface {
	HandleDataStream(ctx context.Context, stream io.ReadWriteCloser, request *ConnectRequest, connIndex uint8)
	HandleRPCStream(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8)
	HandleRPCStreamWithSender(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8, sender DatagramSender)
	HandleDatagram(ctx context.Context, datagram []byte, sender DatagramSender)
}

// DatagramSender can send QUIC datagrams back to the edge.
type DatagramSender interface {
	SendDatagram(data []byte) error
}

// streamReadWriteCloser adapts a *quic.Stream to io.ReadWriteCloser.
type streamReadWriteCloser struct {
	stream *quic.Stream
}

func newStreamReadWriteCloser(stream *quic.Stream) *streamReadWriteCloser {
	return &streamReadWriteCloser{stream: stream}
}

func (s *streamReadWriteCloser) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *streamReadWriteCloser) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *streamReadWriteCloser) Close() error {
	s.stream.CancelRead(0)
	return s.stream.Close()
}
