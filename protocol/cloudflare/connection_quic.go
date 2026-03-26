//go:build with_cloudflared

package cloudflare

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

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
	conn                quicConnection
	logger              log.ContextLogger
	edgeAddr            *EdgeAddr
	connIndex           uint8
	credentials         Credentials
	connectorID         uuid.UUID
	datagramVersion     string
	features            []string
	numPreviousAttempts uint8
	gracePeriod         time.Duration
	registrationClient  registrationRPCClient
	registrationResult  *RegistrationResult
	onConnected         func()

	serveCancel       context.CancelFunc
	registrationClose sync.Once
	shutdownOnce      sync.Once
	closeOnce         sync.Once
}

type quicConnection interface {
	OpenStream() (*quic.Stream, error)
	AcceptStream(ctx context.Context) (*quic.Stream, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(data []byte) error
	LocalAddr() net.Addr
	CloseWithError(code quic.ApplicationErrorCode, reason string) error
}

type closeableQUICConn struct {
	*quic.Conn
	udpConn *net.UDPConn
}

func (c *closeableQUICConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	err := c.Conn.CloseWithError(code, reason)
	_ = c.udpConn.Close()
	return err
}

var (
	quicPortByConnIndex = make(map[uint8]int)
	quicPortAccess      sync.Mutex
)

// NewQUICConnection dials the edge and establishes a QUIC connection.
func NewQUICConnection(
	ctx context.Context,
	edgeAddr *EdgeAddr,
	connIndex uint8,
	credentials Credentials,
	connectorID uuid.UUID,
	datagramVersion string,
	features []string,
	numPreviousAttempts uint8,
	gracePeriod time.Duration,
	controlDialer N.Dialer,
	onConnected func(),
	logger log.ContextLogger,
) (*QUICConnection, error) {
	rootCAs, err := cloudflareRootCertPool()
	if err != nil {
		return nil, E.Cause(err, "load Cloudflare root CAs")
	}

	tlsConfig := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: quicEdgeSNI,
		NextProtos: []string{quicEdgeALPN},
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

	udpConn, err := createUDPConnForConnIndex(ctx, connIndex, edgeAddr, controlDialer)
	if err != nil {
		return nil, E.Cause(err, "listen UDP for QUIC edge")
	}

	conn, err := quic.Dial(ctx, udpConn, edgeAddr.UDP, tlsConfig, quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, E.Cause(err, "dial QUIC edge")
	}

	return &QUICConnection{
		conn:                &closeableQUICConn{Conn: conn, udpConn: udpConn},
		logger:              logger,
		edgeAddr:            edgeAddr,
		connIndex:           connIndex,
		credentials:         credentials,
		connectorID:         connectorID,
		datagramVersion:     datagramVersion,
		features:            features,
		numPreviousAttempts: numPreviousAttempts,
		gracePeriod:         gracePeriod,
		onConnected:         onConnected,
	}, nil
}

func createUDPConnForConnIndex(ctx context.Context, connIndex uint8, edgeAddr *EdgeAddr, controlDialer N.Dialer) (*net.UDPConn, error) {
	quicPortAccess.Lock()
	defer quicPortAccess.Unlock()

	packetConn, err := controlDialer.ListenPacket(ctx, M.SocksaddrFrom(edgeAddr.UDP.AddrPort().Addr(), edgeAddr.UDP.AddrPort().Port()))
	if err != nil {
		return nil, err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		packetConn.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T", packetConn)
	}
	udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		udpConn.Close()
		return nil, fmt.Errorf("unexpected local UDP address type %T", udpConn.LocalAddr())
	}
	quicPortByConnIndex[connIndex] = udpAddr.Port
	return udpConn, nil
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
		q.Close()
		return err
	}

	q.logger.Info("connected to ", q.registrationResult.Location,
		" (connection ", q.registrationResult.ConnectionID, ")")

	serveCtx, serveCancel := context.WithCancel(context.WithoutCancel(ctx))
	q.serveCancel = serveCancel

	errChan := make(chan error, 2)

	go func() {
		errChan <- q.acceptStreams(serveCtx, handler)
	}()

	go func() {
		errChan <- q.handleDatagrams(serveCtx, handler)
	}()

	select {
	case <-ctx.Done():
		q.gracefulShutdown()
		<-errChan
		return ctx.Err()
	case err = <-errChan:
		q.forceClose()
		if ctx.Err() != nil {
			return ctx.Err()
		}
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
	if err := validateRegistrationResult(result); err != nil {
		return err
	}
	q.registrationResult = result
	if q.onConnected != nil {
		q.onConnected()
	}
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
		handler.HandleDataStream(ctx, &nopCloserReadWriter{ReadWriteCloser: rwc}, request, q.connIndex)

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

func (q *QUICConnection) DatagramVersion() string {
	return q.datagramVersion
}

func (q *QUICConnection) OpenRPCStream(ctx context.Context) (io.ReadWriteCloser, error) {
	stream, err := q.conn.OpenStream()
	if err != nil {
		return nil, E.Cause(err, "open rpc stream")
	}
	rwc := newStreamReadWriteCloser(stream)
	if err := WriteRPCStreamSignature(rwc); err != nil {
		rwc.Close()
		return nil, E.Cause(err, "write rpc stream signature")
	}
	return rwc, nil
}

func (q *QUICConnection) gracefulShutdown() {
	q.shutdownOnce.Do(func() {
		if q.registrationClient == nil || q.registrationResult == nil {
			q.closeNow("connection closed")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), q.gracePeriod)
		err := q.registrationClient.Unregister(ctx)
		cancel()
		if err != nil {
			q.logger.Debug("failed to unregister: ", err)
		}
		q.closeRegistrationClient()
		if q.gracePeriod > 0 {
			timer := time.NewTimer(q.gracePeriod)
			<-timer.C
			timer.Stop()
		}
		q.closeNow("graceful shutdown")
	})
}

func (q *QUICConnection) forceClose() {
	q.shutdownOnce.Do(func() {
		q.closeNow("connection closed")
	})
}

func (q *QUICConnection) closeRegistrationClient() {
	q.registrationClose.Do(func() {
		if q.registrationClient != nil {
			_ = q.registrationClient.Close()
		}
	})
}

func (q *QUICConnection) closeNow(reason string) {
	q.closeOnce.Do(func() {
		if q.serveCancel != nil {
			q.serveCancel()
		}
		q.closeRegistrationClient()
		_ = q.conn.CloseWithError(0, reason)
	})
}

// Close closes the QUIC connection immediately.
func (q *QUICConnection) Close() error {
	q.forceClose()
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

// nopCloserReadWriter lets handlers stop consuming the read side without closing
// the underlying stream write side. This matches cloudflared's QUIC HTTP behavior,
// where the request body can be closed before the response is fully written.
type nopCloserReadWriter struct {
	io.ReadWriteCloser

	sawEOF bool
	closed uint32
}

func (n *nopCloserReadWriter) Read(p []byte) (int, error) {
	if n.sawEOF {
		return 0, io.EOF
	}
	if atomic.LoadUint32(&n.closed) > 0 {
		return 0, fmt.Errorf("closed by handler")
	}

	readLen, err := n.ReadWriteCloser.Read(p)
	if err == io.EOF {
		n.sawEOF = true
	}
	return readLen, err
}

func (n *nopCloserReadWriter) Close() error {
	atomic.StoreUint32(&n.closed, 1)
	return nil
}
