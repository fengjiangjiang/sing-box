//go:build with_cloudflared

package cloudflare

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/cloudflare/tunnelrpc"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type blockingRPCStream struct {
	closed chan struct{}
}

func newBlockingRPCStream() *blockingRPCStream {
	return &blockingRPCStream{closed: make(chan struct{})}
}

func (s *blockingRPCStream) Read(_ []byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *blockingRPCStream) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *blockingRPCStream) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

type blockingPacketDialRouter struct {
	testRouter
	entered chan struct{}
	release chan struct{}
}

func (r *blockingPacketDialRouter) DialRoutePacketConnection(ctx context.Context, metadata adapter.InboundContext) (N.PacketConn, error) {
	select {
	case <-r.entered:
	default:
		close(r.entered)
	}

	select {
	case <-r.release:
		return newBlockingPacketConn(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newRPCInbound(t *testing.T, router adapter.Router) *Inbound {
	t.Helper()

	inboundInstance := newLimitedInbound(t, 0)
	inboundInstance.router = router
	return inboundInstance
}

func newRPCClientPair(t *testing.T, ctx context.Context) (tunnelrpc.CloudflaredServer, io.Closer, io.Closer, net.Conn, net.Conn) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	transport := safeTransport(clientSide)
	clientConn := newRPCClientConn(transport, ctx)
	client := tunnelrpc.CloudflaredServer{Client: clientConn.Bootstrap(ctx)}
	return client, clientConn, transport, serverSide, clientSide
}

func TestServeRPCStreamRespectsContextDeadline(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 0)
	stream := newBlockingRPCStream()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		ServeRPCStream(ctx, stream, inboundInstance, NewDatagramV2Muxer(inboundInstance, &captureDatagramSender{}, inboundInstance.logger), inboundInstance.logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeRPCStream to exit after context deadline")
	}
}

func TestServeV3RPCStreamRespectsContextDeadline(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 0)
	stream := newBlockingRPCStream()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		ServeV3RPCStream(ctx, stream, inboundInstance, inboundInstance.logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeV3RPCStream to exit after context deadline")
	}
}

func TestV2RPCAckAllowsConcurrentDispatch(t *testing.T) {
	router := &blockingPacketDialRouter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	inboundInstance := newRPCInbound(t, router)
	muxer := NewDatagramV2Muxer(inboundInstance, &captureDatagramSender{}, inboundInstance.logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, clientConn, transport, serverSide, clientSide := newRPCClientPair(t, ctx)
	defer clientConn.Close()
	defer transport.Close()
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		ServeRPCStream(ctx, serverSide, inboundInstance, muxer, inboundInstance.logger)
		close(done)
	}()

	registerPromise := client.RegisterUdpSession(ctx, func(p tunnelrpc.SessionManager_registerUdpSession_Params) error {
		sessionID := uuid.New()
		if err := p.SetSessionId(sessionID[:]); err != nil {
			return err
		}
		if err := p.SetDstIp([]byte{127, 0, 0, 1}); err != nil {
			return err
		}
		p.SetDstPort(53)
		p.SetCloseAfterIdleHint(int64(time.Second))
		return p.SetTraceContext("")
	})

	select {
	case <-router.entered:
	case <-time.After(time.Second):
		t.Fatal("expected register RPC to enter the blocking dial")
	}

	updateCtx, updateCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer updateCancel()
	updatePromise := client.UpdateConfiguration(updateCtx, func(p tunnelrpc.ConfigurationManager_updateConfiguration_Params) error {
		p.SetVersion(1)
		return p.SetConfig([]byte(`{"ingress":[{"service":"http_status:503"}]}`))
	})
	if _, err := updatePromise.Result().Struct(); err != nil {
		t.Fatalf("expected concurrent update RPC to succeed, got %v", err)
	}

	close(router.release)
	if _, err := registerPromise.Result().Struct(); err != nil {
		t.Fatalf("expected register RPC to complete, got %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeRPCStream to exit")
	}
}
