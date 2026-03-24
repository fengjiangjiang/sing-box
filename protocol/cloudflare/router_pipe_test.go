//go:build with_cloudflared

package cloudflare

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestHandleTCPStreamUsesRouteConnectionEx(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

	router := &countingRouter{}
	inboundInstance := newSpecialServiceInboundWithRouter(t, router)

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	responseDone := respWriter.done
	finished := make(chan struct{})
	go func() {
		inboundInstance.handleTCPStream(context.Background(), serverSide, respWriter, adapter.InboundContext{
			Destination: M.ParseSocksaddr(listener.Addr().String()),
		})
		close(finished)
	}()

	select {
	case <-responseDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connect response")
	}
	if respWriter.err != nil {
		t.Fatal("unexpected response error: ", respWriter.err)
	}

	if err := clientSide.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ping")
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(clientSide, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(payload) {
		t.Fatalf("unexpected echo payload: %q", string(response))
	}
	if router.count.Load() != 1 {
		t.Fatalf("expected RouteConnectionEx to be used once, got %d", router.count.Load())
	}

	_ = clientSide.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP stream handler to exit")
	}
}

func TestHandleTCPStreamWritesOptimisticAck(t *testing.T) {
	router := &blockingRouteRouter{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	inboundInstance := newSpecialServiceInboundWithRouter(t, router)

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	responseDone := respWriter.done
	finished := make(chan struct{})
	go func() {
		inboundInstance.handleTCPStream(context.Background(), serverSide, respWriter, adapter.InboundContext{
			Destination: M.ParseSocksaddr("127.0.0.1:443"),
		})
		close(finished)
	}()

	select {
	case <-router.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for router goroutine to start")
	}
	select {
	case <-responseDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for optimistic connect response")
	}
	if respWriter.err != nil {
		t.Fatal("unexpected response error: ", respWriter.err)
	}

	close(router.release)
	_ = clientSide.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP stream handler to exit")
	}
}

func TestRoutedPipeTCPConnHandshakeAppliesKeepAlive(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	remoteConn := &keepAliveTestConn{Conn: right}
	routerConn := &routedPipeTCPConn{
		Conn: left,
		onHandshake: func(conn net.Conn) {
			_ = applyTCPKeepAlive(conn, 15*time.Second)
		},
	}
	if err := routerConn.ConnHandshakeSuccess(remoteConn); err != nil {
		t.Fatal(err)
	}
	if !remoteConn.enabled {
		t.Fatal("expected keepalive to be enabled")
	}
	if remoteConn.period != 15*time.Second {
		t.Fatalf("unexpected keepalive period: %s", remoteConn.period)
	}
}

type blockingRouteRouter struct {
	testRouter
	started chan struct{}
	release chan struct{}
}

func (r *blockingRouteRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	close(r.started)
	<-r.release
	_ = conn.Close()
	onClose(nil)
}

type keepAliveTestConn struct {
	net.Conn
	enabled bool
	period  time.Duration
}

func (c *keepAliveTestConn) SetKeepAlive(enabled bool) error {
	c.enabled = enabled
	return nil
}

func (c *keepAliveTestConn) SetKeepAlivePeriod(period time.Duration) error {
	c.period = period
	return nil
}
