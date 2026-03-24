//go:build with_cloudflared

package cloudflare

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

type routedPipeTCPOptions struct {
	timeout     time.Duration
	onHandshake func(net.Conn)
}

type routedPipeTCPConn struct {
	net.Conn
	handshakeOnce sync.Once
	onHandshake   func(net.Conn)
}

func (c *routedPipeTCPConn) ConnHandshakeSuccess(conn net.Conn) error {
	if c.onHandshake != nil {
		c.handshakeOnce.Do(func() {
			c.onHandshake(conn)
		})
	}
	return nil
}

func (i *Inbound) dialRouterTCPWithMetadata(ctx context.Context, metadata adapter.InboundContext, options routedPipeTCPOptions) (net.Conn, func(), error) {
	input, output := pipe.Pipe()
	routerConn := &routedPipeTCPConn{
		Conn:        output,
		onHandshake: options.onHandshake,
	}
	done := make(chan struct{})

	routeCtx := ctx
	var cancel context.CancelFunc
	if options.timeout > 0 {
		routeCtx, cancel = context.WithTimeout(ctx, options.timeout)
	}

	var closeOnce sync.Once
	closePipe := func() {
		closeOnce.Do(func() {
			if cancel != nil {
				cancel()
			}
			common.Close(input, routerConn)
		})
	}
	go i.router.RouteConnectionEx(routeCtx, routerConn, metadata, N.OnceClose(func(it error) {
		closePipe()
		close(done)
	}))

	return input, func() {
		closePipe()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}, nil
}

func applyTCPKeepAlive(conn net.Conn, keepAlive time.Duration) error {
	if keepAlive <= 0 {
		return nil
	}
	type keepAliveConn interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}
	tcpConn, ok := conn.(keepAliveConn)
	if !ok {
		return nil
	}
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	return tcpConn.SetKeepAlivePeriod(keepAlive)
}
