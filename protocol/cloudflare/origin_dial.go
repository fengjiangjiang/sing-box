//go:build with_cloudflared

package cloudflare

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type routedOriginDialer interface {
	DialRouteConnection(ctx context.Context, metadata adapter.InboundContext) (net.Conn, error)
	DialRoutePacketConnection(ctx context.Context, metadata adapter.InboundContext) (N.PacketConn, error)
}

func (i *Inbound) dialWarpTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	originDialer, ok := i.router.(routedOriginDialer)
	if !ok {
		return nil, E.New("router does not support cloudflare routed dialing")
	}

	warpRouting := i.configManager.Snapshot().WarpRouting
	if warpRouting.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, warpRouting.ConnectTimeout)
		defer cancel()
	}

	conn, err := originDialer.DialRouteConnection(ctx, adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkTCP,
		Destination: destination,
	})
	if err != nil {
		return nil, err
	}
	_ = applyTCPKeepAlive(conn, warpRouting.TCPKeepAlive)
	return conn, nil
}

func (i *Inbound) dialWarpPacketConnection(ctx context.Context, destination netip.AddrPort) (N.PacketConn, error) {
	originDialer, ok := i.router.(routedOriginDialer)
	if !ok {
		return nil, E.New("router does not support cloudflare routed packet dialing")
	}

	warpRouting := i.configManager.Snapshot().WarpRouting
	if warpRouting.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, warpRouting.ConnectTimeout)
		defer cancel()
	}

	return originDialer.DialRoutePacketConnection(ctx, adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Destination: M.SocksaddrFromNetIP(destination),
		UDPConnect:  true,
	})
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
