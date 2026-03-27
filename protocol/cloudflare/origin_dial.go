//go:build with_cloudflared

package cloudflare

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const originUDPWriteTimeout = 200 * time.Millisecond

type udpWriteDeadlinePacketConn struct {
	N.PacketConn
}

func (c *udpWriteDeadlinePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_ = c.PacketConn.SetWriteDeadline(time.Now().Add(originUDPWriteTimeout))
	defer func() {
		_ = c.PacketConn.SetWriteDeadline(time.Time{})
	}()
	return c.PacketConn.WritePacket(buffer, destination)
}

type routedOriginPacketDialer interface {
	DialRoutePacketConnection(ctx context.Context, metadata adapter.InboundContext) (N.PacketConn, error)
}

func (i *Inbound) dialWarpPacketConnection(ctx context.Context, destination netip.AddrPort) (N.PacketConn, error) {
	originDialer, ok := i.router.(routedOriginPacketDialer)
	if !ok {
		return nil, E.New("router does not support cloudflare routed packet dialing")
	}

	warpRouting := i.configManager.Snapshot().WarpRouting
	if warpRouting.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, warpRouting.ConnectTimeout)
		defer cancel()
	}

	packetConn, err := originDialer.DialRoutePacketConnection(ctx, adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Destination: M.SocksaddrFromNetIP(destination),
		UDPConnect:  true,
	})
	if err != nil {
		return nil, err
	}
	return &udpWriteDeadlinePacketConn{PacketConn: packetConn}, nil
}
