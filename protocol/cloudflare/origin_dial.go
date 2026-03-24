//go:build with_cloudflared

package cloudflare

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

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

	return originDialer.DialRoutePacketConnection(ctx, adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     N.NetworkUDP,
		Destination: M.SocksaddrFromNetIP(destination),
		UDPConnect:  true,
	})
}
