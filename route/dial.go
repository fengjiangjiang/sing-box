package route

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// DialRoutePacketConnection dials a routed connected UDP packet connection for metadata.
func (r *Router) DialRoutePacketConnection(ctx context.Context, metadata adapter.InboundContext) (N.PacketConn, error) {
	metadata.Network = N.NetworkUDP
	metadata.UDPConnect = true
	ctx = adapter.WithContext(ctx, &metadata)

	selectedRule, selectedOutbound, err := r.selectRoutedOutbound(ctx, &metadata, N.NetworkUDP)
	if err != nil {
		return nil, err
	}

	var remoteConn net.Conn
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(
			ctx,
			selectedOutbound,
			N.NetworkUDP,
			metadata.Destination,
			metadata.DestinationAddresses,
			metadata.NetworkStrategy,
			metadata.NetworkType,
			metadata.FallbackNetworkType,
			metadata.FallbackDelay,
		)
	} else {
		remoteConn, err = selectedOutbound.DialContext(ctx, N.NetworkUDP, metadata.Destination)
	}
	if err != nil {
		return nil, err
	}

	var packetConn N.PacketConn = bufio.NewUnbindPacketConn(remoteConn)
	for _, tracker := range r.trackers {
		packetConn = tracker.RoutedPacketConnection(ctx, packetConn, metadata, selectedRule, selectedOutbound)
	}
	if metadata.FakeIP {
		packetConn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(packetConn), metadata.OriginDestination, metadata.Destination)
	}
	return packetConn, nil
}

func (r *Router) selectRoutedOutbound(
	ctx context.Context,
	metadata *adapter.InboundContext,
	network string,
) (adapter.Rule, adapter.Outbound, error) {
	selectedRule, _, buffers, packetBuffers, err := r.matchRule(ctx, metadata, false, false, nil, nil)
	if len(buffers) > 0 {
		buf.ReleaseMulti(buffers)
	}
	if len(packetBuffers) > 0 {
		N.ReleaseMultiPacketBuffer(packetBuffers)
	}
	if err != nil {
		return nil, nil, err
	}

	var selectedOutbound adapter.Outbound
	if selectedRule != nil {
		switch action := selectedRule.Action().(type) {
		case *R.RuleActionRoute:
			var loaded bool
			selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
			if !loaded {
				return nil, nil, E.New("outbound not found: ", action.Outbound)
			}
		case *R.RuleActionBypass:
			if action.Outbound != "" {
				var loaded bool
				selectedOutbound, loaded = r.outbound.Outbound(action.Outbound)
				if !loaded {
					return nil, nil, E.New("outbound not found: ", action.Outbound)
				}
			}
		case *R.RuleActionReject:
			if action.Method == C.RuleActionRejectMethodReply {
				return nil, nil, E.New("reject method `reply` is not supported for dialed connections")
			}
			return nil, nil, action.Error(ctx)
		case *R.RuleActionHijackDNS:
			return nil, nil, E.New("DNS hijack is not supported for dialed connections")
		}
	}

	if selectedOutbound == nil {
		selectedOutbound = r.outbound.Default()
	}
	if !common.Contains(selectedOutbound.Network(), network) {
		return nil, nil, E.New(network, " is not supported by outbound: ", selectedOutbound.Tag())
	}
	return selectedRule, selectedOutbound, nil
}
