//go:build !with_cloudflare_tunnel

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerCloudflareTunnelInbound(registry *inbound.Registry) {
	inbound.Register[option.CloudflareTunnelInboundOptions](registry, C.TypeCloudflareTunnel, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CloudflareTunnelInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`Cloudflare Tunnel is not included in this build, rebuild with -tags with_cloudflare_tunnel`)
	})
}
