//go:build with_cloudflare_tunnel

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/protocol/cloudflare"
)

func registerCloudflareTunnelInbound(registry *inbound.Registry) {
	cloudflare.RegisterInbound(registry)
}
