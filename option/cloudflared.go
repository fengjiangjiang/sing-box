package option

import "github.com/sagernet/sing/common/json/badoption"

type CloudflaredInboundOptions struct {
	Token           string             `json:"token,omitempty"`
	HAConnections   int                `json:"ha_connections,omitempty"`
	Protocol        string             `json:"protocol,omitempty"`
	ControlDialer   DialerOptions      `json:"control_dialer,omitempty"`
	TunnelDialer    DialerOptions      `json:"tunnel_dialer,omitempty"`
	EdgeIPVersion   int                `json:"edge_ip_version,omitempty"`
	DatagramVersion string             `json:"datagram_version,omitempty"`
	GracePeriod     badoption.Duration `json:"grace_period,omitempty"`
	Region          string             `json:"region,omitempty"`
}
