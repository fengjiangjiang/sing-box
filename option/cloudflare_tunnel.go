package option

import "github.com/sagernet/sing/common/json/badoption"

type CloudflareTunnelInboundOptions struct {
	Token             string             `json:"token,omitempty"`
	CredentialPath    string             `json:"credential_path,omitempty"`
	HAConnections     int                `json:"ha_connections,omitempty"`
	Protocol          string             `json:"protocol,omitempty"`
	EdgeIPVersion     int                `json:"edge_ip_version,omitempty"`
	DatagramVersion   string             `json:"datagram_version,omitempty"`
	GracePeriod badoption.Duration `json:"grace_period,omitempty"`
}
