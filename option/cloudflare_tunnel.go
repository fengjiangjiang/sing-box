package option

import "github.com/sagernet/sing/common/json/badoption"

type CloudflareTunnelInboundOptions struct {
	Token           string                               `json:"token,omitempty"`
	CredentialPath  string                               `json:"credential_path,omitempty"`
	HAConnections   int                                  `json:"ha_connections,omitempty"`
	Protocol        string                               `json:"protocol,omitempty"`
	EdgeIPVersion   int                                  `json:"edge_ip_version,omitempty"`
	DatagramVersion string                               `json:"datagram_version,omitempty"`
	GracePeriod     badoption.Duration                   `json:"grace_period,omitempty"`
	Region          string                               `json:"region,omitempty"`
	Ingress         []CloudflareTunnelIngressRule        `json:"ingress,omitempty"`
	OriginRequest   CloudflareTunnelOriginRequestOptions `json:"origin_request,omitempty"`
	WarpRouting     CloudflareTunnelWarpRoutingOptions   `json:"warp_routing,omitempty"`
}

type CloudflareTunnelIngressRule struct {
	Hostname      string                               `json:"hostname,omitempty"`
	Path          string                               `json:"path,omitempty"`
	Service       string                               `json:"service,omitempty"`
	OriginRequest CloudflareTunnelOriginRequestOptions `json:"origin_request,omitempty"`
}

type CloudflareTunnelOriginRequestOptions struct {
	ConnectTimeout         badoption.Duration         `json:"connect_timeout,omitempty"`
	TLSTimeout             badoption.Duration         `json:"tls_timeout,omitempty"`
	TCPKeepAlive           badoption.Duration         `json:"tcp_keep_alive,omitempty"`
	NoHappyEyeballs        bool                       `json:"no_happy_eyeballs,omitempty"`
	KeepAliveTimeout       badoption.Duration         `json:"keep_alive_timeout,omitempty"`
	KeepAliveConnections   int                        `json:"keep_alive_connections,omitempty"`
	HTTPHostHeader         string                     `json:"http_host_header,omitempty"`
	OriginServerName       string                     `json:"origin_server_name,omitempty"`
	MatchSNIToHost         bool                       `json:"match_sni_to_host,omitempty"`
	CAPool                 string                     `json:"ca_pool,omitempty"`
	NoTLSVerify            bool                       `json:"no_tls_verify,omitempty"`
	DisableChunkedEncoding bool                       `json:"disable_chunked_encoding,omitempty"`
	BastionMode            bool                       `json:"bastion_mode,omitempty"`
	ProxyAddress           string                     `json:"proxy_address,omitempty"`
	ProxyPort              uint                       `json:"proxy_port,omitempty"`
	ProxyType              string                     `json:"proxy_type,omitempty"`
	IPRules                []CloudflareTunnelIPRule   `json:"ip_rules,omitempty"`
	HTTP2Origin            bool                       `json:"http2_origin,omitempty"`
	Access                 CloudflareTunnelAccessRule `json:"access,omitempty"`
}

type CloudflareTunnelAccessRule struct {
	Required    bool     `json:"required,omitempty"`
	TeamName    string   `json:"team_name,omitempty"`
	AudTag      []string `json:"aud_tag,omitempty"`
	Environment string   `json:"environment,omitempty"`
}

type CloudflareTunnelIPRule struct {
	Prefix string `json:"prefix,omitempty"`
	Ports  []int  `json:"ports,omitempty"`
	Allow  bool   `json:"allow,omitempty"`
}

type CloudflareTunnelWarpRoutingOptions struct {
	ConnectTimeout badoption.Duration `json:"connect_timeout,omitempty"`
	MaxActiveFlows uint64             `json:"max_active_flows,omitempty"`
	TCPKeepAlive   badoption.Duration `json:"tcp_keep_alive,omitempty"`
}
