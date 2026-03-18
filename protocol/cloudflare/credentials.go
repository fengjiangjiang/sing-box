//go:build with_cloudflare_tunnel

package cloudflare

import "github.com/google/uuid"

// Credentials contains all info needed to run a tunnel.
type Credentials struct {
	AccountTag   string    `json:"AccountTag"`
	TunnelSecret []byte    `json:"TunnelSecret"`
	TunnelID     uuid.UUID `json:"TunnelID"`
	Endpoint     string    `json:"Endpoint,omitempty"`
}

// TunnelToken is the compact token format used in the --token flag.
// Field names match cloudflared's JSON encoding.
type TunnelToken struct {
	AccountTag   string    `json:"a"`
	TunnelSecret []byte    `json:"s"`
	TunnelID     uuid.UUID `json:"t"`
	Endpoint     string    `json:"e,omitempty"`
}

func (t TunnelToken) ToCredentials() Credentials {
	return Credentials{
		AccountTag:   t.AccountTag,
		TunnelSecret: t.TunnelSecret,
		TunnelID:     t.TunnelID,
		Endpoint:     t.Endpoint,
	}
}

// TunnelAuth is the authentication data sent during tunnel registration.
type TunnelAuth struct {
	AccountTag   string
	TunnelSecret []byte
}

func (c *Credentials) Auth() TunnelAuth {
	return TunnelAuth{
		AccountTag:   c.AccountTag,
		TunnelSecret: c.TunnelSecret,
	}
}
