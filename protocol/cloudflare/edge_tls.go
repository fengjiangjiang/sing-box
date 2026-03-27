//go:build with_cloudflared

package cloudflare

import (
	"crypto/tls"
	"crypto/x509"
)

func newEdgeTLSConfig(rootCAs *x509.CertPool, serverName string, nextProtos []string) *tls.Config {
	return &tls.Config{
		RootCAs:          rootCAs,
		ServerName:       serverName,
		NextProtos:       nextProtos,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
}
