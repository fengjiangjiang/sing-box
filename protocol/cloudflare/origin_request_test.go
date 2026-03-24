//go:build with_cloudflare_tunnel

package cloudflare

import "testing"

func TestOriginTLSServerName(t *testing.T) {
	t.Run("origin server name overrides host", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{
			OriginServerName: "origin.example.com",
			MatchSNIToHost:   true,
		}, "request.example.com")
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host strips port", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, "request.example.com:443")
		if serverName != "request.example.com" {
			t.Fatalf("expected request.example.com, got %s", serverName)
		}
	})

	t.Run("disabled match keeps empty server name", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{}, "request.example.com")
		if serverName != "" {
			t.Fatalf("expected empty server name, got %s", serverName)
		}
	})
}
