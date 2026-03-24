//go:build with_cloudflare_tunnel

package cloudflare

import (
	"net/http"
	"net/url"
	"testing"
)

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

func TestApplyHTTPTransportProxy(t *testing.T) {
	transport := &http.Transport{}
	applyHTTPTransportProxy(transport, OriginRequestConfig{
		ProxyAddress: "127.0.0.1",
		ProxyPort:    8080,
		ProxyType:    "http",
	})
	if transport.Proxy == nil {
		t.Fatal("expected proxy function to be configured")
	}
	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected proxy URL: %#v", proxyURL)
	}
}

func TestNewDirectOriginTransportNoHappyEyeballs(t *testing.T) {
	inbound := &Inbound{}
	transport, cleanup, err := inbound.newDirectOriginTransport(ResolvedService{
		Kind: ResolvedServiceHelloWorld,
		BaseURL: &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1:8080",
		},
		OriginRequest: OriginRequestConfig{
			NoHappyEyeballs: true,
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if transport.Proxy != nil {
		t.Fatal("expected no proxy when proxy fields are empty")
	}
	if transport.DialContext == nil {
		t.Fatal("expected custom direct dial context")
	}
}
