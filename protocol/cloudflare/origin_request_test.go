//go:build with_cloudflared

package cloudflare

import (
	"io"
	"net/http"
	"net/url"
	"strings"
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
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
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

func TestNormalizeOriginRequestSetsKeepAliveAndEmptyUserAgent(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.com/path", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	request = normalizeOriginRequest(ConnectionTypeHTTP, request, OriginRequestConfig{})
	if connection := request.Header.Get("Connection"); connection != "keep-alive" {
		t.Fatalf("expected keep-alive connection header, got %q", connection)
	}
	if values, exists := request.Header["User-Agent"]; !exists || len(values) != 1 || values[0] != "" {
		t.Fatalf("expected empty User-Agent header, got %#v", request.Header["User-Agent"])
	}
}

func TestNormalizeOriginRequestDisableChunkedEncoding(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://example.com/path", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Length", "7")

	request = normalizeOriginRequest(ConnectionTypeHTTP, request, OriginRequestConfig{
		DisableChunkedEncoding: true,
	})
	if len(request.TransferEncoding) != 2 || request.TransferEncoding[0] != "gzip" || request.TransferEncoding[1] != "deflate" {
		t.Fatalf("unexpected transfer encoding: %#v", request.TransferEncoding)
	}
	if request.ContentLength != 7 {
		t.Fatalf("expected content length 7, got %d", request.ContentLength)
	}
}

func TestNormalizeOriginRequestWebsocket(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.com/path", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}

	request = normalizeOriginRequest(ConnectionTypeWebsocket, request, OriginRequestConfig{})
	if connection := request.Header.Get("Connection"); connection != "Upgrade" {
		t.Fatalf("expected websocket connection header, got %q", connection)
	}
	if upgrade := request.Header.Get("Upgrade"); upgrade != "websocket" {
		t.Fatalf("expected websocket upgrade header, got %q", upgrade)
	}
	if version := request.Header.Get("Sec-Websocket-Version"); version != "13" {
		t.Fatalf("expected websocket version 13, got %q", version)
	}
	if request.ContentLength != 0 {
		t.Fatalf("expected websocket content length 0, got %d", request.ContentLength)
	}
	if request.Body != nil {
		t.Fatal("expected websocket body to be nil")
	}
}
