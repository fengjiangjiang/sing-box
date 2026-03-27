//go:build with_cloudflared

package cloudflare

import (
	stdTLS "crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
)

func TestNewDirectOriginTransportUnix(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/cf-origin-%d.sock", time.Now().UnixNano())
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go serveTestHTTPOverListener(listener, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("unix-ok"))
	})

	inboundInstance := &Inbound{}
	transport, cleanup, err := inboundInstance.newDirectOriginTransport(ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: socketPath,
		BaseURL: &url.URL{
			Scheme: "http",
			Host:   "localhost",
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	client := &http.Client{Transport: transport}
	resp, err := client.Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "unix-ok" {
		t.Fatalf("unexpected response body: %q", string(body))
	}
}

func TestNewDirectOriginTransportUnixTLS(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/cf-origin-tls-%d.sock", time.Now().UnixNano())
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := boxTLS.GenerateKeyPair(nil, nil, time.Now, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := stdTLS.NewListener(listener, &stdTLS.Config{
		Certificates: []stdTLS.Certificate{*certificate},
	})
	defer tlsListener.Close()

	go serveTestHTTPOverListener(tlsListener, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("unix-tls-ok"))
	})

	inboundInstance := &Inbound{}
	transport, cleanup, err := inboundInstance.newDirectOriginTransport(ResolvedService{
		Kind: ResolvedServiceUnixTLS,
		OriginRequest: OriginRequestConfig{
			NoTLSVerify: true,
		},
		UnixPath: socketPath,
		BaseURL: &url.URL{
			Scheme: "https",
			Host:   "localhost",
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	client := &http.Client{Transport: transport}
	resp, err := client.Get("https://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "unix-tls-ok" {
		t.Fatalf("unexpected response body: %q", string(body))
	}
}

func serveTestHTTPOverListener(listener net.Listener, handler func(http.ResponseWriter, *http.Request)) {
	server := &http.Server{Handler: http.HandlerFunc(handler)}
	_ = server.Serve(listener)
}

func TestDirectOriginTransportCacheReusesMatchingTransports(t *testing.T) {
	inboundInstance := &Inbound{
		directTransports: make(map[string]*http.Transport),
	}
	service := ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		BaseURL:  &url.URL{Scheme: "http", Host: "localhost"},
	}

	transport1, _, err := inboundInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	transport2, _, err := inboundInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if transport1 != transport2 {
		t.Fatal("expected matching direct-origin transports to be reused")
	}

	transport3, _, err := inboundInstance.newDirectOriginTransport(service, "other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if transport3 == transport1 {
		t.Fatal("expected different cache keys to produce different transports")
	}
}

func TestApplyConfigClearsDirectOriginTransportCache(t *testing.T) {
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	inboundInstance := &Inbound{
		logger:           log.NewNOPFactory().NewLogger("test"),
		configManager:    configManager,
		directTransports: make(map[string]*http.Transport),
	}
	service := ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		BaseURL:  &url.URL{Scheme: "http", Host: "localhost"},
	}

	transport1, _, err := inboundInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	result := inboundInstance.ApplyConfig(1, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	transport2, _, err := inboundInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if transport1 == transport2 {
		t.Fatal("expected ApplyConfig to clear direct-origin transport cache")
	}
}
