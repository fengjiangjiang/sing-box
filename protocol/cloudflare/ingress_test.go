//go:build with_cloudflare_tunnel

package cloudflare

import (
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func newTestIngressInbound(t *testing.T) *Inbound {
	t.Helper()
	configManager, err := NewConfigManager(option.CloudflareTunnelInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &Inbound{
		logger:        log.NewNOPFactory().NewLogger("test"),
		configManager: configManager,
	}
}

func mustResolvedService(t *testing.T, rawService string) ResolvedService {
	t.Helper()
	service, err := parseResolvedService(rawService, defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestApplyConfig(t *testing.T) {
	inboundInstance := newTestIngressInbound(t)

	config1 := []byte(`{"ingress":[{"hostname":"a.com","service":"http://localhost:80"},{"hostname":"b.com","service":"http://localhost:81"},{"service":"http_status:404"}]}`)
	result := inboundInstance.ApplyConfig(1, config1)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 1 {
		t.Fatalf("expected version 1, got %d", result.LastAppliedVersion)
	}

	service, loaded := inboundInstance.configManager.Resolve("a.com", "/")
	if !loaded || service.Service != "http://localhost:80" {
		t.Fatalf("expected a.com to resolve to localhost:80, got %#v, loaded=%v", service, loaded)
	}

	result = inboundInstance.ApplyConfig(1, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 1 {
		t.Fatalf("same version should keep current version, got %d", result.LastAppliedVersion)
	}

	service, loaded = inboundInstance.configManager.Resolve("b.com", "/")
	if !loaded || service.Service != "http://localhost:81" {
		t.Fatalf("expected old rules to remain, got %#v, loaded=%v", service, loaded)
	}

	result = inboundInstance.ApplyConfig(2, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 2 {
		t.Fatalf("expected version 2, got %d", result.LastAppliedVersion)
	}

	service, loaded = inboundInstance.configManager.Resolve("anything.com", "/")
	if !loaded || service.StatusCode != 503 {
		t.Fatalf("expected catch-all status 503, got %#v, loaded=%v", service, loaded)
	}
}

func TestApplyConfigInvalidJSON(t *testing.T) {
	inboundInstance := newTestIngressInbound(t)
	result := inboundInstance.ApplyConfig(1, []byte("not json"))
	if result.Err == nil {
		t.Fatal("expected parse error")
	}
	if result.LastAppliedVersion != -1 {
		t.Fatalf("expected version to stay -1, got %d", result.LastAppliedVersion)
	}
}

func TestResolveExactAndWildcard(t *testing.T) {
	inboundInstance := newTestIngressInbound(t)
	inboundInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Hostname: "test.example.com", Service: mustResolvedService(t, "http://localhost:8080")},
			{Hostname: "*.example.com", Service: mustResolvedService(t, "http://localhost:9090")},
			{Service: mustResolvedService(t, "http_status:404")},
		},
	}

	service, loaded := inboundInstance.configManager.Resolve("test.example.com", "/")
	if !loaded || service.Service != "http://localhost:8080" {
		t.Fatalf("expected exact match, got %#v, loaded=%v", service, loaded)
	}

	service, loaded = inboundInstance.configManager.Resolve("sub.example.com", "/")
	if !loaded || service.Service != "http://localhost:9090" {
		t.Fatalf("expected wildcard match, got %#v, loaded=%v", service, loaded)
	}

	service, loaded = inboundInstance.configManager.Resolve("unknown.test", "/")
	if !loaded || service.StatusCode != 404 {
		t.Fatalf("expected catch-all 404, got %#v, loaded=%v", service, loaded)
	}
}

func TestResolveHTTPService(t *testing.T) {
	inboundInstance := newTestIngressInbound(t)
	inboundInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Hostname: "foo.com", Service: mustResolvedService(t, "http://127.0.0.1:8083")},
			{Service: mustResolvedService(t, "http_status:404")},
		},
	}

	service, requestURL, err := inboundInstance.resolveHTTPService("https://foo.com/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if service.Destination.String() != "127.0.0.1:8083" {
		t.Fatalf("expected destination 127.0.0.1:8083, got %s", service.Destination)
	}
	if requestURL != "http://127.0.0.1:8083/path?q=1" {
		t.Fatalf("expected rewritten URL, got %s", requestURL)
	}
}

func TestResolveHTTPServiceStatus(t *testing.T) {
	inboundInstance := newTestIngressInbound(t)
	inboundInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Service: mustResolvedService(t, "http_status:404")},
		},
	}

	service, requestURL, err := inboundInstance.resolveHTTPService("https://any.com/path")
	if err != nil {
		t.Fatal(err)
	}
	if service.StatusCode != 404 {
		t.Fatalf("expected status 404, got %#v", service)
	}
	if requestURL != "https://any.com/path" {
		t.Fatalf("status service should keep request URL, got %s", requestURL)
	}
}
