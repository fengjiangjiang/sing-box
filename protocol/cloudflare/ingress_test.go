//go:build with_cloudflare_tunnel

package cloudflare

import (
	"testing"

	"github.com/sagernet/sing-box/log"
)

func newTestIngressInbound() *Inbound {
	return &Inbound{logger: log.NewNOPFactory().NewLogger("test")}
}

func TestUpdateIngress(t *testing.T) {
	inboundInstance := newTestIngressInbound()

	config1 := []byte(`{"ingress":[{"hostname":"a.com","service":"http://localhost:80"},{"hostname":"b.com","service":"http://localhost:81"},{"service":"http_status:404"}]}`)
	inboundInstance.UpdateIngress(1, config1)

	inboundInstance.ingressAccess.RLock()
	count := len(inboundInstance.ingressRules)
	inboundInstance.ingressAccess.RUnlock()
	if count != 3 {
		t.Fatalf("expected 3 rules, got %d", count)
	}

	inboundInstance.UpdateIngress(1, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	inboundInstance.ingressAccess.RLock()
	count = len(inboundInstance.ingressRules)
	inboundInstance.ingressAccess.RUnlock()
	if count != 3 {
		t.Error("version 1 re-apply should not change rules, got ", count)
	}

	inboundInstance.UpdateIngress(2, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	inboundInstance.ingressAccess.RLock()
	count = len(inboundInstance.ingressRules)
	inboundInstance.ingressAccess.RUnlock()
	if count != 1 {
		t.Error("version 2 should update to 1 rule, got ", count)
	}
}

func TestUpdateIngressInvalidJSON(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.UpdateIngress(1, []byte("not json"))

	inboundInstance.ingressAccess.RLock()
	count := len(inboundInstance.ingressRules)
	inboundInstance.ingressAccess.RUnlock()
	if count != 0 {
		t.Error("invalid JSON should leave rules empty, got ", count)
	}
}

func TestResolveOriginExact(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "test.example.com", Service: "http://localhost:8080"},
		{Hostname: "", Service: "http_status:404"},
	}

	result := inboundInstance.ResolveOrigin("test.example.com")
	if result != "http://localhost:8080" {
		t.Error("expected http://localhost:8080, got ", result)
	}
}

func TestResolveOriginWildcard(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "*.example.com", Service: "http://localhost:9090"},
	}

	result := inboundInstance.ResolveOrigin("sub.example.com")
	if result != "http://localhost:9090" {
		t.Error("wildcard should match sub.example.com, got ", result)
	}

	result = inboundInstance.ResolveOrigin("example.com")
	if result != "" {
		t.Error("wildcard should not match bare example.com, got ", result)
	}
}

func TestResolveOriginCatchAll(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "specific.com", Service: "http://localhost:1"},
		{Hostname: "", Service: "http://localhost:2"},
	}

	result := inboundInstance.ResolveOrigin("anything.com")
	if result != "http://localhost:2" {
		t.Error("catch-all should match, got ", result)
	}
}

func TestResolveOriginNoMatch(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "specific.com", Service: "http://localhost:1"},
	}

	result := inboundInstance.ResolveOrigin("other.com")
	if result != "" {
		t.Error("expected empty for no match, got ", result)
	}
}

func TestResolveOriginURLRewrite(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "foo.com", Service: "http://127.0.0.1:8083"},
	}

	result := inboundInstance.ResolveOriginURL("https://foo.com/path?q=1")
	if result != "http://127.0.0.1:8083/path?q=1" {
		t.Error("expected http://127.0.0.1:8083/path?q=1, got ", result)
	}
}

func TestResolveOriginURLNoMatch(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "other.com", Service: "http://localhost:1"},
	}

	original := "https://unknown.com/page"
	result := inboundInstance.ResolveOriginURL(original)
	if result != original {
		t.Error("no match should return original, got ", result)
	}
}

func TestResolveOriginURLHTTPStatus(t *testing.T) {
	inboundInstance := newTestIngressInbound()
	inboundInstance.ingressRules = []IngressRule{
		{Hostname: "", Service: "http_status:404"},
	}

	original := "https://any.com/page"
	result := inboundInstance.ResolveOriginURL(original)
	if result != original {
		t.Error("http_status service should return original, got ", result)
	}
}
