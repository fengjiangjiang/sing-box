//go:build with_cloudflared

package cloudflare

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestNewInboundRequiresToken(t *testing.T) {
	_, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "test", option.CloudflaredInboundOptions{})
	if err == nil {
		t.Fatal("expected missing token error")
	}
}

func TestValidateRegistrationResultRejectsNonRemoteManaged(t *testing.T) {
	err := validateRegistrationResult(&RegistrationResult{TunnelIsRemotelyManaged: false})
	if err == nil {
		t.Fatal("expected unsupported tunnel error")
	}
	if err != ErrNonRemoteManagedTunnelUnsupported {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeProtocolAutoUsesTokenStyleSentinel(t *testing.T) {
	protocol, err := normalizeProtocol("auto")
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "" {
		t.Fatalf("expected auto protocol to normalize to token-style empty sentinel, got %q", protocol)
	}
}

func TestResolveGracePeriodDefaultsToThirtySeconds(t *testing.T) {
	if got := resolveGracePeriod(nil); got != 30*time.Second {
		t.Fatalf("expected default grace period 30s, got %s", got)
	}
}

func TestResolveGracePeriodPreservesExplicitZero(t *testing.T) {
	var options option.CloudflaredInboundOptions
	if err := json.Unmarshal([]byte(`{"grace_period":"0s"}`), &options); err != nil {
		t.Fatal(err)
	}
	if options.GracePeriod == nil {
		t.Fatal("expected explicit grace period to be set")
	}
	if got := resolveGracePeriod(options.GracePeriod); got != 0 {
		t.Fatalf("expected explicit zero grace period, got %s", got)
	}
}

func TestResolveGracePeriodPreservesNonZeroValue(t *testing.T) {
	var options option.CloudflaredInboundOptions
	if err := json.Unmarshal([]byte(`{"grace_period":"45s"}`), &options); err != nil {
		t.Fatal(err)
	}
	if options.GracePeriod == nil {
		t.Fatal("expected explicit grace period to be set")
	}
	if got := resolveGracePeriod(options.GracePeriod); got != 45*time.Second {
		t.Fatalf("expected grace period 45s, got %s", got)
	}
}
