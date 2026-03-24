//go:build with_cloudflared

package cloudflare

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
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

func TestNormalizeProtocolAcceptsAuto(t *testing.T) {
	protocol, err := normalizeProtocol("auto")
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "" {
		t.Fatalf("expected auto protocol to normalize to empty string, got %q", protocol)
	}
}
