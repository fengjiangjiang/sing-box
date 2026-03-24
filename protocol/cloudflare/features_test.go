//go:build with_cloudflared

package cloudflare

import (
	"context"
	"testing"
)

func TestResolveDatagramVersionConfiguredWins(t *testing.T) {
	version := resolveDatagramVersion(context.Background(), "account", "v3")
	if version != "v3" {
		t.Fatalf("expected configured version to win, got %s", version)
	}
}

func TestResolveDatagramVersionRemoteSelection(t *testing.T) {
	originalLookup := lookupCloudflaredFeatures
	lookupCloudflaredFeatures = func(ctx context.Context) ([]byte, error) {
		return []byte(`{"dv3_2":100}`), nil
	}
	defer func() {
		lookupCloudflaredFeatures = originalLookup
	}()

	version := resolveDatagramVersion(context.Background(), "account", "")
	if version != "v3" {
		t.Fatalf("expected auto-selected v3, got %s", version)
	}
}
