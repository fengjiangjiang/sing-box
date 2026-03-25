//go:build with_cloudflared

package cloudflare

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestFeatureSelectorConfiguredWins(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	selector := newFeatureSelector(ctx, "account", "v3")
	version, features := selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected configured version to win, got %s", version)
	}
	if !slices.Contains(features, "support_datagram_v3_2") {
		t.Fatalf("expected v3 feature list, got %#v", features)
	}
}

func TestFeatureSelectorInitialRemoteSelection(t *testing.T) {
	selector := &featureSelector{
		accountTag:             "account",
		lookup:                 func(context.Context) ([]byte, error) { return []byte(`{"dv3_2":100}`), nil },
		currentDatagramVersion: defaultDatagramVersion,
	}

	if err := selector.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	version, _ := selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected auto-selected v3, got %s", version)
	}
}

func TestFeatureSelectorRefreshUpdatesSnapshot(t *testing.T) {
	record := []byte(`{"dv3_2":0}`)
	selector := &featureSelector{
		accountTag:             "account",
		currentDatagramVersion: defaultDatagramVersion,
		lookup: func(context.Context) ([]byte, error) {
			return record, nil
		},
	}

	if err := selector.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	version, _ := selector.Snapshot()
	if version != defaultDatagramVersion {
		t.Fatalf("expected initial v2, got %s", version)
	}

	record = []byte(`{"dv3_2":100}`)
	if err := selector.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	version, _ = selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected refreshed v3, got %s", version)
	}
}

func TestFeatureSelectorRefreshFailureKeepsPreviousValue(t *testing.T) {
	selector := &featureSelector{
		accountTag:             "account",
		currentDatagramVersion: "v3",
		lookup: func(context.Context) ([]byte, error) {
			return nil, errors.New("lookup failed")
		},
	}

	if err := selector.refresh(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}

	version, _ := selector.Snapshot()
	if version != "v3" {
		t.Fatalf("expected previous version to be retained, got %s", version)
	}
}

func TestInboundUsesFreshFeatureSnapshotOnRetry(t *testing.T) {
	inbound := &Inbound{
		featureSelector: &featureSelector{
			accountTag:             "account",
			currentDatagramVersion: defaultDatagramVersion,
		},
	}

	version, features := inbound.currentConnectionFeatures()
	if version != defaultDatagramVersion {
		t.Fatalf("expected initial v2, got %s", version)
	}
	if slices.Contains(features, "support_datagram_v3_2") {
		t.Fatalf("unexpected v3 feature list: %#v", features)
	}

	inbound.featureSelector.access.Lock()
	inbound.featureSelector.currentDatagramVersion = "v3"
	inbound.featureSelector.access.Unlock()

	version, features = inbound.currentConnectionFeatures()
	if version != "v3" {
		t.Fatalf("expected refreshed v3, got %s", version)
	}
	if !slices.Contains(features, "support_datagram_v3_2") {
		t.Fatalf("expected v3 feature list, got %#v", features)
	}
}
