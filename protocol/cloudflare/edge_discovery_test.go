//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"net"
	"testing"
)

func TestDiscoverEdge(t *testing.T) {
	regions, err := DiscoverEdge(context.Background(), "")
	if err != nil {
		t.Fatal("DiscoverEdge: ", err)
	}
	if len(regions) == 0 {
		t.Fatal("expected at least 1 region")
	}
	for i, region := range regions {
		if len(region) == 0 {
			t.Errorf("region %d is empty", i)
			continue
		}
		for j, addr := range region {
			if addr.TCP == nil {
				t.Errorf("region %d addr %d: TCP is nil", i, j)
			}
			if addr.UDP == nil {
				t.Errorf("region %d addr %d: UDP is nil", i, j)
			}
			if addr.IPVersion != 4 && addr.IPVersion != 6 {
				t.Errorf("region %d addr %d: invalid IPVersion %d", i, j, addr.IPVersion)
			}
		}
	}
}

func TestFilterByIPVersion(t *testing.T) {
	v4Addr := &EdgeAddr{
		TCP:       &net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 7844},
		UDP:       &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 7844},
		IPVersion: 4,
	}
	v6Addr := &EdgeAddr{
		TCP:       &net.TCPAddr{IP: net.ParseIP("2606:4700::1"), Port: 7844},
		UDP:       &net.UDPAddr{IP: net.ParseIP("2606:4700::1"), Port: 7844},
		IPVersion: 6,
	}
	mixed := [][]*EdgeAddr{{v4Addr, v6Addr}}

	tests := []struct {
		name     string
		version  int
		expected int
	}{
		{"auto", 0, 2},
		{"v4 only", 4, 1},
		{"v6 only", 6, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterByIPVersion(mixed, tt.version)
			total := 0
			for _, region := range result {
				total += len(region)
			}
			if total != tt.expected {
				t.Errorf("expected %d addrs, got %d", tt.expected, total)
			}
		})
	}

	t.Run("no match", func(t *testing.T) {
		v4Only := [][]*EdgeAddr{{v4Addr}}
		result := FilterByIPVersion(v4Only, 6)
		if len(result) != 0 {
			t.Error("expected empty result for no match")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		result := FilterByIPVersion(nil, 4)
		if len(result) != 0 {
			t.Error("expected empty result for nil input")
		}
	})
}

func TestGetRegionalServiceName(t *testing.T) {
	if got := getRegionalServiceName(""); got != edgeSRVService {
		t.Fatalf("expected global service %s, got %s", edgeSRVService, got)
	}
	if got := getRegionalServiceName("us"); got != "us-"+edgeSRVService {
		t.Fatalf("expected regional service us-%s, got %s", edgeSRVService, got)
	}
}
