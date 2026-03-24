//go:build with_cloudflared

package cloudflare

import "testing"

func TestQUICInitialPacketSize(t *testing.T) {
	testCases := []struct {
		name      string
		ipVersion int
		expected  uint16
	}{
		{name: "ipv4", ipVersion: 4, expected: 1232},
		{name: "ipv6", ipVersion: 6, expected: 1252},
		{name: "default", ipVersion: 0, expected: 1252},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual := quicInitialPacketSize(testCase.ipVersion); actual != testCase.expected {
				t.Fatalf("quicInitialPacketSize(%d) = %d, want %d", testCase.ipVersion, actual, testCase.expected)
			}
		})
	}
}
