//go:build with_cloudflared

package cloudflare

import (
	"io"
	"strings"
	"testing"
)

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

type mockReadWriteCloser struct {
	reader strings.Reader
	writes []byte
}

func (m *mockReadWriteCloser) Read(p []byte) (int, error) {
	return m.reader.Read(p)
}

func (m *mockReadWriteCloser) Write(p []byte) (int, error) {
	m.writes = append(m.writes, p...)
	return len(p), nil
}

func (m *mockReadWriteCloser) Close() error {
	return nil
}

func TestNOPCloserReadWriterCloseOnlyStopsReads(t *testing.T) {
	inner := &mockReadWriteCloser{reader: *strings.NewReader("payload")}
	wrapper := &nopCloserReadWriter{ReadWriteCloser: inner}

	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := wrapper.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected read to fail after close")
	}

	if _, err := wrapper.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if string(inner.writes) != "response" {
		t.Fatalf("unexpected writes %q", inner.writes)
	}
}

func TestNOPCloserReadWriterTracksEOF(t *testing.T) {
	inner := &mockReadWriteCloser{reader: *strings.NewReader("")}
	wrapper := &nopCloserReadWriter{ReadWriteCloser: inner}

	if _, err := wrapper.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	if _, err := wrapper.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected cached EOF, got %v", err)
	}
}
