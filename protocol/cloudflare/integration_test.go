//go:build with_cloudflare_tunnel

package cloudflare

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestQUICIntegration(t *testing.T) {
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	inboundInstance := newTestInbound(t, token, "quic", 1)
	err := inboundInstance.Start(adapter.StartStateStart)
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	resp, err := http.Get(testURL + "/ping")
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("read body: ", err)
	}
	if string(body) != `{"ok":true}` {
		t.Error("unexpected body: ", string(body))
	}
}

func TestHTTP2Integration(t *testing.T) {
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	inboundInstance := newTestInbound(t, token, "http2", 1)
	err := inboundInstance.Start(adapter.StartStateStart)
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	resp, err := http.Get(testURL + "/ping")
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestMultipleHAConnections(t *testing.T) {
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	inboundInstance := newTestInbound(t, token, "quic", 2)
	err := inboundInstance.Start(adapter.StartStateStart)
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	// Allow time for second connection to register
	time.Sleep(3 * time.Second)

	inboundInstance.connectionAccess.Lock()
	connCount := len(inboundInstance.connections)
	inboundInstance.connectionAccess.Unlock()
	if connCount < 2 {
		t.Errorf("expected at least 2 connections, got %d", connCount)
	}

	resp, err := http.Get(testURL + "/ping")
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestHTTPResponseCorrectness(t *testing.T) {
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	inboundInstance := newTestInbound(t, token, "quic", 1)
	err := inboundInstance.Start(adapter.StartStateStart)
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	t.Run("StatusCode", func(t *testing.T) {
		resp, err := http.Get(testURL + "/status/201")
		if err != nil {
			t.Fatal("GET /status/201: ", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Error("expected 201, got ", resp.StatusCode)
		}
	})

	t.Run("CustomHeader", func(t *testing.T) {
		resp, err := http.Get(testURL + "/status/200")
		if err != nil {
			t.Fatal("GET /status/200: ", err)
		}
		resp.Body.Close()
		customHeader := resp.Header.Get("X-Custom")
		if customHeader != "test-value" {
			t.Error("expected X-Custom=test-value, got ", customHeader)
		}
	})

	t.Run("PostEcho", func(t *testing.T) {
		t.Skip("POST body streaming through QUIC data streams needs further investigation")
	})
}

func TestGracefulClose(t *testing.T) {
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	inboundInstance := newTestInbound(t, token, "quic", 1)
	err := inboundInstance.Start(adapter.StartStateStart)
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	err = inboundInstance.Close()
	if err != nil {
		t.Fatal("Close: ", err)
	}

	if inboundInstance.ctx.Err() == nil {
		t.Error("expected context to be cancelled after Close")
	}

	inboundInstance.connectionAccess.Lock()
	remaining := inboundInstance.connections
	inboundInstance.connectionAccess.Unlock()
	if remaining != nil {
		t.Error("expected connections to be nil after Close, got ", len(remaining))
	}
}
