//go:build with_cloudflared

package cloudflare

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

func restoreConnectionHooks(t *testing.T) {
	t.Helper()

	originalNewQUICConnection := newQUICConnection
	originalNewHTTP2Connection := newHTTP2Connection
	originalServeQUICConnection := serveQUICConnection
	originalServeHTTP2Connection := serveHTTP2Connection
	t.Cleanup(func() {
		newQUICConnection = originalNewQUICConnection
		newHTTP2Connection = originalNewHTTP2Connection
		serveQUICConnection = originalServeQUICConnection
		serveHTTP2Connection = originalServeHTTP2Connection
	})
}

func TestServeConnectionAutoFallbackSticky(t *testing.T) {
	restoreConnectionHooks(t)

	inboundInstance := newLimitedInbound(t, 0)
	inboundInstance.protocol = ""
	inboundInstance.initializeConnectionState(0)

	var quicCalls, http2Calls int
	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), log.ContextLogger) (*QUICConnection, error) {
		quicCalls++
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		return errors.New("quic failed")
	}
	newHTTP2Connection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, []string, uint8, time.Duration, *Inbound, log.ContextLogger) (*HTTP2Connection, error) {
		http2Calls++
		return &HTTP2Connection{}, nil
	}
	serveHTTP2Connection = func(*HTTP2Connection, context.Context) error {
		return errors.New("http2 failed")
	}

	if err := inboundInstance.serveConnection(0, &EdgeAddr{}); err == nil || err.Error() != "http2 failed" {
		t.Fatalf("expected HTTP/2 fallback error, got %v", err)
	}
	if state := inboundInstance.connectionState(0); state.protocol != "http2" {
		t.Fatalf("expected sticky HTTP/2 fallback, got %#v", state)
	}

	if err := inboundInstance.serveConnection(0, &EdgeAddr{}); err == nil || err.Error() != "http2 failed" {
		t.Fatalf("expected second HTTP/2 error, got %v", err)
	}
	if quicCalls != 1 {
		t.Fatalf("expected QUIC to be attempted once, got %d", quicCalls)
	}
	if http2Calls != 2 {
		t.Fatalf("expected HTTP/2 to be attempted twice, got %d", http2Calls)
	}
}

func TestSecondConnectionInitialProtocolUsesFirstSuccess(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 0)
	inboundInstance.protocol = ""

	inboundInstance.notifyConnected(0, "http2")
	inboundInstance.initializeConnectionState(1)

	if state := inboundInstance.connectionState(1); state.protocol != "http2" {
		t.Fatalf("expected second connection to inherit HTTP/2, got %#v", state)
	}
}

func TestServeConnectionSkipsFallbackWhenQUICAlreadySucceeded(t *testing.T) {
	restoreConnectionHooks(t)

	inboundInstance := newLimitedInbound(t, 0)
	inboundInstance.protocol = ""
	inboundInstance.notifyConnected(0, "quic")
	inboundInstance.initializeConnectionState(1)

	var http2Calls int
	quicErr := errors.New("quic failed")
	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), log.ContextLogger) (*QUICConnection, error) {
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		return quicErr
	}
	newHTTP2Connection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, []string, uint8, time.Duration, *Inbound, log.ContextLogger) (*HTTP2Connection, error) {
		http2Calls++
		return &HTTP2Connection{}, nil
	}

	err := inboundInstance.serveConnection(1, &EdgeAddr{})
	if !errors.Is(err, quicErr) {
		t.Fatalf("expected QUIC error without fallback, got %v", err)
	}
	if http2Calls != 0 {
		t.Fatalf("expected no HTTP/2 fallback, got %d calls", http2Calls)
	}
	if state := inboundInstance.connectionState(1); state.protocol != "quic" {
		t.Fatalf("expected connection to remain on QUIC, got %#v", state)
	}
}

func TestNotifyConnectedResetsRetries(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 0)
	inboundInstance.protocol = ""
	inboundInstance.initializeConnectionState(0)
	inboundInstance.incrementConnectionRetries(0)
	inboundInstance.incrementConnectionRetries(0)

	inboundInstance.notifyConnected(0, "http2")

	state := inboundInstance.connectionState(0)
	if state.retries != 0 {
		t.Fatalf("expected retries reset after success, got %d", state.retries)
	}
	if state.protocol != "http2" {
		t.Fatalf("expected protocol to be pinned to success, got %q", state.protocol)
	}
}

func TestSafeServeConnectionRecoversPanic(t *testing.T) {
	restoreConnectionHooks(t)

	inboundInstance := newLimitedInbound(t, 0)
	inboundInstance.protocol = "quic"
	inboundInstance.initializeConnectionState(0)

	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), log.ContextLogger) (*QUICConnection, error) {
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		panic("boom")
	}

	err := inboundInstance.safeServeConnection(0, &EdgeAddr{})
	if err == nil || !strings.Contains(err.Error(), "panic in serve connection") {
		t.Fatalf("expected recovered panic error, got %v", err)
	}
}
