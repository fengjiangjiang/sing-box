//go:build with_cloudflared

package cloudflare

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/cloudflare/tunnelrpc"

	capnp "zombiezen.com/go/capnproto2"
)

func newRegisterUDPSessionCall(t *testing.T, traceContext string) (tunnelrpc.SessionManager_registerUdpSession, func() (tunnelrpc.RegisterUdpSessionResponse, error)) {
	t.Helper()

	_, paramsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	params, err := tunnelrpc.NewSessionManager_registerUdpSession_Params(paramsSeg)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	if err := params.SetSessionId(sessionID[:]); err != nil {
		t.Fatal(err)
	}
	if err := params.SetDstIp([]byte{127, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	params.SetDstPort(53)
	params.SetCloseAfterIdleHint(int64(30))
	if err := params.SetTraceContext(traceContext); err != nil {
		t.Fatal(err)
	}

	_, resultsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, err := tunnelrpc.NewSessionManager_registerUdpSession_Results(resultsSeg)
	if err != nil {
		t.Fatal(err)
	}

	call := tunnelrpc.SessionManager_registerUdpSession{
		Ctx:     context.Background(),
		Params:  params,
		Results: results,
	}
	return call, results.Result
}

func newUnregisterUDPSessionCall(t *testing.T) tunnelrpc.SessionManager_unregisterUdpSession {
	t.Helper()

	_, paramsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	params, err := tunnelrpc.NewSessionManager_unregisterUdpSession_Params(paramsSeg)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	if err := params.SetSessionId(sessionID[:]); err != nil {
		t.Fatal(err)
	}
	if err := params.SetMessage("close"); err != nil {
		t.Fatal(err)
	}

	_, resultsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, err := tunnelrpc.NewSessionManager_unregisterUdpSession_Results(resultsSeg)
	if err != nil {
		t.Fatal(err)
	}

	return tunnelrpc.SessionManager_unregisterUdpSession{
		Ctx:     context.Background(),
		Params:  params,
		Results: results,
	}
}

func TestV3RPCRegisterUDPSessionReturnsUnsupportedResult(t *testing.T) {
	server := &cloudflaredV3Server{
		inbound: &Inbound{Adapter: inbound.NewAdapter(C.TypeCloudflared, "test")},
	}
	call, readResult := newRegisterUDPSessionCall(t, "trace-context")
	if err := server.RegisterUdpSession(call); err != nil {
		t.Fatal(err)
	}

	result, err := readResult()
	if err != nil {
		t.Fatal(err)
	}
	resultErr, err := result.Err()
	if err != nil {
		t.Fatal(err)
	}
	if resultErr != errUnsupportedDatagramV3UDPRegistration.Error() {
		t.Fatalf("unexpected registration error %q", resultErr)
	}
	spans, err := result.Spans()
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Fatalf("expected empty spans, got %x", spans)
	}
}

func TestV3RPCUnregisterUDPSessionReturnsUnsupportedError(t *testing.T) {
	server := &cloudflaredV3Server{
		inbound: &Inbound{Adapter: inbound.NewAdapter(C.TypeCloudflared, "test")},
	}
	err := server.UnregisterUdpSession(newUnregisterUDPSessionCall(t))
	if err == nil {
		t.Fatal("expected unsupported unregister error")
	}
	if err.Error() != errUnsupportedDatagramV3UDPUnregistration.Error() {
		t.Fatalf("unexpected unregister error %v", err)
	}
}
