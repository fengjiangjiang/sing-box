//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/google/uuid"
)

type captureConnectMetadataWriter struct {
	err      error
	metadata []Metadata
}

func (w *captureConnectMetadataWriter) WriteResponse(responseError error, metadata []Metadata) error {
	w.err = responseError
	w.metadata = append([]Metadata(nil), metadata...)
	return nil
}

func newLimitedInbound(t *testing.T, limit uint64) *Inbound {
	t.Helper()
	logFactory, err := log.New(log.Options{Options: option.LogOptions{Level: "debug"}})
	if err != nil {
		t.Fatal(err)
	}
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	config := configManager.Snapshot()
	config.WarpRouting.MaxActiveFlows = limit
	configManager.activeConfig = config
	return &Inbound{
		Adapter:             inbound.NewAdapter(C.TypeCloudflared, "test"),
		ctx:                 ctx,
		cancel:              cancel,
		router:              &testRouter{},
		logger:              logFactory.NewLogger("test"),
		configManager:       configManager,
		flowLimiter:         &FlowLimiter{},
		datagramV3Manager:   NewDatagramV3SessionManager(),
		connectionStates:    make([]connectionState, 1),
		successfulProtocols: make(map[string]struct{}),
		directTransports:    make(map[string]*http.Transport),
	}
}

func TestHandleTCPStreamRespectsMaxActiveFlows(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 1)
	if !inboundInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}

	stream, peer := net.Pipe()
	defer stream.Close()
	defer peer.Close()
	respWriter := &fakeConnectResponseWriter{}
	inboundInstance.handleTCPStream(context.Background(), stream, respWriter, adapter.InboundContext{})
	if respWriter.err == nil {
		t.Fatal("expected too many active flows error")
	}
}

func TestHandleTCPStreamRateLimitMetadata(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 1)
	if !inboundInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}

	stream, peer := net.Pipe()
	defer stream.Close()
	defer peer.Close()

	respWriter := &captureConnectMetadataWriter{}
	inboundInstance.handleTCPStream(context.Background(), stream, respWriter, adapter.InboundContext{})
	if respWriter.err == nil {
		t.Fatal("expected too many active flows error")
	}
	if !hasFlowConnectRateLimited(respWriter.metadata) {
		t.Fatal("expected flow rate limit metadata")
	}
}

func TestHTTP2ResponseWriterFlowRateLimitedMeta(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &http2ResponseWriter{
		writer:  recorder,
		flusher: recorder,
	}

	err := writer.WriteResponse(context.DeadlineExceeded, flowConnectRateLimitedMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, recorder.Code)
	}
	if meta := recorder.Header().Get(h2HeaderResponseMeta); meta != h2ResponseMetaCloudflaredLimited {
		t.Fatalf("unexpected response meta: %q", meta)
	}
}

func TestDatagramV2RegisterSessionRespectsMaxActiveFlows(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 1)
	if !inboundInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}
	muxer := NewDatagramV2Muxer(inboundInstance, &captureDatagramSender{}, inboundInstance.logger)
	err := muxer.RegisterSession(context.Background(), uuidTest(1), net.IPv4(1, 1, 1, 1), 53, 0)
	if err == nil {
		t.Fatal("expected too many active flows error")
	}
}

func TestDatagramV3RegistrationTooManyActiveFlows(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 1)
	if !inboundInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}
	sender := &captureDatagramSender{}
	muxer := NewDatagramV3Muxer(inboundInstance, sender, inboundInstance.logger)

	requestID := RequestID{}
	requestID[15] = 1
	payload := make([]byte, 1+1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{1, 1, 1, 1})

	muxer.handleRegistration(context.Background(), payload)
	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration response, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != v3ResponseTooManyActiveFlows {
		t.Fatalf("unexpected v3 response: %v", sender.sent[0])
	}
}

func uuidTest(last byte) uuid.UUID {
	var value uuid.UUID
	value[15] = last
	return value
}
