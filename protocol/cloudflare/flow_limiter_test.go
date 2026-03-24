//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/google/uuid"
)

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
	config := configManager.Snapshot()
	config.WarpRouting.MaxActiveFlows = limit
	configManager.activeConfig = config
	return &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeCloudflared, "test"),
		router:        &testRouter{},
		logger:        logFactory.NewLogger("test"),
		configManager: configManager,
		flowLimiter:   &FlowLimiter{},
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
