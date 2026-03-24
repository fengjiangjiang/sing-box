//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
)

func TestDatagramV3RegistrationDestinationUnreachable(t *testing.T) {
	sender := &captureDatagramSender{}
	inboundInstance := &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		flowLimiter: &FlowLimiter{},
	}
	muxer := NewDatagramV3Muxer(inboundInstance, sender, nil)

	requestID := RequestID{}
	requestID[15] = 1
	payload := make([]byte, 1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 0)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{0, 0, 0, 0})

	muxer.handleRegistration(context.Background(), payload)
	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration response, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != v3ResponseDestinationUnreachable {
		t.Fatalf("unexpected datagram response: %v", sender.sent[0])
	}
}

func TestDatagramV3RegistrationErrorWithMessage(t *testing.T) {
	sender := &captureDatagramSender{}
	inboundInstance := &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		flowLimiter: &FlowLimiter{},
	}
	muxer := NewDatagramV3Muxer(inboundInstance, sender, nil)

	requestID := RequestID{}
	requestID[15] = 2
	payload := make([]byte, 1+2+2+16+1)
	payload[0] = 1
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	payload[21] = 0xaa

	muxer.handleRegistration(context.Background(), payload)
	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration response, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != v3ResponseErrorWithMsg {
		t.Fatalf("unexpected datagram response: %v", sender.sent[0])
	}
}
