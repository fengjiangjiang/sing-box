//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
)

type v2UnregisterCall struct {
	sessionID uuid.UUID
	message   string
}

type captureRPCDatagramSender struct {
	captureDatagramSender
}

type captureV2SessionRPCClient struct {
	unregisterCh chan v2UnregisterCall
}

func (c *captureV2SessionRPCClient) UnregisterSession(ctx context.Context, sessionID uuid.UUID, message string) error {
	c.unregisterCh <- v2UnregisterCall{sessionID: sessionID, message: message}
	return nil
}

func (c *captureV2SessionRPCClient) Close() error { return nil }

func TestDatagramV2LocalCloseUnregistersRemote(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 0)
	sender := &captureRPCDatagramSender{}
	muxer := NewDatagramV2Muxer(inboundInstance, sender, inboundInstance.logger)
	unregisterCh := make(chan v2UnregisterCall, 1)
	originalClientFactory := newV2SessionRPCClient
	newV2SessionRPCClient = func(ctx context.Context, sender DatagramSender) (v2SessionRPCClient, error) {
		return &captureV2SessionRPCClient{unregisterCh: unregisterCh}, nil
	}
	defer func() {
		newV2SessionRPCClient = originalClientFactory
	}()

	sessionID := uuidTest(7)
	if err := muxer.RegisterSession(context.Background(), sessionID, net.IPv4(127, 0, 0, 1), 53, time.Second); err != nil {
		t.Fatal(err)
	}

	muxer.sessionAccess.RLock()
	session := muxer.sessions[sessionID]
	muxer.sessionAccess.RUnlock()
	if session == nil {
		t.Fatal("expected registered session")
	}

	session.closeWithReason("local close")

	select {
	case call := <-unregisterCh:
		if call.sessionID != sessionID {
			t.Fatalf("unexpected session id: %s", call.sessionID)
		}
		if call.message != "local close" {
			t.Fatalf("unexpected message: %q", call.message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected unregister rpc")
	}
}

func TestDatagramV3RegistrationMigratesSender(t *testing.T) {
	inboundInstance := newLimitedInbound(t, 0)
	sender1 := &captureDatagramSender{}
	sender2 := &captureDatagramSender{}
	muxer1 := NewDatagramV3Muxer(inboundInstance, sender1, inboundInstance.logger)
	muxer2 := NewDatagramV3Muxer(inboundInstance, sender2, inboundInstance.logger)

	requestID := RequestID{}
	requestID[15] = 9
	payload := make([]byte, 1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{127, 0, 0, 1})

	muxer1.handleRegistration(context.Background(), payload)
	session, exists := inboundInstance.datagramV3Manager.Get(requestID)
	if !exists {
		t.Fatal("expected v3 session after first registration")
	}

	muxer2.handleRegistration(context.Background(), payload)

	session.senderAccess.RLock()
	currentSender := session.sender
	session.senderAccess.RUnlock()
	if currentSender != sender2 {
		t.Fatal("expected v3 session sender migration to second sender")
	}

	session.close()
}
