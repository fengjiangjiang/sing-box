//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDatagramV3RegistrationDestinationUnreachable(t *testing.T) {
	sender := &captureDatagramSender{}
	inboundInstance := &Inbound{
		Adapter:           inbound.NewAdapter(C.TypeCloudflared, "test"),
		flowLimiter:       &FlowLimiter{},
		datagramV3Manager: NewDatagramV3SessionManager(),
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
		Adapter:           inbound.NewAdapter(C.TypeCloudflared, "test"),
		flowLimiter:       &FlowLimiter{},
		datagramV3Manager: NewDatagramV3SessionManager(),
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

type scriptedPacketConn struct {
	reads [][]byte
	index int
}

func (c *scriptedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.index >= len(c.reads) {
		return M.Socksaddr{}, io.EOF
	}
	_, err := buffer.Write(c.reads[c.index])
	c.index++
	return M.Socksaddr{}, err
}

func (c *scriptedPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *scriptedPacketConn) Close() error                     { return nil }
func (c *scriptedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type sizeLimitedSender struct {
	sent [][]byte
	max  int
}

func (s *sizeLimitedSender) SendDatagram(data []byte) error {
	if len(data) > s.max {
		return errors.New("datagram too large")
	}
	s.sent = append(s.sent, append([]byte(nil), data...))
	return nil
}

func TestDatagramV3ReadLoopDropsOversizedOriginPackets(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")
	sender := &sizeLimitedSender{max: v3PayloadHeaderLen + maxV3UDPPayloadLen}
	session := &v3Session{
		id:          RequestID{},
		destination: netip.MustParseAddrPort("127.0.0.1:53"),
		origin: &scriptedPacketConn{reads: [][]byte{
			make([]byte, maxV3UDPPayloadLen+1),
			[]byte("ok"),
		}},
		inbound: &Inbound{
			logger: logger,
		},
		writeChan:   make(chan []byte, 1),
		closeChan:   make(chan struct{}),
		contextChan: make(chan context.Context, 1),
		sender:      sender,
	}

	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected read loop to finish")
	}

	if len(sender.sent) != 1 {
		t.Fatalf("expected one datagram after dropping oversized payload, got %d", len(sender.sent))
	}
	if len(sender.sent[0]) != v3PayloadHeaderLen+2 {
		t.Fatalf("unexpected forwarded datagram length: %d", len(sender.sent[0]))
	}
}
