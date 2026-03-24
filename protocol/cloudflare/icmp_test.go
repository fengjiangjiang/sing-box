//go:build with_cloudflare_tunnel

package cloudflare

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

type captureDatagramSender struct {
	sent [][]byte
}

func (s *captureDatagramSender) SendDatagram(data []byte) error {
	s.sent = append(s.sent, append([]byte(nil), data...))
	return nil
}

type fakeDirectRouteDestination struct {
	routeContext tun.DirectRouteContext
	packets      [][]byte
	reply        func(packet []byte) []byte
	closed       bool
}

func (d *fakeDirectRouteDestination) WritePacket(packet *buf.Buffer) error {
	data := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	d.packets = append(d.packets, data)
	if d.reply != nil {
		reply := d.reply(data)
		if reply != nil {
			return d.routeContext.WritePacket(reply)
		}
	}
	return nil
}

func (d *fakeDirectRouteDestination) Close() error {
	d.closed = true
	return nil
}

func (d *fakeDirectRouteDestination) IsClosed() bool {
	return d.closed
}

func TestICMPBridgeHandleV2RoutesEchoRequest(t *testing.T) {
	var (
		preMatchCalls int
		captured      adapter.InboundContext
		destination   *fakeDirectRouteDestination
	)
	router := &testRouter{
		preMatch: func(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error) {
			preMatchCalls++
			captured = metadata
			destination = &fakeDirectRouteDestination{routeContext: routeContext}
			return destination, nil
		},
	}
	inboundInstance := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		router:  router,
	}
	sender := &captureDatagramSender{}
	bridge := NewICMPBridge(inboundInstance, sender, icmpWireV2)

	source := netip.MustParseAddr("198.18.0.2")
	target := netip.MustParseAddr("1.1.1.1")
	packet1 := buildIPv4ICMPPacket(source, target, 8, 0, 1, 1)
	packet2 := buildIPv4ICMPPacket(source, target, 8, 0, 1, 2)

	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet1); err != nil {
		t.Fatal(err)
	}
	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet2); err != nil {
		t.Fatal(err)
	}
	if preMatchCalls != 1 {
		t.Fatalf("expected one direct-route lookup, got %d", preMatchCalls)
	}
	if captured.Network != N.NetworkICMP {
		t.Fatalf("expected NetworkICMP, got %s", captured.Network)
	}
	if captured.Source.Addr != source || captured.Destination.Addr != target {
		t.Fatalf("unexpected metadata source/destination: %#v", captured)
	}
	if len(destination.packets) != 2 {
		t.Fatalf("expected two packets written, got %d", len(destination.packets))
	}
	if len(sender.sent) != 0 {
		t.Fatalf("expected no reply datagrams, got %d", len(sender.sent))
	}
}

func TestICMPBridgeHandleV2TracedReply(t *testing.T) {
	traceIdentity := bytes.Repeat([]byte{0x7a}, icmpTraceIdentityLength)
	sender := &captureDatagramSender{}
	router := &testRouter{
		preMatch: func(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error) {
			return &fakeDirectRouteDestination{
				routeContext: routeContext,
				reply:        buildEchoReply,
			}, nil
		},
	}
	inboundInstance := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		router:  router,
	}
	bridge := NewICMPBridge(inboundInstance, sender, icmpWireV2)

	request := buildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), 8, 0, 9, 7)
	request = append(request, traceIdentity...)
	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIPWithTrace, request); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one reply datagram, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[len(reply)-1] != byte(DatagramV2TypeIPWithTrace) {
		t.Fatalf("expected traced v2 reply, got type %d", reply[len(reply)-1])
	}
	gotIdentity := reply[len(reply)-1-icmpTraceIdentityLength : len(reply)-1]
	if !bytes.Equal(gotIdentity, traceIdentity) {
		t.Fatalf("unexpected trace identity: %x", gotIdentity)
	}
}

func TestICMPBridgeHandleV3Reply(t *testing.T) {
	sender := &captureDatagramSender{}
	router := &testRouter{
		preMatch: func(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error) {
			return &fakeDirectRouteDestination{
				routeContext: routeContext,
				reply:        buildEchoReply,
			}, nil
		},
	}
	inboundInstance := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		router:  router,
	}
	bridge := NewICMPBridge(inboundInstance, sender, icmpWireV3)

	request := buildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), 128, 0, 3, 5)
	if err := bridge.HandleV3(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one reply datagram, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[0] != byte(DatagramV3TypeICMP) {
		t.Fatalf("expected v3 ICMP datagram, got %d", reply[0])
	}
}

func TestICMPBridgeDropsNonEcho(t *testing.T) {
	var preMatchCalls int
	router := &testRouter{
		preMatch: func(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error) {
			preMatchCalls++
			return nil, nil
		},
	}
	inboundInstance := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		router:  router,
	}
	sender := &captureDatagramSender{}
	bridge := NewICMPBridge(inboundInstance, sender, icmpWireV2)

	packet := buildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), 3, 0, 1, 1)
	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet); err != nil {
		t.Fatal(err)
	}
	if preMatchCalls != 0 {
		t.Fatalf("expected no route lookup, got %d", preMatchCalls)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("expected no sender datagrams, got %d", len(sender.sent))
	}
}

func buildEchoReply(packet []byte) []byte {
	info, err := ParseICMPPacket(packet)
	if err != nil {
		panic(err)
	}
	switch info.IPVersion {
	case 4:
		return buildIPv4ICMPPacket(info.Destination, info.SourceIP, 0, 0, info.Identifier, info.Sequence)
	case 6:
		return buildIPv6ICMPPacket(info.Destination, info.SourceIP, 129, 0, info.Identifier, info.Sequence)
	default:
		panic("unsupported version")
	}
}

func buildIPv4ICMPPacket(source, destination netip.Addr, icmpType, icmpCode uint8, identifier, sequence uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	packet[20] = icmpType
	packet[21] = icmpCode
	binary.BigEndian.PutUint16(packet[24:26], identifier)
	binary.BigEndian.PutUint16(packet[26:28], sequence)
	return packet
}

func buildIPv6ICMPPacket(source, destination netip.Addr, icmpType, icmpCode uint8, identifier, sequence uint16) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = 58
	packet[7] = 64
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	packet[40] = icmpType
	packet[41] = icmpCode
	binary.BigEndian.PutUint16(packet[44:46], identifier)
	binary.BigEndian.PutUint16(packet[46:48], sequence)
	return packet
}
