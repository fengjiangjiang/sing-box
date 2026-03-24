//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	icmpFlowTimeout         = 30 * time.Second
	icmpTraceIdentityLength = 16 + 8 + 1
)

type ICMPTraceContext struct {
	Traced   bool
	Identity []byte
}

type ICMPFlowKey struct {
	IPVersion   uint8
	SourceIP    netip.Addr
	Destination netip.Addr
}

type ICMPRequestKey struct {
	Flow       ICMPFlowKey
	Identifier uint16
	Sequence   uint16
}

type ICMPPacketInfo struct {
	IPVersion   uint8
	Protocol    uint8
	SourceIP    netip.Addr
	Destination netip.Addr
	ICMPType    uint8
	ICMPCode    uint8
	Identifier  uint16
	Sequence    uint16
	RawPacket   []byte
}

func (i ICMPPacketInfo) FlowKey() ICMPFlowKey {
	return ICMPFlowKey{
		IPVersion:   i.IPVersion,
		SourceIP:    i.SourceIP,
		Destination: i.Destination,
	}
}

func (i ICMPPacketInfo) RequestKey() ICMPRequestKey {
	return ICMPRequestKey{
		Flow:       i.FlowKey(),
		Identifier: i.Identifier,
		Sequence:   i.Sequence,
	}
}

func (i ICMPPacketInfo) ReplyRequestKey() ICMPRequestKey {
	return ICMPRequestKey{
		Flow: ICMPFlowKey{
			IPVersion:   i.IPVersion,
			SourceIP:    i.Destination,
			Destination: i.SourceIP,
		},
		Identifier: i.Identifier,
		Sequence:   i.Sequence,
	}
}

func (i ICMPPacketInfo) IsEchoRequest() bool {
	switch i.IPVersion {
	case 4:
		return i.ICMPType == 8 && i.ICMPCode == 0
	case 6:
		return i.ICMPType == 128 && i.ICMPCode == 0
	default:
		return false
	}
}

func (i ICMPPacketInfo) IsEchoReply() bool {
	switch i.IPVersion {
	case 4:
		return i.ICMPType == 0 && i.ICMPCode == 0
	case 6:
		return i.ICMPType == 129 && i.ICMPCode == 0
	default:
		return false
	}
}

type icmpWireVersion uint8

const (
	icmpWireV2 icmpWireVersion = iota + 1
	icmpWireV3
)

type icmpFlowState struct {
	writer *ICMPReplyWriter
}

type ICMPReplyWriter struct {
	sender      DatagramSender
	wireVersion icmpWireVersion

	access sync.Mutex
	traces map[ICMPRequestKey]ICMPTraceContext
}

func NewICMPReplyWriter(sender DatagramSender, wireVersion icmpWireVersion) *ICMPReplyWriter {
	return &ICMPReplyWriter{
		sender:      sender,
		wireVersion: wireVersion,
		traces:      make(map[ICMPRequestKey]ICMPTraceContext),
	}
}

func (w *ICMPReplyWriter) RegisterRequestTrace(packetInfo ICMPPacketInfo, traceContext ICMPTraceContext) {
	if !traceContext.Traced {
		return
	}
	w.access.Lock()
	w.traces[packetInfo.RequestKey()] = traceContext
	w.access.Unlock()
}

func (w *ICMPReplyWriter) WritePacket(packet []byte) error {
	packetInfo, err := ParseICMPPacket(packet)
	if err != nil {
		return err
	}
	if !packetInfo.IsEchoReply() {
		return nil
	}

	requestKey := packetInfo.ReplyRequestKey()
	w.access.Lock()
	traceContext, loaded := w.traces[requestKey]
	if loaded {
		delete(w.traces, requestKey)
	}
	w.access.Unlock()

	var datagram []byte
	switch w.wireVersion {
	case icmpWireV2:
		datagram, err = encodeV2ICMPDatagram(packetInfo.RawPacket, traceContext)
	case icmpWireV3:
		datagram = encodeV3ICMPDatagram(packetInfo.RawPacket)
	default:
		err = E.New("unsupported icmp wire version: ", w.wireVersion)
	}
	if err != nil {
		return err
	}
	return w.sender.SendDatagram(datagram)
}

type ICMPBridge struct {
	inbound      *Inbound
	sender       DatagramSender
	wireVersion  icmpWireVersion
	routeMapping *tun.DirectRouteMapping

	flowAccess sync.Mutex
	flows      map[ICMPFlowKey]*icmpFlowState
}

func NewICMPBridge(inbound *Inbound, sender DatagramSender, wireVersion icmpWireVersion) *ICMPBridge {
	return &ICMPBridge{
		inbound:      inbound,
		sender:       sender,
		wireVersion:  wireVersion,
		routeMapping: tun.NewDirectRouteMapping(icmpFlowTimeout),
		flows:        make(map[ICMPFlowKey]*icmpFlowState),
	}
}

func (b *ICMPBridge) HandleV2(ctx context.Context, datagramType DatagramV2Type, payload []byte) error {
	traceContext := ICMPTraceContext{}
	switch datagramType {
	case DatagramV2TypeIP:
	case DatagramV2TypeIPWithTrace:
		if len(payload) < icmpTraceIdentityLength {
			return E.New("icmp trace payload is too short")
		}
		traceContext.Traced = true
		traceContext.Identity = append([]byte(nil), payload[len(payload)-icmpTraceIdentityLength:]...)
		payload = payload[:len(payload)-icmpTraceIdentityLength]
	default:
		return E.New("unsupported v2 icmp datagram type: ", datagramType)
	}
	return b.handlePacket(ctx, payload, traceContext)
}

func (b *ICMPBridge) HandleV3(ctx context.Context, payload []byte) error {
	return b.handlePacket(ctx, payload, ICMPTraceContext{})
}

func (b *ICMPBridge) handlePacket(ctx context.Context, payload []byte, traceContext ICMPTraceContext) error {
	packetInfo, err := ParseICMPPacket(payload)
	if err != nil {
		return err
	}
	if !packetInfo.IsEchoRequest() {
		return nil
	}

	state := b.getFlowState(packetInfo.FlowKey())
	if traceContext.Traced {
		state.writer.RegisterRequestTrace(packetInfo, traceContext)
	}

	action, err := b.routeMapping.Lookup(tun.DirectRouteSession{
		Source:      packetInfo.SourceIP,
		Destination: packetInfo.Destination,
	}, func(timeout time.Duration) (tun.DirectRouteDestination, error) {
		metadata := adapter.InboundContext{
			Inbound:           b.inbound.Tag(),
			InboundType:       b.inbound.Type(),
			IPVersion:         packetInfo.IPVersion,
			Network:           N.NetworkICMP,
			Source:            M.SocksaddrFrom(packetInfo.SourceIP, 0),
			Destination:       M.SocksaddrFrom(packetInfo.Destination, 0),
			OriginDestination: M.SocksaddrFrom(packetInfo.Destination, 0),
		}
		return b.inbound.router.PreMatch(metadata, state.writer, timeout, false)
	})
	if err != nil {
		return nil
	}
	return action.WritePacket(buf.As(packetInfo.RawPacket).ToOwned())
}

func (b *ICMPBridge) getFlowState(key ICMPFlowKey) *icmpFlowState {
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	state, loaded := b.flows[key]
	if loaded {
		return state
	}
	state = &icmpFlowState{
		writer: NewICMPReplyWriter(b.sender, b.wireVersion),
	}
	b.flows[key] = state
	return state
}

func ParseICMPPacket(packet []byte) (ICMPPacketInfo, error) {
	if len(packet) < 1 {
		return ICMPPacketInfo{}, E.New("empty IP packet")
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return parseIPv4ICMPPacket(packet)
	case 6:
		return parseIPv6ICMPPacket(packet)
	default:
		return ICMPPacketInfo{}, E.New("unsupported IP version: ", version)
	}
}

func parseIPv4ICMPPacket(packet []byte) (ICMPPacketInfo, error) {
	if len(packet) < 20 {
		return ICMPPacketInfo{}, E.New("IPv4 packet too short")
	}
	headerLen := int(packet[0]&0x0F) * 4
	if headerLen < 20 || len(packet) < headerLen+8 {
		return ICMPPacketInfo{}, E.New("invalid IPv4 header length")
	}
	if packet[9] != 1 {
		return ICMPPacketInfo{}, E.New("IPv4 packet is not ICMP")
	}
	sourceIP, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv4 source address")
	}
	destinationIP, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv4 destination address")
	}
	return ICMPPacketInfo{
		IPVersion:   4,
		Protocol:    1,
		SourceIP:    sourceIP,
		Destination: destinationIP,
		ICMPType:    packet[headerLen],
		ICMPCode:    packet[headerLen+1],
		Identifier:  binary.BigEndian.Uint16(packet[headerLen+4 : headerLen+6]),
		Sequence:    binary.BigEndian.Uint16(packet[headerLen+6 : headerLen+8]),
		RawPacket:   append([]byte(nil), packet...),
	}, nil
}

func parseIPv6ICMPPacket(packet []byte) (ICMPPacketInfo, error) {
	if len(packet) < 48 {
		return ICMPPacketInfo{}, E.New("IPv6 packet too short")
	}
	if packet[6] != 58 {
		return ICMPPacketInfo{}, E.New("IPv6 packet is not ICMP")
	}
	sourceIP, ok := netip.AddrFromSlice(packet[8:24])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv6 source address")
	}
	destinationIP, ok := netip.AddrFromSlice(packet[24:40])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv6 destination address")
	}
	return ICMPPacketInfo{
		IPVersion:   6,
		Protocol:    58,
		SourceIP:    sourceIP,
		Destination: destinationIP,
		ICMPType:    packet[40],
		ICMPCode:    packet[41],
		Identifier:  binary.BigEndian.Uint16(packet[44:46]),
		Sequence:    binary.BigEndian.Uint16(packet[46:48]),
		RawPacket:   append([]byte(nil), packet...),
	}, nil
}

func encodeV2ICMPDatagram(packet []byte, traceContext ICMPTraceContext) ([]byte, error) {
	if traceContext.Traced {
		data := make([]byte, 0, len(packet)+len(traceContext.Identity)+1)
		data = append(data, packet...)
		data = append(data, traceContext.Identity...)
		data = append(data, byte(DatagramV2TypeIPWithTrace))
		return data, nil
	}
	data := make([]byte, 0, len(packet)+1)
	data = append(data, packet...)
	data = append(data, byte(DatagramV2TypeIP))
	return data, nil
}

func encodeV3ICMPDatagram(packet []byte) []byte {
	data := make([]byte, 0, len(packet)+1)
	data = append(data, byte(DatagramV3TypeICMP))
	data = append(data, packet...)
	return data
}
