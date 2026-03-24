//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// V3 wire format: [1B type | payload] (prefix-based)

// DatagramV3Type identifies the type of a V3 datagram.
type DatagramV3Type byte

const (
	DatagramV3TypeRegistration         DatagramV3Type = 0
	DatagramV3TypePayload              DatagramV3Type = 1
	DatagramV3TypeICMP                 DatagramV3Type = 2
	DatagramV3TypeRegistrationResponse DatagramV3Type = 3

	// V3 registration header sizes
	v3RegistrationFlagLen = 1
	v3RegistrationPortLen = 2
	v3RegistrationIdleLen = 2
	v3RequestIDLength     = 16
	v3IPv4AddrLen         = 4
	v3IPv6AddrLen         = 16
	v3RegistrationBaseLen = 1 + v3RegistrationFlagLen + v3RegistrationPortLen + v3RegistrationIdleLen + v3RequestIDLength // 22
	v3PayloadHeaderLen    = 1 + v3RequestIDLength                                                                         // 17
	v3RegistrationRespLen = 1 + 1 + v3RequestIDLength + 2                                                                 // 20

	// V3 registration flags
	v3FlagIPv6   byte = 0x01
	v3FlagTraced byte = 0x02
	v3FlagBundle byte = 0x04

	// V3 registration response types
	v3ResponseOK                     byte = 0x00
	v3ResponseDestinationUnreachable byte = 0x01
	v3ResponseUnableToBindSocket     byte = 0x02
	v3ResponseTooManyActiveFlows     byte = 0x03
	v3ResponseErrorWithMsg           byte = 0xFF
)

// RequestID is a 128-bit session identifier for V3.
type RequestID [v3RequestIDLength]byte

// DatagramV3Muxer handles V3 datagram demuxing and session management.
type DatagramV3Muxer struct {
	inbound *Inbound
	logger  log.ContextLogger
	sender  DatagramSender
	icmp    *ICMPBridge

	sessionAccess sync.RWMutex
	sessions      map[RequestID]*v3Session
}

// NewDatagramV3Muxer creates a new V3 datagram muxer.
func NewDatagramV3Muxer(inbound *Inbound, sender DatagramSender, logger log.ContextLogger) *DatagramV3Muxer {
	return &DatagramV3Muxer{
		inbound:  inbound,
		logger:   logger,
		sender:   sender,
		icmp:     NewICMPBridge(inbound, sender, icmpWireV3),
		sessions: make(map[RequestID]*v3Session),
	}
}

// HandleDatagram demuxes an incoming V3 datagram.
func (m *DatagramV3Muxer) HandleDatagram(ctx context.Context, data []byte) {
	if len(data) < 1 {
		return
	}

	datagramType := DatagramV3Type(data[0])
	payload := data[1:]

	switch datagramType {
	case DatagramV3TypeRegistration:
		m.handleRegistration(ctx, payload)
	case DatagramV3TypePayload:
		m.handlePayload(payload)
	case DatagramV3TypeICMP:
		if err := m.icmp.HandleV3(ctx, payload); err != nil {
			m.logger.Debug("drop V3 ICMP datagram: ", err)
		}
	case DatagramV3TypeRegistrationResponse:
		// Unexpected - we never send registrations
		m.logger.Debug("received unexpected V3 registration response")
	}
}

func (m *DatagramV3Muxer) handleRegistration(ctx context.Context, data []byte) {
	if len(data) < v3RegistrationFlagLen+v3RegistrationPortLen+v3RegistrationIdleLen+v3RequestIDLength {
		m.logger.Debug("V3 registration too short")
		return
	}

	flags := data[0]
	destinationPort := binary.BigEndian.Uint16(data[1:3])
	idleDurationSeconds := binary.BigEndian.Uint16(data[3:5])

	var requestID RequestID
	copy(requestID[:], data[5:5+v3RequestIDLength])

	offset := 5 + v3RequestIDLength
	var destination netip.AddrPort

	if flags&v3FlagIPv6 != 0 {
		if len(data) < offset+v3IPv6AddrLen {
			m.logger.Debug("V3 registration too short for IPv6")
			return
		}
		var addr [16]byte
		copy(addr[:], data[offset:offset+v3IPv6AddrLen])
		destination = netip.AddrPortFrom(netip.AddrFrom16(addr), destinationPort)
		offset += v3IPv6AddrLen
	} else {
		if len(data) < offset+v3IPv4AddrLen {
			m.logger.Debug("V3 registration too short for IPv4")
			return
		}
		var addr [4]byte
		copy(addr[:], data[offset:offset+v3IPv4AddrLen])
		destination = netip.AddrPortFrom(netip.AddrFrom4(addr), destinationPort)
		offset += v3IPv4AddrLen
	}

	closeAfterIdle := time.Duration(idleDurationSeconds) * time.Second
	if closeAfterIdle == 0 {
		closeAfterIdle = 210 * time.Second
	}

	m.sessionAccess.Lock()
	if existing, exists := m.sessions[requestID]; exists {
		m.sessionAccess.Unlock()
		// Session already exists - re-ack
		m.sendRegistrationResponse(requestID, v3ResponseOK, "")
		// Handle bundled payload
		if flags&v3FlagBundle != 0 && len(data) > offset {
			existing.writeToOrigin(data[offset:])
		}
		return
	}

	session := newV3Session(requestID, destination, closeAfterIdle, m)
	m.sessions[requestID] = session
	m.sessionAccess.Unlock()

	m.logger.Info("registered V3 UDP session to ", destination)
	m.sendRegistrationResponse(requestID, v3ResponseOK, "")

	// Handle bundled first payload
	if flags&v3FlagBundle != 0 && len(data) > offset {
		session.writeToOrigin(data[offset:])
	}

	go m.serveV3Session(ctx, session)
}

func (m *DatagramV3Muxer) handlePayload(data []byte) {
	if len(data) < v3RequestIDLength {
		return
	}

	var requestID RequestID
	copy(requestID[:], data[:v3RequestIDLength])
	payload := data[v3RequestIDLength:]

	m.sessionAccess.RLock()
	session, exists := m.sessions[requestID]
	m.sessionAccess.RUnlock()

	if !exists {
		return
	}

	session.writeToOrigin(payload)
}

func (m *DatagramV3Muxer) sendRegistrationResponse(requestID RequestID, responseType byte, errorMessage string) {
	errorBytes := []byte(errorMessage)
	data := make([]byte, v3RegistrationRespLen+len(errorBytes))
	data[0] = byte(DatagramV3TypeRegistrationResponse)
	data[1] = responseType
	copy(data[2:2+v3RequestIDLength], requestID[:])
	binary.BigEndian.PutUint16(data[2+v3RequestIDLength:], uint16(len(errorBytes)))
	copy(data[v3RegistrationRespLen:], errorBytes)
	m.sender.SendDatagram(data)
}

func (m *DatagramV3Muxer) sendPayload(requestID RequestID, payload []byte) {
	data := make([]byte, v3PayloadHeaderLen+len(payload))
	data[0] = byte(DatagramV3TypePayload)
	copy(data[1:1+v3RequestIDLength], requestID[:])
	copy(data[v3PayloadHeaderLen:], payload)
	m.sender.SendDatagram(data)
}

func (m *DatagramV3Muxer) unregisterSession(requestID RequestID) {
	m.sessionAccess.Lock()
	session, exists := m.sessions[requestID]
	if exists {
		delete(m.sessions, requestID)
	}
	m.sessionAccess.Unlock()

	if exists {
		session.close()
	}
}

func (m *DatagramV3Muxer) serveV3Session(ctx context.Context, session *v3Session) {
	defer m.unregisterSession(session.id)

	metadata := adapter.InboundContext{
		Inbound:     m.inbound.Tag(),
		InboundType: m.inbound.Type(),
		Network:     N.NetworkUDP,
	}
	metadata.Destination = M.SocksaddrFromNetIP(session.destination)

	done := make(chan struct{})
	m.inbound.router.RoutePacketConnectionEx(
		ctx,
		session,
		metadata,
		N.OnceClose(func(it error) {
			close(done)
		}),
	)
	<-done
}

// Close closes all V3 sessions.
func (m *DatagramV3Muxer) Close() {
	m.sessionAccess.Lock()
	sessions := m.sessions
	m.sessions = make(map[RequestID]*v3Session)
	m.sessionAccess.Unlock()

	for _, session := range sessions {
		session.close()
	}
}

// v3Session represents a V3 UDP session.
type v3Session struct {
	id             RequestID
	destination    netip.AddrPort
	closeAfterIdle time.Duration
	muxer          *DatagramV3Muxer

	writeChan chan []byte
	closeOnce sync.Once
	closeChan chan struct{}
}

func newV3Session(id RequestID, destination netip.AddrPort, closeAfterIdle time.Duration, muxer *DatagramV3Muxer) *v3Session {
	return &v3Session{
		id:             id,
		destination:    destination,
		closeAfterIdle: closeAfterIdle,
		muxer:          muxer,
		writeChan:      make(chan []byte, 512),
		closeChan:      make(chan struct{}),
	}
}

func (s *v3Session) writeToOrigin(payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)
	select {
	case s.writeChan <- data:
	default:
	}
}

func (s *v3Session) close() {
	s.closeOnce.Do(func() {
		close(s.closeChan)
	})
}

// ReadPacket implements N.PacketConn.
func (s *v3Session) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case data := <-s.writeChan:
		_, err := buffer.Write(data)
		return M.SocksaddrFromNetIP(s.destination), err
	case <-s.closeChan:
		return M.Socksaddr{}, io.EOF
	}
}

// WritePacket implements N.PacketConn.
func (s *v3Session) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	s.muxer.sendPayload(s.id, buffer.Bytes())
	return nil
}

func (s *v3Session) Close() error {
	s.close()
	return nil
}

func (s *v3Session) LocalAddr() net.Addr                { return nil }
func (s *v3Session) SetDeadline(_ time.Time) error      { return nil }
func (s *v3Session) SetReadDeadline(_ time.Time) error  { return nil }
func (s *v3Session) SetWriteDeadline(_ time.Time) error { return nil }
