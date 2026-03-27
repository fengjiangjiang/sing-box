//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxDialer "github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.CloudflaredInboundOptions](registry, C.TypeCloudflared, NewInbound)
}

var ErrNonRemoteManagedTunnelUnsupported = errors.New("cloudflared only supports remote-managed tunnels")

var (
	newQUICConnection   = NewQUICConnection
	newHTTP2Connection  = NewHTTP2Connection
	serveQUICConnection = func(connection *QUICConnection, ctx context.Context, handler StreamHandler) error {
		return connection.Serve(ctx, handler)
	}
	serveHTTP2Connection = func(connection *HTTP2Connection, ctx context.Context) error {
		return connection.Serve(ctx)
	}
)

type Inbound struct {
	inbound.Adapter
	ctx             context.Context
	cancel          context.CancelFunc
	router          adapter.Router
	logger          log.ContextLogger
	credentials     Credentials
	connectorID     uuid.UUID
	haConnections   int
	protocol        string
	region          string
	edgeIPVersion   int
	datagramVersion string
	featureSelector *featureSelector
	gracePeriod     time.Duration
	configManager   *ConfigManager
	flowLimiter     *FlowLimiter
	accessCache     *accessValidatorCache
	controlDialer   N.Dialer
	tunnelDialer    N.Dialer

	connectionAccess sync.Mutex
	connections      []io.Closer
	done             sync.WaitGroup

	datagramMuxerAccess sync.Mutex
	datagramV2Muxers    map[DatagramSender]*DatagramV2Muxer
	datagramV3Muxers    map[DatagramSender]*DatagramV3Muxer
	datagramV3Manager   *DatagramV3SessionManager

	connectedAccess  sync.Mutex
	connectedIndices map[uint8]struct{}
	connectedNotify  chan uint8

	stateAccess             sync.Mutex
	connectionStates        []connectionState
	successfulProtocols     map[string]struct{}
	firstSuccessfulProtocol string

	directTransportAccess sync.Mutex
	directTransports      map[string]*http.Transport
}

type connectionState struct {
	protocol string
	retries  uint8
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CloudflaredInboundOptions) (adapter.Inbound, error) {
	if options.Token == "" {
		return nil, E.New("missing token")
	}
	credentials, err := parseToken(options.Token)
	if err != nil {
		return nil, E.Cause(err, "parse token")
	}

	haConnections := options.HAConnections
	if haConnections <= 0 {
		haConnections = 4
	}

	protocol, err := normalizeProtocol(options.Protocol)
	if err != nil {
		return nil, err
	}

	edgeIPVersion := options.EdgeIPVersion
	if edgeIPVersion != 0 && edgeIPVersion != 4 && edgeIPVersion != 6 {
		return nil, E.New("unsupported edge_ip_version: ", edgeIPVersion, ", expected 0, 4 or 6")
	}

	datagramVersion := options.DatagramVersion
	if datagramVersion != "" && datagramVersion != "v2" && datagramVersion != "v3" {
		return nil, E.New("unsupported datagram_version: ", datagramVersion, ", expected v2 or v3")
	}

	gracePeriod := time.Duration(options.GracePeriod)
	if gracePeriod == 0 {
		gracePeriod = 30 * time.Second
	}

	configManager, err := NewConfigManager()
	if err != nil {
		return nil, E.Cause(err, "build cloudflared runtime config")
	}
	controlDialer, err := boxDialer.NewWithOptions(boxDialer.Options{
		Context:        ctx,
		Options:        options.ControlDialer,
		RemoteIsDomain: true,
	})
	if err != nil {
		return nil, E.Cause(err, "build cloudflared control dialer")
	}
	tunnelDialer, err := boxDialer.NewWithOptions(boxDialer.Options{
		Context: ctx,
		Options: options.TunnelDialer,
	})
	if err != nil {
		return nil, E.Cause(err, "build cloudflared tunnel dialer")
	}

	region := options.Region
	if region != "" && credentials.Endpoint != "" {
		return nil, E.New("region cannot be specified when credentials already include an endpoint")
	}
	if region == "" {
		region = credentials.Endpoint
	}

	inboundCtx, cancel := context.WithCancel(ctx)

	return &Inbound{
		Adapter:             inbound.NewAdapter(C.TypeCloudflared, tag),
		ctx:                 inboundCtx,
		cancel:              cancel,
		router:              router,
		logger:              logger,
		credentials:         credentials,
		connectorID:         uuid.New(),
		haConnections:       haConnections,
		protocol:            protocol,
		region:              region,
		edgeIPVersion:       edgeIPVersion,
		datagramVersion:     datagramVersion,
		featureSelector:     newFeatureSelector(inboundCtx, credentials.AccountTag, datagramVersion),
		gracePeriod:         gracePeriod,
		configManager:       configManager,
		flowLimiter:         &FlowLimiter{},
		accessCache:         &accessValidatorCache{values: make(map[string]accessValidator), dialer: controlDialer},
		controlDialer:       controlDialer,
		tunnelDialer:        tunnelDialer,
		datagramV2Muxers:    make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers:    make(map[DatagramSender]*DatagramV3Muxer),
		datagramV3Manager:   NewDatagramV3SessionManager(),
		connectedIndices:    make(map[uint8]struct{}),
		connectedNotify:     make(chan uint8, haConnections),
		connectionStates:    make([]connectionState, haConnections),
		successfulProtocols: make(map[string]struct{}),
		directTransports:    make(map[string]*http.Transport),
	}, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	i.logger.Info("starting Cloudflare Tunnel with ", i.haConnections, " HA connections")

	regions, err := DiscoverEdge(i.ctx, i.region, i.controlDialer)
	if err != nil {
		return E.Cause(err, "discover edge")
	}
	regions = FilterByIPVersion(regions, i.edgeIPVersion)
	edgeAddrs := flattenRegions(regions)
	if len(edgeAddrs) == 0 {
		return E.New("no edge addresses available")
	}
	if cappedHAConnections := effectiveHAConnections(i.haConnections, len(edgeAddrs)); cappedHAConnections != i.haConnections {
		i.logger.Info("requested ", i.haConnections, " HA connections but only ", cappedHAConnections, " edge addresses are available")
		i.haConnections = cappedHAConnections
	}

	for connIndex := 0; connIndex < i.haConnections; connIndex++ {
		i.initializeConnectionState(uint8(connIndex))
		i.done.Add(1)
		go i.superviseConnection(uint8(connIndex), edgeAddrs)
		select {
		case readyConnIndex := <-i.connectedNotify:
			if readyConnIndex != uint8(connIndex) {
				i.logger.Debug("received unexpected ready notification for connection ", readyConnIndex)
			}
		case <-time.After(firstConnectionReadyTimeout):
		case <-i.ctx.Done():
			if connIndex == 0 {
				return i.ctx.Err()
			}
			return nil
		}
	}
	return nil
}

func (i *Inbound) notifyConnected(connIndex uint8, protocol string) {
	i.stateAccess.Lock()
	if i.successfulProtocols == nil {
		i.successfulProtocols = make(map[string]struct{})
	}
	i.ensureConnectionStateLocked(connIndex)
	state := i.connectionStates[connIndex]
	state.retries = 0
	state.protocol = protocol
	i.connectionStates[connIndex] = state
	if protocol != "" {
		i.successfulProtocols[protocol] = struct{}{}
		if i.firstSuccessfulProtocol == "" {
			i.firstSuccessfulProtocol = protocol
		}
	}
	i.stateAccess.Unlock()

	if i.connectedNotify == nil {
		return
	}
	i.connectedAccess.Lock()
	if _, loaded := i.connectedIndices[connIndex]; loaded {
		i.connectedAccess.Unlock()
		return
	}
	i.connectedIndices[connIndex] = struct{}{}
	i.connectedAccess.Unlock()
	i.connectedNotify <- connIndex
}

func (i *Inbound) ApplyConfig(version int32, config []byte) ConfigUpdateResult {
	result := i.configManager.Apply(version, config)
	if result.Err != nil {
		i.logger.Error("update ingress configuration: ", result.Err)
		return result
	}
	i.resetDirectOriginTransports()
	i.logger.Info("updated ingress configuration (version ", result.LastAppliedVersion, ")")
	return result
}

func (i *Inbound) maxActiveFlows() uint64 {
	return i.configManager.Snapshot().WarpRouting.MaxActiveFlows
}

func (i *Inbound) Close() error {
	i.cancel()
	i.done.Wait()
	i.connectionAccess.Lock()
	for _, connection := range i.connections {
		connection.Close()
	}
	i.connections = nil
	i.connectionAccess.Unlock()
	i.resetDirectOriginTransports()
	return nil
}

const (
	backoffBaseTime             = time.Second
	backoffMaxTime              = 2 * time.Minute
	firstConnectionReadyTimeout = 15 * time.Second
)

func (i *Inbound) superviseConnection(connIndex uint8, edgeAddrs []*EdgeAddr) {
	defer i.done.Done()

	edgeIndex := initialEdgeAddrIndex(connIndex, len(edgeAddrs))
	for {
		select {
		case <-i.ctx.Done():
			return
		default:
		}

		edgeAddr := edgeAddrs[edgeIndex]
		err := i.safeServeConnection(connIndex, edgeAddr)
		if err == nil || i.ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrNonRemoteManagedTunnelUnsupported) {
			i.logger.Error("connection ", connIndex, " failed permanently: ", err)
			i.cancel()
			return
		}

		retries := i.incrementConnectionRetries(connIndex)
		edgeIndex = rotateEdgeAddrIndex(edgeIndex, len(edgeAddrs))
		backoff := backoffDuration(int(retries))
		var retryableErr *RetryableError
		if errors.As(err, &retryableErr) && retryableErr.Delay > 0 {
			backoff = retryableErr.Delay
		}
		i.logger.Error("connection ", connIndex, " failed: ", err, ", retrying in ", backoff)

		select {
		case <-time.After(backoff):
		case <-i.ctx.Done():
			return
		}
	}
}

func (i *Inbound) serveConnection(connIndex uint8, edgeAddr *EdgeAddr) error {
	state := i.connectionState(connIndex)
	protocol := state.protocol
	numPreviousAttempts := state.retries
	datagramVersion, features := i.currentConnectionFeatures()

	switch protocol {
	case "quic":
		err := i.serveQUIC(connIndex, edgeAddr, datagramVersion, features, numPreviousAttempts)
		if err == nil || i.ctx.Err() != nil {
			return err
		}
		if errors.Is(err, ErrNonRemoteManagedTunnelUnsupported) {
			return err
		}
		if !i.protocolIsAuto() {
			return err
		}
		if i.hasSuccessfulProtocol("quic") {
			return err
		}
		i.setConnectionProtocol(connIndex, "http2")
		i.logger.Warn("QUIC connection failed, falling back to HTTP/2: ", err)
		return i.serveHTTP2(connIndex, edgeAddr, features, numPreviousAttempts)
	case "http2":
		return i.serveHTTP2(connIndex, edgeAddr, features, numPreviousAttempts)
	default:
		return E.New("unsupported protocol: ", protocol)
	}
}

func (i *Inbound) safeServeConnection(connIndex uint8, edgeAddr *EdgeAddr) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = E.New("panic in serve connection: ", recovered, "\n", string(debug.Stack()))
		}
	}()
	return i.serveConnection(connIndex, edgeAddr)
}

func (i *Inbound) serveQUIC(connIndex uint8, edgeAddr *EdgeAddr, datagramVersion string, features []string, numPreviousAttempts uint8) error {
	i.logger.Info("connecting to edge via QUIC (connection ", connIndex, ")")

	connection, err := newQUICConnection(
		i.ctx, edgeAddr, connIndex,
		i.credentials, i.connectorID, datagramVersion,
		features, numPreviousAttempts, i.gracePeriod, i.tunnelDialer, func() {
			i.notifyConnected(connIndex, "quic")
		}, i.logger,
	)
	if err != nil {
		return E.Cause(err, "create QUIC connection")
	}

	i.trackConnection(connection)
	defer func() {
		i.untrackConnection(connection)
		i.RemoveDatagramMuxer(connection)
	}()

	return serveQUICConnection(connection, i.ctx, i)
}

func (i *Inbound) currentConnectionFeatures() (string, []string) {
	if i.featureSelector != nil {
		return i.featureSelector.Snapshot()
	}
	version := i.datagramVersion
	if version == "" {
		version = defaultDatagramVersion
	}
	return version, DefaultFeatures(version)
}

func (i *Inbound) serveHTTP2(connIndex uint8, edgeAddr *EdgeAddr, features []string, numPreviousAttempts uint8) error {
	i.logger.Info("connecting to edge via HTTP/2 (connection ", connIndex, ")")

	connection, err := newHTTP2Connection(
		i.ctx, edgeAddr, connIndex,
		i.credentials, i.connectorID,
		features, numPreviousAttempts, i.gracePeriod, i, i.logger,
	)
	if err != nil {
		return E.Cause(err, "create HTTP/2 connection")
	}

	i.trackConnection(connection)
	defer i.untrackConnection(connection)

	return serveHTTP2Connection(connection, i.ctx)
}

func (i *Inbound) initializeConnectionState(connIndex uint8) {
	i.stateAccess.Lock()
	defer i.stateAccess.Unlock()
	i.ensureConnectionStateLocked(connIndex)
	if i.connectionStates[connIndex].protocol == "" {
		i.connectionStates[connIndex].protocol = i.initialProtocolLocked()
	}
}

func (i *Inbound) connectionState(connIndex uint8) connectionState {
	i.stateAccess.Lock()
	defer i.stateAccess.Unlock()
	i.ensureConnectionStateLocked(connIndex)
	state := i.connectionStates[connIndex]
	if state.protocol == "" {
		state.protocol = i.initialProtocolLocked()
		i.connectionStates[connIndex] = state
	}
	return state
}

func (i *Inbound) incrementConnectionRetries(connIndex uint8) uint8 {
	i.stateAccess.Lock()
	defer i.stateAccess.Unlock()
	i.ensureConnectionStateLocked(connIndex)
	state := i.connectionStates[connIndex]
	state.retries++
	i.connectionStates[connIndex] = state
	return state.retries
}

func (i *Inbound) setConnectionProtocol(connIndex uint8, protocol string) {
	i.stateAccess.Lock()
	defer i.stateAccess.Unlock()
	i.ensureConnectionStateLocked(connIndex)
	state := i.connectionStates[connIndex]
	state.protocol = protocol
	i.connectionStates[connIndex] = state
}

func (i *Inbound) hasSuccessfulProtocol(protocol string) bool {
	i.stateAccess.Lock()
	defer i.stateAccess.Unlock()
	if i.successfulProtocols == nil {
		return false
	}
	_, ok := i.successfulProtocols[protocol]
	return ok
}

func (i *Inbound) protocolIsAuto() bool {
	return i.protocol == ""
}

func (i *Inbound) ensureConnectionStateLocked(connIndex uint8) {
	requiredLen := int(connIndex) + 1
	if len(i.connectionStates) >= requiredLen {
		return
	}
	grown := make([]connectionState, requiredLen)
	copy(grown, i.connectionStates)
	i.connectionStates = grown
}

func (i *Inbound) initialProtocolLocked() string {
	if i.protocol != "" {
		return i.protocol
	}
	if i.firstSuccessfulProtocol != "" {
		return i.firstSuccessfulProtocol
	}
	return "quic"
}

func (i *Inbound) resetDirectOriginTransports() {
	i.directTransportAccess.Lock()
	transports := i.directTransports
	i.directTransports = make(map[string]*http.Transport)
	i.directTransportAccess.Unlock()

	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func (i *Inbound) trackConnection(connection io.Closer) {
	i.connectionAccess.Lock()
	defer i.connectionAccess.Unlock()
	i.connections = append(i.connections, connection)
}

func (i *Inbound) untrackConnection(connection io.Closer) {
	i.connectionAccess.Lock()
	defer i.connectionAccess.Unlock()
	for index, tracked := range i.connections {
		if tracked == connection {
			i.connections = append(i.connections[:index], i.connections[index+1:]...)
			break
		}
	}
}

func backoffDuration(retries int) time.Duration {
	backoff := backoffBaseTime * (1 << min(retries, 7))
	if backoff > backoffMaxTime {
		backoff = backoffMaxTime
	}
	// Add jitter: random duration in [backoff/2, backoff)
	jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
	return backoff/2 + jitter
}

func initialEdgeAddrIndex(connIndex uint8, size int) int {
	if size <= 1 {
		return 0
	}
	return int(connIndex) % size
}

func rotateEdgeAddrIndex(current int, size int) int {
	if size <= 1 {
		return 0
	}
	return (current + 1) % size
}

func flattenRegions(regions [][]*EdgeAddr) []*EdgeAddr {
	var result []*EdgeAddr
	for _, region := range regions {
		result = append(result, region...)
	}
	return result
}

func effectiveHAConnections(requested, available int) int {
	if available <= 0 {
		return 0
	}
	if requested > available {
		return available
	}
	return requested
}

func parseToken(token string) (Credentials, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return Credentials{}, E.Cause(err, "decode token")
	}
	var tunnelToken TunnelToken
	err = json.Unmarshal(data, &tunnelToken)
	if err != nil {
		return Credentials{}, E.Cause(err, "unmarshal token")
	}
	return tunnelToken.ToCredentials(), nil
}

// "auto" does not choose a transport here. We normalize it to an empty
// sentinel so serveConnection can apply the token-style behavior later.
// In the token-provided, remotely-managed tunnel path supported here, that
// matches cloudflared's NewProtocolSelector(..., tunnelTokenProvided=true)
// branch rather than the non-token remote-percentage selector.
func normalizeProtocol(protocol string) (string, error) {
	if protocol == "auto" {
		return "", nil
	}
	if protocol != "" && protocol != "quic" && protocol != "http2" {
		return "", E.New("unsupported protocol: ", protocol, ", expected auto, quic or http2")
	}
	return protocol, nil
}
