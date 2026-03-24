//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"encoding/base64"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"github.com/google/uuid"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.CloudflareTunnelInboundOptions](registry, C.TypeCloudflareTunnel, NewInbound)
}

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
	gracePeriod     time.Duration
	configManager   *ConfigManager
	flowLimiter     *FlowLimiter

	connectionAccess sync.Mutex
	connections      []io.Closer
	done             sync.WaitGroup

	datagramMuxerAccess sync.Mutex
	datagramV2Muxers    map[DatagramSender]*DatagramV2Muxer
	datagramV3Muxers    map[DatagramSender]*DatagramV3Muxer

	helloWorldAccess sync.Mutex
	helloWorldServer *http.Server
	helloWorldURL    *url.URL
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CloudflareTunnelInboundOptions) (adapter.Inbound, error) {
	credentials, err := parseCredentials(options.Token, options.CredentialPath)
	if err != nil {
		return nil, E.Cause(err, "parse credentials")
	}

	haConnections := options.HAConnections
	if haConnections <= 0 {
		haConnections = 4
	}

	protocol := options.Protocol
	if protocol != "" && protocol != "quic" && protocol != "http2" {
		return nil, E.New("unsupported protocol: ", protocol, ", expected quic or http2")
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

	configManager, err := NewConfigManager(options)
	if err != nil {
		return nil, E.Cause(err, "build cloudflare tunnel runtime config")
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
		Adapter:          inbound.NewAdapter(C.TypeCloudflareTunnel, tag),
		ctx:              inboundCtx,
		cancel:           cancel,
		router:           router,
		logger:           logger,
		credentials:      credentials,
		connectorID:      uuid.New(),
		haConnections:    haConnections,
		protocol:         protocol,
		region:           region,
		edgeIPVersion:    edgeIPVersion,
		datagramVersion:  datagramVersion,
		gracePeriod:      gracePeriod,
		configManager:    configManager,
		flowLimiter:      &FlowLimiter{},
		datagramV2Muxers: make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers: make(map[DatagramSender]*DatagramV3Muxer),
	}, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	i.logger.Info("starting Cloudflare Tunnel with ", i.haConnections, " HA connections")

	regions, err := DiscoverEdge(i.ctx, i.region)
	if err != nil {
		return E.Cause(err, "discover edge")
	}
	regions = FilterByIPVersion(regions, i.edgeIPVersion)
	edgeAddrs := flattenRegions(regions)
	if len(edgeAddrs) == 0 {
		return E.New("no edge addresses available")
	}

	features := DefaultFeatures(i.datagramVersion)

	for connIndex := 0; connIndex < i.haConnections; connIndex++ {
		i.done.Add(1)
		go i.superviseConnection(uint8(connIndex), edgeAddrs, features)
		if connIndex == 0 {
			// Wait a bit for the first connection before starting others
			select {
			case <-time.After(time.Second):
			case <-i.ctx.Done():
				return i.ctx.Err()
			}
		} else {
			select {
			case <-time.After(time.Second):
			case <-i.ctx.Done():
				return nil
			}
		}
	}
	return nil
}

func (i *Inbound) ApplyConfig(version int32, config []byte) ConfigUpdateResult {
	result := i.configManager.Apply(version, config)
	if result.Err != nil {
		i.logger.Error("update ingress configuration: ", result.Err)
		return result
	}
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
	if i.helloWorldServer != nil {
		i.helloWorldServer.Close()
	}
	return nil
}

func (i *Inbound) ensureHelloWorldURL() (*url.URL, error) {
	i.helloWorldAccess.Lock()
	defer i.helloWorldAccess.Unlock()
	if i.helloWorldURL != nil {
		return i.helloWorldURL, nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("Hello World"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, E.Cause(err, "listen hello world server")
	}
	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	i.helloWorldServer = server
	i.helloWorldURL = &url.URL{
		Scheme: "http",
		Host:   listener.Addr().String(),
	}
	return i.helloWorldURL, nil
}

const (
	backoffBaseTime = time.Second
	backoffMaxTime  = 2 * time.Minute
)

func (i *Inbound) superviseConnection(connIndex uint8, edgeAddrs []*EdgeAddr, features []string) {
	defer i.done.Done()

	retries := 0
	for {
		select {
		case <-i.ctx.Done():
			return
		default:
		}

		edgeAddr := edgeAddrs[rand.Intn(len(edgeAddrs))]
		err := i.serveConnection(connIndex, edgeAddr, features, uint8(retries))
		if err == nil || i.ctx.Err() != nil {
			return
		}

		retries++
		backoff := backoffDuration(retries)
		i.logger.Error("connection ", connIndex, " failed: ", err, ", retrying in ", backoff)

		select {
		case <-time.After(backoff):
		case <-i.ctx.Done():
			return
		}
	}
}

func (i *Inbound) serveConnection(connIndex uint8, edgeAddr *EdgeAddr, features []string, numPreviousAttempts uint8) error {
	protocol := i.protocol
	if protocol == "" {
		protocol = "quic"
	}

	switch protocol {
	case "quic":
		return i.serveQUIC(connIndex, edgeAddr, features, numPreviousAttempts)
	case "http2":
		return i.serveHTTP2(connIndex, edgeAddr, features, numPreviousAttempts)
	default:
		return E.New("unsupported protocol: ", protocol)
	}
}

func (i *Inbound) serveQUIC(connIndex uint8, edgeAddr *EdgeAddr, features []string, numPreviousAttempts uint8) error {
	i.logger.Info("connecting to edge via QUIC (connection ", connIndex, ")")

	connection, err := NewQUICConnection(
		i.ctx, edgeAddr, connIndex,
		i.credentials, i.connectorID,
		features, numPreviousAttempts, i.gracePeriod, i.logger,
	)
	if err != nil {
		return E.Cause(err, "create QUIC connection")
	}

	i.trackConnection(connection)
	defer func() {
		i.untrackConnection(connection)
		i.RemoveDatagramMuxer(connection)
	}()

	return connection.Serve(i.ctx, i)
}

func (i *Inbound) serveHTTP2(connIndex uint8, edgeAddr *EdgeAddr, features []string, numPreviousAttempts uint8) error {
	i.logger.Info("connecting to edge via HTTP/2 (connection ", connIndex, ")")

	connection, err := NewHTTP2Connection(
		i.ctx, edgeAddr, connIndex,
		i.credentials, i.connectorID,
		features, numPreviousAttempts, i.gracePeriod, i, i.logger,
	)
	if err != nil {
		return E.Cause(err, "create HTTP/2 connection")
	}

	i.trackConnection(connection)
	defer i.untrackConnection(connection)

	return connection.Serve(i.ctx)
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

func flattenRegions(regions [][]*EdgeAddr) []*EdgeAddr {
	var result []*EdgeAddr
	for _, region := range regions {
		result = append(result, region...)
	}
	return result
}

func parseCredentials(token string, credentialPath string) (Credentials, error) {
	if token == "" && credentialPath == "" {
		return Credentials{}, E.New("either token or credential_path must be specified")
	}
	if token != "" && credentialPath != "" {
		return Credentials{}, E.New("token and credential_path are mutually exclusive")
	}
	if token != "" {
		return parseToken(token)
	}
	return parseCredentialFile(credentialPath)
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

func parseCredentialFile(path string) (Credentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, E.Cause(err, "read credential file")
	}
	var credentials Credentials
	err = json.Unmarshal(data, &credentials)
	if err != nil {
		return Credentials{}, E.Cause(err, "unmarshal credential file")
	}
	if credentials.TunnelID == (uuid.UUID{}) {
		return Credentials{}, E.New("credential file missing tunnel ID")
	}
	return credentials, nil
}
