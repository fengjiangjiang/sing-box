//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"encoding/base64"
	"io"
	"math/rand"
	"net/url"
	"os"
	"strings"
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
	ctx               context.Context
	cancel            context.CancelFunc
	router            adapter.ConnectionRouterEx
	logger            log.ContextLogger
	credentials       Credentials
	connectorID       uuid.UUID
	haConnections     int
	protocol          string
	edgeIPVersion     int
	datagramVersion   string
	gracePeriod time.Duration

	connectionAccess sync.Mutex
	connections      []io.Closer
	done             sync.WaitGroup

	datagramMuxerAccess sync.Mutex
	datagramV2Muxers    map[DatagramSender]*DatagramV2Muxer
	datagramV3Muxers    map[DatagramSender]*DatagramV3Muxer

	ingressAccess  sync.RWMutex
	ingressVersion int32
	ingressRules   []IngressRule
}

// IngressRule maps a hostname pattern to an origin service URL.
type IngressRule struct {
	Hostname string
	Service  string
}

type ingressConfig struct {
	Ingress []ingressConfigRule `json:"ingress"`
}

type ingressConfigRule struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
}

// UpdateIngress applies a new ingress configuration from the edge.
func (i *Inbound) UpdateIngress(version int32, config []byte) {
	i.ingressAccess.Lock()
	defer i.ingressAccess.Unlock()

	if version <= i.ingressVersion {
		return
	}

	var parsed ingressConfig
	err := json.Unmarshal(config, &parsed)
	if err != nil {
		i.logger.Error("parse ingress config: ", err)
		return
	}

	rules := make([]IngressRule, 0, len(parsed.Ingress))
	for _, rule := range parsed.Ingress {
		rules = append(rules, IngressRule{
			Hostname: rule.Hostname,
			Service:  rule.Service,
		})
	}
	i.ingressRules = rules
	i.ingressVersion = version
	i.logger.Info("updated ingress configuration (version ", version, ", ", len(rules), " rules)")
}

// ResolveOrigin finds the origin service URL for a given hostname.
// Returns the service URL if matched, or empty string if no match.
func (i *Inbound) ResolveOrigin(hostname string) string {
	i.ingressAccess.RLock()
	defer i.ingressAccess.RUnlock()

	for _, rule := range i.ingressRules {
		if rule.Hostname == "" {
			return rule.Service
		}
		if matchIngress(rule.Hostname, hostname) {
			return rule.Service
		}
	}
	return ""
}

func matchIngress(pattern, hostname string) bool {
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(hostname, suffix)
	}
	return false
}

// ResolveOriginURL rewrites a request URL to point to the origin service.
// For example, https://testbox.badnet.work/path → http://127.0.0.1:8083/path
func (i *Inbound) ResolveOriginURL(requestURL string) string {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return requestURL
	}
	hostname := parsed.Hostname()
	origin := i.ResolveOrigin(hostname)
	if origin == "" || strings.HasPrefix(origin, "http_status:") {
		return requestURL
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return requestURL
	}
	parsed.Scheme = originURL.Scheme
	parsed.Host = originURL.Host
	return parsed.String()
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

	inboundCtx, cancel := context.WithCancel(ctx)

	return &Inbound{
		Adapter:           inbound.NewAdapter(C.TypeCloudflareTunnel, tag),
		ctx:               inboundCtx,
		cancel:            cancel,
		router:            router,
		logger:            logger,
		credentials:       credentials,
		connectorID:       uuid.New(),
		haConnections:     haConnections,
		protocol:          protocol,
		edgeIPVersion:     edgeIPVersion,
		datagramVersion:   datagramVersion,
		gracePeriod: gracePeriod,
		datagramV2Muxers:  make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers:  make(map[DatagramSender]*DatagramV3Muxer),
	}, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	i.logger.Info("starting Cloudflare Tunnel with ", i.haConnections, " HA connections")

	regions, err := DiscoverEdge(i.ctx)
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

func (i *Inbound) Close() error {
	i.cancel()
	i.done.Wait()
	i.connectionAccess.Lock()
	for _, connection := range i.connections {
		connection.Close()
	}
	i.connections = nil
	i.connectionAccess.Unlock()
	return nil
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
