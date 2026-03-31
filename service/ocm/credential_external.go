package ocm

import (
	"bytes"
	"context"
	stdTLS "crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"

	"github.com/hashicorp/yamux"
)

const reverseProxyBaseURL = "http://reverse-proxy"

type externalCredential struct {
	tag               string
	baseURL           string
	token             string
	credentialDialer  N.Dialer
	forwardHTTPClient *http.Client
	state             credentialState
	stateAccess       sync.RWMutex
	pollAccess        sync.Mutex
	usageTracker      *AggregatedUsage
	logger            log.ContextLogger

	statusSubscriber *observable.Subscriber[struct{}]
	onBecameUnusable func()
	interrupted      bool
	requestContext   context.Context
	cancelRequests   context.CancelFunc
	requestAccess    sync.Mutex

	// Reverse proxy fields
	reverse                 bool
	reverseHTTPClient       *http.Client
	reverseCredentialDialer N.Dialer
	reverseSession          *yamux.Session
	reverseAccess           sync.RWMutex
	closed                  bool
	reverseContext          context.Context
	reverseCancel           context.CancelFunc
	connectorDialer         N.Dialer
	connectorDestination    M.Socksaddr
	connectorRequestPath    string
	connectorURL            *url.URL
	connectorTLS            *stdTLS.Config
	reverseService          http.Handler
}

type reverseSessionDialer struct {
	credential *externalCredential
}

type statusStreamResult struct {
	duration time.Duration
	frames   int
}

func (d reverseSessionDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	return d.credential.openReverseConnection(ctx)
}

func (d reverseSessionDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func externalCredentialURLPort(parsedURL *url.URL) uint16 {
	portString := parsedURL.Port()
	if portString != "" {
		port, err := strconv.ParseUint(portString, 10, 16)
		if err == nil {
			return uint16(port)
		}
	}
	if parsedURL.Scheme == "https" {
		return 443
	}
	return 80
}

func externalCredentialServerPort(parsedURL *url.URL, configuredPort uint16) uint16 {
	if configuredPort != 0 {
		return configuredPort
	}
	return externalCredentialURLPort(parsedURL)
}

func externalCredentialBaseURL(parsedURL *url.URL) string {
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		baseURL += parsedURL.Path
	}
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL
}

func externalCredentialReversePath(parsedURL *url.URL, endpointPath string) string {
	pathPrefix := parsedURL.EscapedPath()
	if pathPrefix == "/" {
		pathPrefix = ""
	} else {
		pathPrefix = strings.TrimSuffix(pathPrefix, "/")
	}
	return pathPrefix + endpointPath
}

func newExternalCredential(ctx context.Context, tag string, options option.OCMExternalCredentialOptions, logger log.ContextLogger) (*externalCredential, error) {
	requestContext, cancelRequests := context.WithCancel(context.Background())
	reverseContext, reverseCancel := context.WithCancel(context.Background())

	credential := &externalCredential{
		tag:            tag,
		token:          options.Token,
		logger:         logger,
		requestContext: requestContext,
		cancelRequests: cancelRequests,
		reverse:        options.Reverse,
		reverseContext: reverseContext,
		reverseCancel:  reverseCancel,
	}

	if options.URL == "" {
		// Receiver mode: no URL, wait for reverse connection
		credential.baseURL = reverseProxyBaseURL
		credential.credentialDialer = reverseSessionDialer{credential: credential}
		credential.forwardHTTPClient = &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return credential.openReverseConnection(ctx)
				},
			},
		}
	} else {
		// Normal or connector mode: has URL
		parsedURL, err := url.Parse(options.URL)
		if err != nil {
			return nil, E.Cause(err, "parse url for credential ", tag)
		}

		credentialDialer, err := dialer.NewWithOptions(dialer.Options{
			Context: ctx,
			Options: option.DialerOptions{
				Detour: options.Detour,
			},
			RemoteIsDomain: true,
		})
		if err != nil {
			return nil, E.Cause(err, "create dialer for credential ", tag)
		}

		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if options.Server != "" {
					destination := M.ParseSocksaddrHostPort(options.Server, externalCredentialServerPort(parsedURL, options.ServerPort))
					return credentialDialer.DialContext(ctx, network, destination)
				}
				return credentialDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		}

		if parsedURL.Scheme == "https" {
			transport.TLSClientConfig = &stdTLS.Config{
				ServerName: parsedURL.Hostname(),
				RootCAs:    adapter.RootPoolFromContext(ctx),
				Time:       ntp.TimeFuncFromContext(ctx),
			}
		}

		credential.baseURL = externalCredentialBaseURL(parsedURL)

		if options.Reverse {
			// Connector mode: we dial out to serve, not to proxy
			credential.credentialDialer = credentialDialer
			credential.connectorDialer = credentialDialer
			if options.Server != "" {
				credential.connectorDestination = M.ParseSocksaddrHostPort(options.Server, externalCredentialServerPort(parsedURL, options.ServerPort))
			} else {
				credential.connectorDestination = M.ParseSocksaddrHostPort(parsedURL.Hostname(), externalCredentialURLPort(parsedURL))
			}
			credential.connectorRequestPath = externalCredentialReversePath(parsedURL, "/ocm/v1/reverse")
			credential.connectorURL = parsedURL
			if parsedURL.Scheme == "https" {
				credential.connectorTLS = &stdTLS.Config{
					ServerName: parsedURL.Hostname(),
					RootCAs:    adapter.RootPoolFromContext(ctx),
					Time:       ntp.TimeFuncFromContext(ctx),
				}
			}
			credential.forwardHTTPClient = &http.Client{Transport: transport}
		} else {
			// Normal mode: standard HTTP client for proxying
			credential.credentialDialer = credentialDialer
			credential.forwardHTTPClient = &http.Client{Transport: transport}
			credential.reverseCredentialDialer = reverseSessionDialer{credential: credential}
			credential.reverseHTTPClient = &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: false,
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return credential.openReverseConnection(ctx)
					},
				},
			}
		}
	}

	if options.UsagesPath != "" {
		credential.usageTracker = &AggregatedUsage{
			LastUpdated:  time.Now(),
			Combinations: make([]CostCombination, 0),
			filePath:     options.UsagesPath,
			logger:       logger,
		}
	}

	return credential, nil
}

func (c *externalCredential) start() error {
	if c.usageTracker != nil {
		err := c.usageTracker.Load()
		if err != nil {
			c.logger.Warn("load usage statistics for ", c.tag, ": ", err)
		}
	}
	if c.reverse && c.connectorURL != nil {
		go c.connectorLoop()
	} else {
		go c.statusStreamLoop()
	}
	return nil
}

func (c *externalCredential) setOnBecameUnusable(fn func()) {
	c.onBecameUnusable = fn
}

func (c *externalCredential) setStatusSubscriber(subscriber *observable.Subscriber[struct{}]) {
	c.statusSubscriber = subscriber
}

func (c *externalCredential) emitStatusUpdate() {
	if c.statusSubscriber != nil {
		c.statusSubscriber.Emit(struct{}{})
	}
}

func (c *externalCredential) tagName() string {
	return c.tag
}

func (c *externalCredential) isExternal() bool {
	return true
}

func (c *externalCredential) isAvailable() bool {
	return c.unavailableError() == nil
}

func (c *externalCredential) isUsable() bool {
	if !c.isAvailable() {
		return false
	}
	c.stateAccess.RLock()
	if c.state.consecutivePollFailures > 0 {
		c.stateAccess.RUnlock()
		return false
	}
	if !c.state.upstreamRejectedUntil.IsZero() && time.Now().Before(c.state.upstreamRejectedUntil) {
		c.stateAccess.RUnlock()
		return false
	}
	if c.state.hardRateLimited {
		if time.Now().Before(c.state.rateLimitResetAt) {
			c.stateAccess.RUnlock()
			return false
		}
		c.stateAccess.RUnlock()
		c.stateAccess.Lock()
		if c.state.hardRateLimited && !time.Now().Before(c.state.rateLimitResetAt) {
			c.state.hardRateLimited = false
		}
		usable := c.checkExternalReservesLocked()
		c.stateAccess.Unlock()
		return usable
	}
	usable := c.checkExternalReservesLocked()
	c.stateAccess.RUnlock()
	return usable
}

// checkExternalReservesLocked checks reserves with no reserve margin:
// only 100% utilization is considered unusable for external credentials.
func (c *externalCredential) checkExternalReservesLocked() bool {
	return c.state.checkReserves(100, 100)
}

func (c *externalCredential) fiveHourUtilization() float64 {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.fiveHourUtilization
}

func (c *externalCredential) weeklyUtilization() float64 {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.weeklyUtilization
}

func (c *externalCredential) fiveHourCap() float64 {
	return 100
}

func (c *externalCredential) weeklyCap() float64 {
	return 100
}

func (c *externalCredential) planWeight() float64 {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	if c.state.remotePlanWeight > 0 {
		return c.state.remotePlanWeight
	}
	return 10
}

func (c *externalCredential) weeklyResetTime() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.weeklyReset
}

func (c *externalCredential) fiveHourResetTime() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.fiveHourReset
}

func (c *externalCredential) markRateLimited(resetAt time.Time) {
	c.logger.Warn("rate limited for ", c.tag, ", reset in ", log.FormatDuration(time.Until(resetAt)))
	c.stateAccess.Lock()
	c.state.hardRateLimited = true
	c.state.rateLimitResetAt = resetAt
	c.state.setAvailability(availabilityStateRateLimited, availabilityReasonHardRateLimit, resetAt)
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	c.emitStatusUpdate()
}

func (c *externalCredential) markUpstreamRejected() {
	c.logger.Warn("upstream rejected credential ", c.tag, ", marking unavailable for ", log.FormatDuration(defaultPollInterval))
	c.stateAccess.Lock()
	c.state.upstreamRejectedUntil = time.Now().Add(defaultPollInterval)
	c.state.setAvailability(availabilityStateTemporarilyBlocked, availabilityReasonUpstreamRejected, c.state.upstreamRejectedUntil)
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	c.emitStatusUpdate()
}

func (c *externalCredential) markTemporarilyBlocked(reason availabilityReason, resetAt time.Time) {
	c.stateAccess.Lock()
	c.state.setAvailability(availabilityStateTemporarilyBlocked, reason, resetAt)
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	c.emitStatusUpdate()
}

func (c *externalCredential) earliestReset() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	if c.state.hardRateLimited {
		return c.state.rateLimitResetAt
	}
	earliest := c.state.fiveHourReset
	if !c.state.weeklyReset.IsZero() && (earliest.IsZero() || c.state.weeklyReset.Before(earliest)) {
		earliest = c.state.weeklyReset
	}
	return earliest
}

func (c *externalCredential) unavailableError() error {
	if c.baseURL == reverseProxyBaseURL {
		session := c.getReverseSession()
		if session == nil || session.IsClosed() {
			return E.New("credential ", c.tag, " is unavailable: reverse connection not established")
		}
	}
	return nil
}

func (c *externalCredential) getAccessToken() (string, error) {
	return c.token, nil
}

func (c *externalCredential) buildProxyRequest(ctx context.Context, original *http.Request, bodyBytes []byte, _ http.Header) (*http.Request, error) {
	baseURL := c.baseURL
	if c.reverseHTTPClient != nil {
		session := c.getReverseSession()
		if session != nil && !session.IsClosed() {
			baseURL = reverseProxyBaseURL
		}
	}
	proxyURL := baseURL + original.URL.RequestURI()
	var body io.Reader
	if bodyBytes != nil {
		body = bytes.NewReader(bodyBytes)
	} else {
		body = original.Body
	}
	proxyRequest, err := http.NewRequestWithContext(ctx, original.Method, proxyURL, body)
	if err != nil {
		return nil, err
	}

	for key, values := range original.Header {
		if !isHopByHopHeader(key) && !isReverseProxyHeader(key) && !isAPIKeyHeader(key) && key != "Authorization" {
			proxyRequest.Header[key] = values
		}
	}

	proxyRequest.Header.Set("Authorization", "Bearer "+c.token)

	return proxyRequest, nil
}

func (c *externalCredential) openReverseConnection(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	session := c.getReverseSession()
	if session == nil || session.IsClosed() {
		return nil, E.New("reverse connection not established for ", c.tag)
	}
	conn, err := session.Open()
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	default:
	}
	return conn, nil
}

func (c *externalCredential) updateStateFromHeaders(headers http.Header) {
	c.stateAccess.Lock()
	isFirstUpdate := c.state.lastUpdated.IsZero()
	oldFiveHour := c.state.fiveHourUtilization
	oldWeekly := c.state.weeklyUtilization
	oldPlanWeight := c.state.remotePlanWeight
	oldFiveHourReset := c.state.fiveHourReset
	oldWeeklyReset := c.state.weeklyReset
	hadData := false

	activeLimitIdentifier := normalizeRateLimitIdentifier(headers.Get("x-codex-active-limit"))
	if activeLimitIdentifier == "" {
		activeLimitIdentifier = "codex"
	}

	fiveHourResetAt := headers.Get("x-" + activeLimitIdentifier + "-primary-reset-at")
	if fiveHourResetAt != "" {
		value, err := strconv.ParseInt(fiveHourResetAt, 10, 64)
		if err == nil {
			hadData = true
			c.state.fiveHourReset = time.Unix(value, 0)
		}
	}
	fiveHourPercent := headers.Get("x-" + activeLimitIdentifier + "-primary-used-percent")
	if fiveHourPercent != "" {
		value, err := strconv.ParseFloat(fiveHourPercent, 64)
		if err == nil {
			hadData = true
			c.state.fiveHourUtilization = value
		}
	}

	weeklyResetAt := headers.Get("x-" + activeLimitIdentifier + "-secondary-reset-at")
	if weeklyResetAt != "" {
		value, err := strconv.ParseInt(weeklyResetAt, 10, 64)
		if err == nil {
			hadData = true
			c.state.weeklyReset = time.Unix(value, 0)
		}
	}
	weeklyPercent := headers.Get("x-" + activeLimitIdentifier + "-secondary-used-percent")
	if weeklyPercent != "" {
		value, err := strconv.ParseFloat(weeklyPercent, 64)
		if err == nil {
			hadData = true
			c.state.weeklyUtilization = value
		}
	}
	if planWeight := headers.Get("X-OCM-Plan-Weight"); planWeight != "" {
		value, err := strconv.ParseFloat(planWeight, 64)
		if err == nil && value > 0 {
			c.state.remotePlanWeight = value
		}
	}
	if snapshots := parseRateLimitSnapshotsFromHeaders(headers); len(snapshots) > 0 {
		hadData = true
		applyRateLimitSnapshotsLocked(&c.state, snapshots, headers.Get("x-codex-active-limit"), c.state.remotePlanWeight, c.state.accountType)
	}
	if hadData {
		c.state.consecutivePollFailures = 0
		c.state.upstreamRejectedUntil = time.Time{}
		c.state.lastUpdated = time.Now()
		c.state.noteSnapshotData()
	}
	if isFirstUpdate || int(c.state.fiveHourUtilization*100) != int(oldFiveHour*100) || int(c.state.weeklyUtilization*100) != int(oldWeekly*100) {
		resetSuffix := ""
		if !c.state.weeklyReset.IsZero() {
			resetSuffix = ", resets=" + log.FormatDuration(time.Until(c.state.weeklyReset))
		}
		c.logger.Debug("usage update for ", c.tag, ": 5h=", c.state.fiveHourUtilization, "%, weekly=", c.state.weeklyUtilization, "%", resetSuffix)
	}
	utilizationChanged := c.state.fiveHourUtilization != oldFiveHour || c.state.weeklyUtilization != oldWeekly
	planWeightChanged := c.state.remotePlanWeight != oldPlanWeight
	resetChanged := c.state.fiveHourReset != oldFiveHourReset || c.state.weeklyReset != oldWeeklyReset
	shouldEmit := (hadData && (utilizationChanged || resetChanged)) || planWeightChanged
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	if shouldEmit {
		c.emitStatusUpdate()
	}
}

func (c *externalCredential) checkTransitionLocked() bool {
	upstreamRejected := !c.state.upstreamRejectedUntil.IsZero() && time.Now().Before(c.state.upstreamRejectedUntil)
	unusable := c.state.hardRateLimited || !c.checkExternalReservesLocked() || c.state.consecutivePollFailures > 0 || upstreamRejected
	if unusable && !c.interrupted {
		c.interrupted = true
		return true
	}
	if !unusable && c.interrupted {
		c.interrupted = false
	}
	return false
}

func (c *externalCredential) wrapRequestContext(parent context.Context) *credentialRequestContext {
	c.requestAccess.Lock()
	credentialContext := c.requestContext
	c.requestAccess.Unlock()
	derived, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(credentialContext, func() {
		cancel()
	})
	return &credentialRequestContext{
		Context:      derived,
		releaseFuncs: []func() bool{stop},
		cancelFunc:   cancel,
	}
}

func (c *externalCredential) interruptConnections() {
	c.logger.Warn("interrupting connections for ", c.tag)
	c.requestAccess.Lock()
	c.cancelRequests()
	c.requestContext, c.cancelRequests = context.WithCancel(context.Background())
	c.requestAccess.Unlock()
	if c.onBecameUnusable != nil {
		c.onBecameUnusable()
	}
}

func (c *externalCredential) doPollUsageRequest(ctx context.Context) (*http.Response, error) {
	buildRequest := func(baseURL string) func() (*http.Request, error) {
		return func() (*http.Request, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/ocm/v1/status", nil)
			if err != nil {
				return nil, err
			}
			request.Header.Set("Authorization", "Bearer "+c.token)
			return request, nil
		}
	}
	// Try reverse transport first (single attempt, no retry)
	if c.reverseHTTPClient != nil {
		session := c.getReverseSession()
		if session != nil && !session.IsClosed() {
			request, err := buildRequest(reverseProxyBaseURL)()
			if err != nil {
				return nil, err
			}
			reverseClient := &http.Client{
				Transport: c.reverseHTTPClient.Transport,
				Timeout:   5 * time.Second,
			}
			response, err := reverseClient.Do(request)
			if err == nil {
				return response, nil
			}
			// Reverse failed, fall through to forward if available
		}
	}
	// Forward transport with retries
	if c.forwardHTTPClient != nil {
		forwardClient := &http.Client{
			Transport: c.forwardHTTPClient.Transport,
			Timeout:   5 * time.Second,
		}
		return doHTTPWithRetry(ctx, forwardClient, buildRequest(c.baseURL))
	}
	return nil, E.New("no transport available")
}

func (c *externalCredential) pollUsage() {
	if !c.pollAccess.TryLock() {
		return
	}
	defer c.pollAccess.Unlock()
	defer c.markUsagePollAttempted()

	ctx := c.getReverseContext()
	response, err := c.doPollUsageRequest(ctx)
	if err != nil {
		c.logger.Debug("poll usage for ", c.tag, ": ", err)
		c.incrementPollFailures()
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		c.logger.Debug("poll usage for ", c.tag, ": status ", response.StatusCode, " ", string(body))
		c.incrementPollFailures()
		return
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		c.logger.Debug("poll usage for ", c.tag, ": read body: ", err)
		c.incrementPollFailures()
		return
	}
	var rawFields map[string]json.RawMessage
	err = json.Unmarshal(body, &rawFields)
	if err != nil {
		c.logger.Debug("poll usage for ", c.tag, ": decode: ", err)
		c.incrementPollFailures()
		return
	}
	if rawFields["limits"] == nil && (rawFields["five_hour_utilization"] == nil || rawFields["five_hour_reset"] == nil ||
		rawFields["weekly_utilization"] == nil || rawFields["weekly_reset"] == nil ||
		rawFields["plan_weight"] == nil) {
		c.logger.Error("poll usage for ", c.tag, ": invalid response")
		c.incrementPollFailures()
		return
	}
	var statusResponse statusPayload
	err = json.Unmarshal(body, &statusResponse)
	if err != nil {
		c.logger.Debug("poll usage for ", c.tag, ": decode: ", err)
		c.incrementPollFailures()
		return
	}

	c.stateAccess.Lock()
	isFirstUpdate := c.state.lastUpdated.IsZero()
	oldFiveHour := c.state.fiveHourUtilization
	oldWeekly := c.state.weeklyUtilization
	c.state.consecutivePollFailures = 0
	c.state.upstreamRejectedUntil = time.Time{}
	c.state.fiveHourUtilization = statusResponse.FiveHourUtilization
	c.state.weeklyUtilization = statusResponse.WeeklyUtilization
	if statusResponse.FiveHourReset > 0 {
		c.state.fiveHourReset = time.Unix(statusResponse.FiveHourReset, 0)
	}
	if statusResponse.WeeklyReset > 0 {
		c.state.weeklyReset = time.Unix(statusResponse.WeeklyReset, 0)
	}
	if statusResponse.PlanWeight > 0 {
		c.state.remotePlanWeight = statusResponse.PlanWeight
	}
	if c.state.hardRateLimited && time.Now().After(c.state.rateLimitResetAt) {
		c.state.hardRateLimited = false
	}
	if isFirstUpdate || int(c.state.fiveHourUtilization*100) != int(oldFiveHour*100) || int(c.state.weeklyUtilization*100) != int(oldWeekly*100) {
		resetSuffix := ""
		if !c.state.weeklyReset.IsZero() {
			resetSuffix = ", resets=" + log.FormatDuration(time.Until(c.state.weeklyReset))
		}
		c.logger.Debug("poll usage for ", c.tag, ": 5h=", c.state.fiveHourUtilization, "%, weekly=", c.state.weeklyUtilization, "%", resetSuffix)
	}
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	c.emitStatusUpdate()
}

func (c *externalCredential) statusStreamLoop() {
	var consecutiveFailures int
	ctx := c.getReverseContext()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		result, err := c.connectStatusStream(ctx)
		if ctx.Err() != nil {
			return
		}
		if !shouldRetryStatusStreamError(err) {
			c.logger.Warn("status stream for ", c.tag, " disconnected: ", err, ", not retrying")
			return
		}
		var backoff time.Duration
		consecutiveFailures, backoff = c.nextStatusStreamBackoff(result, consecutiveFailures)
		c.logger.Debug("status stream for ", c.tag, " disconnected: ", err, ", reconnecting in ", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (c *externalCredential) connectStatusStream(ctx context.Context) (statusStreamResult, error) {
	startTime := time.Now()
	result := statusStreamResult{}
	response, err := c.doStreamStatusRequest(ctx)
	if err != nil {
		result.duration = time.Since(startTime)
		return result, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		result.duration = time.Since(startTime)
		return result, &statusStreamHTTPError{code: response.StatusCode, body: string(body)}
	}

	decoder := json.NewDecoder(response.Body)
	for {
		var rawMessage json.RawMessage
		err = decoder.Decode(&rawMessage)
		if err != nil {
			result.duration = time.Since(startTime)
			return result, err
		}
		var rawFields map[string]json.RawMessage
		err = json.Unmarshal(rawMessage, &rawFields)
		if err != nil {
			result.duration = time.Since(startTime)
			return result, E.Cause(err, "decode status frame")
		}
		if rawFields["limits"] == nil && (rawFields["five_hour_utilization"] == nil || rawFields["five_hour_reset"] == nil ||
			rawFields["weekly_utilization"] == nil || rawFields["weekly_reset"] == nil ||
			rawFields["plan_weight"] == nil) {
			result.duration = time.Since(startTime)
			return result, E.New("invalid response")
		}
		var statusResponse statusPayload
		err = json.Unmarshal(rawMessage, &statusResponse)
		if err != nil {
			result.duration = time.Since(startTime)
			return result, E.Cause(err, "decode status frame")
		}

		c.stateAccess.Lock()
		isFirstUpdate := c.state.lastUpdated.IsZero()
		oldFiveHour := c.state.fiveHourUtilization
		oldWeekly := c.state.weeklyUtilization
		c.state.consecutivePollFailures = 0
		c.state.upstreamRejectedUntil = time.Time{}
		c.state.fiveHourUtilization = statusResponse.FiveHourUtilization
		c.state.weeklyUtilization = statusResponse.WeeklyUtilization
		if statusResponse.FiveHourReset > 0 {
			c.state.fiveHourReset = time.Unix(statusResponse.FiveHourReset, 0)
		}
		if statusResponse.WeeklyReset > 0 {
			c.state.weeklyReset = time.Unix(statusResponse.WeeklyReset, 0)
		}
		if statusResponse.PlanWeight > 0 {
			c.state.remotePlanWeight = statusResponse.PlanWeight
		}
		if c.state.hardRateLimited && time.Now().After(c.state.rateLimitResetAt) {
			c.state.hardRateLimited = false
		}
		if isFirstUpdate || int(c.state.fiveHourUtilization*100) != int(oldFiveHour*100) || int(c.state.weeklyUtilization*100) != int(oldWeekly*100) {
			resetSuffix := ""
			if !c.state.weeklyReset.IsZero() {
				resetSuffix = ", resets=" + log.FormatDuration(time.Until(c.state.weeklyReset))
			}
			c.logger.Debug("poll usage for ", c.tag, ": 5h=", c.state.fiveHourUtilization, "%, weekly=", c.state.weeklyUtilization, "%", resetSuffix)
		}
		shouldInterrupt := c.checkTransitionLocked()
		c.stateAccess.Unlock()
		if shouldInterrupt {
			c.interruptConnections()
		}
		result.frames++
		c.markUsageStreamUpdated()
		c.emitStatusUpdate()
	}
}

type statusStreamHTTPError struct {
	code int
	body string
}

func (e *statusStreamHTTPError) Error() string {
	return "status " + strconv.Itoa(e.code) + " " + e.body
}

func shouldRetryStatusStreamError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *statusStreamHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.code != http.StatusUnauthorized && httpErr.code != http.StatusForbidden
	}
	return true
}

func (c *externalCredential) nextStatusStreamBackoff(result statusStreamResult, consecutiveFailures int) (int, time.Duration) {
	if result.duration >= connectorBackoffResetThreshold {
		consecutiveFailures = 0
	}
	consecutiveFailures++
	return consecutiveFailures, connectorBackoff(consecutiveFailures)
}

func (c *externalCredential) doStreamStatusRequest(ctx context.Context) (*http.Response, error) {
	buildRequest := func(baseURL string) (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/ocm/v1/status?watch=true", nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+c.token)
		return request, nil
	}
	if c.reverseHTTPClient != nil {
		session := c.getReverseSession()
		if session != nil && !session.IsClosed() {
			request, err := buildRequest(reverseProxyBaseURL)
			if err != nil {
				return nil, err
			}
			response, err := c.reverseHTTPClient.Do(request)
			if err == nil {
				return response, nil
			}
		}
	}
	if c.forwardHTTPClient != nil {
		request, err := buildRequest(c.baseURL)
		if err != nil {
			return nil, err
		}
		return c.forwardHTTPClient.Do(request)
	}
	return nil, E.New("no transport available")
}

func (c *externalCredential) lastUpdatedTime() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.lastUpdated
}

func (c *externalCredential) hasSnapshotData() bool {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.hasSnapshotData()
}

func (c *externalCredential) availabilityStatus() availabilityStatus {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.currentAvailability()
}


func (c *externalCredential) markUsageStreamUpdated() {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	c.state.lastUpdated = time.Now()
}

func (c *externalCredential) markUsagePollAttempted() {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	c.state.lastUpdated = time.Now()
}

func (c *externalCredential) pollBackoff(baseInterval time.Duration) time.Duration {
	return baseInterval
}

func (c *externalCredential) incrementPollFailures() {
	c.stateAccess.Lock()
	c.state.consecutivePollFailures++
	c.state.setAvailability(availabilityStateTemporarilyBlocked, availabilityReasonPollFailed, time.Time{})
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	c.emitStatusUpdate()
}

func (c *externalCredential) usageTrackerOrNil() *AggregatedUsage {
	return c.usageTracker
}

func (c *externalCredential) httpClient() *http.Client {
	if c.reverseHTTPClient != nil {
		session := c.getReverseSession()
		if session != nil && !session.IsClosed() {
			return c.reverseHTTPClient
		}
	}
	return c.forwardHTTPClient
}

func (c *externalCredential) ocmDialer() N.Dialer {
	if c.reverseCredentialDialer != nil {
		session := c.getReverseSession()
		if session != nil && !session.IsClosed() {
			return c.reverseCredentialDialer
		}
	}
	return c.credentialDialer
}

func (c *externalCredential) ocmIsAPIKeyMode() bool {
	return false
}

func (c *externalCredential) ocmGetAccountID() string {
	return ""
}

func (c *externalCredential) ocmGetBaseURL() string {
	if c.reverseHTTPClient != nil {
		session := c.getReverseSession()
		if session != nil && !session.IsClosed() {
			return reverseProxyBaseURL
		}
	}
	return c.baseURL
}

func (c *externalCredential) close() {
	var session *yamux.Session
	c.reverseAccess.Lock()
	if !c.closed {
		c.closed = true
		if c.reverseCancel != nil {
			c.reverseCancel()
		}
		session = c.reverseSession
		c.reverseSession = nil
	}
	c.reverseAccess.Unlock()
	if session != nil {
		session.Close()
	}
	if c.usageTracker != nil {
		c.usageTracker.cancelPendingSave()
		err := c.usageTracker.Save()
		if err != nil {
			c.logger.Error("save usage statistics for ", c.tag, ": ", err)
		}
	}
}

func (c *externalCredential) getReverseSession() *yamux.Session {
	c.reverseAccess.RLock()
	defer c.reverseAccess.RUnlock()
	return c.reverseSession
}

func (c *externalCredential) setReverseSession(session *yamux.Session) bool {
	var emitStatus bool
	var restartStatusStream bool
	var triggerUsageRefresh bool
	c.reverseAccess.Lock()
	if c.closed {
		c.reverseAccess.Unlock()
		return false
	}
	wasAvailable := c.baseURL == reverseProxyBaseURL && c.reverseSession != nil && !c.reverseSession.IsClosed()
	old := c.reverseSession
	c.reverseSession = session
	isAvailable := c.baseURL == reverseProxyBaseURL && c.reverseSession != nil && !c.reverseSession.IsClosed()
	emitStatus = wasAvailable != isAvailable
	if isAvailable && !wasAvailable {
		c.reverseCancel()
		c.reverseContext, c.reverseCancel = context.WithCancel(context.Background())
		restartStatusStream = true
		triggerUsageRefresh = true
	}
	c.reverseAccess.Unlock()
	if old != nil {
		old.Close()
	}
	if restartStatusStream {
		c.logger.Debug("poll usage for ", c.tag, ": reverse session ready, restarting status stream")
		go c.statusStreamLoop()
	}
	if triggerUsageRefresh {
		go c.pollUsage()
	}
	if emitStatus {
		c.emitStatusUpdate()
	}
	return true
}

func (c *externalCredential) clearReverseSession(session *yamux.Session) {
	var emitStatus bool
	c.reverseAccess.Lock()
	wasAvailable := c.baseURL == reverseProxyBaseURL && c.reverseSession != nil && !c.reverseSession.IsClosed()
	if c.reverseSession == session {
		c.reverseSession = nil
	}
	isAvailable := c.baseURL == reverseProxyBaseURL && c.reverseSession != nil && !c.reverseSession.IsClosed()
	emitStatus = wasAvailable != isAvailable
	c.reverseAccess.Unlock()
	if emitStatus {
		c.emitStatusUpdate()
	}
}

func (c *externalCredential) getReverseContext() context.Context {
	c.reverseAccess.RLock()
	defer c.reverseAccess.RUnlock()
	return c.reverseContext
}

func (c *externalCredential) resetReverseContext() {
	c.reverseAccess.Lock()
	if c.closed {
		c.reverseAccess.Unlock()
		return
	}
	c.reverseCancel()
	c.reverseContext, c.reverseCancel = context.WithCancel(context.Background())
	c.reverseAccess.Unlock()
}
