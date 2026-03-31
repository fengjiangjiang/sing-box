package ccm

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing/common/observable"
)

const (
	defaultPollInterval     = 60 * time.Minute
	failedPollRetryInterval = time.Minute
	httpRetryMaxBackoff     = 5 * time.Minute
)

const (
	httpRetryMaxAttempts  = 3
	httpRetryInitialDelay = 200 * time.Millisecond
)

const sessionExpiry = 24 * time.Hour

func doHTTPWithRetry(ctx context.Context, client *http.Client, buildRequest func() (*http.Request, error)) (*http.Response, error) {
	var lastError error
	for attempt := range httpRetryMaxAttempts {
		if attempt > 0 {
			delay := httpRetryInitialDelay * time.Duration(1<<(attempt-1))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, lastError
			case <-timer.C:
			}
		}
		request, err := buildRequest()
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err == nil {
			return response, nil
		}
		lastError = err
		if ctx.Err() != nil {
			return nil, lastError
		}
	}
	return nil, lastError
}

type credentialState struct {
	fiveHourUtilization       float64
	fiveHourReset             time.Time
	weeklyUtilization         float64
	weeklyReset               time.Time
	hardRateLimited           bool
	rateLimitResetAt          time.Time
	availabilityState         availabilityState
	availabilityReason        availabilityReason
	availabilityResetAt       time.Time
	lastKnownDataAt           time.Time
	accountUUID               string
	accountType               string
	rateLimitTier             string
	oauthAccount              *claudeOAuthAccount
	remotePlanWeight          float64
	remoteWeeklyBurnFactor    float64
	lastUpdated               time.Time
	consecutivePollFailures   int
	usageAPIRetryDelay        time.Duration
	unavailable               bool
	upstreamRejectedUntil     time.Time
	lastCredentialLoadAttempt time.Time
	lastCredentialLoadError   string
}

func (s *credentialState) checkReserves(cap5h, capWeekly float64) bool {
	now := time.Now()
	if s.fiveHourUtilization >= cap5h {
		if s.fiveHourReset.IsZero() || now.Before(s.fiveHourReset) {
			return false
		}
	}
	if s.weeklyUtilization >= capWeekly {
		if s.weeklyReset.IsZero() || now.Before(s.weeklyReset) {
			return false
		}
	}
	return true
}

type credentialRequestContext struct {
	context.Context
	releaseOnce  sync.Once
	cancelOnce   sync.Once
	releaseFuncs []func() bool
	cancelFunc   context.CancelFunc
}

func (c *credentialRequestContext) addInterruptLink(stop func() bool) {
	c.releaseFuncs = append(c.releaseFuncs, stop)
}

func (c *credentialRequestContext) releaseCredentialInterrupt() {
	c.releaseOnce.Do(func() {
		for _, f := range c.releaseFuncs {
			f()
		}
	})
}

func (c *credentialRequestContext) cancelRequest() {
	c.releaseCredentialInterrupt()
	c.cancelOnce.Do(c.cancelFunc)
}

type Credential interface {
	tagName() string
	isAvailable() bool
	isUsable() bool
	isExternal() bool
	hasSnapshotData() bool
	fiveHourUtilization() float64
	weeklyUtilization() float64
	fiveHourCap() float64
	weeklyCap() float64
	planWeight() float64
	weeklyBurnFactor() float64
	fiveHourResetTime() time.Time
	weeklyResetTime() time.Time
	markRateLimited(resetAt time.Time)
	markUpstreamRejected()
	availabilityStatus() availabilityStatus
	earliestReset() time.Time
	unavailableError() error

	getAccessToken() (string, error)
	buildProxyRequest(ctx context.Context, original *http.Request, bodyBytes []byte, serviceHeaders http.Header) (*http.Request, error)
	updateStateFromHeaders(header http.Header)

	wrapRequestContext(ctx context.Context) *credentialRequestContext
	interruptConnections()

	setStatusSubscriber(*observable.Subscriber[struct{}])
	start() error
	pollUsage()
	lastUpdatedTime() time.Time
	pollBackoff(base time.Duration) time.Duration
	usageTrackerOrNil() *AggregatedUsage
	httpClient() *http.Client
	close()
}

type credentialSelectionScope string

const (
	credentialSelectionScopeAll         credentialSelectionScope = "all"
	credentialSelectionScopeNonExternal credentialSelectionScope = "non_external"
)

type credentialSelection struct {
	scope  credentialSelectionScope
	filter func(Credential) bool
}

func (s credentialSelection) allows(credential Credential) bool {
	return s.filter == nil || s.filter(credential)
}

func (s credentialSelection) scopeOrDefault() credentialSelectionScope {
	if s.scope == "" {
		return credentialSelectionScopeAll
	}
	return s.scope
}

// Claude Code's unified rate-limit handling parses these reset headers with
// Number(...), compares them against Date.now()/1000, and renders them via
// new Date(seconds*1000), so keep the wire format pinned to Unix epoch seconds.
func parseAnthropicResetHeaderValue(headerName string, headerValue string) time.Time {
	unixEpoch, err := strconv.ParseInt(headerValue, 10, 64)
	if err != nil {
		panic("invalid " + headerName + " header: expected Unix epoch seconds, got " + strconv.Quote(headerValue))
	}
	if unixEpoch <= 0 {
		panic("invalid " + headerName + " header: expected positive Unix epoch seconds, got " + strconv.Quote(headerValue))
	}
	return time.Unix(unixEpoch, 0)
}

func parseOptionalAnthropicResetHeader(headers http.Header, headerName string) (time.Time, bool) {
	headerValue := headers.Get(headerName)
	if headerValue == "" {
		return time.Time{}, false
	}
	return parseAnthropicResetHeaderValue(headerName, headerValue), true
}

func parseRequiredAnthropicResetHeader(headers http.Header, headerName string) time.Time {
	headerValue := headers.Get(headerName)
	if headerValue == "" {
		panic("missing required " + headerName + " header")
	}
	return parseAnthropicResetHeaderValue(headerName, headerValue)
}

func (s *credentialState) noteSnapshotData() {
	s.lastKnownDataAt = time.Now()
}

func (s credentialState) hasSnapshotData() bool {
	return !s.lastKnownDataAt.IsZero() ||
		s.fiveHourUtilization > 0 ||
		s.weeklyUtilization > 0 ||
		!s.fiveHourReset.IsZero() ||
		!s.weeklyReset.IsZero()
}

func (s *credentialState) setAvailability(state availabilityState, reason availabilityReason, resetAt time.Time) {
	s.availabilityState = state
	s.availabilityReason = reason
	s.availabilityResetAt = resetAt
}

func (s credentialState) currentAvailability() availabilityStatus {
	now := time.Now()
	switch {
	case s.unavailable:
		return availabilityStatus{
			State:   availabilityStateUnavailable,
			Reason:  availabilityReasonUnknown,
			ResetAt: s.availabilityResetAt,
		}
	case s.hardRateLimited && (s.rateLimitResetAt.IsZero() || now.Before(s.rateLimitResetAt)):
		reason := s.availabilityReason
		if reason == "" {
			reason = availabilityReasonHardRateLimit
		}
		return availabilityStatus{
			State:   availabilityStateRateLimited,
			Reason:  reason,
			ResetAt: s.rateLimitResetAt,
		}
	case !s.upstreamRejectedUntil.IsZero() && now.Before(s.upstreamRejectedUntil):
		return availabilityStatus{
			State:   availabilityStateTemporarilyBlocked,
			Reason:  availabilityReasonUpstreamRejected,
			ResetAt: s.upstreamRejectedUntil,
		}
	case s.consecutivePollFailures > 0:
		return availabilityStatus{
			State:  availabilityStateTemporarilyBlocked,
			Reason: availabilityReasonPollFailed,
		}
	default:
		return availabilityStatus{State: availabilityStateUsable}
	}
}

func parseRateLimitResetFromHeaders(headers http.Header) time.Time {
	claim := headers.Get("anthropic-ratelimit-unified-representative-claim")
	switch claim {
	case "5h":
		return parseRequiredAnthropicResetHeader(headers, "anthropic-ratelimit-unified-5h-reset")
	case "7d":
		return parseRequiredAnthropicResetHeader(headers, "anthropic-ratelimit-unified-7d-reset")
	default:
		panic("invalid anthropic-ratelimit-unified-representative-claim header: " + strconv.Quote(claim))
	}
}
