package ocm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
)

type testCredential struct {
	tag           string
	external      bool
	available     bool
	usable        bool
	hasData       bool
	fiveHour      float64
	weekly        float64
	fiveHourCapV  float64
	weeklyCapV    float64
	weight        float64
	fiveReset     time.Time
	weeklyReset   time.Time
	availability  availabilityStatus
	lastHeaders   http.Header
	rateLimitedAt time.Time
	lastUpdated   time.Time
	backoff       time.Duration
}

func (c *testCredential) tagName() string              { return c.tag }
func (c *testCredential) isAvailable() bool            { return c.available }
func (c *testCredential) isUsable() bool               { return c.usable }
func (c *testCredential) isExternal() bool             { return c.external }
func (c *testCredential) hasSnapshotData() bool        { return c.hasData }
func (c *testCredential) fiveHourUtilization() float64 { return c.fiveHour }
func (c *testCredential) weeklyUtilization() float64   { return c.weekly }
func (c *testCredential) fiveHourCap() float64         { return c.fiveHourCapV }
func (c *testCredential) weeklyCap() float64           { return c.weeklyCapV }
func (c *testCredential) planWeight() float64          { return c.weight }
func (c *testCredential) weeklyResetTime() time.Time   { return c.weeklyReset }
func (c *testCredential) fiveHourResetTime() time.Time { return c.fiveReset }
func (c *testCredential) markRateLimited(resetAt time.Time) {
	c.rateLimitedAt = resetAt
}
func (c *testCredential) markUpstreamRejected() {}
func (c *testCredential) markTemporarilyBlocked(reason availabilityReason, resetAt time.Time) {
	c.availability = availabilityStatus{State: availabilityStateTemporarilyBlocked, Reason: reason, ResetAt: resetAt}
}
func (c *testCredential) availabilityStatus() availabilityStatus { return c.availability }
func (c *testCredential) earliestReset() time.Time               { return c.fiveReset }
func (c *testCredential) unavailableError() error                { return nil }
func (c *testCredential) getAccessToken() (string, error)        { return "", nil }
func (c *testCredential) buildProxyRequest(context.Context, *http.Request, []byte, http.Header) (*http.Request, error) {
	return nil, nil
}
func (c *testCredential) updateStateFromHeaders(headers http.Header) {
	c.lastHeaders = headers.Clone()
}
func (c *testCredential) wrapRequestContext(context.Context) *credentialRequestContext { return nil }
func (c *testCredential) interruptConnections()                                        {}
func (c *testCredential) setOnBecameUnusable(func())                                   {}
func (c *testCredential) setStatusSubscriber(*observable.Subscriber[struct{}])         {}
func (c *testCredential) start() error                                                 { return nil }
func (c *testCredential) pollUsage()                                                   {}
func (c *testCredential) lastUpdatedTime() time.Time {
	if c.lastUpdated.IsZero() {
		return time.Now()
	}
	return c.lastUpdated
}
func (c *testCredential) pollBackoff(base time.Duration) time.Duration { return c.backoff }
func (c *testCredential) usageTrackerOrNil() *AggregatedUsage                          { return nil }
func (c *testCredential) httpClient() *http.Client                                     { return nil }
func (c *testCredential) close()                                                       {}
func (c *testCredential) ocmDialer() N.Dialer                                          { return nil }
func (c *testCredential) ocmIsAPIKeyMode() bool                                        { return false }
func (c *testCredential) ocmGetAccountID() string                                      { return "" }
func (c *testCredential) ocmGetBaseURL() string                                        { return "" }

type testProvider struct {
	credentials   []Credential
	onPollIfStale func()
}

func (p *testProvider) selectCredential(string, credentialSelection) (Credential, bool, error) {
	return nil, false, nil
}
func (p *testProvider) onRateLimited(string, Credential, time.Time, credentialSelection) Credential {
	return nil
}
func (p *testProvider) linkProviderInterrupt(Credential, credentialSelection, func()) func() bool {
	return func() bool { return true }
}
func (p *testProvider) pollIfStale() {
	if p.onPollIfStale != nil {
		p.onPollIfStale()
	}
}
func (p *testProvider) pollCredentialIfStale(Credential) {}
func (p *testProvider) allCredentials() []Credential     { return p.credentials }
func (p *testProvider) close()                           {}

func TestHandleWebSocketErrorEventConnectionLimitDoesNotUseRateLimitPath(t *testing.T) {
	t.Parallel()

	credential := &testCredential{availability: availabilityStatus{State: availabilityStateUsable}}
	service := &Service{}
	service.handleWebSocketErrorEvent([]byte(`{"type":"error","status_code":400,"error":{"code":"websocket_connection_limit_reached"}}`), credential)

	if credential.availability.State != availabilityStateTemporarilyBlocked || credential.availability.Reason != availabilityReasonConnectionLimit {
		t.Fatalf("expected temporary connection limit block, got %#v", credential.availability)
	}
}

func TestWriteCredentialUnavailableErrorReturns429ForRateLimitedCredentials(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	provider := &testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       false,
			hasData:      true,
			weight:       1,
			availability: availabilityStatus{State: availabilityStateRateLimited, Reason: availabilityReasonHardRateLimit, ResetAt: time.Now().Add(time.Minute)},
		},
	}}

	writeCredentialUnavailableError(recorder, request, provider, provider.credentials[0], credentialSelection{}, "all credentials rate-limited")

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", recorder.Code)
	}
	var body map[string]map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"]["type"] != "usage_limit_reached" {
		t.Fatalf("expected usage_limit_reached type, got %#v", body)
	}
}

func TestComputeAggregatedUtilizationTreatsFullCapacityWhenFiveHourResetPassed(t *testing.T) {
	t.Parallel()
	service := &Service{}
	status := service.computeAggregatedUtilization(&testProvider{credentials: []Credential{
		&testCredential{
			tag: "a", available: true, usable: true, hasData: true,
			fiveHour: 80, weekly: 30,
			fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1,
			fiveReset:   time.Now().Add(-1 * time.Hour),
			weeklyReset: time.Now().Add(3 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	if status.fiveHourUtilization > 1 {
		t.Fatalf("expected near-zero 5h utilization when reset passed, got %v", status.fiveHourUtilization)
	}
	if status.weeklyUtilization < 29 || status.weeklyUtilization > 31 {
		t.Fatalf("expected ~30 weekly utilization, got %v", status.weeklyUtilization)
	}
}

func TestComputeAggregatedUtilizationTreatsFullCapacityWhenWeeklyResetPassed(t *testing.T) {
	t.Parallel()
	service := &Service{}
	status := service.computeAggregatedUtilization(&testProvider{credentials: []Credential{
		&testCredential{
			tag: "a", available: true, usable: true, hasData: true,
			fiveHour: 30, weekly: 80,
			fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1,
			fiveReset:   time.Now().Add(3 * time.Hour),
			weeklyReset: time.Now().Add(-1 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	if status.weeklyUtilization > 1 {
		t.Fatalf("expected near-zero weekly utilization when reset passed, got %v", status.weeklyUtilization)
	}
	if status.fiveHourUtilization < 29 || status.fiveHourUtilization > 31 {
		t.Fatalf("expected ~30 5h utilization, got %v", status.fiveHourUtilization)
	}
}

func TestComputeAggregatedUtilizationPreservesFutureResets(t *testing.T) {
	t.Parallel()
	service := &Service{}
	status := service.computeAggregatedUtilization(&testProvider{credentials: []Credential{
		&testCredential{
			tag: "a", available: true, usable: true, hasData: true,
			fiveHour: 80, weekly: 50,
			fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1,
			fiveReset:   time.Now().Add(3 * time.Hour),
			weeklyReset: time.Now().Add(5 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	if status.fiveHourUtilization < 79 || status.fiveHourUtilization > 81 {
		t.Fatalf("expected ~80 5h utilization when resets are future, got %v", status.fiveHourUtilization)
	}
	if status.weeklyUtilization < 49 || status.weeklyUtilization > 51 {
		t.Fatalf("expected ~50 weekly utilization when resets are future, got %v", status.weeklyUtilization)
	}
}

func TestComputeAggregatedUtilizationTracksEarliestCredentialReset(t *testing.T) {
	t.Parallel()
	earlyReset := time.Now().Add(1 * time.Minute)
	lateReset := time.Now().Add(5 * time.Hour)
	service := &Service{}
	status := service.computeAggregatedUtilization(&testProvider{credentials: []Credential{
		&testCredential{
			tag: "a", available: true, usable: true, hasData: true,
			fiveHour: 50, weekly: 30,
			fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1,
			fiveReset: earlyReset, weeklyReset: lateReset,
			availability: availabilityStatus{State: availabilityStateUsable},
		},
		&testCredential{
			tag: "b", available: true, usable: true, hasData: true,
			fiveHour: 50, weekly: 30,
			fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1,
			fiveReset: lateReset, weeklyReset: lateReset,
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	result := status.nextResetTime()
	diff := result.Sub(earlyReset)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("expected nextResetTime near earliest credential reset %v, got %v (diff: %v)", earlyReset, result, diff)
	}
}

func TestNextResetTimeReturnsEarliestFutureReset(t *testing.T) {
	t.Parallel()
	earliest := time.Now().Add(30 * time.Minute)
	status := aggregatedStatus{
		earliestCredentialReset: earliest,
	}
	result := status.nextResetTime()
	if result.IsZero() {
		t.Fatal("expected non-zero next reset time")
	}
	diff := result.Sub(earliest)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("expected next reset near %v, got %v", earliest, result)
	}
}

func TestNextResetTimeReturnsZeroWhenBothZero(t *testing.T) {
	t.Parallel()
	status := aggregatedStatus{}
	if !status.nextResetTime().IsZero() {
		t.Fatal("expected zero next reset time when no resets are set")
	}
}

func TestHandleStatusStreamPushesUpdateWhenResetTimeElapses(t *testing.T) {
	t.Parallel()

	resetTime := time.Now().Add(100 * time.Millisecond)
	subscriber := observable.NewSubscriber[struct{}](8)
	observer := observable.NewObserver[struct{}](subscriber, 8)
	defer observer.Close()
	service := &Service{statusObserver: observer}

	provider := &testProvider{credentials: []Credential{
		&testCredential{
			tag: "a", available: true, usable: true, hasData: true,
			fiveHour: 90, fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1, fiveReset: resetTime,
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}

	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/ocm/v1/status?watch=true", nil).WithContext(ctx)

	service.handleStatusStream(recorder, request, provider, nil)

	body := recorder.Body.String()
	frames := strings.Split(strings.TrimSpace(body), "\n")
	if len(frames) < 2 {
		t.Fatalf("expected at least 2 frames, got %d: %q", len(frames), body)
	}
	var lastPayload statusPayload
	if err := json.Unmarshal([]byte(frames[len(frames)-1]), &lastPayload); err != nil {
		t.Fatalf("failed to parse last frame: %v", err)
	}
	if lastPayload.FiveHourUtilization > 1 {
		t.Fatalf("expected near-zero 5h utilization in post-reset frame, got %v", lastPayload.FiveHourUtilization)
	}
}

func TestHandleStatusStreamRearmsTimerWhenFirstResetDoesNotChangePayload(t *testing.T) {
	t.Parallel()

	now := time.Now()
	subscriber := observable.NewSubscriber[struct{}](8)
	observer := observable.NewObserver[struct{}](subscriber, 8)
	defer observer.Close()
	service := &Service{statusObserver: observer}

	// Credential A: 0% utilization, early reset — payload unchanged after reset
	// Credential B: 90% utilization, later reset — payload changes after reset
	provider := &testProvider{credentials: []Credential{
		&testCredential{
			tag: "a", available: true, usable: true, hasData: true,
			fiveHour: 0, fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1, fiveReset: now.Add(100 * time.Millisecond),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
		&testCredential{
			tag: "b", available: true, usable: true, hasData: true,
			fiveHour: 90, fiveHourCapV: 100, weeklyCapV: 100,
			weight: 1, fiveReset: now.Add(300 * time.Millisecond),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}

	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/ocm/v1/status?watch=true", nil).WithContext(ctx)

	service.handleStatusStream(recorder, request, provider, nil)

	body := recorder.Body.String()
	frames := strings.Split(strings.TrimSpace(body), "\n")
	if len(frames) < 2 {
		t.Fatalf("expected at least 2 frames (initial + post-second-reset), got %d: %q", len(frames), body)
	}
	var lastPayload statusPayload
	if err := json.Unmarshal([]byte(frames[len(frames)-1]), &lastPayload); err != nil {
		t.Fatalf("failed to parse last frame: %v", err)
	}
	if lastPayload.FiveHourUtilization > 1 {
		t.Fatalf("expected near-zero 5h utilization after second reset, got %v", lastPayload.FiveHourUtilization)
	}
}

func TestHandleStatusStreamSubscriptionResetsTimerWhenOnlyResetTimeChanges(t *testing.T) {
	t.Parallel()

	subscriber := observable.NewSubscriber[struct{}](8)
	observer := observable.NewObserver[struct{}](subscriber, 8)
	defer observer.Close()
	service := &Service{statusObserver: observer}

	credA := &testCredential{
		tag: "a", available: true, usable: true, hasData: true,
		fiveHour: 90, fiveHourCapV: 100, weeklyCapV: 100,
		weight: 1, fiveReset: time.Now().Add(10 * time.Minute),
		availability: availabilityStatus{State: availabilityStateUsable},
	}
	credB := &testCredential{
		tag: "b", available: true, usable: true, hasData: true,
		fiveHour: 90, fiveHourCapV: 100, weeklyCapV: 100,
		weight: 9999, fiveReset: time.Now().Add(10 * time.Minute),
		availability: availabilityStatus{State: availabilityStateUsable},
	}
	provider := &testProvider{credentials: []Credential{credA, credB}}

	go func() {
		time.Sleep(50 * time.Millisecond)
		credA.fiveReset = time.Now().Add(100 * time.Millisecond)
		subscriber.Emit(struct{}{})
	}()

	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/ocm/v1/status?watch=true", nil).WithContext(ctx)

	service.handleStatusStream(recorder, request, provider, nil)

	body := recorder.Body.String()
	frames := strings.Split(strings.TrimSpace(body), "\n")
	if len(frames) < 2 {
		t.Fatalf("expected at least 2 frames (initial + post-reset via subscription), got %d: %q", len(frames), body)
	}
}

func TestNextWatchPollDelayFreshCredential(t *testing.T) {
	t.Parallel()
	provider := &testProvider{credentials: []Credential{
		&testCredential{lastUpdated: time.Now(), backoff: defaultPollInterval},
	}}
	delay := nextWatchPollDelay(provider)
	if delay < defaultPollInterval-2*time.Second || delay > defaultPollInterval {
		t.Fatalf("expected delay near %v for fresh credential, got %v", defaultPollInterval, delay)
	}
}

func TestNextWatchPollDelayStaleCredential(t *testing.T) {
	t.Parallel()
	provider := &testProvider{credentials: []Credential{
		&testCredential{lastUpdated: time.Now().Add(-2 * defaultPollInterval), backoff: defaultPollInterval},
	}}
	delay := nextWatchPollDelay(provider)
	if delay != time.Second {
		t.Fatalf("expected 1s floor for stale credential, got %v", delay)
	}
}

func TestNextWatchPollDelayRespectsShortBackoff(t *testing.T) {
	t.Parallel()
	provider := &testProvider{credentials: []Credential{
		&testCredential{lastUpdated: time.Now().Add(-30 * time.Second), backoff: time.Minute},
	}}
	delay := nextWatchPollDelay(provider)
	if delay < 25*time.Second || delay > 35*time.Second {
		t.Fatalf("expected delay ~30s for short backoff, got %v", delay)
	}
}

func TestNextWatchPollDelayPicksShortestAcrossCredentials(t *testing.T) {
	t.Parallel()
	provider := &testProvider{credentials: []Credential{
		&testCredential{lastUpdated: time.Now(), backoff: defaultPollInterval},
		&testCredential{lastUpdated: time.Now().Add(-55 * time.Second), backoff: time.Minute},
	}}
	delay := nextWatchPollDelay(provider)
	if delay < time.Second || delay > 10*time.Second {
		t.Fatalf("expected delay ~5s (shortest credential), got %v", delay)
	}
}

func TestNextWatchPollDelayEmptyProvider(t *testing.T) {
	t.Parallel()
	provider := &testProvider{credentials: []Credential{}}
	delay := nextWatchPollDelay(provider)
	if delay != defaultPollInterval {
		t.Fatalf("expected %v for empty provider, got %v", defaultPollInterval, delay)
	}
}

func TestHandleStatusStreamResetsPollTimerOnSubscription(t *testing.T) {
	t.Parallel()

	subscriber := observable.NewSubscriber[struct{}](8)
	observer := observable.NewObserver[struct{}](subscriber, 8)
	defer observer.Close()
	service := &Service{statusObserver: observer}

	cred := &testCredential{
		tag: "a", available: true, usable: true, hasData: true,
		fiveHour: 50, fiveHourCapV: 100, weeklyCapV: 100,
		weight: 1,
		availability: availabilityStatus{State: availabilityStateUsable},
		lastUpdated:  time.Now(),
		backoff:      defaultPollInterval,
	}

	var pollCount atomic.Int32
	provider := &testProvider{
		credentials:   []Credential{cred},
		onPollIfStale: func() { pollCount.Add(1) },
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		// Simulate backoff shortening from another request path
		cred.lastUpdated = time.Now().Add(-10 * time.Second)
		cred.backoff = 5 * time.Second
		subscriber.Emit(struct{}{})
	}()

	recorder := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/ocm/v1/status?watch=true", nil).WithContext(ctx)

	service.handleStatusStream(recorder, request, provider, nil)

	// Initial pollIfStale (1) + post-subscription timer-driven call (2+)
	if pollCount.Load() < 2 {
		t.Fatalf("expected pollIfStale called at least 2 times, got %d", pollCount.Load())
	}
}
