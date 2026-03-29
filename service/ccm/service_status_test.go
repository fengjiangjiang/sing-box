package ccm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing/common/observable"
)

type testCredential struct {
	tag          string
	external     bool
	available    bool
	usable       bool
	hasData      bool
	fiveHour     float64
	weekly       float64
	fiveHourCapV float64
	weeklyCapV   float64
	weight       float64
	burnFactor   float64
	fiveReset    time.Time
	weeklyReset  time.Time
	availability availabilityStatus
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
func (c *testCredential) weeklyBurnFactor() float64 {
	if c.burnFactor > 0 {
		return c.burnFactor
	}
	return ccmWeeklyBurnFactorMin
}
func (c *testCredential) fiveHourResetTime() time.Time           { return c.fiveReset }
func (c *testCredential) weeklyResetTime() time.Time             { return c.weeklyReset }
func (c *testCredential) markRateLimited(time.Time)              {}
func (c *testCredential) markUpstreamRejected()                  {}
func (c *testCredential) availabilityStatus() availabilityStatus { return c.availability }
func (c *testCredential) earliestReset() time.Time               { return c.fiveReset }
func (c *testCredential) unavailableError() error                { return nil }
func (c *testCredential) getAccessToken() (string, error)        { return "", nil }
func (c *testCredential) buildProxyRequest(context.Context, *http.Request, []byte, http.Header) (*http.Request, error) {
	return nil, nil
}
func (c *testCredential) updateStateFromHeaders(http.Header)                           {}
func (c *testCredential) wrapRequestContext(context.Context) *credentialRequestContext { return nil }
func (c *testCredential) interruptConnections()                                        {}
func (c *testCredential) setStatusSubscriber(*observable.Subscriber[struct{}])         {}
func (c *testCredential) start() error                                                 { return nil }
func (c *testCredential) pollUsage()                                                   {}
func (c *testCredential) lastUpdatedTime() time.Time                                   { return time.Now() }
func (c *testCredential) pollBackoff(time.Duration) time.Duration                      { return 0 }
func (c *testCredential) usageTrackerOrNil() *AggregatedUsage                          { return nil }
func (c *testCredential) httpClient() *http.Client                                     { return nil }
func (c *testCredential) close()                                                       {}

type testProvider struct {
	credentials []Credential
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
func (p *testProvider) pollIfStale()                     {}
func (p *testProvider) pollCredentialIfStale(Credential) {}
func (p *testProvider) allCredentials() []Credential     { return p.credentials }
func (p *testProvider) close()                           {}

func TestComputeAggregatedUtilizationPreservesSnapshotForRateLimitedCredential(t *testing.T) {
	t.Parallel()

	reset := time.Now().Add(15 * time.Minute)
	service := &Service{}
	status := service.computeAggregatedUtilization(&testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       false,
			hasData:      true,
			fiveHour:     42,
			weekly:       18,
			fiveHourCapV: 100,
			weeklyCapV:   100,
			weight:       1,
			fiveReset:    reset,
			weeklyReset:  reset.Add(2 * time.Hour),
			availability: availabilityStatus{State: availabilityStateRateLimited, Reason: availabilityReasonHardRateLimit, ResetAt: reset},
		},
	}}, nil)

	if status.fiveHourUtilization != 42 || status.weeklyUtilization != 18 {
		t.Fatalf("expected preserved utilization, got 5h=%v weekly=%v", status.fiveHourUtilization, status.weeklyUtilization)
	}
	if status.availability.State != availabilityStateRateLimited {
		t.Fatalf("expected rate-limited availability, got %#v", status.availability)
	}
}

func TestRewriteResponseHeadersComputesUnifiedStatus(t *testing.T) {
	t.Parallel()

	reset := time.Now().Add(80 * time.Minute)
	service := &Service{}
	headers := make(http.Header)
	service.rewriteResponseHeaders(headers, &testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       true,
			hasData:      true,
			fiveHour:     92,
			weekly:       30,
			fiveHourCapV: 100,
			weeklyCapV:   100,
			weight:       1,
			fiveReset:    reset,
			weeklyReset:  time.Now().Add(4 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	if headers.Get("anthropic-ratelimit-unified-status") != "allowed_warning" {
		t.Fatalf("expected allowed_warning, got %q", headers.Get("anthropic-ratelimit-unified-status"))
	}
	if headers.Get("anthropic-ratelimit-unified-representative-claim") != "5h" {
		t.Fatalf("expected 5h representative claim, got %q", headers.Get("anthropic-ratelimit-unified-representative-claim"))
	}
	if headers.Get("anthropic-ratelimit-unified-5h-surpassed-threshold") != "true" {
		t.Fatalf("expected 5h threshold header")
	}
}

func TestRewriteResponseHeadersStripsUpstreamHeaders(t *testing.T) {
	t.Parallel()

	service := &Service{}
	headers := make(http.Header)
	headers.Set("anthropic-ratelimit-unified-overage-status", "rejected")
	headers.Set("anthropic-ratelimit-unified-overage-disabled-reason", "org_level_disabled")
	headers.Set("anthropic-ratelimit-unified-fallback", "available")
	service.rewriteResponseHeaders(headers, &testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       true,
			hasData:      true,
			fiveHour:     10,
			weekly:       5,
			fiveHourCapV: 100,
			weeklyCapV:   100,
			weight:       1,
			fiveReset:    time.Now().Add(3 * time.Hour),
			weeklyReset:  time.Now().Add(5 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	if headers.Get("anthropic-ratelimit-unified-overage-status") != "" {
		t.Fatalf("expected overage-status stripped, got %q", headers.Get("anthropic-ratelimit-unified-overage-status"))
	}
	if headers.Get("anthropic-ratelimit-unified-overage-disabled-reason") != "" {
		t.Fatalf("expected overage-disabled-reason stripped, got %q", headers.Get("anthropic-ratelimit-unified-overage-disabled-reason"))
	}
	if headers.Get("anthropic-ratelimit-unified-fallback") != "" {
		t.Fatalf("expected fallback stripped, got %q", headers.Get("anthropic-ratelimit-unified-fallback"))
	}
	if headers.Get("anthropic-ratelimit-unified-status") != "allowed" {
		t.Fatalf("expected allowed status, got %q", headers.Get("anthropic-ratelimit-unified-status"))
	}
}

func TestRewriteResponseHeadersRejectedOnHardRateLimit(t *testing.T) {
	t.Parallel()

	reset := time.Now().Add(10 * time.Minute)
	service := &Service{}
	headers := make(http.Header)
	service.rewriteResponseHeaders(headers, &testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       false,
			hasData:      true,
			fiveHour:     50,
			weekly:       20,
			fiveHourCapV: 100,
			weeklyCapV:   100,
			weight:       1,
			fiveReset:    reset,
			weeklyReset:  time.Now().Add(5 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateRateLimited, Reason: availabilityReasonHardRateLimit, ResetAt: reset},
		},
	}}, nil)

	if headers.Get("anthropic-ratelimit-unified-status") != "rejected" {
		t.Fatalf("expected rejected (hard rate limited), got %q", headers.Get("anthropic-ratelimit-unified-status"))
	}
}

func TestComputeAggregatedUtilizationAggregatesWeeklyBurnFactor(t *testing.T) {
	t.Parallel()

	service := &Service{}
	status := service.computeAggregatedUtilization(&testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       true,
			hasData:      true,
			weekly:       80,
			weeklyCapV:   100,
			weight:       1,
			burnFactor:   1.2,
			availability: availabilityStatus{State: availabilityStateUsable},
		},
		&testCredential{
			tag:          "b",
			available:    true,
			usable:       true,
			hasData:      true,
			weekly:       40,
			weeklyCapV:   100,
			weight:       2,
			burnFactor:   1.8,
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}}, nil)

	expected := (20*1*1.2 + 60*2*1.8) / (20*1 + 60*2)
	if diff := status.weeklyBurnFactor - expected; diff < -0.000001 || diff > 0.000001 {
		t.Fatalf("expected weekly burn factor %v, got %v", expected, status.weeklyBurnFactor)
	}
}

func TestWriteCredentialUnavailableErrorReturns429ForRateLimitedCredentials(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	provider := &testProvider{credentials: []Credential{
		&testCredential{
			tag:          "a",
			available:    true,
			usable:       false,
			hasData:      true,
			fiveHourCapV: 100,
			weeklyCapV:   100,
			weight:       1,
			availability: availabilityStatus{State: availabilityStateRateLimited, Reason: availabilityReasonHardRateLimit, ResetAt: time.Now().Add(time.Minute)},
		},
	}}

	writeCredentialUnavailableError(recorder, request, provider, provider.credentials[0], credentialSelection{}, "all credentials rate-limited")

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", recorder.Code)
	}
}
