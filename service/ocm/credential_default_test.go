package ocm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/observable"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newJSONResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestCheckReservesLockedReturnsTrueWhenFiveHourResetPassed(t *testing.T) {
	t.Parallel()
	credential := &defaultCredential{cap5h: 99, capWeekly: 99}
	credential.state.fiveHourUtilization = 100
	credential.state.fiveHourReset = time.Now().Add(-1 * time.Hour)
	credential.state.weeklyUtilization = 10

	credential.stateAccess.RLock()
	result := credential.checkReservesLocked()
	credential.stateAccess.RUnlock()
	if !result {
		t.Fatal("checkReservesLocked should return true when five-hour reset has passed")
	}
}

func TestCheckReservesLockedReturnsTrueWhenWeeklyResetPassed(t *testing.T) {
	t.Parallel()
	credential := &defaultCredential{cap5h: 99, capWeekly: 99}
	credential.state.fiveHourUtilization = 10
	credential.state.weeklyUtilization = 100
	credential.state.weeklyReset = time.Now().Add(-1 * time.Hour)

	credential.stateAccess.RLock()
	result := credential.checkReservesLocked()
	credential.stateAccess.RUnlock()
	if !result {
		t.Fatal("checkReservesLocked should return true when weekly reset has passed")
	}
}

func TestCheckReservesLockedReturnsFalseWhenResetNotReached(t *testing.T) {
	t.Parallel()
	credential := &defaultCredential{cap5h: 99, capWeekly: 99}
	credential.state.fiveHourUtilization = 100
	credential.state.fiveHourReset = time.Now().Add(1 * time.Hour)

	credential.stateAccess.RLock()
	result := credential.checkReservesLocked()
	credential.stateAccess.RUnlock()
	if result {
		t.Fatal("checkReservesLocked should return false when reset has not been reached")
	}
}

func TestCheckReservesLockedReturnsFalseWhenResetIsZero(t *testing.T) {
	t.Parallel()
	credential := &defaultCredential{cap5h: 99, capWeekly: 99}
	credential.state.fiveHourUtilization = 100

	credential.stateAccess.RLock()
	result := credential.checkReservesLocked()
	credential.stateAccess.RUnlock()
	if result {
		t.Fatal("checkReservesLocked should return false when reset time is zero (unknown)")
	}
}

func TestPollUsageEmitsStatusUpdateOn429(t *testing.T) {
	t.Parallel()

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		resp := newJSONResponse(http.StatusTooManyRequests, `{}`)
		resp.Header.Set("Retry-After", "5")
		return resp, nil
	})

	requestContext, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	lastRefresh := time.Now()
	credential := &defaultCredential{
		tag:               "test",
		serviceContext:    context.Background(),
		cap5h:            99,
		capWeekly:        99,
		forwardHTTPClient: &http.Client{Transport: transport},
		logger:           log.NewNOPFactory().Logger(),
		requestContext:    requestContext,
		cancelRequests:    cancelRequests,
	}
	credential.credentials = &oauthCredentials{
		Tokens:      &tokenData{AccessToken: "test-token"},
		LastRefresh: &lastRefresh,
	}
	credential.state.lastUpdated = time.Now()

	subscriber := observable.NewSubscriber[struct{}](8)
	observer := observable.NewObserver[struct{}](subscriber, 8)
	defer observer.Close()

	subscription, _, err := observer.Subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer observer.UnSubscribe(subscription)

	credential.statusSubscriber = subscriber

	credential.pollUsage()

	select {
	case <-subscription:
	case <-time.After(time.Second):
		t.Fatal("expected status update emission on 429, but subscriber received nothing")
	}

	credential.stateAccess.RLock()
	delay := credential.state.usageAPIRetryDelay
	credential.stateAccess.RUnlock()
	if delay != 5*time.Second {
		t.Fatalf("expected usageAPIRetryDelay 5s, got %v", delay)
	}
}
