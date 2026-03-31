package ocm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

func TestShouldRetryStatusStreamErrorReturnsTrueForHTTPError(t *testing.T) {
	t.Parallel()
	err := &statusStreamHTTPError{code: 502, body: "Bad Gateway"}
	if !shouldRetryStatusStreamError(err) {
		t.Fatal("expected HTTP status error to be retryable")
	}
}

func TestShouldRetryStatusStreamErrorReturnsTrueForUnexpectedEOF(t *testing.T) {
	t.Parallel()
	if !shouldRetryStatusStreamError(io.ErrUnexpectedEOF) {
		t.Fatal("expected ErrUnexpectedEOF to be retryable")
	}
}

func TestShouldRetryStatusStreamErrorReturnsTrueForJSONDecodeError(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("decode status frame: %w", errors.New("unexpected character"))
	if !shouldRetryStatusStreamError(err) {
		t.Fatal("expected JSON decode error to be retryable")
	}
}

func TestExternalCheckReservesLockedReturnsTrueWhenFiveHourResetPassed(t *testing.T) {
	t.Parallel()
	c := &externalCredential{}
	c.state.fiveHourUtilization = 100
	c.state.fiveHourReset = time.Now().Add(-1 * time.Hour)
	c.state.weeklyUtilization = 50
	c.state.weeklyReset = time.Now().Add(3 * time.Hour)
	if !c.checkExternalReservesLocked() {
		t.Fatal("checkExternalReservesLocked should return true when five-hour reset has passed")
	}
}

func TestExternalCheckReservesLockedReturnsTrueWhenWeeklyResetPassed(t *testing.T) {
	t.Parallel()
	c := &externalCredential{}
	c.state.fiveHourUtilization = 50
	c.state.weeklyUtilization = 100
	c.state.weeklyReset = time.Now().Add(-1 * time.Hour)
	if !c.checkExternalReservesLocked() {
		t.Fatal("checkExternalReservesLocked should return true when weekly reset has passed")
	}
}

func TestExternalCheckReservesLockedReturnsFalseWhenResetInFuture(t *testing.T) {
	t.Parallel()
	c := &externalCredential{}
	c.state.fiveHourUtilization = 100
	c.state.fiveHourReset = time.Now().Add(1 * time.Hour)
	if c.checkExternalReservesLocked() {
		t.Fatal("checkExternalReservesLocked should return false when reset is in the future")
	}
}

func TestExternalCheckReservesLockedReturnsFalseWhenResetIsZero(t *testing.T) {
	t.Parallel()
	c := &externalCredential{}
	c.state.fiveHourUtilization = 100
	if c.checkExternalReservesLocked() {
		t.Fatal("checkExternalReservesLocked should return false when reset time is zero")
	}
}

func TestShouldRetryStatusStreamErrorReturnsFalseFor401(t *testing.T) {
	t.Parallel()
	err := &statusStreamHTTPError{code: 401, body: "Unauthorized"}
	if shouldRetryStatusStreamError(err) {
		t.Fatal("expected 401 error to be non-retryable")
	}
}

func TestShouldRetryStatusStreamErrorReturnsFalseFor403(t *testing.T) {
	t.Parallel()
	err := &statusStreamHTTPError{code: 403, body: "Forbidden"}
	if shouldRetryStatusStreamError(err) {
		t.Fatal("expected 403 error to be non-retryable")
	}
}

func TestExternalCheckTransitionLockedUsableWhenResetPassed(t *testing.T) {
	t.Parallel()
	c := &externalCredential{}
	c.state.fiveHourUtilization = 100
	c.state.fiveHourReset = time.Now().Add(-1 * time.Hour)
	c.state.weeklyUtilization = 50
	c.interrupted = true
	c.checkTransitionLocked()
	if c.interrupted {
		t.Fatal("interrupted should be cleared when reset has passed and credential is usable")
	}
}

func newTestExternalCredential(baseURL string) *externalCredential {
	ctx, cancel := context.WithCancel(context.Background())
	return &externalCredential{
		tag:               "test",
		baseURL:           baseURL,
		token:             "test-token",
		forwardHTTPClient: &http.Client{Timeout: 5 * time.Second},
		logger:            log.NewNOPFactory().Logger(),
		reverseContext:     ctx,
		reverseCancel:      cancel,
		requestContext:     ctx,
		cancelRequests:     cancel,
	}
}

func TestStatusStreamLoopReconnectsAfterRetryableHTTPError(t *testing.T) {
	t.Parallel()
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("Bad Gateway"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(statusPayload{
			FiveHourUtilization: 42,
			FiveHourReset:       time.Now().Add(time.Hour).Unix(),
			WeeklyUtilization:   18,
			WeeklyReset:         time.Now().Add(24 * time.Hour).Unix(),
			PlanWeight:          1.0,
		})
	}))
	defer server.Close()

	c := newTestExternalCredential(server.URL)
	defer c.reverseCancel()

	done := make(chan struct{})
	go func() {
		c.statusStreamLoop()
		close(done)
	}()

	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			c.reverseCancel()
			<-done
			t.Fatal("timed out waiting for reconnection and frame processing")
		default:
		}
		c.stateAccess.RLock()
		got := c.state.fiveHourUtilization
		c.stateAccess.RUnlock()
		if got == 42 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if attempts := attempt.Load(); attempts < 2 {
		t.Fatalf("expected at least 2 connection attempts, got %d", attempts)
	}
	c.reverseCancel()
	<-done
}

func TestStatusStreamLoopStopsOnNonRetryableError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	c := newTestExternalCredential(server.URL)
	defer c.reverseCancel()

	done := make(chan struct{})
	go func() {
		c.statusStreamLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		c.reverseCancel()
		<-done
		t.Fatal("statusStreamLoop should have exited immediately on 401")
	}
}

func TestStatusStreamLoopReconnectsAfterStreamEOF(t *testing.T) {
	t.Parallel()
	var attempt atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempt.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		payload := statusPayload{
			FiveHourUtilization: float64(n * 10),
			FiveHourReset:       time.Now().Add(time.Hour).Unix(),
			WeeklyUtilization:   float64(n * 5),
			WeeklyReset:         time.Now().Add(24 * time.Hour).Unix(),
			PlanWeight:          1.0,
		}
		json.NewEncoder(w).Encode(payload)
		if flusher != nil {
			flusher.Flush()
		}
		// Close connection after one frame to simulate EOF
	}))
	defer server.Close()

	c := newTestExternalCredential(server.URL)
	defer c.reverseCancel()

	done := make(chan struct{})
	go func() {
		c.statusStreamLoop()
		close(done)
	}()

	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			c.reverseCancel()
			<-done
			t.Fatal("timed out waiting for second frame")
		default:
		}
		if attempt.Load() >= 2 {
			c.stateAccess.RLock()
			got := c.state.fiveHourUtilization
			c.stateAccess.RUnlock()
			if got == 20 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	c.reverseCancel()
	<-done
}

func TestStatusStreamLoopExitsOnContextCancelDuringBackoff(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Bad Gateway"))
	}))
	defer server.Close()

	c := newTestExternalCredential(server.URL)

	done := make(chan struct{})
	go func() {
		c.statusStreamLoop()
		close(done)
	}()

	// Give time for the first attempt and entry into backoff
	time.Sleep(200 * time.Millisecond)
	c.reverseCancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("statusStreamLoop should have exited promptly after context cancel")
	}
}

func TestStatusStreamLoopUpdatesStateFromFrames(t *testing.T) {
	t.Parallel()
	frameCh := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)

		resetTime := time.Now().Add(2 * time.Hour).Unix()
		payload := statusPayload{
			FiveHourUtilization: 55.5,
			FiveHourReset:       resetTime,
			WeeklyUtilization:   33.3,
			WeeklyReset:         resetTime,
			PlanWeight:          2.5,
		}
		json.NewEncoder(w).Encode(payload)
		if flusher != nil {
			flusher.Flush()
		}
		close(frameCh)
		// Block until client disconnects
		<-r.Context().Done()
	}))
	defer server.Close()

	c := newTestExternalCredential(server.URL)
	defer c.reverseCancel()

	done := make(chan struct{})
	go func() {
		c.statusStreamLoop()
		close(done)
	}()

	select {
	case <-frameCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for frame to be served")
	}
	// Wait for frame processing
	time.Sleep(100 * time.Millisecond)

	c.stateAccess.RLock()
	fiveHour := c.state.fiveHourUtilization
	weekly := c.state.weeklyUtilization
	planWeight := c.state.remotePlanWeight
	updated := c.state.lastUpdated
	c.stateAccess.RUnlock()

	if fiveHour != 55.5 {
		t.Fatalf("expected fiveHourUtilization=55.5, got %v", fiveHour)
	}
	if weekly != 33.3 {
		t.Fatalf("expected weeklyUtilization=33.3, got %v", weekly)
	}
	if planWeight != 2.5 {
		t.Fatalf("expected remotePlanWeight=2.5, got %v", planWeight)
	}
	if updated.IsZero() {
		t.Fatal("expected lastUpdated to be set")
	}

	c.reverseCancel()
	<-done
}
