package ccm

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing/common/observable"
)

func TestGetAccessTokenMarksUnavailableWhenLockFails(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, ".credentials.json")
	credentials := &oauthCredentials{
		AccessToken:      "old-token",
		RefreshToken:     "refresh-token",
		ExpiresAt:        time.Now().Add(time.Hour).UnixMilli(),
		Scopes:           []string{"user:profile", "user:inference"},
		SubscriptionType: optionalStringPointer("max"),
		RateLimitTier:    optionalStringPointer("default_claude_max_20x"),
	}
	writeTestCredentials(t, credentialPath, credentials)

	credential := newTestDefaultCredential(t, credentialPath, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatal("refresh should not be attempted when lock acquisition fails")
		return nil, nil
	}))
	if err := credential.reloadCredentials(true); err != nil {
		t.Fatal(err)
	}

	expiredCredentials := cloneCredentials(credentials)
	expiredCredentials.ExpiresAt = time.Now().Add(-time.Minute).UnixMilli()
	writeTestCredentials(t, credentialPath, expiredCredentials)
	credential.absorbCredentials(expiredCredentials)

	credential.acquireLock = func(string) (func(), error) {
		return nil, errors.New("permission denied")
	}

	_, err := credential.getAccessToken()
	if err == nil {
		t.Fatal("expected error when lock acquisition fails, got nil")
	}
	if credential.isUsable() {
		t.Fatal("credential should be marked unavailable after lock failure")
	}
}

func TestGetAccessTokenMarksUnavailableOnUnwritableFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, ".credentials.json")
	credentials := &oauthCredentials{
		AccessToken:  "old-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
		Scopes:       []string{"user:profile", "user:inference"},
	}
	writeTestCredentials(t, credentialPath, credentials)

	credential := newTestDefaultCredential(t, credentialPath, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatal("refresh should not be attempted when file is not writable")
		return nil, nil
	}))
	if err := credential.reloadCredentials(true); err != nil {
		t.Fatal(err)
	}

	expiredCredentials := cloneCredentials(credentials)
	expiredCredentials.ExpiresAt = time.Now().Add(-time.Minute).UnixMilli()
	writeTestCredentials(t, credentialPath, expiredCredentials)
	credential.absorbCredentials(expiredCredentials)

	os.Chmod(credentialPath, 0o444)
	t.Cleanup(func() { os.Chmod(credentialPath, 0o644) })

	_, err := credential.getAccessToken()
	if err == nil {
		t.Fatal("expected error when credential file is not writable, got nil")
	}
	if credential.isUsable() {
		t.Fatal("credential should be marked unavailable after write permission failure")
	}
}

func TestGetAccessTokenAbsorbsRefreshDoneByAnotherProcess(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, ".credentials.json")
	oldCredentials := &oauthCredentials{
		AccessToken:      "old-token",
		RefreshToken:     "refresh-token",
		ExpiresAt:        time.Now().Add(-time.Minute).UnixMilli(),
		Scopes:           []string{"user:profile", "user:inference"},
		SubscriptionType: optionalStringPointer("max"),
		RateLimitTier:    optionalStringPointer("default_claude_max_20x"),
	}
	writeTestCredentials(t, credentialPath, oldCredentials)

	newCredentials := cloneCredentials(oldCredentials)
	newCredentials.AccessToken = "new-token"
	newCredentials.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/oauth/token" {
			writeTestCredentials(t, credentialPath, newCredentials)
			return newJSONResponse(http.StatusInternalServerError, `{"error":"boom"}`), nil
		}
		t.Fatalf("unexpected path %s", request.URL.Path)
		return nil, nil
	})

	credential := newTestDefaultCredential(t, credentialPath, transport)
	if err := credential.reloadCredentials(true); err != nil {
		t.Fatal(err)
	}

	token, err := credential.getAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "new-token" {
		t.Fatalf("expected refreshed token from disk, got %q", token)
	}
}

func TestCustomCredentialPathDoesNotEnableClaudeConfigSync(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, ".credentials.json")
	writeTestCredentials(t, credentialPath, &oauthCredentials{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(time.Hour).UnixMilli(),
		Scopes:      []string{"user:profile"},
	})

	credential := newTestDefaultCredential(t, credentialPath, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request to %s", request.URL.Path)
		return nil, nil
	}))
	if err := credential.reloadCredentials(true); err != nil {
		t.Fatal(err)
	}

	token, err := credential.getAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "token" {
		t.Fatalf("expected token, got %q", token)
	}
	if credential.shouldUseClaudeConfig() {
		t.Fatal("custom credential path should not enable Claude config sync")
	}
	if _, err := os.Stat(filepath.Join(directory, ".claude.json")); !os.IsNotExist(err) {
		t.Fatalf("did not expect config file to be created, stat err=%v", err)
	}
}

func TestDefaultCredentialHydratesProfileAndWritesConfig(t *testing.T) {
	configDir := t.TempDir()
	credentialPath := filepath.Join(configDir, ".credentials.json")

	writeTestCredentials(t, credentialPath, &oauthCredentials{
		AccessToken:  "old-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(-time.Minute).UnixMilli(),
		Scopes:       []string{"user:profile", "user:inference"},
	})

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/oauth/token":
			return newJSONResponse(http.StatusOK, `{
				"access_token":"new-token",
				"refresh_token":"new-refresh",
				"expires_in":3600,
				"account":{"uuid":"account","email_address":"user@example.com"},
				"organization":{"uuid":"org"}
			}`), nil
		case "/api/oauth/profile":
			return newJSONResponse(http.StatusOK, `{
				"account":{
					"uuid":"account",
					"email":"user@example.com",
					"display_name":"User",
					"created_at":"2024-01-01T00:00:00Z"
				},
				"organization":{
					"uuid":"org",
					"organization_type":"claude_max",
					"rate_limit_tier":"default_claude_max_20x",
					"has_extra_usage_enabled":true,
					"billing_type":"individual",
					"subscription_created_at":"2024-01-02T00:00:00Z"
				}
			}`), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})

	credential := newTestDefaultCredential(t, credentialPath, transport)
	credential.syncClaudeConfig = true
	credential.claudeDirectory = configDir
	credential.claudeConfigPath = resolveClaudeConfigWritePath(configDir)
	if err := credential.reloadCredentials(true); err != nil {
		t.Fatal(err)
	}

	token, err := credential.getAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "new-token" {
		t.Fatalf("expected refreshed token, got %q", token)
	}

	updatedCredentials := readTestCredentials(t, credentialPath)
	if updatedCredentials.SubscriptionType == nil || *updatedCredentials.SubscriptionType != "max" {
		t.Fatalf("expected subscription type to be persisted, got %#v", updatedCredentials.SubscriptionType)
	}
	if updatedCredentials.RateLimitTier == nil || *updatedCredentials.RateLimitTier != "default_claude_max_20x" {
		t.Fatalf("expected rate limit tier to be persisted, got %#v", updatedCredentials.RateLimitTier)
	}

	configPath := tempConfigPath(t, configDir)
	config, err := readClaudeCodeConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if config.OAuthAccount == nil || config.OAuthAccount.AccountUUID != "account" || config.OAuthAccount.EmailAddress != "user@example.com" {
		t.Fatalf("unexpected oauth account: %#v", config.OAuthAccount)
	}
	if config.OAuthAccount.BillingType == nil || *config.OAuthAccount.BillingType != "individual" {
		t.Fatalf("expected billing type to be hydrated, got %#v", config.OAuthAccount.BillingType)
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

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, ".credentials.json")
	writeTestCredentials(t, credentialPath, &oauthCredentials{
		AccessToken:  "token",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
		Scopes:       []string{"user:profile", "user:inference"},
	})

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		resp := newJSONResponse(http.StatusTooManyRequests, `{}`)
		resp.Header.Set("Retry-After", "5")
		return resp, nil
	})

	credential := newTestDefaultCredential(t, credentialPath, transport)
	if err := credential.reloadCredentials(true); err != nil {
		t.Fatal(err)
	}

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
