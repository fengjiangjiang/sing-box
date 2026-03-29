package ccm

import (
	"bytes"
	"context"
	stdTLS "crypto/tls"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

type claudeProfileSnapshot struct {
	OAuthAccount     *claudeOAuthAccount
	AccountType      string
	RateLimitTier    string
	SubscriptionType *string
}

type defaultCredential struct {
	tag                string
	serviceContext     context.Context
	credentialPath     string
	claudeDirectory    string
	credentialFilePath string
	configDir          string
	claudeConfigPath   string
	syncClaudeConfig   bool
	deviceID           string
	credentials        *oauthCredentials
	access             sync.RWMutex
	state              credentialState
	stateAccess        sync.RWMutex
	pollAccess         sync.Mutex
	reloadAccess       sync.Mutex
	watcherAccess      sync.Mutex
	cap5h              float64
	capWeekly          float64
	usageTracker       *AggregatedUsage
	forwardHTTPClient  *http.Client
	acquireLock        func(string) (func(), error)
	logger             log.ContextLogger
	watcher            *fswatch.Watcher
	watcherRetryAt     time.Time

	statusSubscriber *observable.Subscriber[struct{}]

	// Connection interruption
	interrupted    bool
	requestContext context.Context
	cancelRequests context.CancelFunc
	requestAccess  sync.Mutex
}

func newDefaultCredential(ctx context.Context, tag string, options option.CCMDefaultCredentialOptions, logger log.ContextLogger) (*defaultCredential, error) {
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
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &stdTLS.Config{
				RootCAs: adapter.RootPoolFromContext(ctx),
				Time:    ntp.TimeFuncFromContext(ctx),
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return credentialDialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	reserve5h := options.Reserve5h
	if reserve5h == 0 {
		reserve5h = 1
	}
	reserveWeekly := options.ReserveWeekly
	if reserveWeekly == 0 {
		reserveWeekly = 1
	}
	var cap5h float64
	if options.Limit5h > 0 {
		cap5h = float64(options.Limit5h)
	} else {
		cap5h = float64(100 - reserve5h)
	}
	var capWeekly float64
	if options.LimitWeekly > 0 {
		capWeekly = float64(options.LimitWeekly)
	} else {
		capWeekly = float64(100 - reserveWeekly)
	}
	requestContext, cancelRequests := context.WithCancel(context.Background())
	credential := &defaultCredential{
		tag:               tag,
		serviceContext:    ctx,
		credentialPath:    options.CredentialPath,
		claudeDirectory:   options.ClaudeDirectory,
		syncClaudeConfig:  options.ClaudeDirectory != "" || options.CredentialPath == "",
		cap5h:             cap5h,
		capWeekly:         capWeekly,
		forwardHTTPClient: httpClient,
		acquireLock:       acquireCredentialLock,
		logger:            logger,
		requestContext:    requestContext,
		cancelRequests:    cancelRequests,
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

func (c *defaultCredential) start() error {
	if c.claudeDirectory != "" {
		if c.credentialPath == "" {
			c.credentialPath = filepath.Join(c.claudeDirectory, ".credentials.json")
		}
	}
	credentialFilePath, err := resolveCredentialFilePath(c.credentialPath)
	if err != nil {
		return E.Cause(err, "resolve credential path for ", c.tag)
	}
	c.credentialFilePath = credentialFilePath
	c.configDir = resolveConfigDir(c.credentialPath, credentialFilePath)
	if c.syncClaudeConfig {
		if c.claudeDirectory == "" {
			c.claudeDirectory = c.configDir
		}
		c.claudeConfigPath = resolveClaudeConfigWritePath(c.claudeDirectory)
		c.loadClaudeCodeConfig()
	}
	err = c.ensureCredentialWatcher()
	if err != nil {
		c.logger.Error("start credential watcher for ", c.tag, ": ", err)
	}
	err = c.reloadCredentials(true)
	if err != nil {
		c.logger.Error("initial credential load for ", c.tag, ": ", err)
	}
	if c.usageTracker != nil {
		err = c.usageTracker.Load()
		if err != nil {
			c.logger.Warn("load usage statistics for ", c.tag, ": ", err)
		}
	}
	go c.pollUsage()
	return nil
}

func (c *defaultCredential) loadClaudeCodeConfig() {
	configFilePath := resolveClaudeConfigFile(c.claudeDirectory)
	if configFilePath == "" {
		return
	}
	config, err := readClaudeCodeConfig(configFilePath)
	if err != nil {
		c.logger.Warn("read claude code config for ", c.tag, ": ", err)
		return
	}
	c.stateAccess.Lock()
	c.state.oauthAccount = cloneClaudeOAuthAccount(config.OAuthAccount)
	if config.OAuthAccount != nil && config.OAuthAccount.AccountUUID != "" {
		c.state.accountUUID = config.OAuthAccount.AccountUUID
	}
	c.stateAccess.Unlock()
	if config.UserID != "" {
		c.deviceID = config.UserID
	}
	c.claudeConfigPath = configFilePath
	c.logger.Debug("loaded claude code config for ", c.tag, ": account=", c.state.accountUUID, ", device=", c.deviceID)
}

func (c *defaultCredential) setStatusSubscriber(subscriber *observable.Subscriber[struct{}]) {
	c.statusSubscriber = subscriber
}

func (c *defaultCredential) emitStatusUpdate() {
	if c.statusSubscriber != nil {
		c.statusSubscriber.Emit(struct{}{})
	}
}

type statusSnapshot struct {
	available bool
	weight    float64
}

type refreshFailureError struct {
	err  error
	hard bool
}

func (e *refreshFailureError) Error() string {
	return e.err.Error()
}

func (e *refreshFailureError) Unwrap() error {
	return e.err
}

func newRefreshFailure(err error, hard bool) error {
	if err == nil {
		return nil
	}
	return &refreshFailureError{err: err, hard: hard}
}

func isHardRefreshFailure(err error) bool {
	refreshErr, ok := err.(*refreshFailureError)
	return ok && refreshErr.hard
}

func (c *defaultCredential) statusSnapshotLocked() statusSnapshot {
	if c.state.unavailable {
		return statusSnapshot{}
	}
	return statusSnapshot{true, ccmPlanWeight(c.state.accountType, c.state.rateLimitTier)}
}

func (c *defaultCredential) getAccessToken() (string, error) {
	c.retryCredentialReloadIfNeeded()

	c.access.RLock()
	currentCredentials := cloneCredentials(c.credentials)
	c.access.RUnlock()
	if currentCredentials == nil {
		err := c.reloadCredentials(true)
		if err != nil {
			return "", err
		}
		c.access.RLock()
		currentCredentials = cloneCredentials(c.credentials)
		c.access.RUnlock()
	}
	if currentCredentials == nil {
		return "", c.unavailableError()
	}
	if !currentCredentials.needsRefresh() || !slices.Contains(currentCredentials.Scopes, "user:inference") {
		return currentCredentials.AccessToken, nil
	}
	refreshErr := c.tryRefreshCredentials(false)
	if refreshErr != nil {
		return "", refreshErr
	}
	c.access.RLock()
	defer c.access.RUnlock()
	if c.credentials != nil && c.credentials.AccessToken != "" {
		return c.credentials.AccessToken, nil
	}
	return "", c.unavailableError()
}

func (c *defaultCredential) shouldUseClaudeConfig() bool {
	return c.syncClaudeConfig && c.claudeConfigPath != ""
}

func (c *defaultCredential) absorbCredentials(credentials *oauthCredentials) {
	c.access.Lock()
	c.credentials = cloneCredentials(credentials)
	c.access.Unlock()

	c.stateAccess.Lock()
	before := c.statusSnapshotLocked()
	c.state.unavailable = false
	c.state.lastCredentialLoadAttempt = time.Now()
	c.state.lastCredentialLoadError = ""
	c.applyCredentialMetadataLocked(credentials)
	c.checkTransitionLocked()
	shouldEmit := before != c.statusSnapshotLocked()
	c.stateAccess.Unlock()
	if shouldEmit {
		c.emitStatusUpdate()
	}
}

func (c *defaultCredential) applyCredentialMetadataLocked(credentials *oauthCredentials) {
	if credentials == nil {
		return
	}
	if credentials.SubscriptionType != nil && *credentials.SubscriptionType != "" {
		c.state.accountType = *credentials.SubscriptionType
	}
	if credentials.RateLimitTier != nil && *credentials.RateLimitTier != "" {
		c.state.rateLimitTier = *credentials.RateLimitTier
	}
}

func (c *defaultCredential) absorbOAuthAccount(account *claudeOAuthAccount) {
	c.stateAccess.Lock()
	c.state.oauthAccount = mergeClaudeOAuthAccount(c.state.oauthAccount, account)
	if c.state.oauthAccount != nil && c.state.oauthAccount.AccountUUID != "" {
		c.state.accountUUID = c.state.oauthAccount.AccountUUID
	}
	c.stateAccess.Unlock()
}

func (c *defaultCredential) persistOAuthAccount() {
	if !c.shouldUseClaudeConfig() {
		return
	}
	c.stateAccess.RLock()
	account := cloneClaudeOAuthAccount(c.state.oauthAccount)
	c.stateAccess.RUnlock()
	if account == nil {
		return
	}
	if err := writeClaudeCodeOAuthAccount(c.claudeConfigPath, account); err != nil {
		c.logger.Debug("write claude code config for ", c.tag, ": ", err)
	}
}

func (c *defaultCredential) needsProfileHydration() bool {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.needsProfileHydrationLocked()
}

func (c *defaultCredential) needsProfileHydrationLocked() bool {
	if c.state.accountUUID == "" || c.state.accountType == "" || c.state.rateLimitTier == "" {
		return true
	}
	if c.state.oauthAccount == nil {
		return true
	}
	return c.state.oauthAccount.BillingType == nil ||
		c.state.oauthAccount.AccountCreatedAt == nil ||
		c.state.oauthAccount.SubscriptionCreatedAt == nil
}

func (c *defaultCredential) currentCredentials() *oauthCredentials {
	c.access.RLock()
	defer c.access.RUnlock()
	return cloneCredentials(c.credentials)
}

func (c *defaultCredential) persistCredentials(credentials *oauthCredentials) error {
	if credentials == nil {
		return nil
	}
	return platformWriteCredentials(credentials, c.credentialPath)
}

func (c *defaultCredential) shouldAttemptRefresh(credentials *oauthCredentials, force bool) bool {
	if credentials == nil || credentials.RefreshToken == "" {
		return false
	}
	if !slices.Contains(credentials.Scopes, "user:inference") {
		return false
	}
	if force {
		return true
	}
	return credentials.needsRefresh()
}

func (c *defaultCredential) markRefreshUnavailable(err error) error {
	return newRefreshFailure(c.markCredentialsUnavailable(err), true)
}

func (c *defaultCredential) refreshCredentialsIfNeeded(force bool) error {
	currentCredentials := c.currentCredentials()
	if !c.shouldAttemptRefresh(currentCredentials, force) {
		return nil
	}
	return c.tryRefreshCredentials(force)
}

func (c *defaultCredential) tryRefreshCredentials(force bool) error {
	latestCredentials, err := platformReadCredentials(c.credentialPath)
	if err == nil && latestCredentials != nil {
		c.absorbCredentials(latestCredentials)
	}
	currentCredentials := c.currentCredentials()
	if !c.shouldAttemptRefresh(currentCredentials, force) {
		return nil
	}
	acquireLock := c.acquireLock
	if acquireLock == nil {
		acquireLock = acquireCredentialLock
	}
	release, err := acquireLock(c.configDir)
	if err != nil {
		lockErr := E.Cause(err, "acquire credential lock for ", c.tag)
		c.logger.Error(lockErr)
		return c.markRefreshUnavailable(lockErr)
	}
	defer release()

	latestCredentials, err = platformReadCredentials(c.credentialPath)
	if err == nil && latestCredentials != nil {
		c.absorbCredentials(latestCredentials)
		currentCredentials = latestCredentials
	} else {
		currentCredentials = c.currentCredentials()
	}
	if !c.shouldAttemptRefresh(currentCredentials, force) {
		return nil
	}
	err = platformCanWriteCredentials(c.credentialPath)
	if err != nil {
		writeErr := E.Cause(err, "credential file not writable for ", c.tag)
		c.logger.Error(writeErr)
		return c.markRefreshUnavailable(writeErr)
	}

	baseCredentials := cloneCredentials(currentCredentials)
	refreshResult, retryDelay, err := refreshToken(c.serviceContext, c.forwardHTTPClient, currentCredentials)
	if err != nil {
		if retryDelay != 0 {
			c.logger.Error("refresh token for ", c.tag, ": retry delay=", retryDelay, ", error=", err)
		} else {
			c.logger.Error("refresh token for ", c.tag, ": ", err)
		}
		latestCredentials, readErr := platformReadCredentials(c.credentialPath)
		if readErr == nil && latestCredentials != nil {
			c.absorbCredentials(latestCredentials)
			if latestCredentials.AccessToken != "" && (latestCredentials.AccessToken != baseCredentials.AccessToken || !latestCredentials.needsRefresh()) {
				return nil
			}
		}
		return newRefreshFailure(E.Cause(err, "refresh token for ", c.tag), false)
	}
	if refreshResult == nil || refreshResult.Credentials == nil {
		return newRefreshFailure(E.New("refresh token for ", c.tag, ": empty result"), false)
	}

	refreshedCredentials := cloneCredentials(refreshResult.Credentials)
	err = c.persistCredentials(refreshedCredentials)
	if err != nil {
		persistErr := E.Cause(err, "persist refreshed token for ", c.tag)
		c.logger.Error(persistErr)
		return c.markRefreshUnavailable(persistErr)
	}
	c.absorbCredentials(refreshedCredentials)

	if refreshResult.TokenAccount != nil {
		c.absorbOAuthAccount(refreshResult.TokenAccount)
		c.persistOAuthAccount()
	}
	if c.needsProfileHydration() {
		profileSnapshot, profileErr := c.fetchProfileSnapshot(c.forwardHTTPClient, refreshedCredentials.AccessToken)
		if profileErr != nil {
			c.logger.Error("fetch profile for ", c.tag, ": ", profileErr)
		} else if profileSnapshot != nil {
			credentialsChanged := c.applyProfileSnapshot(profileSnapshot)
			c.persistOAuthAccount()
			if credentialsChanged {
				err = c.persistCredentials(c.currentCredentials())
				if err != nil {
					c.logger.Error("persist credential metadata for ", c.tag, ": ", err)
				}
			}
		}
	}
	return nil
}

func (c *defaultCredential) recoverAuthFailure(failedAccessToken string) (bool, error) {
	latestCredentials, err := platformReadCredentials(c.credentialPath)
	if err == nil && latestCredentials != nil {
		c.absorbCredentials(latestCredentials)
		if latestCredentials.AccessToken != "" && latestCredentials.AccessToken != failedAccessToken {
			return true, nil
		}
	}
	err = c.tryRefreshCredentials(true)
	if err != nil {
		return false, err
	}
	currentCredentials := c.currentCredentials()
	return currentCredentials != nil && currentCredentials.AccessToken != "" && currentCredentials.AccessToken != failedAccessToken, nil
}

func (c *defaultCredential) applyProfileSnapshot(snapshot *claudeProfileSnapshot) bool {
	if snapshot == nil {
		return false
	}

	credentialsChanged := false
	c.access.Lock()
	if c.credentials != nil {
		updatedCredentials := cloneCredentials(c.credentials)
		if snapshot.SubscriptionType != nil {
			updatedCredentials.SubscriptionType = cloneStringPointer(snapshot.SubscriptionType)
		}
		if snapshot.RateLimitTier != "" {
			updatedCredentials.RateLimitTier = cloneStringPointer(&snapshot.RateLimitTier)
		}
		credentialsChanged = !credentialsEqual(c.credentials, updatedCredentials)
		c.credentials = updatedCredentials
	}
	c.access.Unlock()

	c.stateAccess.Lock()
	before := c.statusSnapshotLocked()
	if snapshot.OAuthAccount != nil {
		c.state.oauthAccount = mergeClaudeOAuthAccount(c.state.oauthAccount, snapshot.OAuthAccount)
		if c.state.oauthAccount != nil && c.state.oauthAccount.AccountUUID != "" {
			c.state.accountUUID = c.state.oauthAccount.AccountUUID
		}
	}
	if snapshot.AccountType != "" {
		c.state.accountType = snapshot.AccountType
	}
	if snapshot.RateLimitTier != "" {
		c.state.rateLimitTier = snapshot.RateLimitTier
	}
	c.checkTransitionLocked()
	shouldEmit := before != c.statusSnapshotLocked()
	c.stateAccess.Unlock()
	if shouldEmit {
		c.emitStatusUpdate()
	}
	return credentialsChanged
}

func (c *defaultCredential) fetchProfileSnapshot(httpClient *http.Client, accessToken string) (*claudeProfileSnapshot, error) {
	ctx := c.serviceContext
	response, err := doHTTPWithRetry(ctx, httpClient, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, claudeAPIBaseURL+"/api/oauth/profile", nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+accessToken)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", ccmUserAgentValue)
		return request, nil
	})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return nil, E.New("status ", response.StatusCode, " ", string(body))
	}

	var profileResponse struct {
		Account *struct {
			UUID        string `json:"uuid"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			CreatedAt   string `json:"created_at"`
		} `json:"account"`
		Organization *struct {
			UUID                  string  `json:"uuid"`
			OrganizationType      string  `json:"organization_type"`
			RateLimitTier         string  `json:"rate_limit_tier"`
			HasExtraUsageEnabled  *bool   `json:"has_extra_usage_enabled"`
			BillingType           *string `json:"billing_type"`
			SubscriptionCreatedAt *string `json:"subscription_created_at"`
		} `json:"organization"`
	}
	if err := json.NewDecoder(response.Body).Decode(&profileResponse); err != nil {
		return nil, err
	}
	if profileResponse.Organization == nil {
		return nil, nil
	}

	accountType := normalizeClaudeOrganizationType(profileResponse.Organization.OrganizationType)
	snapshot := &claudeProfileSnapshot{
		AccountType:   accountType,
		RateLimitTier: profileResponse.Organization.RateLimitTier,
	}
	if accountType != "" {
		snapshot.SubscriptionType = cloneStringPointer(&accountType)
	}
	account := &claudeOAuthAccount{}
	if profileResponse.Account != nil {
		account.AccountUUID = profileResponse.Account.UUID
		account.EmailAddress = profileResponse.Account.Email
		account.DisplayName = optionalStringPointer(profileResponse.Account.DisplayName)
		account.AccountCreatedAt = optionalStringPointer(profileResponse.Account.CreatedAt)
	}
	account.OrganizationUUID = profileResponse.Organization.UUID
	account.HasExtraUsageEnabled = cloneBoolPointer(profileResponse.Organization.HasExtraUsageEnabled)
	account.BillingType = cloneStringPointer(profileResponse.Organization.BillingType)
	account.SubscriptionCreatedAt = cloneStringPointer(profileResponse.Organization.SubscriptionCreatedAt)
	if account.AccountUUID != "" || account.EmailAddress != "" || account.OrganizationUUID != "" || account.DisplayName != nil ||
		account.HasExtraUsageEnabled != nil || account.BillingType != nil || account.AccountCreatedAt != nil || account.SubscriptionCreatedAt != nil {
		snapshot.OAuthAccount = account
	}
	return snapshot, nil
}

func normalizeClaudeOrganizationType(organizationType string) string {
	switch organizationType {
	case "claude_pro":
		return "pro"
	case "claude_max":
		return "max"
	case "claude_team":
		return "team"
	case "claude_enterprise":
		return "enterprise"
	default:
		return ""
	}
}

func optionalStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (c *defaultCredential) updateStateFromHeaders(headers http.Header) {
	c.stateAccess.Lock()
	isFirstUpdate := c.state.lastUpdated.IsZero()
	oldFiveHour := c.state.fiveHourUtilization
	oldWeekly := c.state.weeklyUtilization
	hadData := false

	fiveHourResetChanged := false
	if value, exists := parseOptionalAnthropicResetHeader(headers, "anthropic-ratelimit-unified-5h-reset"); exists {
		hadData = true
		if value.After(c.state.fiveHourReset) {
			fiveHourResetChanged = true
			c.state.fiveHourReset = value
		}
	}
	if utilization := headers.Get("anthropic-ratelimit-unified-5h-utilization"); utilization != "" {
		value, err := strconv.ParseFloat(utilization, 64)
		if err == nil {
			hadData = true
			newValue := math.Ceil(value * 100)
			if newValue >= c.state.fiveHourUtilization || fiveHourResetChanged {
				c.state.fiveHourUtilization = newValue
			}
		}
	}

	weeklyResetChanged := false
	if value, exists := parseOptionalAnthropicResetHeader(headers, "anthropic-ratelimit-unified-7d-reset"); exists {
		hadData = true
		if value.After(c.state.weeklyReset) {
			weeklyResetChanged = true
			c.state.weeklyReset = value
		}
	}
	if utilization := headers.Get("anthropic-ratelimit-unified-7d-utilization"); utilization != "" {
		value, err := strconv.ParseFloat(utilization, 64)
		if err == nil {
			hadData = true
			newValue := math.Ceil(value * 100)
			if newValue >= c.state.weeklyUtilization || weeklyResetChanged {
				c.state.weeklyUtilization = newValue
			}
		}
	}
	if hadData {
		c.state.consecutivePollFailures = 0
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
	shouldEmit := hadData && (c.state.fiveHourUtilization != oldFiveHour || c.state.weeklyUtilization != oldWeekly || fiveHourResetChanged || weeklyResetChanged)
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	if shouldEmit {
		c.emitStatusUpdate()
	}
}

func (c *defaultCredential) markRateLimited(resetAt time.Time) {
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

func (c *defaultCredential) markUpstreamRejected() {}

func (c *defaultCredential) isUsable() bool {
	c.retryCredentialReloadIfNeeded()

	c.stateAccess.RLock()
	if c.state.unavailable {
		c.stateAccess.RUnlock()
		return false
	}
	if c.state.consecutivePollFailures > 0 {
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
		usable := c.checkReservesLocked()
		c.stateAccess.Unlock()
		return usable
	}
	usable := c.checkReservesLocked()
	c.stateAccess.RUnlock()
	return usable
}

func (c *defaultCredential) checkReservesLocked() bool {
	if c.state.fiveHourUtilization >= c.cap5h {
		return false
	}
	if c.state.weeklyUtilization >= c.capWeekly {
		return false
	}
	return true
}

// checkTransitionLocked detects usable→unusable transition.
// Must be called with stateAccess write lock held.
func (c *defaultCredential) checkTransitionLocked() bool {
	unusable := c.state.unavailable || c.state.hardRateLimited || !c.checkReservesLocked() || c.state.consecutivePollFailures > 0
	if unusable && !c.interrupted {
		c.interrupted = true
		return true
	}
	if !unusable && c.interrupted {
		c.interrupted = false
	}
	return false
}

func (c *defaultCredential) interruptConnections() {
	c.logger.Warn("interrupting connections for ", c.tag)
	c.requestAccess.Lock()
	c.cancelRequests()
	c.requestContext, c.cancelRequests = context.WithCancel(context.Background())
	c.requestAccess.Unlock()
}

func (c *defaultCredential) wrapRequestContext(parent context.Context) *credentialRequestContext {
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

func (c *defaultCredential) weeklyUtilization() float64 {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.weeklyUtilization
}

func (c *defaultCredential) hasSnapshotData() bool {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.hasSnapshotData()
}

func (c *defaultCredential) planWeight() float64 {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return ccmPlanWeight(c.state.accountType, c.state.rateLimitTier)
}

func (c *defaultCredential) weeklyBurnFactor() float64 {
	c.stateAccess.RLock()
	fiveHourUtilization := c.state.fiveHourUtilization
	weeklyUtilization := c.state.weeklyUtilization
	fiveHourReset := c.state.fiveHourReset
	weeklyReset := c.state.weeklyReset
	rateLimitTier := c.state.rateLimitTier
	c.stateAccess.RUnlock()
	return computeCredentialWeeklyBurnFactor(
		time.Now(),
		fiveHourReset,
		weeklyReset,
		fiveHourUtilization,
		weeklyUtilization,
		c.cap5h,
		c.capWeekly,
		ccmPlanWeight5h(rateLimitTier),
	)
}

func (c *defaultCredential) fiveHourResetTime() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.fiveHourReset
}

func (c *defaultCredential) weeklyResetTime() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.weeklyReset
}

func (c *defaultCredential) isAvailable() bool {
	c.retryCredentialReloadIfNeeded()

	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return !c.state.unavailable
}

func (c *defaultCredential) availabilityStatus() availabilityStatus {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.currentAvailability()
}

func (c *defaultCredential) unavailableError() error {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	if !c.state.unavailable {
		return nil
	}
	if c.state.lastCredentialLoadError == "" {
		return E.New("credential ", c.tag, " is unavailable")
	}
	return E.New("credential ", c.tag, " is unavailable: ", c.state.lastCredentialLoadError)
}

func (c *defaultCredential) lastUpdatedTime() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.lastUpdated
}

func (c *defaultCredential) markUsagePollAttempted() {
	c.stateAccess.Lock()
	defer c.stateAccess.Unlock()
	c.state.lastUpdated = time.Now()
}

func (c *defaultCredential) incrementPollFailures() {
	c.stateAccess.Lock()
	c.state.consecutivePollFailures++
	c.state.setAvailability(availabilityStateTemporarilyBlocked, availabilityReasonPollFailed, time.Time{})
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
}

func (c *defaultCredential) pollBackoff(baseInterval time.Duration) time.Duration {
	c.stateAccess.RLock()
	failures := c.state.consecutivePollFailures
	retryDelay := c.state.usageAPIRetryDelay
	c.stateAccess.RUnlock()
	if failures <= 0 {
		if retryDelay > 0 {
			return retryDelay
		}
		return baseInterval
	}
	backoff := failedPollRetryInterval * time.Duration(1<<(failures-1))
	if backoff > httpRetryMaxBackoff {
		return httpRetryMaxBackoff
	}
	return backoff
}

func (c *defaultCredential) isPollBackoffAtCap() bool {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	failures := c.state.consecutivePollFailures
	return failures > 0 && failedPollRetryInterval*time.Duration(1<<(failures-1)) >= httpRetryMaxBackoff
}

func (c *defaultCredential) earliestReset() time.Time {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	if c.state.unavailable {
		return time.Time{}
	}
	if c.state.hardRateLimited {
		return c.state.rateLimitResetAt
	}
	earliest := c.state.fiveHourReset
	if !c.state.weeklyReset.IsZero() && (earliest.IsZero() || c.state.weeklyReset.Before(earliest)) {
		earliest = c.state.weeklyReset
	}
	return earliest
}

func (c *defaultCredential) pollUsage() {
	if !c.pollAccess.TryLock() {
		return
	}
	defer c.pollAccess.Unlock()
	defer c.markUsagePollAttempted()

	c.retryCredentialReloadIfNeeded()
	if !c.isAvailable() {
		return
	}

	accessToken, err := c.getAccessToken()
	if err != nil {
		if !c.isPollBackoffAtCap() {
			c.logger.Error("poll usage for ", c.tag, ": get token: ", err)
		}
		if !isHardRefreshFailure(err) {
			c.incrementPollFailures()
		}
		return
	}

	ctx := c.serviceContext
	httpClient := &http.Client{
		Transport: c.forwardHTTPClient.Transport,
		Timeout:   5 * time.Second,
	}

	doUsageRequest := func(token string) (*http.Response, error) {
		return doHTTPWithRetry(ctx, httpClient, func() (*http.Request, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, claudeAPIBaseURL+"/api/oauth/usage", nil)
			if err != nil {
				return nil, err
			}
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("User-Agent", ccmUserAgentValue)
			request.Header.Set("anthropic-beta", anthropicBetaOAuthValue)
			return request, nil
		})
	}

	var response *http.Response
	attemptedAuthRecovery := false
	for {
		response, err = doUsageRequest(accessToken)
		if err != nil {
			if !c.isPollBackoffAtCap() {
				c.logger.Error("poll usage for ", c.tag, ": ", err)
			}
			c.incrementPollFailures()
			return
		}
		if response.StatusCode == http.StatusOK {
			break
		}
		if response.StatusCode == http.StatusTooManyRequests {
			retryDelay := time.Minute
			if retryAfter := response.Header.Get("Retry-After"); retryAfter != "" {
				seconds, parseErr := strconv.ParseInt(retryAfter, 10, 64)
				if parseErr == nil && seconds > 0 {
					retryDelay = time.Duration(seconds) * time.Second
				}
			}
			response.Body.Close()
			c.logger.Warn("poll usage for ", c.tag, ": usage API rate limited, retry in ", log.FormatDuration(retryDelay))
			c.stateAccess.Lock()
			c.state.usageAPIRetryDelay = retryDelay
			c.stateAccess.Unlock()
			return
		}

		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		recoverableAuthFailure := !attemptedAuthRecovery &&
			(response.StatusCode == http.StatusUnauthorized ||
				(response.StatusCode == http.StatusForbidden && bytes.Contains(body, []byte("OAuth token has been revoked"))))
		if recoverableAuthFailure {
			if !c.isPollBackoffAtCap() {
				c.logger.Error("poll usage for ", c.tag, ": status ", response.StatusCode, " ", string(body))
			}
			attemptedAuthRecovery = true
			recovered, recoverErr := c.recoverAuthFailure(accessToken)
			if recoverErr != nil {
				if !isHardRefreshFailure(recoverErr) {
					if !c.isPollBackoffAtCap() {
						c.logger.Error("poll usage for ", c.tag, ": auth recovery: ", recoverErr)
					}
					c.incrementPollFailures()
				}
				return
			}
			if !recovered {
				if !c.isPollBackoffAtCap() {
					c.logger.Error("poll usage for ", c.tag, ": auth recovery did not produce a new token")
				}
				c.incrementPollFailures()
				return
			}
			accessToken, err = c.getAccessToken()
			if err != nil {
				if !c.isPollBackoffAtCap() {
					c.logger.Error("poll usage for ", c.tag, ": get token after auth recovery: ", err)
				}
				if !isHardRefreshFailure(err) {
					c.incrementPollFailures()
				}
				return
			}
			continue
		}

		if !c.isPollBackoffAtCap() {
			c.logger.Error("poll usage for ", c.tag, ": status ", response.StatusCode, " ", string(body))
		}
		c.incrementPollFailures()
		return
	}
	defer response.Body.Close()

	var usageResponse struct {
		FiveHour struct {
			Utilization float64   `json:"utilization"`
			ResetsAt    time.Time `json:"resets_at"`
		} `json:"five_hour"`
		SevenDay struct {
			Utilization float64   `json:"utilization"`
			ResetsAt    time.Time `json:"resets_at"`
		} `json:"seven_day"`
	}
	err = json.NewDecoder(response.Body).Decode(&usageResponse)
	if err != nil {
		if !c.isPollBackoffAtCap() {
			c.logger.Error("poll usage for ", c.tag, ": decode: ", err)
		}
		c.incrementPollFailures()
		return
	}

	c.stateAccess.Lock()
	isFirstUpdate := c.state.lastUpdated.IsZero()
	oldFiveHour := c.state.fiveHourUtilization
	oldWeekly := c.state.weeklyUtilization
	c.state.consecutivePollFailures = 0
	c.state.usageAPIRetryDelay = 0
	c.state.fiveHourUtilization = usageResponse.FiveHour.Utilization
	if !usageResponse.FiveHour.ResetsAt.IsZero() {
		c.state.fiveHourReset = usageResponse.FiveHour.ResetsAt
	}
	c.state.weeklyUtilization = usageResponse.SevenDay.Utilization
	if !usageResponse.SevenDay.ResetsAt.IsZero() {
		c.state.weeklyReset = usageResponse.SevenDay.ResetsAt
	}
	if c.state.hardRateLimited && time.Now().After(c.state.rateLimitResetAt) {
		c.state.hardRateLimited = false
	}
	c.state.noteSnapshotData()
	if isFirstUpdate || int(c.state.fiveHourUtilization*100) != int(oldFiveHour*100) || int(c.state.weeklyUtilization*100) != int(oldWeekly*100) {
		resetSuffix := ""
		if !c.state.weeklyReset.IsZero() {
			resetSuffix = ", resets=" + log.FormatDuration(time.Until(c.state.weeklyReset))
		}
		c.logger.Debug("poll usage for ", c.tag, ": 5h=", c.state.fiveHourUtilization, "%, weekly=", c.state.weeklyUtilization, "%", resetSuffix)
	}
	needsProfileFetch := c.needsProfileHydrationLocked()
	shouldInterrupt := c.checkTransitionLocked()
	c.stateAccess.Unlock()
	if shouldInterrupt {
		c.interruptConnections()
	}
	c.emitStatusUpdate()

	if needsProfileFetch {
		profileSnapshot, err := c.fetchProfileSnapshot(httpClient, accessToken)
		if err != nil {
			c.logger.Error("fetch profile for ", c.tag, ": ", err)
			return
		}
		if profileSnapshot != nil {
			credentialsChanged := c.applyProfileSnapshot(profileSnapshot)
			c.persistOAuthAccount()
			if credentialsChanged {
				c.persistCredentials(c.currentCredentials())
			}
		}
	}
}

func (c *defaultCredential) close() {
	if c.watcher != nil {
		err := c.watcher.Close()
		if err != nil {
			c.logger.Error("close credential watcher for ", c.tag, ": ", err)
		}
	}
	if c.usageTracker != nil {
		c.usageTracker.cancelPendingSave()
		err := c.usageTracker.Save()
		if err != nil {
			c.logger.Error("save usage statistics for ", c.tag, ": ", err)
		}
	}
}

func (c *defaultCredential) tagName() string {
	return c.tag
}

func (c *defaultCredential) isExternal() bool {
	return false
}

func (c *defaultCredential) fiveHourUtilization() float64 {
	c.stateAccess.RLock()
	defer c.stateAccess.RUnlock()
	return c.state.fiveHourUtilization
}

func (c *defaultCredential) fiveHourCap() float64 {
	return c.cap5h
}

func (c *defaultCredential) weeklyCap() float64 {
	return c.capWeekly
}

func (c *defaultCredential) usageTrackerOrNil() *AggregatedUsage {
	return c.usageTracker
}

func (c *defaultCredential) httpClient() *http.Client {
	return c.forwardHTTPClient
}

func (c *defaultCredential) buildProxyRequest(ctx context.Context, original *http.Request, bodyBytes []byte, serviceHeaders http.Header) (*http.Request, error) {
	accessToken, err := c.getAccessToken()
	if err != nil {
		return nil, E.Cause(err, "get access token for ", c.tag)
	}

	proxyURL := claudeAPIBaseURL + original.URL.RequestURI()
	var body io.Reader
	if bodyBytes != nil {
		bodyBytes = c.injectMetadataFields(bodyBytes)
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

	serviceOverridesAcceptEncoding := len(serviceHeaders.Values("Accept-Encoding")) > 0
	if c.usageTracker != nil && !serviceOverridesAcceptEncoding {
		proxyRequest.Header.Del("Accept-Encoding")
	}

	anthropicBetaHeader := proxyRequest.Header.Get("anthropic-beta")
	if anthropicBetaHeader != "" {
		proxyRequest.Header.Set("anthropic-beta", anthropicBetaOAuthValue+","+anthropicBetaHeader)
	} else {
		proxyRequest.Header.Set("anthropic-beta", anthropicBetaOAuthValue)
	}

	for key, values := range serviceHeaders {
		proxyRequest.Header.Del(key)
		proxyRequest.Header[key] = values
	}
	proxyRequest.Header.Set("Authorization", "Bearer "+accessToken)

	return proxyRequest, nil
}

// injectMetadataFields fills in account_uuid and device_id in metadata.user_id
// when the client sends them empty (e.g. using ANTHROPIC_AUTH_TOKEN).
//
// Claude Code >= 2.1.78 (@anthropic-ai/claude-code) sets metadata as:
//
//	{user_id: JSON.stringify({device_id, account_uuid, session_id})}
//
// ref: cli.js L66() — metadata constructor
func (c *defaultCredential) injectMetadataFields(bodyBytes []byte) []byte {
	c.stateAccess.RLock()
	accountUUID := c.state.accountUUID
	c.stateAccess.RUnlock()
	deviceID := c.deviceID
	if accountUUID == "" && deviceID == "" {
		return bodyBytes
	}

	var body map[string]json.RawMessage
	err := json.Unmarshal(bodyBytes, &body)
	if err != nil {
		return bodyBytes
	}
	metadataRaw, hasMetadata := body["metadata"]
	if !hasMetadata {
		return bodyBytes
	}

	var metadata map[string]json.RawMessage
	err = json.Unmarshal(metadataRaw, &metadata)
	if err != nil {
		return bodyBytes
	}
	userIDRaw, hasUserID := metadata["user_id"]
	if !hasUserID {
		return bodyBytes
	}

	var userIDStr string
	err = json.Unmarshal(userIDRaw, &userIDStr)
	if err != nil || userIDStr == "" {
		return bodyBytes
	}

	var userIDObject map[string]json.RawMessage
	err = json.Unmarshal([]byte(userIDStr), &userIDObject)
	if err != nil {
		return bodyBytes
	}

	modified := false

	if accountUUID != "" {
		existingRaw, hasExisting := userIDObject["account_uuid"]
		needsInject := !hasExisting
		if hasExisting {
			var existing string
			needsInject = json.Unmarshal(existingRaw, &existing) != nil || existing == ""
		}
		if needsInject {
			accountUUIDJSON, marshalErr := json.Marshal(accountUUID)
			if marshalErr == nil {
				userIDObject["account_uuid"] = json.RawMessage(accountUUIDJSON)
				modified = true
			}
		}
	}

	if deviceID != "" {
		existingRaw, hasExisting := userIDObject["device_id"]
		needsInject := !hasExisting
		if hasExisting {
			var existing string
			needsInject = json.Unmarshal(existingRaw, &existing) != nil || existing == ""
		}
		if needsInject {
			deviceIDJSON, marshalErr := json.Marshal(deviceID)
			if marshalErr == nil {
				userIDObject["device_id"] = json.RawMessage(deviceIDJSON)
				modified = true
			}
		}
	}

	if !modified {
		return bodyBytes
	}

	newUserIDBytes, err := json.Marshal(userIDObject)
	if err != nil {
		return bodyBytes
	}
	newUserIDRaw, err := json.Marshal(string(newUserIDBytes))
	if err != nil {
		return bodyBytes
	}
	metadata["user_id"] = json.RawMessage(newUserIDRaw)

	newMetadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return bodyBytes
	}
	body["metadata"] = json.RawMessage(newMetadataBytes)

	newBodyBytes, err := json.Marshal(body)
	if err != nil {
		return bodyBytes
	}
	return newBodyBytes
}
