package ccm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

type statusPayload struct {
	FiveHourUtilization float64 `json:"five_hour_utilization"`
	FiveHourReset       int64   `json:"five_hour_reset"`
	WeeklyUtilization   float64 `json:"weekly_utilization"`
	WeeklyReset         int64   `json:"weekly_reset"`
	PlanWeight          float64 `json:"plan_weight"`
	WeeklyBurnFactor    float64 `json:"weekly_burn_factor"`
}

type aggregatedStatus struct {
	fiveHourUtilization    float64
	weeklyUtilization      float64
	totalWeight            float64
	fiveHourReset          time.Time
	weeklyReset            time.Time
	weeklyBurnFactor       float64
	earliestCredentialReset time.Time
	availability           availabilityStatus
}

func resetToEpoch(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s aggregatedStatus) equal(other aggregatedStatus) bool {
	return s.toPayload() == other.toPayload()
}

func (s aggregatedStatus) nextResetTime() time.Time {
	return s.earliestCredentialReset
}

func (s aggregatedStatus) toPayload() statusPayload {
	weeklyBurnFactor := s.weeklyBurnFactor
	if weeklyBurnFactor <= 0 {
		weeklyBurnFactor = ccmWeeklyBurnFactorMin
	}
	return statusPayload{
		FiveHourUtilization: s.fiveHourUtilization,
		FiveHourReset:       resetToEpoch(s.fiveHourReset),
		WeeklyUtilization:   s.weeklyUtilization,
		WeeklyReset:         resetToEpoch(s.weeklyReset),
		PlanWeight:          s.totalWeight,
		WeeklyBurnFactor:    weeklyBurnFactor,
	}
}

type aggregateInput struct {
	availability availabilityStatus
}

func aggregateAvailability(inputs []aggregateInput) availabilityStatus {
	if len(inputs) == 0 {
		return availabilityStatus{
			State:  availabilityStateUnavailable,
			Reason: availabilityReasonNoCredentials,
		}
	}
	var earliestRateLimit time.Time
	var hasRateLimited bool
	var blocked availabilityStatus
	var hasBlocked bool
	var hasUnavailable bool
	for _, input := range inputs {
		availability := input.availability.normalized()
		switch availability.State {
		case availabilityStateUsable:
			return availabilityStatus{State: availabilityStateUsable}
		case availabilityStateRateLimited:
			hasRateLimited = true
			if !availability.ResetAt.IsZero() && (earliestRateLimit.IsZero() || availability.ResetAt.Before(earliestRateLimit)) {
				earliestRateLimit = availability.ResetAt
			}
			if blocked.State == "" {
				blocked = availabilityStatus{
					State:   availabilityStateRateLimited,
					Reason:  availabilityReasonHardRateLimit,
					ResetAt: earliestRateLimit,
				}
			}
		case availabilityStateTemporarilyBlocked:
			if !hasBlocked {
				blocked = availability
				hasBlocked = true
			}
			if !availability.ResetAt.IsZero() && (blocked.ResetAt.IsZero() || availability.ResetAt.Before(blocked.ResetAt)) {
				blocked.ResetAt = availability.ResetAt
			}
		case availabilityStateUnavailable:
			hasUnavailable = true
		}
	}
	if hasRateLimited {
		blocked.ResetAt = earliestRateLimit
		return blocked
	}
	if hasBlocked {
		return blocked
	}
	if hasUnavailable {
		return availabilityStatus{
			State:  availabilityStateUnavailable,
			Reason: availabilityReasonUnknown,
		}
	}
	return availabilityStatus{
		State:  availabilityStateUnknown,
		Reason: availabilityReasonUnknown,
	}
}

func chooseRepresentativeClaim(fiveHourUtilization float64, fiveHourReset time.Time, weeklyUtilization float64, weeklyReset time.Time, now time.Time) string {
	fiveHourWarning := claudeFiveHourWarning(fiveHourUtilization, fiveHourReset, now)
	weeklyWarning := claudeWeeklyWarning(weeklyUtilization, weeklyReset, now)
	type claimCandidate struct {
		name        string
		priority    int
		utilization float64
	}
	candidateFor := func(name string, utilization float64, warning bool) claimCandidate {
		priority := 0
		switch {
		case utilization >= 100:
			priority = 2
		case warning:
			priority = 1
		}
		return claimCandidate{name: name, priority: priority, utilization: utilization}
	}
	five := candidateFor("5h", fiveHourUtilization, fiveHourWarning)
	weekly := candidateFor("7d", weeklyUtilization, weeklyWarning)
	switch {
	case five.priority > weekly.priority:
		return five.name
	case weekly.priority > five.priority:
		return weekly.name
	case five.utilization > weekly.utilization:
		return five.name
	case weekly.utilization > five.utilization:
		return weekly.name
	case !fiveHourReset.IsZero():
		return five.name
	case !weeklyReset.IsZero():
		return weekly.name
	default:
		return "5h"
	}
}

func (s *Service) handleStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, r, http.StatusMethodNotAllowed, "invalid_request_error", "method not allowed")
		return
	}

	var provider credentialProvider
	var userConfig *option.CCMUser
	if len(s.options.Users) > 0 {
		if r.Header.Get("X-Api-Key") != "" || r.Header.Get("Api-Key") != "" {
			writeJSONError(w, r, http.StatusBadRequest, "invalid_request_error",
				"API key authentication is not supported; use Authorization: Bearer with a CCM user token")
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "missing api key")
			return
		}
		clientToken := strings.TrimPrefix(authHeader, "Bearer ")
		if clientToken == authHeader {
			writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "invalid api key format")
			return
		}
		username, ok := s.userManager.Authenticate(clientToken)
		if !ok {
			writeJSONError(w, r, http.StatusUnauthorized, "authentication_error", "invalid api key")
			return
		}

		userConfig = s.userConfigMap[username]
		var err error
		provider, err = credentialForUser(s.userConfigMap, s.providers, username)
		if err != nil {
			writeJSONError(w, r, http.StatusInternalServerError, "api_error", err.Error())
			return
		}
	} else {
		provider = s.providers[s.options.Credentials[0].Tag]
	}
	if provider == nil {
		writeJSONError(w, r, http.StatusInternalServerError, "api_error", "no credential available")
		return
	}

	if r.URL.Query().Get("watch") == "true" {
		s.handleStatusStream(w, r, provider, userConfig)
		return
	}

	provider.pollIfStale()
	status := s.computeAggregatedUtilization(provider, userConfig)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status.toPayload())
}

func (s *Service) handleStatusStream(w http.ResponseWriter, r *http.Request, provider credentialProvider, userConfig *option.CCMUser) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, r, http.StatusInternalServerError, "api_error", "streaming not supported")
		return
	}

	subscription, done, err := s.statusObserver.Subscribe()
	if err != nil {
		writeJSONError(w, r, http.StatusInternalServerError, "api_error", "service closing")
		return
	}
	defer s.statusObserver.UnSubscribe(subscription)

	provider.pollIfStale()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	last := s.computeAggregatedUtilization(provider, userConfig)
	buf := &bytes.Buffer{}
	json.NewEncoder(buf).Encode(last.toPayload())
	_, writeErr := w.Write(buf.Bytes())
	if writeErr != nil {
		return
	}
	flusher.Flush()

	var resetTimer *time.Timer
	var resetCh <-chan time.Time
	if nextReset := last.nextResetTime(); !nextReset.IsZero() {
		resetTimer = time.NewTimer(time.Until(nextReset))
		resetCh = resetTimer.C
	}
	defer func() {
		if resetTimer != nil {
			resetTimer.Stop()
		}
	}()

	pollTimer := time.NewTimer(nextWatchPollDelay(provider))
	defer pollTimer.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-resetCh:
			resetCh = nil
			current := s.computeAggregatedUtilization(provider, userConfig)
			if !current.equal(last) {
				buf.Reset()
				json.NewEncoder(buf).Encode(current.toPayload())
				_, writeErr = w.Write(buf.Bytes())
				if writeErr != nil {
					return
				}
				flusher.Flush()
			}
			last = current
			if nextReset := current.nextResetTime(); !nextReset.IsZero() {
				resetTimer.Reset(time.Until(nextReset))
				resetCh = resetTimer.C
			}
		case <-pollTimer.C:
			provider.pollIfStale()
			pollTimer.Reset(nextWatchPollDelay(provider))
		case <-subscription:
			for {
				select {
				case <-subscription:
				default:
					goto drained
				}
			}
		drained:
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollTimer.Reset(nextWatchPollDelay(provider))
			current := s.computeAggregatedUtilization(provider, userConfig)
			payloadChanged := !current.equal(last)
			resetChanged := !current.earliestCredentialReset.Equal(last.earliestCredentialReset)
			if !payloadChanged && !resetChanged {
				continue
			}
			last = current
			if payloadChanged {
				buf.Reset()
				json.NewEncoder(buf).Encode(current.toPayload())
				_, writeErr = w.Write(buf.Bytes())
				if writeErr != nil {
					return
				}
				flusher.Flush()
			}
			if resetTimer != nil {
				resetTimer.Stop()
			}
			resetCh = nil
			if nextReset := last.nextResetTime(); !nextReset.IsZero() {
				resetTimer = time.NewTimer(time.Until(nextReset))
				resetCh = resetTimer.C
			}
		}
	}
}

func nextWatchPollDelay(provider credentialProvider) time.Duration {
	next := defaultPollInterval
	for _, cred := range provider.allCredentials() {
		remaining := cred.pollBackoff(defaultPollInterval) - time.Since(cred.lastUpdatedTime())
		if remaining < next {
			next = remaining
		}
	}
	if next < time.Second {
		next = time.Second
	}
	return next
}

func (s *Service) computeAggregatedUtilization(provider credentialProvider, userConfig *option.CCMUser) aggregatedStatus {
	visibleInputs := make([]aggregateInput, 0, len(provider.allCredentials()))
	var totalWeightedRemaining5h, totalWeightedRemainingWeekly, totalWeight float64
	var totalBurnBase, totalWeightedBurnFactor float64
	now := time.Now()
	var totalWeightedHoursUntil5hReset, total5hResetWeight float64
	var totalWeightedHoursUntilWeeklyReset, totalWeeklyResetWeight float64
	var earliestCredentialReset time.Time
	var hasSnapshotData bool
	for _, credential := range provider.allCredentials() {
		if userConfig != nil && userConfig.ExternalCredential != "" && credential.tagName() == userConfig.ExternalCredential {
			continue
		}
		if userConfig != nil && !userConfig.AllowExternalUsage && credential.isExternal() {
			continue
		}
		visibleInputs = append(visibleInputs, aggregateInput{
			availability: credential.availabilityStatus(),
		})
		if !credential.hasSnapshotData() {
			continue
		}
		hasSnapshotData = true
		weight := credential.planWeight()
		fiveHourReset := credential.fiveHourResetTime()
		remaining5h := credential.fiveHourCap() - credential.fiveHourUtilization()
		if remaining5h < 0 {
			remaining5h = 0
		}
		if !fiveHourReset.IsZero() && !now.Before(fiveHourReset) {
			remaining5h = credential.fiveHourCap()
		}
		weeklyReset := credential.weeklyResetTime()
		remainingWeekly := credential.weeklyCap() - credential.weeklyUtilization()
		if remainingWeekly < 0 {
			remainingWeekly = 0
		}
		if !weeklyReset.IsZero() && !now.Before(weeklyReset) {
			remainingWeekly = credential.weeklyCap()
		}
		totalWeightedRemaining5h += remaining5h * weight
		totalWeightedRemainingWeekly += remainingWeekly * weight
		totalWeight += weight
		burnBase := remainingWeekly * weight
		totalBurnBase += burnBase
		weeklyBurnFactor := credential.weeklyBurnFactor()
		if weeklyBurnFactor < ccmWeeklyBurnFactorMin {
			weeklyBurnFactor = ccmWeeklyBurnFactorMin
		} else if weeklyBurnFactor > ccmWeeklyBurnFactorMax {
			weeklyBurnFactor = ccmWeeklyBurnFactorMax
		}
		totalWeightedBurnFactor += burnBase * weeklyBurnFactor

		if !fiveHourReset.IsZero() {
			hours := fiveHourReset.Sub(now).Hours()
			if hours > 0 {
				totalWeightedHoursUntil5hReset += hours * weight
				total5hResetWeight += weight
				if earliestCredentialReset.IsZero() || fiveHourReset.Before(earliestCredentialReset) {
					earliestCredentialReset = fiveHourReset
				}
			}
		}
		if !weeklyReset.IsZero() {
			hours := weeklyReset.Sub(now).Hours()
			if hours > 0 {
				totalWeightedHoursUntilWeeklyReset += hours * weight
				totalWeeklyResetWeight += weight
				if earliestCredentialReset.IsZero() || weeklyReset.Before(earliestCredentialReset) {
					earliestCredentialReset = weeklyReset
				}
			}
		}
	}
	availability := aggregateAvailability(visibleInputs)
	if totalWeight == 0 {
		result := aggregatedStatus{availability: availability}
		if !hasSnapshotData {
			result.fiveHourUtilization = 100
			result.weeklyUtilization = 100
		}
		return result
	}
	result := aggregatedStatus{
		fiveHourUtilization:     100 - totalWeightedRemaining5h/totalWeight,
		weeklyUtilization:       100 - totalWeightedRemainingWeekly/totalWeight,
		totalWeight:             totalWeight,
		weeklyBurnFactor:        ccmWeeklyBurnFactorMin,
		earliestCredentialReset: earliestCredentialReset,
		availability:            availability,
	}
	if totalBurnBase > 0 {
		result.weeklyBurnFactor = totalWeightedBurnFactor / totalBurnBase
	}
	if total5hResetWeight > 0 {
		avgHours := totalWeightedHoursUntil5hReset / total5hResetWeight
		result.fiveHourReset = now.Add(time.Duration(avgHours * float64(time.Hour)))
	}
	if totalWeeklyResetWeight > 0 {
		avgHours := totalWeightedHoursUntilWeeklyReset / totalWeeklyResetWeight
		result.weeklyReset = now.Add(time.Duration(avgHours * float64(time.Hour)))
	}
	return result
}

func (s *Service) rewriteResponseHeaders(headers http.Header, provider credentialProvider, userConfig *option.CCMUser) {
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "anthropic-ratelimit-unified-") {
			headers.Del(key)
		}
	}
	status := s.computeAggregatedUtilization(provider, userConfig)
	now := time.Now()
	headers.Set("anthropic-ratelimit-unified-5h-utilization", strconv.FormatFloat(status.fiveHourUtilization/100, 'f', 6, 64))
	headers.Set("anthropic-ratelimit-unified-7d-utilization", strconv.FormatFloat(status.weeklyUtilization/100, 'f', 6, 64))
	if !status.fiveHourReset.IsZero() {
		headers.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(status.fiveHourReset.Unix(), 10))
	}
	if !status.weeklyReset.IsZero() {
		headers.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(status.weeklyReset.Unix(), 10))
	}
	if status.totalWeight > 0 {
		headers.Set("X-CCM-Plan-Weight", strconv.FormatFloat(status.totalWeight, 'f', -1, 64))
	}
	fiveHourWarning := claudeFiveHourWarning(status.fiveHourUtilization, status.fiveHourReset, now)
	weeklyWarning := claudeWeeklyWarning(status.weeklyUtilization, status.weeklyReset, now)
	switch {
	case status.fiveHourUtilization >= 100 || status.weeklyUtilization >= 100 ||
		status.availability.State == availabilityStateRateLimited:
		headers.Set("anthropic-ratelimit-unified-status", "rejected")
	case fiveHourWarning || weeklyWarning:
		headers.Set("anthropic-ratelimit-unified-status", "allowed_warning")
	default:
		headers.Set("anthropic-ratelimit-unified-status", "allowed")
	}
	claim := chooseRepresentativeClaim(status.fiveHourUtilization, status.fiveHourReset, status.weeklyUtilization, status.weeklyReset, now)
	headers.Set("anthropic-ratelimit-unified-representative-claim", claim)
	switch claim {
	case "7d":
		if !status.weeklyReset.IsZero() {
			headers.Set("anthropic-ratelimit-unified-reset", strconv.FormatInt(status.weeklyReset.Unix(), 10))
		}
	default:
		if !status.fiveHourReset.IsZero() {
			headers.Set("anthropic-ratelimit-unified-reset", strconv.FormatInt(status.fiveHourReset.Unix(), 10))
		}
	}
	if fiveHourWarning || status.fiveHourUtilization >= 100 {
		headers.Set("anthropic-ratelimit-unified-5h-surpassed-threshold", "true")
	}
	if weeklyWarning || status.weeklyUtilization >= 100 {
		headers.Set("anthropic-ratelimit-unified-7d-surpassed-threshold", "true")
	}
}
