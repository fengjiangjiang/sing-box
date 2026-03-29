package ccm

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

func TestBalancerPickLeastUsedDoesNotBoostEarlierResetByDefault(t *testing.T) {
	t.Parallel()

	now := time.Now()
	provider := newBalancerProvider([]Credential{
		&testCredential{
			tag:          "later",
			available:    true,
			usable:       true,
			hasData:      true,
			weekly:       50,
			weeklyCapV:   100,
			weight:       1,
			burnFactor:   1,
			weeklyReset:  now.Add(6 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
		&testCredential{
			tag:          "earlier",
			available:    true,
			usable:       true,
			hasData:      true,
			weekly:       50,
			weeklyCapV:   100,
			weight:       1,
			burnFactor:   1,
			weeklyReset:  now.Add(24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}, "", 0, log.NewNOPFactory().Logger())

	best := provider.pickLeastUsed(nil)
	if best == nil || best.tagName() != "later" {
		t.Fatalf("expected later reset credential, got %#v", best)
	}
}

func TestBalancerPickLeastUsedUsesWeeklyBurnFactor(t *testing.T) {
	t.Parallel()

	now := time.Now()
	provider := newBalancerProvider([]Credential{
		&testCredential{
			tag:          "calm",
			available:    true,
			usable:       true,
			hasData:      true,
			weekly:       50,
			weeklyCapV:   100,
			weight:       1,
			burnFactor:   1,
			weeklyReset:  now.Add(6 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
		&testCredential{
			tag:          "urgent",
			available:    true,
			usable:       true,
			hasData:      true,
			weekly:       50,
			weeklyCapV:   100,
			weight:       1,
			burnFactor:   1.5,
			weeklyReset:  now.Add(6 * 24 * time.Hour),
			availability: availabilityStatus{State: availabilityStateUsable},
		},
	}, "", 0, log.NewNOPFactory().Logger())

	best := provider.pickLeastUsed(nil)
	if best == nil || best.tagName() != "urgent" {
		t.Fatalf("expected urgent credential, got %#v", best)
	}
}

func TestExternalCredentialPollUsageDefaultsMissingWeeklyBurnFactor(t *testing.T) {
	t.Parallel()

	requestContext, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()
	reverseContext, reverseCancel := context.WithCancel(context.Background())
	defer reverseCancel()

	credential := &externalCredential{
		tag:     "remote",
		baseURL: "http://remote",
		token:   "token",
		forwardHTTPClient: &http.Client{
			Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return newJSONResponse(http.StatusOK, `{
					"five_hour_utilization": 10,
					"five_hour_reset": 1893456000,
					"weekly_utilization": 20,
					"weekly_reset": 1893801600,
					"plan_weight": 5
				}`), nil
			}),
		},
		logger:         log.NewNOPFactory().Logger(),
		requestContext: requestContext,
		cancelRequests: cancelRequests,
		reverseContext: reverseContext,
		reverseCancel:  reverseCancel,
	}

	credential.pollUsage()

	if factor := credential.weeklyBurnFactor(); factor != ccmWeeklyBurnFactorMin {
		t.Fatalf("expected default weekly burn factor %v, got %v", ccmWeeklyBurnFactorMin, factor)
	}
}
