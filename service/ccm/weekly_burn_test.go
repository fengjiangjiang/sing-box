package ccm

import (
	"testing"
	"time"
)

func TestCCMPlanWeight5h(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		rateLimitTier string
		expected      float64
	}{
		{name: "20x", rateLimitTier: "default_claude_max_20x", expected: 20},
		{name: "5x", rateLimitTier: "default_claude_max_5x", expected: 5},
		{name: "default", rateLimitTier: "unknown", expected: 1},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if actual := ccmPlanWeight5h(test.rateLimitTier); actual != test.expected {
				t.Fatalf("expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func TestComputeWeeklyBurnDeadlineUsesLatestPossibleWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := computeWeeklyBurnDeadline(
		now,
		now.Add(5*time.Hour),
		now.Add(20*time.Hour),
		100,
		96,
		100,
		100,
		5,
	)

	expected := now.Add(20 * time.Hour)
	if !deadline.Equal(expected) {
		t.Fatalf("expected deadline %v, got %v", expected, deadline)
	}
}

func TestComputeWeeklyBurnDeadlineNeedsMultipleWindows(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := computeWeeklyBurnDeadline(
		now,
		now.Add(5*time.Hour),
		now.Add(20*time.Hour),
		100,
		90,
		100,
		100,
		5,
	)

	expected := now.Add(15 * time.Hour)
	if !deadline.Equal(expected) {
		t.Fatalf("expected deadline %v, got %v", expected, deadline)
	}
}

func TestComputeWeeklyBurnDeadlineReturnsNowWhenAlreadyImpossible(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := computeWeeklyBurnDeadline(
		now,
		now.Add(5*time.Hour),
		now.Add(20*time.Hour),
		100,
		75,
		100,
		100,
		5,
	)

	if !deadline.Equal(now) {
		t.Fatalf("expected deadline %v, got %v", now, deadline)
	}
}

func TestComputeWeeklyBurnFactorStaysNearOneBeforeDeadline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	factor := computeWeeklyBurnFactor(now, now.Add(90*time.Hour), now.Add(100*time.Hour))
	if factor < 1 || factor > 1.05 {
		t.Fatalf("expected factor close to 1, got %v", factor)
	}
}

func TestComputeWeeklyBurnFactorRisesNearDeadline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	factor := computeWeeklyBurnFactor(now, now.Add(time.Hour), now.Add(100*time.Hour))
	if factor <= 1.9 || factor > ccmWeeklyBurnFactorMax {
		t.Fatalf("expected factor near 2, got %v", factor)
	}
}

func TestComputeWeeklyBurnFactorCapsAfterDeadline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	factor := computeWeeklyBurnFactor(now, now.Add(-time.Minute), now.Add(100*time.Hour))
	if factor != ccmWeeklyBurnFactorMax {
		t.Fatalf("expected factor %v, got %v", ccmWeeklyBurnFactorMax, factor)
	}
}
