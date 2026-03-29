package ccm

import "time"

const (
	ccmFiveHourWindowDuration = 5 * time.Hour
	ccmWeeklyBurnFactorMin    = 1.0
	ccmWeeklyBurnFactorMax    = 2.0
)

type burnWindow struct {
	end      time.Time
	capacity float64
}

func ccmPlanWeight5h(rateLimitTier string) float64 {
	switch rateLimitTier {
	case "default_claude_max_20x":
		return 20
	case "default_claude_max_5x":
		return 5
	default:
		return 1
	}
}

func ccmWeeklyBurnCapacity(limitPercent float64, planWeight5h float64) float64 {
	if limitPercent <= 0 || planWeight5h <= 0 {
		return 0
	}
	return limitPercent * planWeight5h / 75
}

func computeWeeklyBurnDeadline(
	now time.Time,
	fiveHourReset time.Time,
	weeklyReset time.Time,
	fiveHourUtilization float64,
	weeklyUtilization float64,
	fiveHourCap float64,
	weeklyCap float64,
	planWeight5h float64,
) time.Time {
	if weeklyCap <= 0 || planWeight5h <= 0 || weeklyReset.IsZero() {
		return time.Time{}
	}
	remainingWeekly := weeklyCap - weeklyUtilization
	if remainingWeekly <= 0 {
		return weeklyReset
	}
	if !weeklyReset.After(now) {
		return now
	}
	if fiveHourCap <= 0 || fiveHourReset.IsZero() || !fiveHourReset.After(now) {
		return time.Time{}
	}

	currentWindowEnd := fiveHourReset
	if weeklyReset.Before(currentWindowEnd) {
		currentWindowEnd = weeklyReset
	}

	windows := []burnWindow{{
		end:      currentWindowEnd,
		capacity: ccmWeeklyBurnCapacity(fiveHourCap-fiveHourUtilization, planWeight5h),
	}}

	if currentWindowEnd.Equal(fiveHourReset) {
		fullWindowBurn := ccmWeeklyBurnCapacity(fiveHourCap, planWeight5h)
		if fullWindowBurn > 0 {
			for windowEnd := fiveHourReset.Add(ccmFiveHourWindowDuration); !windowEnd.After(weeklyReset); windowEnd = windowEnd.Add(ccmFiveHourWindowDuration) {
				windows = append(windows, burnWindow{
					end:      windowEnd,
					capacity: fullWindowBurn,
				})
			}
		}
	}

	remaining := remainingWeekly
	for i := len(windows) - 1; i >= 0; i-- {
		remaining -= windows[i].capacity
		if remaining <= 0 {
			return windows[i].end
		}
	}

	return now
}

func computeWeeklyBurnFactor(now time.Time, burnDeadline time.Time, weeklyReset time.Time) float64 {
	if weeklyReset.IsZero() || burnDeadline.IsZero() {
		return ccmWeeklyBurnFactorMin
	}
	if !weeklyReset.After(now) || !burnDeadline.After(now) {
		return ccmWeeklyBurnFactorMax
	}

	timeLeft := weeklyReset.Sub(now)
	if timeLeft <= 0 {
		return ccmWeeklyBurnFactorMax
	}
	requiredSpan := weeklyReset.Sub(burnDeadline)
	if requiredSpan <= 0 {
		return ccmWeeklyBurnFactorMin
	}

	pressure := requiredSpan.Seconds() / timeLeft.Seconds()
	if pressure < 0 {
		pressure = 0
	} else if pressure > 1 {
		pressure = 1
	}
	return ccmWeeklyBurnFactorMin + pressure*pressure
}

func computeCredentialWeeklyBurnFactor(
	now time.Time,
	fiveHourReset time.Time,
	weeklyReset time.Time,
	fiveHourUtilization float64,
	weeklyUtilization float64,
	fiveHourCap float64,
	weeklyCap float64,
	planWeight5h float64,
) float64 {
	burnDeadline := computeWeeklyBurnDeadline(
		now,
		fiveHourReset,
		weeklyReset,
		fiveHourUtilization,
		weeklyUtilization,
		fiveHourCap,
		weeklyCap,
		planWeight5h,
	)
	return computeWeeklyBurnFactor(now, burnDeadline, weeklyReset)
}
