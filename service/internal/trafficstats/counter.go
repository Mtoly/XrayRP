package trafficstats

import "math"

// Add accumulates non-negative traffic without allowing the signed report
// counters to wrap into negative values.
func Add(current int64, delta uint64) int64 {
	if current < 0 || current == math.MaxInt64 {
		return math.MaxInt64
	}
	if delta > uint64(math.MaxInt64-current) {
		return math.MaxInt64
	}
	return current + int64(delta)
}
