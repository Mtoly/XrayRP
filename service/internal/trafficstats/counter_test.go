package trafficstats

import (
	"math"
	"testing"
)

func TestAdd(t *testing.T) {
	tests := []struct {
		name    string
		current int64
		delta   uint64
		want    int64
	}{
		{name: "normal", current: 10, delta: 20, want: 30},
		{name: "exact maximum", current: math.MaxInt64 - 1, delta: 1, want: math.MaxInt64},
		{name: "overflow", current: math.MaxInt64 - 1, delta: 2, want: math.MaxInt64},
		{name: "uint64 maximum", current: 0, delta: math.MaxUint64, want: math.MaxInt64},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Add(test.current, test.delta); got != test.want {
				t.Fatalf("Add(%d, %d) = %d, want %d", test.current, test.delta, got, test.want)
			}
		})
	}
}
