package limiter_test

import (
	"reflect"
	"testing"

	commonlimiter "github.com/Mtoly/XrayRP/common/limiter"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

var (
	_ func(*commonlimiter.Limiter, string, string, string, buf.Reader, buf.Writer) (buf.Reader, buf.Writer, bool) = (*commonlimiter.Limiter).Admit
	_ func(*commonlimiter.Limiter, string, string, string) (*rate.Limiter, bool, bool)                            = (*commonlimiter.Limiter).GetUserBucket
	_ func(*commonlimiter.Limiter, buf.Writer, *rate.Limiter) buf.Writer                                          = (*commonlimiter.Limiter).RateWriter
	_ func(*commonlimiter.Limiter, buf.Reader, *rate.Limiter) buf.Reader                                          = (*commonlimiter.Limiter).RateReader
	_ buf.Writer                                                                                                  = (*commonlimiter.Writer)(nil)
	_ buf.Reader                                                                                                  = (*commonlimiter.Reader)(nil)
)

func TestLegacyRateWrapperTypeNamesRemainStable(t *testing.T) {
	if got := reflect.TypeOf((*commonlimiter.Writer)(nil)).Elem().Name(); got != "Writer" {
		t.Fatalf("Writer reflection name = %q, want Writer", got)
	}
	if got := reflect.TypeOf((*commonlimiter.Reader)(nil)).Elem().Name(); got != "Reader" {
		t.Fatalf("Reader reflection name = %q, want Reader", got)
	}
}
