package limiter

import (
	"sync"
	"sync/atomic"
)

// A controller can replace an inbound tag while its previously admitted links
// still exist. Those tags share one policy/renewal owner until the last tag is
// removed. The owner ID is process-local and never participates in Redis keys.
type sharedInboundAdmission struct {
	config    *GlobalDeviceLimitConfig
	admission *GlobalAdmission
	refs      atomic.Int32
}

type inboundAdmissionReference struct {
	shared *sharedInboundAdmission
	once   sync.Once
	err    error
}

func (r *inboundAdmissionReference) Close() error {
	r.once.Do(func() {
		if r.shared.refs.Add(-1) == 0 {
			r.err = r.shared.admission.Close()
		}
	})
	return r.err
}
