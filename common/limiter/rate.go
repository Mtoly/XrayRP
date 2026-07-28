package limiter

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// rateWaitTimeout is the maximum time to wait for rate limiter tokens.
// Using a package-level constant avoids creating a new duration per I/O op.
const rateWaitTimeout = 30 * time.Second

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	owner   *Limiter
}

type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
	owner   *Limiter
}

type limitedWriter = Writer
type limitedReader = Reader

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return l.rateWriter(writer, limiter)
}

func (l *Limiter) RateReader(reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	return l.rateReader(reader, limiter)
}

func (l *Limiter) rateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &limitedWriter{
		writer:  writer,
		limiter: limiter,
		owner:   l,
	}
}

func (l *Limiter) rateReader(reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	return &limitedReader{
		reader:  reader,
		limiter: limiter,
		owner:   l,
	}
}

func (l *Limiter) Admit(tag, userKey, ip string, reader buf.Reader, writer buf.Writer) (buf.Reader, buf.Writer, bool) {
	bucket, speedLimited, rejected := l.getUserBucket(tag, userKey, ip)
	if rejected || !speedLimited || bucket == nil {
		return reader, writer, rejected
	}
	return l.rateReader(reader, bucket), l.rateWriter(writer, bucket), false
}

func waitRate(owner *Limiter, limiter *rate.Limiter, count int) error {
	if owner != nil && owner.closed.Load() {
		return context.Canceled
	}
	if limiter.AllowN(time.Now(), count) {
		return nil
	}

	ctx := context.Background()
	end := func() {}
	if owner != nil {
		var ok bool
		ctx, ok = owner.beginOwnedOperation()
		if !ok {
			return context.Canceled
		}
		end = owner.endOwnedOperation
	}
	defer end()

	if owner != nil && owner.onRateWaitEntered != nil {
		owner.onRateWaitEntered()
	}
	waitCtx, cancel := context.WithTimeout(ctx, rateWaitTimeout)
	defer cancel()
	return WaitN(waitCtx, limiter, uint64(count))
}
func (w *limitedWriter) Close() error {
	return common.Close(w.writer)
}

func (w *limitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := waitRate(w.owner, w.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (r *limitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	if err := waitRate(r.owner, r.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	return mb, nil
}

func (r *limitedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	type timeoutReader interface {
		ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	}

	var mb buf.MultiBuffer
	var err error
	if tr, ok := r.reader.(timeoutReader); ok {
		mb, err = tr.ReadMultiBufferTimeout(timeout)
	} else {
		mb, err = r.reader.ReadMultiBuffer()
	}
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	if err := waitRate(r.owner, r.limiter, int(mb.Len())); err != nil {
		buf.ReleaseMulti(mb)
		return nil, err
	}
	return mb, nil
}
