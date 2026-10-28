package limiter

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// A lease belongs to the logical bidirectional link, not its parent transport.
// EOF in one direction is a half-close; only both directions ending release it.
// Interruption or context cancellation terminates the entire logical link.
type leasedLink struct {
	mu       sync.Mutex
	lease    *GlobalLease
	readEnd  bool
	writeEnd bool
	stop     func() bool
}

func (l *leasedLink) end(read, write bool) {
	l.mu.Lock()
	l.readEnd = l.readEnd || read
	l.writeEnd = l.writeEnd || write
	lease := l.lease
	if !l.readEnd || !l.writeEnd {
		lease = nil
	} else {
		l.lease = nil
		if l.stop != nil {
			l.stop()
		}
	}
	l.mu.Unlock()
	if lease != nil {
		_ = lease.Close()
	}
}

type leasedReader struct {
	reader buf.Reader
	link   *leasedLink
}

type leasedWriter struct {
	writer buf.Writer
	link   *leasedLink
}

func (r *leasedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		r.link.end(true, false)
	}
	return mb, err
}

func (r *leasedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	if reader, ok := r.reader.(interface {
		ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	}); ok {
		mb, err := reader.ReadMultiBufferTimeout(timeout)
		if err != nil && err != buf.ErrReadTimeout && err != buf.ErrNotTimeoutReader {
			r.link.end(true, false)
		}
		return mb, err
	}
	return nil, buf.ErrNotTimeoutReader
}

func (r *leasedReader) Close() error {
	err := common.Close(r.reader)
	r.link.end(true, false)
	return err
}

func (r *leasedReader) Interrupt() {
	common.Interrupt(r.reader)
	r.link.end(true, true)
}

func (w *leasedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	err := w.writer.WriteMultiBuffer(mb)
	if err != nil {
		w.link.end(true, true)
	}
	return err
}

func (w *leasedWriter) Close() error {
	err := common.Close(w.writer)
	w.link.end(false, true)
	return err
}

func (w *leasedWriter) Interrupt() {
	common.Interrupt(w.writer)
	w.link.end(true, true)
}

func (l *Limiter) AdmitContext(ctx context.Context, tag, userKey, ip string, reader buf.Reader, writer buf.Writer) (buf.Reader, buf.Writer, bool) {
	bucket, speedLimited, rejected, lease := l.getUserBucketWithLease(ctx, tag, userKey, ip)
	if rejected {
		return reader, writer, true
	}
	if speedLimited && bucket != nil {
		reader, writer = l.rateReader(reader, bucket), l.rateWriter(writer, bucket)
	}
	if lease != nil {
		link := &leasedLink{lease: lease}
		link.mu.Lock()
		link.stop = context.AfterFunc(ctx, func() { link.end(true, true) })
		link.mu.Unlock()
		reader, writer = &leasedReader{reader: reader, link: link}, &leasedWriter{writer: writer, link: link}
	}
	return reader, writer, false
}
