package limiter

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

type nonTimeoutLeaseReader struct{ read bool }

func (r *nonTimeoutLeaseReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.read = true
	return nil, io.EOF
}

func TestLeasedReaderPreservesUnsupportedTimeout(t *testing.T) {
	underlying := &nonTimeoutLeaseReader{}
	link := &leasedLink{}
	reader := &leasedReader{reader: underlying, link: link}
	_, err := reader.ReadMultiBufferTimeout(time.Millisecond)
	if err != buf.ErrNotTimeoutReader || underlying.read || link.readEnd {
		t.Fatalf("unsupported timed read consumed stream or ended lease: error=%v, read=%v, ended=%v", err, underlying.read, link.readEnd)
	}
}

func TestLeasedLinkWaitsForBothDirections(t *testing.T) {
	link := &leasedLink{}
	link.end(true, false)
	if !link.readEnd || link.writeEnd {
		t.Fatal("reader EOF ended writer direction")
	}
	link.end(false, true)
	if !link.readEnd || !link.writeEnd {
		t.Fatal("writer close did not complete link")
	}
}

func TestLeasedReaderInterruptReachesRateWrappedPipe(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(1024))
	defer writer.Close()
	owner := New()
	defer owner.Close()
	wrapped := &leasedReader{
		reader: owner.RateReader(reader, nil),
		link:   &leasedLink{},
	}
	wrapped.Interrupt()
	_, err := wrapped.ReadMultiBuffer()
	if err == nil {
		t.Fatal("interrupted reader remained open")
	}
}

func TestLeasedWriterCloseAndReaderEOFCompleteLink(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(1024))
	link := &leasedLink{}
	leasedIn := &leasedReader{reader: reader, link: link}
	leasedOut := &leasedWriter{writer: writer, link: link}
	if err := leasedOut.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := leasedIn.ReadMultiBuffer()
	if err != io.EOF {
		t.Fatalf("closed pipe error = %v, want EOF", err)
	}
	if !link.readEnd || !link.writeEnd {
		t.Fatal("EOF plus close did not complete link")
	}
}

func TestAdmitContextWithoutRedisKeepsUnrestrictedLink(t *testing.T) {
	reader, writer := pipe.New(pipe.WithSizeLimit(1024))
	defer reader.Interrupt()
	defer writer.Close()
	var owner *Limiter
	gotReader, gotWriter, rejected := owner.AdmitContext(context.Background(), "missing", "missing", "192.0.2.1", reader, writer)
	if !rejected || gotReader != buf.Reader(reader) || gotWriter != buf.Writer(writer) {
		t.Fatal("missing limiter changed rejected link ownership")
	}
}
