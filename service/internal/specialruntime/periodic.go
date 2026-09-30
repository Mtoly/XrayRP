package specialruntime

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Mtoly/XrayRP/service"
)

// managedPeriodic runs execute immediately on Start, then waits interval after
// every callback, retries later errors, and joins in-flight work when closed.
type managedPeriodic struct {
	interval       time.Duration
	execute        func() error
	executeContext func(context.Context) error

	mu         sync.Mutex
	stop       chan struct{}
	done       chan struct{}
	runContext context.Context
	cancel     context.CancelFunc
	started    bool
	running    bool
	terminal   bool
	active     int
	runErr     error
	newTimer   func(time.Duration) managedPeriodicTimer
}

func NewPeriodic(interval time.Duration, execute func() error) *managedPeriodic {
	return &managedPeriodic{
		interval: interval,
		execute:  execute,
	}
}

func NewPeriodicContext(interval time.Duration, execute func(context.Context) error) *managedPeriodic {
	return &managedPeriodic{
		interval:       interval,
		executeContext: execute,
	}
}

type managedPeriodicTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type standardManagedPeriodicTimer struct {
	*time.Timer
}

func (t standardManagedPeriodicTimer) C() <-chan time.Time {
	return t.Timer.C
}

func newManagedPeriodicTimer(interval time.Duration) managedPeriodicTimer {
	return standardManagedPeriodicTimer{Timer: time.NewTimer(interval)}
}

func (p *managedPeriodic) Start() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultStartTimeout)
	defer cancel()
	return p.StartContext(ctx)
}

func (p *managedPeriodic) StartContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	p.mu.Lock()
	if p.terminal {
		p.mu.Unlock()
		return errors.New("periodic task cannot restart after termination")
	}
	if p.started {
		p.mu.Unlock()
		return nil
	}
	if p.execute == nil && p.executeContext == nil {
		p.mu.Unlock()
		return errors.New("periodic task execute callback is nil")
	}
	runContext, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p.started = true
	p.running = true
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.runContext = runContext
	p.cancel = cancel
	p.runErr = nil
	stop := p.stop
	done := p.done
	interval := p.interval
	newTimer := p.newTimer
	if newTimer == nil {
		newTimer = newManagedPeriodicTimer
	}
	p.mu.Unlock()

	// The initial iteration is owned by both the StartContext caller and the
	// periodic lifecycle: either one canceling must cancel it. The caller is the
	// parent so its cancellation and deadline classification (context.Canceled
	// or context.DeadlineExceeded) is preserved; the lifecycle is bridged in as
	// an additional cancellation source. Later iterations run against the
	// lifecycle runContext alone, so a caller that returns after a successful
	// startup cannot stop the periodic loop.
	initialContext, cancelInitial := context.WithCancel(ctx)
	stopLifecycleWatch := context.AfterFunc(runContext, cancelInitial)
	initialErr := p.executeOnce(initialContext)
	stopLifecycleWatch()
	cancelInitial()

	if err := initialErr; err != nil {
		p.mu.Lock()
		stopped := !p.running
		p.mu.Unlock()
		if !stopped || !errors.Is(err, context.Canceled) {
			cancel()
			p.mu.Lock()
			p.running = false
			p.started = false
			p.terminal = true
			p.cancel = nil
			p.mu.Unlock()
			close(done)
			return err
		}
		// A lifecycle stop canceled the initial iteration. That is a clean
		// shutdown rather than a start failure, matching how later iterations
		// treat cancellation caused by Stop.
	}

	p.mu.Lock()
	stopped := !p.running
	p.mu.Unlock()
	if stopped {
		cancel()
		p.mu.Lock()
		p.started = false
		p.terminal = true
		p.cancel = nil
		p.mu.Unlock()
		close(done)
		return nil
	}

	go p.run(runContext, stop, done, interval, newTimer)
	return nil
}

func (p *managedPeriodic) executeOnce(ctx context.Context) error {
	operationCtx, cancel := service.WithDefaultTimeout(ctx, service.DefaultSyncTimeout)
	defer cancel()
	if err := operationCtx.Err(); err != nil {
		return err
	}
	var err error
	if p.executeContext != nil {
		err = p.executeContext(operationCtx)
	} else {
		err = p.execute()
	}
	if err != nil {
		return err
	}
	return operationCtx.Err()
}

func (p *managedPeriodic) run(ctx context.Context, stop <-chan struct{}, done chan struct{}, interval time.Duration, newTimer func(time.Duration) managedPeriodicTimer) {
	var runErr error
	defer func() {
		p.mu.Lock()
		p.runErr = runErr
		p.running = false
		p.started = false
		p.terminal = true
		p.cancel = nil
		p.mu.Unlock()
		close(done)
	}()

	if interval <= 0 {
		interval = time.Nanosecond
	}
	for {
		timer := newTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-stop:
			timer.Stop()
			return
		case <-timer.C():
		}

		p.mu.Lock()
		if !p.running {
			p.mu.Unlock()
			return
		}
		p.active++
		p.mu.Unlock()

		err := p.executeOnce(ctx)
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
		if err != nil && !errors.Is(err, context.Canceled) {
			runErr = err
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (p *managedPeriodic) Stop() error {
	return p.StopContext(context.Background())
}

func (p *managedPeriodic) StopContext(context.Context) error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	close(p.stop)
	cancel := p.cancel
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (p *managedPeriodic) Wait() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultJoinTimeout)
	defer cancel()
	return p.WaitContext(ctx)
}

func (p *managedPeriodic) WaitContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	if done != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	p.mu.Lock()
	err := p.runErr
	p.mu.Unlock()
	return err
}

func (p *managedPeriodic) Close() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultCloseTimeout)
	defer cancel()
	return p.CloseContext(ctx)
}

func (p *managedPeriodic) CloseContext(ctx context.Context) error {
	return errors.Join(p.StopContext(ctx), p.WaitContext(ctx))
}
