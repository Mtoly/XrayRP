package specialruntime

import (
	"errors"
	"sync"
	"time"
)

// managedPeriodic runs execute immediately on Start, then waits interval after
// every callback, retries later errors, and joins in-flight work when closed.
type managedPeriodic struct {
	interval time.Duration
	execute  func() error

	mu       sync.Mutex
	stop     chan struct{}
	done     chan struct{}
	started  bool
	running  bool
	terminal bool
	active   int
	runErr   error
	newTimer func(time.Duration) managedPeriodicTimer
}

func NewPeriodic(interval time.Duration, execute func() error) *managedPeriodic {
	return &managedPeriodic{
		interval: interval,
		execute:  execute,
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
	p.mu.Lock()
	if p.terminal {
		p.mu.Unlock()
		return errors.New("periodic task cannot restart after termination")
	}
	if p.started {
		p.mu.Unlock()
		return nil
	}
	if p.execute == nil {
		p.mu.Unlock()
		return errors.New("periodic task execute callback is nil")
	}
	p.started = true
	p.running = true
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.runErr = nil
	stop := p.stop
	done := p.done
	interval := p.interval
	execute := p.execute
	newTimer := p.newTimer
	if newTimer == nil {
		newTimer = newManagedPeriodicTimer
	}
	p.mu.Unlock()

	if err := execute(); err != nil {
		p.mu.Lock()
		p.running = false
		p.started = false
		p.terminal = true
		p.mu.Unlock()
		close(done)
		return err
	}

	p.mu.Lock()
	stopped := !p.running
	p.mu.Unlock()
	if stopped {
		p.mu.Lock()
		p.started = false
		p.terminal = true
		p.mu.Unlock()
		close(done)
		return nil
	}

	go p.run(stop, done, interval, execute, newTimer)
	return nil
}

func (p *managedPeriodic) run(stop <-chan struct{}, done chan struct{}, interval time.Duration, execute func() error, newTimer func(time.Duration) managedPeriodicTimer) {
	var runErr error
	defer func() {
		p.mu.Lock()
		p.runErr = runErr
		p.running = false
		p.started = false
		p.terminal = true
		p.mu.Unlock()
		close(done)
	}()

	if interval <= 0 {
		interval = time.Nanosecond
	}
	for {
		timer := newTimer(interval)
		select {
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

		err := execute()
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
		if err != nil {
			runErr = err
		}
	}
}

func (p *managedPeriodic) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	close(p.stop)
	p.mu.Unlock()
	return nil
}

func (p *managedPeriodic) Wait() error {
	p.mu.Lock()
	done := p.done
	p.mu.Unlock()
	if done != nil {
		<-done
	}
	p.mu.Lock()
	err := p.runErr
	p.mu.Unlock()
	return err
}

func (p *managedPeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}
