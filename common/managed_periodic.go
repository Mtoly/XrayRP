package common

import (
	"errors"
	"sync"
	"time"
)

// ManagedPeriodic runs Execute immediately on Start, then waits Interval after
// each successful callback, and waits for an in-flight callback when closed.
type ManagedPeriodic struct {
	Interval time.Duration
	Execute  func() error

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

func (p *ManagedPeriodic) Start() error {
	p.mu.Lock()
	if p.terminal {
		p.mu.Unlock()
		return errors.New("periodic task cannot restart after termination")
	}
	if p.started {
		p.mu.Unlock()
		return nil
	}
	if p.Execute == nil {
		p.mu.Unlock()
		return errors.New("periodic task Execute is nil")
	}
	p.started = true
	p.running = true
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	p.runErr = nil
	stop := p.stop
	done := p.done
	interval := p.Interval
	execute := p.Execute
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

func (p *ManagedPeriodic) run(stop <-chan struct{}, done chan struct{}, interval time.Duration, execute func() error, newTimer func(time.Duration) managedPeriodicTimer) {
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
			return
		}
	}
}

func (p *ManagedPeriodic) Stop() error {
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

func (p *ManagedPeriodic) Wait() error {
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

func (p *ManagedPeriodic) Close() error {
	return errors.Join(p.Stop(), p.Wait())
}
