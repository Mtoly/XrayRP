package operation

import (
	"context"
	"sync"
)

// Gate is a zero-value context-aware binary operation lock.
type Gate struct {
	once  sync.Once
	token chan struct{}
}

func (g *Gate) init() {
	g.once.Do(func() {
		g.token = make(chan struct{}, 1)
		g.token <- struct{}{}
	})
}

func (g *Gate) Lock(ctx context.Context) error {
	g.init()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.token:
		return nil
	}
}

func (g *Gate) TryLock() bool {
	g.init()
	select {
	case <-g.token:
		return true
	default:
		return false
	}
}

func (g *Gate) Unlock() {
	g.init()
	select {
	case g.token <- struct{}{}:
	default:
		panic("operation gate unlock of unlocked gate")
	}
}
