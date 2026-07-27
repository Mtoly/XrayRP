package panelhttp

import (
	"fmt"
	"sync"
	"testing"
)

func TestETagStatePublishesOnlyNonEmptyCandidates(t *testing.T) {
	var state ETagState

	if got := state.Get("users"); got != "" {
		t.Fatalf("zero-value state = %q, want empty", got)
	}
	state.Publish("users", "last-known-good")
	state.Publish("users", "")

	if got := state.Get("users"); got != "last-known-good" {
		t.Fatalf("etag after empty candidate = %q, want last-known-good", got)
	}
}

func TestETagStateSupportsConcurrentReadersAndPublishers(t *testing.T) {
	var state ETagState
	state.Publish("node", "initial")

	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(2)
		go func(id int) {
			defer workers.Done()
			<-start
			state.Publish("node", fmt.Sprintf("etag-%d", id))
		}(i)
		go func() {
			defer workers.Done()
			<-start
			for read := 0; read < 100; read++ {
				if state.Get("node") == "" {
					t.Error("concurrent read observed an empty published ETag")
					return
				}
			}
		}()
	}

	close(start)
	workers.Wait()
	if got := state.Get("node"); got == "" {
		t.Fatal("concurrent publication left an empty ETag")
	}
}
