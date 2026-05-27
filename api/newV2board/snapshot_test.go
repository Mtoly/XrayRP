package newV2board

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mtoly/XrayRP/api"
)

func TestUniProxySnapshotCacheRoundTrip(t *testing.T) {
	client := New(&api.Config{APIHost: "http://127.0.0.1", NodeID: 1, NodeType: "V2ray"})
	snapshot := &serverConfig{ServerPort: 443}

	client.storeUniProxySnapshot(snapshot)
	cached, ok := client.cachedUniProxySnapshot()
	if !ok {
		t.Fatal("expected cached UniProxy snapshot")
	}
	if cached != snapshot {
		t.Fatalf("expected cached snapshot pointer %p, got %p", snapshot, cached)
	}
}

func TestFetchUniProxySnapshotWithoutETagDoesNotSendOrStoreETag(t *testing.T) {
	var gotIfNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "etag-from-cert-fetch")
		_, _ = w.Write([]byte(`{"server_port":443,"network":"tcp"}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	snapshot, err := client.fetchUniProxySnapshot(false)
	if err != nil {
		t.Fatalf("fetchUniProxySnapshot returned error: %v", err)
	}
	if snapshot.ServerPort != 443 {
		t.Fatalf("expected server port 443, got %d", snapshot.ServerPort)
	}
	if gotIfNoneMatch != "" {
		t.Fatalf("expected fetch without ETag to omit If-None-Match, got %q", gotIfNoneMatch)
	}
	if got := client.eTags["node"]; got != "" {
		t.Fatalf("expected fetch without ETag to leave node etag empty, got %q", got)
	}
	cached, ok := client.cachedUniProxySnapshot()
	if !ok || cached != snapshot {
		t.Fatalf("expected fetched snapshot to be cached, got ok=%v cached=%p snapshot=%p", ok, cached, snapshot)
	}
}

func TestFetchUniProxySnapshotWithETagSendsAndUpdatesETag(t *testing.T) {
	var gotIfNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "new-etag")
		_, _ = w.Write([]byte(`{"server_port":8443,"network":"tcp"}`))
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	client.eTags["node"] = "old-etag"

	snapshot, err := client.fetchUniProxySnapshot(true)
	if err != nil {
		t.Fatalf("fetchUniProxySnapshot returned error: %v", err)
	}
	if snapshot.ServerPort != 8443 {
		t.Fatalf("expected server port 8443, got %d", snapshot.ServerPort)
	}
	if gotIfNoneMatch != "old-etag" {
		t.Fatalf("expected If-None-Match old-etag, got %q", gotIfNoneMatch)
	}
	if got := client.eTags["node"]; got != "new-etag" {
		t.Fatalf("expected updated node etag new-etag, got %q", got)
	}
	cached, ok := client.cachedUniProxySnapshot()
	if !ok || cached != snapshot {
		t.Fatalf("expected fetched snapshot to be cached, got ok=%v cached=%p snapshot=%p", ok, cached, snapshot)
	}
}

func TestFetchUniProxySnapshotWithETagReturnsNodeNotModified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != "old-etag" {
			t.Fatalf("expected If-None-Match old-etag, got %q", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := New(&api.Config{APIHost: server.URL, NodeID: 1, NodeType: "V2ray"})
	client.eTags["node"] = "old-etag"

	_, err := client.fetchUniProxySnapshot(true)
	if err == nil || err.Error() != api.NodeNotModified {
		t.Fatalf("expected NodeNotModified error, got %v", err)
	}
}
