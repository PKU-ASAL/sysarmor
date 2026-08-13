package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPIndexerIndexesDocument(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	indexer, err := NewHTTPIndexer(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPIndexer() error = %v", err)
	}
	if err := indexer.Index(context.Background(), Document{Index: "sysarmor-events", ID: "ev-a", Body: []byte(`{"id":"ev-a"}`)}); err != nil {
		t.Fatalf("Index() error = %v", err)
	}
	if gotPath != "/sysarmor-events/_doc/ev-a" {
		t.Fatalf("path = %s", gotPath)
	}
}

func TestHTTPIndexerBulkIndexesNDJSON(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/_bulk" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		_, _ = w.Write([]byte(`{"errors":false,"items":[{"index":{"status":201}},{"index":{"status":200}}]}`))
	}))
	defer server.Close()
	indexer, _ := NewHTTPIndexer(server.URL)
	err := indexer.BulkIndex(context.Background(), []Document{
		{Index: "events", ID: "ev-1", Body: []byte(`{"id":"ev-1"}`)},
		{Index: "signals", ID: "sig-1", Body: []byte(`{"id":"sig-1"}`)},
	})
	if err != nil {
		t.Fatalf("BulkIndex() error = %v", err)
	}
	for _, want := range []string{`{"index":{"_id":"ev-1","_index":"events"}}`, `{"id":"ev-1"}`, `{"index":{"_id":"sig-1","_index":"signals"}}`} {
		if !strings.Contains(body, want) {
			t.Fatalf("bulk body missing %s: %s", want, body)
		}
	}
	if !strings.HasSuffix(body, "\n") {
		t.Fatalf("bulk body must end with newline: %q", body)
	}
}

func TestHTTPIndexerClassifiesBulkItemErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		class  ErrorClass
	}{{"throttled", 429, ErrorTransient}, {"mapping", 400, ErrorPermanent}, {"index missing", 404, ErrorPermanent}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"errors":true,"items":[{"index":{"status":%d,"error":{"type":"failure","reason":"broken"}}}]}`, tc.status)
			}))
			defer server.Close()
			indexer, _ := NewHTTPIndexer(server.URL)
			err := indexer.BulkIndex(context.Background(), []Document{{Index: "events", ID: "ev-1", Body: []byte(`{}`)}})
			if ErrorClassOf(err) != tc.class {
				t.Fatalf("class = %q error=%v, want %q", ErrorClassOf(err), err, tc.class)
			}
		})
	}
}

func TestHTTPIndexerBulkTransientFailureDominatesPermanent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"index":{"status":400}},{"index":{"status":429}}]}`))
	}))
	defer server.Close()
	indexer, _ := NewHTTPIndexer(server.URL)
	err := indexer.BulkIndex(context.Background(), []Document{{Index: "events", ID: "bad", Body: []byte(`{}`)}, {Index: "signals", ID: "retry", Body: []byte(`{}`)}})
	if ErrorClassOf(err) != ErrorTransient {
		t.Fatalf("class = %q error=%v", ErrorClassOf(err), err)
	}
}

func TestHTTPIndexerSearchesDocuments(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_source":{"id":"ev-a"}},{"_source":{"id":"ev-b"}}]}}`))
	}))
	defer server.Close()

	indexer, err := NewHTTPIndexer(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPIndexer() error = %v", err)
	}
	docs, err := indexer.Search(context.Background(), SearchRequest{Index: "sysarmor-events", Size: 10})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if gotPath != "/sysarmor-events/_search" {
		t.Fatalf("path = %s", gotPath)
	}
	if len(docs) != 2 || string(docs[0]) != `{"id":"ev-a"}` {
		t.Fatalf("docs = %s", docs)
	}
}

func TestHTTPIndexerUsesBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != "admin" {
			t.Fatalf("basic auth = %q/%q ok=%t", username, password, ok)
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer server.Close()

	indexer, err := NewHTTPIndexerWithAuth(server.URL, "admin", "admin")
	if err != nil {
		t.Fatalf("NewHTTPIndexerWithAuth() error = %v", err)
	}
	if _, err := indexer.Search(context.Background(), SearchRequest{Index: "sysarmor-events", Size: 10}); err != nil {
		t.Fatalf("Search() error = %v", err)
	}
}

func TestHTTPIndexerSearchPushesFilters(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatalf("decode body: %v body=%s", err, data)
		}
		_, _ = w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer server.Close()

	indexer, err := NewHTTPIndexer(server.URL)
	if err != nil {
		t.Fatalf("NewHTTPIndexer() error = %v", err)
	}
	_, err = indexer.Search(context.Background(), SearchRequest{
		Index:     "sysarmor-signals",
		Size:      25,
		Offset:    50,
		Query:     "credential access",
		Labels:    map[string]string{"scenario": "apt-staged-drop"},
		Exact:     map[string]string{"tenant_id": "default", "where": "SIGNAL_WHERE_CLOUD"},
		Bool:      map[string]bool{"terminal": true},
		TimeField: "@timestamp",
		TimeFrom:  "2026-07-08T21:00:00Z",
		TimeTo:    "2026-07-08T21:10:00Z",
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	encoded, _ := json.Marshal(body)
	got := string(encoded)
	for _, want := range []string{
		`"size":25`,
		`"from":50`,
		`"labels.scenario.keyword":"apt-staged-drop"`,
		`"tenant_id":"default"`,
		`"where":"SIGNAL_WHERE_CLOUD"`,
		`"terminal":true`,
		`"query":"credential access"`,
		`"@timestamp":{"gte":"2026-07-08T21:00:00Z","lte":"2026-07-08T21:10:00Z"}`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("search body missing %s: %s", want, got)
		}
	}
	for _, unwanted := range []string{`"tenant_id.keyword"`, `"where.keyword"`} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("exact keyword field unexpectedly gained .keyword suffix %s: %s", unwanted, got)
		}
	}
}
