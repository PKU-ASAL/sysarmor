package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
)

func TestReadHistoryDocumentsReadsEveryPage(t *testing.T) {
	first := make([]platformopensearch.SearchHit, historyPageSize)
	for index := range first {
		first[index] = platformopensearch.SearchHit{Source: json.RawMessage(fmt.Sprintf(`{"id":"event-%d"}`, index)), Sort: []any{index}}
	}
	searcher := &historyPageSearcherStub{pages: []platformopensearch.SearchPage{
		{Hits: first},
		{Hits: []platformopensearch.SearchHit{{Source: json.RawMessage(`{"id":"last"}`), Sort: []any{historyPageSize}}}},
	}}

	documents, err := readHistoryDocuments(context.Background(), searcher, platformopensearch.SearchRequest{Index: "events"})

	if err != nil || len(documents) != historyPageSize+1 || len(searcher.requests) != 2 || len(searcher.requests[1].SearchAfter) == 0 {
		t.Fatalf("documents=%d requests=%+v err=%v", len(documents), searcher.requests, err)
	}
}

type historyPageSearcherStub struct {
	requests []platformopensearch.SearchRequest
	pages    []platformopensearch.SearchPage
}

func (stub *historyPageSearcherStub) SearchPage(_ context.Context, request platformopensearch.SearchRequest) (platformopensearch.SearchPage, error) {
	stub.requests = append(stub.requests, request)
	index := len(stub.requests) - 1
	if index >= len(stub.pages) {
		return platformopensearch.SearchPage{}, nil
	}
	return stub.pages[index], nil
}
