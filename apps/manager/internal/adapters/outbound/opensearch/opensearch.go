package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

var ErrDisabled = errors.New("opensearch indexing is disabled")

type Document = ports.SearchDocument

type Indexer interface {
	Index(context.Context, Document) error
}

type Projector = ports.DocumentProjector

type ErrorClass string

const (
	ErrorTransient ErrorClass = "transient"
	ErrorPermanent ErrorClass = "permanent"
)

type ProjectionError struct {
	Class  ErrorClass
	Status int
	Index  string
	ID     string
	Cause  error
}

func (e *ProjectionError) Error() string {
	return fmt.Sprintf("opensearch projection class=%s status=%d index=%s id=%s: %v", e.Class, e.Status, e.Index, e.ID, e.Cause)
}

func (e *ProjectionError) Unwrap() error { return e.Cause }

func ErrorClassOf(err error) ErrorClass {
	var projection *ProjectionError
	if errors.As(err, &projection) {
		return projection.Class
	}
	return ErrorTransient
}

type Searcher interface {
	Search(context.Context, SearchRequest) ([]json.RawMessage, error)
}

type SearchRequest struct {
	Index     string
	Size      int
	Offset    int
	Query     string
	Labels    map[string]string
	Exact     map[string]string
	Bool      map[string]bool
	TimeField string
	TimeFrom  string
	TimeTo    string
	SortField string
	SortDesc  bool
}

type DisabledIndexer struct{}

func (DisabledIndexer) Index(context.Context, Document) error {
	return ErrDisabled
}

type NoopIndexer struct{}

func (NoopIndexer) Index(context.Context, Document) error {
	return nil
}

func (NoopIndexer) BulkIndex(context.Context, []Document) error { return nil }

type HTTPIndexer struct {
	base     string
	username string
	password string
	client   *http.Client
}

func NewHTTPIndexer(baseURL string) (*HTTPIndexer, error) {
	return NewHTTPIndexerWithAuth(baseURL, "", "")
}

func NewHTTPIndexerWithAuth(baseURL, username, password string) (*HTTPIndexer, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, ErrDisabled
	}
	return &HTTPIndexer{
		base:     baseURL,
		username: strings.TrimSpace(username),
		password: password,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (i *HTTPIndexer) Index(ctx context.Context, doc Document) error {
	if i == nil || i.client == nil || i.base == "" {
		return ErrDisabled
	}
	if doc.Index == "" || doc.ID == "" {
		return fmt.Errorf("opensearch index and id are required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, i.base+"/"+doc.Index+"/_doc/"+doc.ID, bytes.NewReader(doc.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	i.setAuth(req)
	resp, err := i.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("opensearch index status %s", resp.Status)
	}
	return nil
}

func (i *HTTPIndexer) BulkIndex(ctx context.Context, docs []Document) error {
	if i == nil || i.client == nil || i.base == "" {
		return ErrDisabled
	}
	if len(docs) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, doc := range docs {
		if doc.Index == "" || doc.ID == "" || !json.Valid(doc.Body) {
			return &ProjectionError{Class: ErrorPermanent, Index: doc.Index, ID: doc.ID, Cause: fmt.Errorf("valid index, id, and JSON body are required")}
		}
		metadata, _ := json.Marshal(map[string]any{"index": map[string]string{"_index": doc.Index, "_id": doc.ID}})
		body.Write(metadata)
		body.WriteByte('\n')
		body.Write(doc.Body)
		body.WriteByte('\n')
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.base+"/_bulk", &body)
	if err != nil {
		return &ProjectionError{Class: ErrorPermanent, Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	i.setAuth(req)
	resp, err := i.client.Do(req)
	if err != nil {
		return &ProjectionError{Class: ErrorTransient, Cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &ProjectionError{Class: classifyStatus(resp.StatusCode), Status: resp.StatusCode, Cause: fmt.Errorf("bulk status %s", resp.Status)}
	}
	return decodeBulkResponse(resp.Body, docs)
}

func decodeBulkResponse(reader io.Reader, docs []Document) error {
	var response struct {
		Items []map[string]struct {
			Status int `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return &ProjectionError{Class: ErrorTransient, Cause: fmt.Errorf("decode bulk response: %w", err)}
	}
	if len(response.Items) != len(docs) {
		return &ProjectionError{Class: ErrorTransient, Cause: fmt.Errorf("bulk item count %d, want %d", len(response.Items), len(docs))}
	}
	var permanent *ProjectionError
	var transient *ProjectionError
	for index, operations := range response.Items {
		if len(operations) != 1 {
			return &ProjectionError{Class: ErrorTransient, Cause: fmt.Errorf("bulk item %d has %d operations", index, len(operations))}
		}
		for _, item := range operations {
			if item.Status >= 200 && item.Status < 300 {
				continue
			}
			cause := fmt.Errorf("bulk item failed")
			if item.Error != nil {
				cause = fmt.Errorf("%s: %s", item.Error.Type, item.Error.Reason)
			}
			failure := &ProjectionError{Class: classifyStatus(item.Status), Status: item.Status, Index: docs[index].Index, ID: docs[index].ID, Cause: cause}
			if failure.Class == ErrorTransient && transient == nil {
				transient = failure
			} else if permanent == nil {
				permanent = failure
			}
		}
	}
	if transient != nil {
		return transient
	}
	if permanent != nil {
		return permanent
	}
	return nil
}

func classifyStatus(status int) ErrorClass {
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 {
		return ErrorTransient
	}
	return ErrorPermanent
}

func (i *HTTPIndexer) Search(ctx context.Context, search SearchRequest) ([]json.RawMessage, error) {
	if i == nil || i.client == nil || i.base == "" {
		return nil, ErrDisabled
	}
	index := strings.TrimSpace(search.Index)
	if index == "" {
		return nil, fmt.Errorf("opensearch index is required")
	}
	size := search.Size
	if size <= 0 {
		size = 100
	}
	bodyMap := map[string]any{
		"size":  size,
		"from":  max(search.Offset, 0),
		"query": searchQuery(search),
	}
	if sortField := strings.TrimSpace(search.SortField); sortField != "" {
		order := "asc"
		if search.SortDesc {
			order = "desc"
		}
		bodyMap["sort"] = []map[string]any{{sortField: map[string]any{"order": order, "unmapped_type": "keyword"}}}
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, i.base+"/"+index+"/_search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	i.setAuth(req)
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("opensearch search status %s", resp.Status)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		if len(hit.Source) > 0 {
			out = append(out, hit.Source)
		}
	}
	return out, nil
}

func searchQuery(search SearchRequest) map[string]any {
	filters := make([]map[string]any, 0, len(search.Labels)+len(search.Exact)+len(search.Bool)+1)
	for key, value := range search.Labels {
		if key = strings.TrimSpace(key); key != "" {
			filters = append(filters, termFilter("labels."+key+".keyword", value))
		}
	}
	for field, value := range search.Exact {
		if field = strings.TrimSpace(field); field != "" {
			filters = append(filters, termFilter(field, value))
		}
	}
	for field, value := range search.Bool {
		if field = strings.TrimSpace(field); field != "" {
			filters = append(filters, map[string]any{"term": map[string]any{field: value}})
		}
	}
	if rangeFilter := timeRangeFilter(search); rangeFilter != nil {
		filters = append(filters, rangeFilter)
	}
	query := strings.TrimSpace(search.Query)
	if len(filters) == 0 && query == "" {
		return map[string]any{"match_all": map[string]any{}}
	}
	boolQuery := map[string]any{}
	if len(filters) > 0 {
		boolQuery["filter"] = filters
	}
	if query != "" {
		boolQuery["must"] = []map[string]any{{
			"simple_query_string": map[string]any{
				"query":            query,
				"default_operator": "and",
			},
		}}
	}
	return map[string]any{"bool": boolQuery}
}

func termFilter(field, value string) map[string]any {
	return map[string]any{"term": map[string]any{field: value}}
}

func timeRangeFilter(search SearchRequest) map[string]any {
	field := strings.TrimSpace(search.TimeField)
	if field == "" || (strings.TrimSpace(search.TimeFrom) == "" && strings.TrimSpace(search.TimeTo) == "") {
		return nil
	}
	rangeBody := map[string]any{}
	if from := strings.TrimSpace(search.TimeFrom); from != "" {
		rangeBody["gte"] = from
	}
	if to := strings.TrimSpace(search.TimeTo); to != "" {
		rangeBody["lte"] = to
	}
	return map[string]any{"range": map[string]any{field: rangeBody}}
}

func (i *HTTPIndexer) setAuth(req *http.Request) {
	if i.username != "" || i.password != "" {
		req.SetBasicAuth(i.username, i.password)
	}
}
