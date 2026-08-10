package managerapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
)

type searchFieldsResponse struct {
	Indexes []string              `json:"indexes"`
	Fields  []searchFieldResponse `json:"fields"`
}

type searchFieldResponse struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Searchable   bool   `json:"searchable"`
	Aggregatable bool   `json:"aggregatable"`
}

type telemetrySearchRequest struct {
	Indexes []string     `json:"indexes"`
	Query   string       `json:"query"`
	Time    searchTime   `json:"time"`
	Sort    []searchSort `json:"sort"`
	Limit   int          `json:"limit"`
	Offset  int          `json:"offset"`
	Buckets int          `json:"bucket_count"`
}

type searchTime struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

type searchSort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
}

type telemetrySearchResponse struct {
	Total         int                  `json:"total"`
	TotalRelation string               `json:"total_relation"`
	Rows          []telemetrySearchRow `json:"rows"`
}

type telemetrySearchRow struct {
	Index     string         `json:"index"`
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Host      string         `json:"host,omitempty"`
	Summary   string         `json:"summary,omitempty"`
	Tactic    string         `json:"tactic,omitempty"`
	Source    map[string]any `json:"source,omitempty"`
	Raw       map[string]any `json:"raw,omitempty"`
}

type telemetryHistogramResponse struct {
	Buckets []telemetryHistogramBucket `json:"buckets"`
}

type telemetryHistogramBucket struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Total   int    `json:"total"`
	Events  int    `json:"events"`
	Signals int    `json:"signals"`
}

var telemetrySearchFields = []searchFieldResponse{
	{Name: "@timestamp", Type: "date", Searchable: true, Aggregatable: true},
	{Name: "agent.id", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "event.action", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "event.kind", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "event.severity", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "event.summary", Type: "text", Searchable: true, Aggregatable: false},
	{Name: "event.tactic", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "host.name", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "process.name", Type: "keyword", Searchable: true, Aggregatable: true},
	{Name: "user.name", Type: "keyword", Searchable: true, Aggregatable: true},
}

func (s *Server) searchFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	indexes, err := resolveTelemetryIndexes(strings.Split(r.URL.Query().Get("index"), ","))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, searchFieldsResponse{Indexes: indexes, Fields: telemetrySearchFields})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := decodeTelemetrySearchRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	docs, err := s.searchTelemetryDocuments(r, req, searchLimitFromInt(req.Limit))
	if err != nil {
		http.Error(w, fmt.Sprintf("search telemetry: %v", err), http.StatusBadGateway)
		return
	}
	rows := make([]telemetrySearchRow, 0, len(docs))
	for _, doc := range docs {
		rows = append(rows, telemetryRowFromDocument(doc))
	}
	writeJSON(w, telemetrySearchResponse{Total: len(rows), TotalRelation: "eq", Rows: rows})
}

func (s *Server) searchHistogram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := decodeTelemetrySearchRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	docs, err := s.searchTelemetryDocuments(r, req, 1000)
	if err != nil {
		http.Error(w, fmt.Sprintf("search telemetry histogram: %v", err), http.StatusBadGateway)
		return
	}
	buckets := buildTelemetryHistogram(docs, req.Time, req.Buckets)
	writeJSON(w, telemetryHistogramResponse{Buckets: buckets})
}

func decodeTelemetrySearchRequest(r *http.Request) (telemetrySearchRequest, error) {
	var req telemetrySearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, fmt.Errorf("invalid search request")
	}
	if req.Time.Field == "" {
		req.Time.Field = "@timestamp"
	}
	if req.Buckets == 0 {
		req.Buckets = 12
	}
	if req.Buckets < 1 || req.Buckets > 100 {
		return req, fmt.Errorf("bucket_count must be between 1 and 100")
	}
	if _, err := resolveTelemetryIndexes(req.Indexes); err != nil {
		return req, err
	}
	if _, _, err := parseTelemetryQuery(req.Query); err != nil {
		return req, err
	}
	return req, nil
}

func (s *Server) searchTelemetryDocuments(r *http.Request, req telemetrySearchRequest, limit int) ([]telemetryDocument, error) {
	indexes, err := resolveTelemetryIndexes(req.Indexes)
	if err != nil {
		return nil, err
	}
	exact, freeText, err := parseTelemetryQuery(req.Query)
	if err != nil {
		return nil, err
	}
	exact["tenant_id"] = requestTenantID(r)
	docs := make([]telemetryDocument, 0)
	for _, index := range indexes {
		raw, err := s.searchTelemetry(r.Context(), platformopensearch.SearchRequest{
			Index:     index,
			Size:      limit,
			Offset:    max(req.Offset, 0),
			Query:     strings.Join(freeText, " "),
			Exact:     opensearchExactFields(exact),
			TimeField: req.Time.Field,
			TimeFrom:  req.Time.From,
			TimeTo:    req.Time.To,
			SortField: firstSortField(req.Sort),
			SortDesc:  firstSortDesc(req.Sort),
		})
		if err != nil {
			return nil, err
		}
		docs = append(docs, filterTelemetryDocuments(index, raw, exact, freeText, req.Time)...)
	}
	sort.SliceStable(docs, func(i, j int) bool {
		return docs[i].timestamp.After(docs[j].timestamp)
	})
	if limit > 0 && len(docs) > limit {
		return docs[:limit], nil
	}
	return docs, nil
}

func resolveTelemetryIndexes(raw []string) ([]string, error) {
	if len(raw) == 0 || strings.TrimSpace(strings.Join(raw, "")) == "" {
		return []string{platformopensearch.EventsReadAlias, platformopensearch.SignalsReadAlias}, nil
	}
	seen := map[string]bool{}
	indexes := make([]string, 0, len(raw))
	for _, item := range raw {
		switch strings.TrimSpace(item) {
		case "events-*", "sysarmor-events", platformopensearch.EventsReadAlias:
			addIndex(&indexes, seen, platformopensearch.EventsReadAlias)
		case "signals-*", "sysarmor-signals", platformopensearch.SignalsReadAlias:
			addIndex(&indexes, seen, platformopensearch.SignalsReadAlias)
		case "events-*,signals-*", "sysarmor-events,sysarmor-signals", platformopensearch.EventsReadAlias + "," + platformopensearch.SignalsReadAlias:
			addIndex(&indexes, seen, platformopensearch.EventsReadAlias)
			addIndex(&indexes, seen, platformopensearch.SignalsReadAlias)
		case "":
			continue
		default:
			return nil, fmt.Errorf("unsupported index %q", item)
		}
	}
	return indexes, nil
}

func addIndex(indexes *[]string, seen map[string]bool, index string) {
	if !seen[index] {
		*indexes = append(*indexes, index)
		seen[index] = true
	}
}

func opensearchExactFields(exact map[string]string) map[string]string {
	out := make(map[string]string, len(exact))
	for field, value := range exact {
		if field != "@timestamp" && field != "tenant_id" {
			field += ".keyword"
		}
		out[field] = value
	}
	return out
}

func parseTelemetryQuery(query string) (map[string]string, []string, error) {
	exact := map[string]string{}
	freeText := []string{}
	for _, token := range strings.Fields(query) {
		if strings.EqualFold(token, "and") || strings.EqualFold(token, "or") {
			continue
		}
		field, value, ok := strings.Cut(token, ":")
		if !ok {
			freeText = append(freeText, token)
			continue
		}
		if !isTelemetrySearchField(field) {
			return nil, nil, fmt.Errorf("unsupported search field %q", field)
		}
		if value != "" {
			exact[field] = strings.Trim(value, `"`)
		}
	}
	return exact, freeText, nil
}

func isTelemetrySearchField(name string) bool {
	for _, field := range telemetrySearchFields {
		if field.Name == name {
			return true
		}
	}
	return false
}

type telemetryDocument struct {
	index     string
	source    map[string]any
	timestamp time.Time
}

func filterTelemetryDocuments(index string, raw []json.RawMessage, exact map[string]string, freeText []string, tr searchTime) []telemetryDocument {
	out := make([]telemetryDocument, 0, len(raw))
	for _, item := range raw {
		doc, ok := decodeRawDocument(item)
		if !ok || !documentMatchesExact(doc, exact) || !documentMatchesText(doc, freeText) {
			continue
		}
		ts := documentTime(doc, tr.Field)
		if !timeMatches(ts, tr) {
			continue
		}
		out = append(out, telemetryDocument{index: index, source: doc, timestamp: ts})
	}
	return out
}

func decodeRawDocument(raw json.RawMessage) (map[string]any, bool) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	return doc, true
}

func documentMatchesExact(doc map[string]any, exact map[string]string) bool {
	for field, want := range exact {
		if got := strings.TrimSpace(documentString(doc, field)); !strings.EqualFold(got, want) {
			return false
		}
	}
	return true
}

func documentMatchesText(doc map[string]any, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	haystack := strings.ToLower(fmt.Sprint(doc))
	for _, term := range terms {
		if !strings.Contains(haystack, strings.ToLower(term)) {
			return false
		}
	}
	return true
}

func timeMatches(ts time.Time, tr searchTime) bool {
	if ts.IsZero() {
		return true
	}
	from, hasFrom := parseSearchTime(tr.From)
	to, hasTo := parseSearchTime(tr.To)
	if hasFrom && ts.Before(from) {
		return false
	}
	return !hasTo || !ts.After(to)
}

func telemetryRowFromDocument(doc telemetryDocument) telemetrySearchRow {
	source := telemetrySource(doc.source)
	return telemetrySearchRow{
		Index:     doc.index,
		ID:        firstNonEmptyString(documentString(doc.source, "id"), documentString(doc.source, "_id")),
		Timestamp: documentString(doc.source, "@timestamp"),
		Severity:  documentString(doc.source, "event.severity"),
		Host:      documentString(doc.source, "host.name"),
		Summary:   firstNonEmptyString(documentString(doc.source, "event.summary"), documentString(doc.source, "summary"), documentString(doc.source, "message")),
		Tactic:    documentString(doc.source, "event.tactic"),
		Source:    source,
		Raw:       doc.source,
	}
}

func telemetrySource(doc map[string]any) map[string]any {
	source := map[string]any{}
	for _, field := range []string{"event.kind", "host.name", "event.summary", "event.tactic", "event.severity"} {
		if value := documentString(doc, field); value != "" {
			source[field] = value
		}
	}
	return source
}

func buildTelemetryHistogram(docs []telemetryDocument, tr searchTime, bucketCount int) []telemetryHistogramBucket {
	from, okFrom := parseSearchTime(tr.From)
	to, okTo := parseSearchTime(tr.To)
	if !okFrom || !okTo || !to.After(from) {
		to = time.Now().UTC()
		from = to.Add(-30 * time.Minute)
	}
	width := to.Sub(from) / time.Duration(bucketCount)
	buckets := make([]telemetryHistogramBucket, bucketCount)
	for i := range buckets {
		start := from.Add(time.Duration(i) * width)
		end := start.Add(width)
		if i == bucketCount-1 {
			end = to
		}
		buckets[i] = telemetryHistogramBucket{Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339)}
	}
	for _, doc := range docs {
		addTelemetryDocumentToBucket(buckets, doc)
	}
	return buckets
}

func addTelemetryDocumentToBucket(buckets []telemetryHistogramBucket, doc telemetryDocument) {
	for i := range buckets {
		start, _ := time.Parse(time.RFC3339, buckets[i].Start)
		end, _ := time.Parse(time.RFC3339, buckets[i].End)
		if doc.timestamp.Before(start) || !doc.timestamp.Before(end) {
			continue
		}
		buckets[i].Total++
		if doc.index == platformopensearch.SignalsReadAlias {
			buckets[i].Signals++
		} else {
			buckets[i].Events++
		}
		return
	}
}

func documentString(doc map[string]any, path string) string {
	if value, ok := doc[path]; ok {
		return fmt.Sprint(value)
	}
	var current any = doc
	for _, part := range strings.Split(path, ".") {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[part]
	}
	if current == nil {
		return ""
	}
	return fmt.Sprint(current)
}

func documentTime(doc map[string]any, field string) time.Time {
	value := firstNonEmptyString(documentString(doc, field), documentString(doc, "timestamp"))
	ts, _ := parseSearchTime(value)
	return ts
}

func parseSearchTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func searchLimitFromInt(limit int) int {
	if limit <= 0 {
		return 500
	}
	return min(limit, 1000)
}

func firstSortField(sort []searchSort) string {
	if len(sort) == 0 {
		return "@timestamp"
	}
	return sort[0].Field
}

func firstSortDesc(sort []searchSort) bool {
	if len(sort) == 0 {
		return true
	}
	return strings.EqualFold(sort[0].Direction, "desc")
}
