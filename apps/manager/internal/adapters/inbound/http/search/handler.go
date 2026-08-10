package search

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type Service interface {
	Search(context.Context, managerapp.RequestContext, telemetryapp.SearchQuery) ([]domaintelemetry.IndexedDocument, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Service Service
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) resolve(writer http.ResponseWriter, request *http.Request) (managerapp.RequestContext, bool) {
	if handler == nil || handler.options.Resolve == nil {
		writeFailure(writer, failure.New(failure.Unauthenticated, "unauthorized"))
		return managerapp.RequestContext{}, false
	}
	requestContext, err := handler.options.Resolve(request)
	if err != nil {
		writeFailure(writer, err)
		return managerapp.RequestContext{}, false
	}
	if handler.options.Service == nil {
		writeFailure(writer, failure.New(failure.Internal, "telemetry search service is not configured"))
		return managerapp.RequestContext{}, false
	}
	return requestContext, true
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

func (handler *Handler) Fields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	indexes, err := resolveTelemetryIndexes(strings.Split(r.URL.Query().Get("index"), ","))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, searchFieldsResponse{Indexes: publicIndexes(indexes), Fields: telemetrySearchFields})
}

func (handler *Handler) Search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := decodeTelemetrySearchRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	requestContext, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	docs, err := handler.searchTelemetryDocuments(r.Context(), requestContext, req, searchLimitFromInt(req.Limit))
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

func (handler *Handler) Histogram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req, err := decodeTelemetrySearchRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	requestContext, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	docs, err := handler.searchTelemetryDocuments(r.Context(), requestContext, req, 1000)
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

func (handler *Handler) searchTelemetryDocuments(ctx context.Context, request managerapp.RequestContext, req telemetrySearchRequest, limit int) ([]telemetryDocument, error) {
	indexes, err := resolveTelemetryIndexes(req.Indexes)
	if err != nil {
		return nil, err
	}
	exact, freeText, err := parseTelemetryQuery(req.Query)
	if err != nil {
		return nil, err
	}
	values, err := handler.options.Service.Search(ctx, request, telemetryapp.SearchQuery{Indexes: indexes,
		Query: strings.Join(freeText, " "), Exact: exact, Limit: limit, Offset: max(req.Offset, 0),
		TimeField: req.Time.Field, TimeFrom: req.Time.From, TimeTo: req.Time.To,
		SortField: firstSortField(req.Sort), SortDesc: firstSortDesc(req.Sort)})
	if err != nil {
		return nil, err
	}
	docs := make([]telemetryDocument, 0, len(values))
	for _, value := range values {
		raw := []json.RawMessage{json.RawMessage(value.Document)}
		docs = append(docs, filterTelemetryDocuments(publicIndex(value.Index), raw, exact, freeText, req.Time)...)
	}
	sort.SliceStable(docs, func(i, j int) bool {
		return docs[i].timestamp.After(docs[j].timestamp)
	})
	if limit > 0 && len(docs) > limit {
		return docs[:limit], nil
	}
	return docs, nil
}

func resolveTelemetryIndexes(raw []string) ([]domaintelemetry.Index, error) {
	if len(raw) == 0 || strings.TrimSpace(strings.Join(raw, "")) == "" {
		return []domaintelemetry.Index{domaintelemetry.IndexEvents, domaintelemetry.IndexSignals}, nil
	}
	seen := map[string]bool{}
	indexes := make([]domaintelemetry.Index, 0, len(raw))
	for _, item := range raw {
		switch strings.TrimSpace(item) {
		case "events-*", "sysarmor-events", "sysarmor-events-read":
			addIndex(&indexes, seen, domaintelemetry.IndexEvents)
		case "signals-*", "sysarmor-signals", "sysarmor-signals-read":
			addIndex(&indexes, seen, domaintelemetry.IndexSignals)
		case "events-*,signals-*", "sysarmor-events,sysarmor-signals", "sysarmor-events-read,sysarmor-signals-read":
			addIndex(&indexes, seen, domaintelemetry.IndexEvents)
			addIndex(&indexes, seen, domaintelemetry.IndexSignals)
		case "":
			continue
		default:
			return nil, fmt.Errorf("unsupported index %q", item)
		}
	}
	return indexes, nil
}

func addIndex(indexes *[]domaintelemetry.Index, seen map[string]bool, index domaintelemetry.Index) {
	if !seen[string(index)] {
		*indexes = append(*indexes, index)
		seen[string(index)] = true
	}
}

func publicIndexes(indexes []domaintelemetry.Index) []string {
	result := make([]string, 0, len(indexes))
	for _, index := range indexes {
		result = append(result, publicIndex(index))
	}
	return result
}

func publicIndex(index domaintelemetry.Index) string {
	if index == domaintelemetry.IndexSignals {
		return "sysarmor-signals-read"
	}
	return "sysarmor-events-read"
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
		if doc.index == "sysarmor-signals-read" {
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

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		http.Error(writer, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
	}
}

func writeFailure(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch failure.KindOf(err) {
	case failure.InvalidArgument, failure.FailedPrecondition:
		status = http.StatusBadRequest
	case failure.Unauthenticated:
		status = http.StatusUnauthorized
	case failure.PermissionDenied:
		status = http.StatusForbidden
	case failure.RetryableDependency:
		status = http.StatusBadGateway
	}
	http.Error(writer, err.Error(), status)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
