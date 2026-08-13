package search

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
