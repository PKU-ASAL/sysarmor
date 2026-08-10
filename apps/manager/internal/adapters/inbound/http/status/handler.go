package status

import (
	"encoding/json"
	"net/http"
)

type StorageStatus struct {
	Backend               string `json:"backend"`
	Path                  string `json:"path,omitempty"`
	StateVersion          int    `json:"state_version"`
	MigrationVersion      int    `json:"migration_version"`
	PostgresSchemaVersion int    `json:"postgres_schema_version"`
}

type Handler struct{ status StorageStatus }

func NewHandler(status StorageStatus) *Handler { return &Handler{status: status} }

func (handler *Handler) Health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, struct {
		OK    bool          `json:"ok"`
		Store StorageStatus `json:"store"`
	}{OK: true, Store: handler.status})
}

func (handler *Handler) StoreStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(writer, handler.status)
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
