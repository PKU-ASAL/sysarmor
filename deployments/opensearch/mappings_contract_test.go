package opensearch_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestIncidentContributingSignalLocalRarityIsFloat(t *testing.T) {
	raw, err := os.ReadFile("mappings/incidents-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Mappings struct {
			Properties map[string]struct {
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
			} `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}

	got := document.Mappings.Properties["contributingSignals"].Properties["localRarity"].Type
	if got != "float" {
		t.Fatalf("contributingSignals.localRarity type = %q, want float", got)
	}
}
