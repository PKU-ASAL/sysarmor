package policy

import (
	"encoding/json"
	"testing"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func TestPolicyDocumentRoundTripPreservesPublishedContract(t *testing.T) {
	input := []byte(`{"policy_id":"p1","version":7,"tenant_id":"t1","mode":"observe","published":true,"telemetry":{"max_batch_items":256}}`)
	decoded, err := DecodePolicyDocument(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := EncodePolicyDocument(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document["telemetry"]; !ok {
		t.Fatal("missing telemetry")
	}
	if _, legacy := document["data_plane"]; legacy {
		t.Fatal("legacy data_plane emitted")
	}
}

func TestDetectionProtoCopiesDomainParameters(t *testing.T) {
	value := domainpolicy.Policy{
		EndpointRules: []string{"endpoint-a"}, CloudRules: []string{"cloud-a"},
		Converge: &domainpolicy.ConvergeParams{
			Mode: "rarity_structural", TopK: 8, MaxPathHops: 6,
			AdditiveRiskThreshold: 4, CrossLineage: true,
		},
		Rarity: &domainpolicy.RarityParams{
			CMSWidth: 64, CMSDepth: 4, BaselineWindowNS: 100,
		},
	}

	got := DetectionProto(value)
	if got.GetConverge().GetTopK() != 8 || got.GetConverge().GetAdditiveRiskThreshold() != 4 {
		t.Fatalf("converge = %+v", got.GetConverge())
	}
	if got.GetRarity().GetCmsWidth() != 64 || got.GetRarity().GetBaselineWindowNs() != 100 {
		t.Fatalf("rarity = %+v", got.GetRarity())
	}
}
