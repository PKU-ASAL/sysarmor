package policy

import (
	"encoding/json"
	"strings"
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

func TestDecodePolicyDocumentRejectsMissingIdentity(t *testing.T) {
	tests := []struct {
		name     string
		document string
		field    string
	}{
		{name: "null document", document: `null`, field: "policy_id"},
		{name: "missing policy id", document: `{"version":1}`, field: "policy_id"},
		{name: "missing version", document: `{"policy_id":"policy-a"}`, field: "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodePolicyDocument([]byte(tt.document))
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error = %v, want field %q", err, tt.field)
			}
		})
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

func TestEndpointPolicyRoundTripPreservesLearningModelReference(t *testing.T) {
	input := []byte(`{
		"policy_id":"learning-a","version":3,
		"collection":{"behaviors":["process.exec"]},
		"detection":{"learning_model":{"ref":"model:process-profile-v2","version":"2","digest":"sha256:abc"}},
		"telemetry":{},"response":{}
	}`)

	decoded, err := DecodeEndpointPolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Detection.LearningModel == nil || decoded.Detection.LearningModel.Ref != "model:process-profile-v2" || decoded.Detection.LearningModel.Version != "2" {
		t.Fatalf("learning model = %+v", decoded.Detection.LearningModel)
	}
	output, err := EncodeEndpointPolicy(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), `"learning_model":{"ref":"model:process-profile-v2","version":"2","digest":"sha256:abc"}`) {
		t.Fatalf("encoded endpoint policy = %s", output)
	}
}

func TestEndpointPolicyRejectsIncompleteLearningModelReference(t *testing.T) {
	_, err := DecodeEndpointPolicy([]byte(`{
		"policy_id":"learning-a","version":3,
		"collection":{},"detection":{"learning_model":{"ref":"model:a","version":"2"}},
		"telemetry":{},"response":{}
	}`))
	if err == nil || !strings.Contains(err.Error(), "learning model") {
		t.Fatalf("error = %v", err)
	}
}
