package kafka

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	streamingv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/streaming/v1"
	"google.golang.org/protobuf/proto"
)

func TestEncodePolicySnapshotUsesPublishedIdentityAndDetection(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	payload, err := encodePolicySnapshot(ports.PolicySnapshot{TenantID: tenantID, PolicyID: policy.ID("policy-a"), Version: 7, Document: []byte(`{"cloud_rules":["cloud-a"],"converge":{"mode":"rarity_structural","top_k":8,"max_path_hops":6,"cross_lineage":true},"rarity":{"cms_width":1024,"cms_depth":4}}`)})
	if err != nil {
		t.Fatal(err)
	}
	var snapshot streamingv1.DetectionPolicySnapshot
	if err := proto.Unmarshal(payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.GetPolicyId() != "policy-a" || snapshot.GetPolicyVersion() != 7 || len(snapshot.GetDetection().GetCloudRules()) != 1 || snapshot.GetDetection().GetConverge().GetTopK() != 8 || snapshot.GetDetection().GetRarity().GetCmsWidth() != 1024 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}
