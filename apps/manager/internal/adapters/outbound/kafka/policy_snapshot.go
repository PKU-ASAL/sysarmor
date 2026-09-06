package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	policyv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/policy/v1"
	streamingv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/streaming/v1"
	"google.golang.org/protobuf/proto"
)

const PolicySnapshotTopic = "sysarmor.control.policy.endpoint.published.v1"

var knownDetectors = map[string]struct{}{
	"rule-correlation-v1": {},
	"nodlink":             {},
}

const retiredEvidenceProvider = "provenance-shortest-path-v1"

type PolicySnapshotPublisher struct{ writer *kafkago.Writer }

func NewPolicySnapshotPublisher(brokers []string) (*PolicySnapshotPublisher, error) {
	publisher, err := NewBatchPublisher(brokers)
	if err != nil {
		return nil, err
	}
	return &PolicySnapshotPublisher{writer: publisher.writer}, nil
}

func (publisher *PolicySnapshotPublisher) PublishPolicySnapshot(ctx context.Context, item ports.PolicySnapshot) error {
	payload, err := encodePolicySnapshot(item)
	if err != nil {
		return err
	}
	key := item.TenantID.String() + ":" + item.PolicyID.String()
	return publisher.writer.WriteMessages(ctx, kafkago.Message{Topic: PolicySnapshotTopic, Key: []byte(key), Value: payload})
}

func (publisher *PolicySnapshotPublisher) Close() error { return publisher.writer.Close() }

func encodePolicySnapshot(item ports.PolicySnapshot) ([]byte, error) {
	var document struct {
		CloudRules []string `json:"cloud_rules"`
		Detectors  []string `json:"detectors"`
		Converge   struct {
			Mode                  string `json:"mode"`
			TopK                  uint32 `json:"top_k"`
			MaxPathHops           uint32 `json:"max_path_hops"`
			AdditiveRiskThreshold uint32 `json:"additive_risk_threshold"`
			CrossLineage          bool   `json:"cross_lineage"`
			StateRetentionNS      uint64 `json:"state_retention_ns"`
		} `json:"converge"`
		Rarity struct {
			CMSWidth         uint32 `json:"cms_width"`
			CMSDepth         uint32 `json:"cms_depth"`
			BaselineWindowNS uint64 `json:"baseline_window_ns"`
		} `json:"rarity"`
	}
	if err := json.Unmarshal(item.Document, &document); err != nil {
		return nil, fmt.Errorf("decode policy document: %w", err)
	}
	detectors, err := normalizeDetectors(document.Detectors)
	if err != nil {
		return nil, err
	}
	detection := &policyv1.DetectionPolicy{
		CloudRules: document.CloudRules,
		Detectors:  detectors,
		Converge: &policyv1.ConvergeParams{
			Mode: document.Converge.Mode, TopK: document.Converge.TopK,
			MaxPathHops:           document.Converge.MaxPathHops,
			AdditiveRiskThreshold: document.Converge.AdditiveRiskThreshold,
			CrossLineage:          document.Converge.CrossLineage,
			StateRetentionNs:      document.Converge.StateRetentionNS,
		},
		Rarity: &policyv1.RarityParams{
			CmsWidth: document.Rarity.CMSWidth, CmsDepth: document.Rarity.CMSDepth,
			BaselineWindowNs: document.Rarity.BaselineWindowNS,
		},
	}
	snapshot := &streamingv1.DetectionPolicySnapshot{
		SchemaVersion: "sysarmor.detection.policy/v1",
		TenantId:      item.TenantID.String(), PolicyId: item.PolicyID.String(), PolicyVersion: uint64(item.Version), Detection: detection,
	}
	return proto.Marshal(snapshot)
}

func validateDetectors(detectors []string) error {
	_, err := normalizeDetectors(detectors)
	return err
}

func normalizeDetectors(detectors []string) ([]string, error) {
	seen := make(map[string]struct{}, len(detectors))
	normalized := make([]string, 0, len(detectors))
	for _, name := range detectors {
		if name == "" {
			return nil, fmt.Errorf("detector name must not be empty")
		}
		if name == retiredEvidenceProvider {
			continue
		}
		if _, ok := knownDetectors[name]; !ok {
			return nil, fmt.Errorf("unknown detector %q; known detectors: %v", name, sortedDetectorNames())
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate detector %q", name)
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
	}
	return normalized, nil
}

func sortedDetectorNames() []string {
	names := make([]string, 0, len(knownDetectors))
	for name := range knownDetectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
