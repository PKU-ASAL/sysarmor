package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

const FeatureSchemaV1 = "FeatureSchemaV1"

type Bundle struct {
	ModelRef      string
	ModelVersion  string
	ModelDigest   string
	FeatureSchema string
	Mean          []float32
	Scale         []float32
	Threshold     float32
}

type Detector struct{ bundle Bundle }

func NewDetector(bundle Bundle) (*Detector, error) {
	if err := validate(bundle); err != nil {
		return nil, err
	}
	return &Detector{bundle: cloneBundle(bundle)}, nil
}

func (detector *Detector) Process(event domainevent.Event) []*domaindetection.Signal {
	if detector == nil {
		return nil
	}
	score := detector.score(event)
	if score < detector.bundle.Threshold {
		return nil
	}
	return []*domaindetection.Signal{detector.signal(event, score)}
}

func (detector *Detector) score(event domainevent.Event) float32 {
	features := Features(event)
	var distance float32
	for index, feature := range features {
		z := (feature - detector.bundle.Mean[index]) / detector.bundle.Scale[index]
		distance += z * z
	}
	return float32(math.Sqrt(float64(distance)))
}

func (detector *Detector) signal(event domainevent.Event, score float32) *domaindetection.Signal {
	baseRisk := uint32(math.Min(100, math.Max(1, float64(score*20))))
	hash := sha256.Sum256([]byte(event.ID + "|" + detector.bundle.ModelDigest + "|" + strconv.FormatFloat(float64(score), 'f', 6, 32)))
	signal := &domaindetection.Signal{
		ID: "sig-model-" + hex.EncodeToString(hash[:8]), Name: "model_anomaly",
		Where: domaindetection.SignalWhereEndpoint, Stage: domaindetection.SignalStageCandidate,
		DetectorKind: domaindetection.DetectorKindModel, BaseRisk: baseRisk, LocalRarity: score,
		LineageID: event.LineageID, EventRefs: []string{event.ID},
		ModelRef: detector.bundle.ModelRef, ModelVersion: detector.bundle.ModelVersion,
		ModelDigest: detector.bundle.ModelDigest, FeatureSchema: detector.bundle.FeatureSchema,
		Confidence: 80, Mode: "shadow", Entities: entities(event), Labels: cloneLabels(event.Labels),
	}
	return signal
}

func Features(event domainevent.Event) []float32 {
	return []float32{
		behaviorCode(event.Behavior), float32(len(event.Subject.Argv)) / 8,
		boolFeature(event.SubjectPresent), boolFeature(event.ParentStableID != ""),
		boolFeature(event.Object.FilePath != ""), boolFeature(event.Object.SocketAddress != ""),
	}
}

func behaviorCode(value string) float32 {
	value = strings.TrimSpace(value)
	if value == "" {
		return -1
	}
	hash := uint32(2166136261)
	for _, value := range []byte(value) {
		hash = (hash ^ uint32(value)) * 16777619
	}
	return float32(hash%16) / 15
}

func boolFeature(value bool) float32 {
	if value {
		return 1
	}
	return 0
}

func entities(event domainevent.Event) []domaindetection.Entity {
	var result []domaindetection.Entity
	if event.Subject.StableID != "" {
		result = append(result, domaindetection.Entity{Kind: "process", Key: event.Subject.StableID, Role: "subject"})
	}
	if event.Object.FilePath != "" {
		result = append(result, domaindetection.Entity{Kind: "file", Key: event.Object.FilePath, Role: "object"})
	}
	if event.Object.SocketAddress != "" {
		result = append(result, domaindetection.Entity{Kind: "socket", Key: event.Object.SocketAddress, Role: "object"})
	}
	return result
}

func validate(bundle Bundle) error {
	if strings.TrimSpace(bundle.ModelRef) == "" || strings.TrimSpace(bundle.ModelVersion) == "" || strings.TrimSpace(bundle.ModelDigest) == "" {
		return fmt.Errorf("model provenance is required")
	}
	if bundle.FeatureSchema != FeatureSchemaV1 || len(bundle.Mean) != 6 || len(bundle.Scale) != 6 || bundle.Threshold <= 0 || !finite(bundle.Threshold) {
		return fmt.Errorf("unsupported model bundle schema")
	}
	for _, mean := range bundle.Mean {
		if !finite(mean) {
			return fmt.Errorf("model mean must be finite")
		}
	}
	for _, scale := range bundle.Scale {
		if scale <= 0 || !finite(scale) {
			return fmt.Errorf("model scale must be finite and positive")
		}
	}
	return nil
}

func finite(value float32) bool {
	return !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
}

func cloneBundle(bundle Bundle) Bundle {
	bundle.Mean = append([]float32(nil), bundle.Mean...)
	bundle.Scale = append([]float32(nil), bundle.Scale...)
	return bundle
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
