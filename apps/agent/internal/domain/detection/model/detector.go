package model

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"sync"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

const (
	materialScoreIncrease = 0.25
	maxEmissionStates     = 4096
)

type emissionState struct {
	revision uint64
	score    float32
}

type Detector struct {
	bundle    Bundle
	embedding compiledEmbedding
	mu        sync.Mutex
	emitted   map[string]emissionState
}

func NewDetector(bundle Bundle) (*Detector, error) {
	if err := validateBundle(bundle); err != nil {
		return nil, err
	}
	cloned := cloneBundle(bundle)
	return &Detector{bundle: cloned, embedding: compileEmbedding(cloned.Embedding), emitted: make(map[string]emissionState)}, nil
}

func (detector *Detector) Score(profile domainprocess.Snapshot) float32 {
	if detector == nil {
		return 0
	}
	vector := processVector(profileFeatures(profile, detector.bundle.Rarity), detector.embedding)
	reconstruction := reconstruct(vector, detector.bundle.VAE)
	errorValue := reconstructionError(vector, reconstruction)
	stability := lookupWeight(processName(profile.Binary), detector.bundle.Stability.Processes, detector.bundle.Stability.Default)
	return float32(math.Log(math.Max(float64(errorValue/stability), 1e-12)))
}

func (detector *Detector) Process(profile domainprocess.Snapshot) []*domaindetection.Signal {
	if detector == nil || profile.StableID == "" {
		return nil
	}
	score := detector.Score(profile)
	if score < detector.bundle.Threshold {
		detector.forget(profile.StableID)
		return nil
	}
	if !detector.shouldEmit(profile, score) {
		return nil
	}
	return []*domaindetection.Signal{detector.candidate(profile, score)}
}

func (detector *Detector) shouldEmit(profile domainprocess.Snapshot, score float32) bool {
	detector.mu.Lock()
	defer detector.mu.Unlock()
	previous, exists := detector.emitted[profile.StableID]
	emit := !exists || profile.State == domainprocess.StateExited ||
		(profile.Revision != previous.revision && score-previous.score >= materialScoreIncrease)
	if profile.State == domainprocess.StateExited {
		delete(detector.emitted, profile.StableID)
	} else if emit {
		detector.emitted[profile.StableID] = emissionState{revision: profile.Revision, score: score}
		detector.evictEmissionState(profile.StableID)
	}
	return emit
}

func (detector *Detector) evictEmissionState(current string) {
	if len(detector.emitted) <= maxEmissionStates {
		return
	}
	victim := ""
	for stableID := range detector.emitted {
		if stableID != current && (victim == "" || stableID < victim) {
			victim = stableID
		}
	}
	delete(detector.emitted, victim)
}

func (detector *Detector) forget(stableID string) {
	detector.mu.Lock()
	delete(detector.emitted, stableID)
	detector.mu.Unlock()
}

func (detector *Detector) candidate(profile domainprocess.Snapshot, score float32) *domaindetection.Signal {
	material := profile.StableID + "|" + strconv.FormatUint(profile.Revision, 10) + "|" +
		detector.bundle.ModelDigest + "|" + strconv.FormatFloat(float64(score), 'f', 6, 32)
	hash := sha256.Sum256([]byte(material))
	return &domaindetection.Signal{
		ID: "sig-model-" + hex.EncodeToString(hash[:8]), Name: "model_anomaly",
		Where: domaindetection.SignalWhereEndpoint, Stage: domaindetection.SignalStageCandidate,
		DetectorKind: domaindetection.DetectorKindModel, BaseRisk: risk(score), LocalRarity: score,
		LineageID: profile.LineageID, EventRefs: append([]string(nil), profile.EventRefs...),
		ModelRef: detector.bundle.ModelRef, ModelVersion: detector.bundle.ModelVersion,
		ModelDigest: detector.bundle.ModelDigest, FeatureSchema: detector.bundle.FeatureSchema,
		Confidence: 80, Mode: "shadow", Entities: profileEntities(profile), Labels: cloneLabels(profile.Labels),
	}
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

func risk(score float32) uint32 {
	return uint32(math.Min(100, math.Max(1, float64(score*20))))
}

func profileEntities(profile domainprocess.Snapshot) []domaindetection.Entity {
	result := []domaindetection.Entity{{Kind: "process", Key: profile.StableID, Role: "subject"}}
	if profile.ParentStableID != "" {
		result = append(result, domaindetection.Entity{Kind: "process", Key: profile.ParentStableID, Role: "parent"})
	}
	for _, path := range profile.Files {
		result = append(result, domaindetection.Entity{Kind: "file", Key: path, Role: "object"})
	}
	for _, address := range profile.Networks {
		result = append(result, domaindetection.Entity{Kind: "socket", Key: address, Role: "object"})
	}
	return result
}
