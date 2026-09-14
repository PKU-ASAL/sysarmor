package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type encoder struct{ data []byte }

func DigestSignals(signals []domaintelemetry.Signal, context []string) string {
	encoded := make([][]byte, 0, len(signals))
	for _, signal := range signals {
		encoded = append(encoded, encodeSignal(signal))
	}
	sort.Slice(encoded, func(i, j int) bool { return bytes.Compare(encoded[i], encoded[j]) < 0 })
	context = append([]string(nil), context...)
	sort.Strings(context)
	var value encoder
	value.strings(context)
	for _, signal := range encoded {
		value.bytes(signal)
	}
	digest := sha256.Sum256(value.data)
	return hex.EncodeToString(digest[:])
}

func encodeSignal(signal domaintelemetry.Signal) []byte {
	var value encoder
	value.string(signal.ID)
	value.string(signal.Name)
	value.int32(int32(signal.Where))
	value.uint32(signal.BaseRisk)
	value.uint32(math.Float32bits(signal.LocalRarity))
	value.uint32(math.Float32bits(signal.GlobalRarity))
	value.string(signal.LineageID)
	value.entities(signal.Entities)
	value.strings(signal.EventRefs)
	value.strings(signal.SignalRefs)
	value.int32(int32(signal.Stage))
	value.int32(int32(signal.DetectorKind))
	value.evidence(signal.Evidence)
	value.boolean(signal.CrossLineage)
	value.response(signal.Response)
	value.string(signal.RuleID)
	value.uint64(signal.RuleVersion)
	value.string(signal.RulesetRef)
	value.string(signal.ModelRef)
	value.string(signal.ModelVersion)
	value.string(signal.ModelDigest)
	value.string(signal.FeatureSchema)
	value.contents(signal.ContextRefs)
	value.contents(signal.IOCRefs)
	value.string(signal.Severity)
	value.uint32(signal.Confidence)
	value.string(signal.Mode)
	value.labels(signal.Labels)
	return value.data
}

func (value *encoder) evidence(evidence *domaintelemetry.EvidenceBundle) {
	value.boolean(evidence != nil)
	if evidence == nil {
		return
	}
	value.string(evidence.ID)
	value.strings(evidence.EventRefs)
	value.strings(evidence.RawRefs)
	value.entities(evidence.Entities)
	value.string(evidence.Summary)
}

func (value *encoder) response(response *domaintelemetry.ResponseIntent) {
	value.boolean(response != nil)
	if response == nil {
		return
	}
	value.string(response.Intent)
	value.string(response.RecommendedAction)
	value.uint32(response.Confidence)
	value.string(response.Reason)
}

func (value *encoder) entities(entities []domaintelemetry.Entity) {
	entities = append([]domaintelemetry.Entity(nil), entities...)
	sort.Slice(entities, func(i, j int) bool {
		return entityLess(entities[i], entities[j])
	})
	value.uint64(uint64(len(entities)))
	for _, entity := range entities {
		value.string(entity.Kind)
		value.string(entity.Key)
		value.string(entity.Role)
	}
}

func entityLess(left, right domaintelemetry.Entity) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	if left.Key != right.Key {
		return left.Key < right.Key
	}
	return left.Role < right.Role
}

func (value *encoder) contents(contents []domaintelemetry.ContentRef) {
	value.uint64(uint64(len(contents)))
	for _, content := range contents {
		value.string(content.Ref)
		value.string(content.Version)
		value.string(content.Digest)
	}
}

func (value *encoder) labels(labels map[string]string) {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	value.uint64(uint64(len(keys)))
	for _, key := range keys {
		value.string(key)
		value.string(labels[key])
	}
}

func (value *encoder) strings(items []string) {
	value.uint64(uint64(len(items)))
	for _, item := range items {
		value.string(item)
	}
}

func (value *encoder) string(item string) { value.bytes([]byte(item)) }

func (value *encoder) bytes(item []byte) {
	value.uint64(uint64(len(item)))
	value.data = append(value.data, item...)
}

func (value *encoder) boolean(item bool) {
	if item {
		value.data = append(value.data, 1)
		return
	}
	value.data = append(value.data, 0)
}

func (value *encoder) int32(item int32) {
	value.data = binary.LittleEndian.AppendUint32(value.data, uint32(item))
}

func (value *encoder) uint32(item uint32) {
	value.data = binary.LittleEndian.AppendUint32(value.data, item)
}

func (value *encoder) uint64(item uint64) {
	value.data = binary.LittleEndian.AppendUint64(value.data, item)
}
