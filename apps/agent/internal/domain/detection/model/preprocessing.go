package model

import (
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

type featureSentence struct {
	tokens []string
	weight float32
}

func profileFeatures(profile domainprocess.Snapshot, rarity Rarity) []featureSentence {
	resources := make([]featureSentence, 0, len(profile.Files)+len(profile.Networks))
	var resourceWeight float32
	for _, path := range profile.Files {
		weight := lookupWeight(path, rarity.Files, rarity.DefaultFile)
		resources = appendFeature(resources, naturalTokens(path), weight)
		resourceWeight += weight
	}
	for _, address := range profile.Networks {
		weight := lookupWeight(address, rarity.Networks, rarity.DefaultNetwork)
		resources = appendFeature(resources, naturalTokens(address), weight)
		resourceWeight += weight
	}
	commandWeight := (rarity.DefaultFile + rarity.DefaultNetwork) / 2
	if len(resources) > 0 {
		commandWeight = resourceWeight / float32(len(resources))
	}
	command := strings.Join(append([]string{profile.Binary}, profile.Argv...), " ")
	result := appendFeature(nil, naturalTokens(command), commandWeight)
	return append(result, resources...)
}

func appendFeature(target []featureSentence, tokens []string, weight float32) []featureSentence {
	if len(tokens) == 0 {
		return target
	}
	return append(target, featureSentence{tokens: tokens, weight: weight})
}

func naturalTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(current rune) bool {
		return !unicode.IsLetter(current) && !unicode.IsNumber(current)
	})
}

func processName(binary string) string {
	return strings.ToLower(filepath.Base(strings.TrimSpace(binary)))
}

func lookupWeight(value string, values []WeightedValue, fallback float32) float32 {
	index := sort.Search(len(values), func(index int) bool { return values[index].Value >= value })
	if index < len(values) && values[index].Value == value {
		return values[index].Weight
	}
	return fallback
}
