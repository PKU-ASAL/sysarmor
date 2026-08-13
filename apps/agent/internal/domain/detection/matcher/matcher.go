package matcher

import (
	"sort"
	"strings"
	"sync/atomic"
)

// Matcher is the stable string-matching boundary used by compiled endpoint
// rules. The initial implementations are deliberately simple baselines; faster
// trie/Aho-Corasick/etc. implementations can replace them behind this interface.
type Matcher interface {
	Match(string) bool
}

type Strategy string

const (
	StrategyLinear    Strategy = "linear"
	StrategyOptimized Strategy = "optimized"
)

var defaultStrategy atomic.Value

func init() {
	defaultStrategy.Store(StrategyLinear)
}

func SetDefaultStrategy(strategy Strategy) {
	switch strategy {
	case StrategyLinear, StrategyOptimized:
		defaultStrategy.Store(strategy)
	default:
		defaultStrategy.Store(StrategyLinear)
	}
}

func DefaultStrategy() Strategy {
	strategy, ok := defaultStrategy.Load().(Strategy)
	if !ok {
		return StrategyLinear
	}
	return strategy
}

type emptyMatcher struct{}

func (emptyMatcher) Match(string) bool { return false }

type exactMatcher struct {
	values map[string]struct{}
}

func NewExact(values []string) Matcher {
	values = normalize(values)
	if len(values) == 0 {
		return emptyMatcher{}
	}
	m := exactMatcher{values: make(map[string]struct{}, len(values))}
	for _, value := range values {
		m.values[value] = struct{}{}
	}
	return m
}

func (m exactMatcher) Match(value string) bool {
	_, ok := m.values[value]
	return ok
}

type prefixMatcher struct {
	prefixes []string
}

func NewPrefix(prefixes []string) Matcher {
	prefixes = normalize(prefixes)
	if len(prefixes) == 0 {
		return emptyMatcher{}
	}
	if useOptimized(len(prefixes)) {
		return newBucketPrefixMatcher(prefixes)
	}
	return prefixMatcher{prefixes: prefixes}
}

func (m prefixMatcher) Match(value string) bool {
	for _, prefix := range m.prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

type suffixMatcher struct {
	suffixes []string
}

func NewSuffix(suffixes []string) Matcher {
	suffixes = normalize(suffixes)
	if len(suffixes) == 0 {
		return emptyMatcher{}
	}
	if useOptimized(len(suffixes)) {
		return newBucketSuffixMatcher(suffixes)
	}
	return suffixMatcher{suffixes: suffixes}
}

func (m suffixMatcher) Match(value string) bool {
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

type containsMatcher struct {
	patterns []string
}

func NewContains(patterns []string) Matcher {
	patterns = normalize(patterns)
	if len(patterns) == 0 {
		return emptyMatcher{}
	}
	if useOptimized(len(patterns)) {
		return newBucketContainsMatcher(patterns)
	}
	return containsMatcher{patterns: patterns}
}

func (m containsMatcher) Match(value string) bool {
	for _, pattern := range m.patterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}

type bucketPrefixMatcher struct {
	prefixes []string
	index    int
	buckets  [256][]string
}

func newBucketPrefixMatcher(prefixes []string) Matcher {
	m := &bucketPrefixMatcher{prefixes: prefixes, index: bestSharedIndex(prefixes, false)}
	for _, prefix := range prefixes {
		if len(prefix) <= m.index {
			continue
		}
		key := prefix[m.index]
		m.buckets[key] = append(m.buckets[key], prefix)
	}
	for i := range m.buckets {
		sortByLengthDesc(m.buckets[i])
	}
	return m
}

func (m *bucketPrefixMatcher) Match(value string) bool {
	if len(value) <= m.index {
		return false
	}
	for _, prefix := range m.buckets[value[m.index]] {
		if len(prefix) <= len(value) && strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

type bucketSuffixMatcher struct {
	suffixes []string
	index    int
	buckets  [256][]string
}

func newBucketSuffixMatcher(suffixes []string) Matcher {
	m := &bucketSuffixMatcher{suffixes: suffixes, index: bestSharedIndex(suffixes, true)}
	for _, suffix := range suffixes {
		if len(suffix) <= m.index {
			continue
		}
		key := suffix[len(suffix)-1-m.index]
		m.buckets[key] = append(m.buckets[key], suffix)
	}
	for i := range m.buckets {
		sortByLengthDesc(m.buckets[i])
	}
	return m
}

func (m *bucketSuffixMatcher) Match(value string) bool {
	if len(value) <= m.index {
		return false
	}
	for _, suffix := range m.buckets[value[len(value)-1-m.index]] {
		if len(suffix) <= len(value) && strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

type bucketContainsMatcher struct {
	patterns []string
	buckets  [256][]string
}

func newBucketContainsMatcher(patterns []string) Matcher {
	m := &bucketContainsMatcher{patterns: patterns}
	frequencies := byteFrequencies(patterns)
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		key := rarestGlobalByte(pattern, frequencies)
		m.buckets[key] = append(m.buckets[key], pattern)
	}
	for i := range m.buckets {
		sortByLengthDesc(m.buckets[i])
	}
	return m
}

func (m *bucketContainsMatcher) Match(value string) bool {
	if value == "" {
		return false
	}
	var seen [256]bool
	for i := 0; i < len(value); i++ {
		key := value[i]
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, pattern := range m.buckets[key] {
			if len(pattern) <= len(value) && strings.Contains(value, pattern) {
				return true
			}
		}
	}
	return false
}

func useOptimized(size int) bool {
	switch DefaultStrategy() {
	case StrategyOptimized:
		return true
	default:
		return false
	}
}

func sortByLengthDesc(values []string) {
	sort.Slice(values, func(i, j int) bool {
		return len(values[i]) > len(values[j])
	})
}

func byteFrequencies(values []string) [256]int {
	var out [256]int
	for _, value := range values {
		var seen [256]bool
		for i := 0; i < len(value); i++ {
			key := value[i]
			if seen[key] {
				continue
			}
			seen[key] = true
			out[key]++
		}
	}
	return out
}

func rarestGlobalByte(value string, frequencies [256]int) byte {
	best := value[0]
	bestCount := frequencies[best]
	for i := 1; i < len(value); i++ {
		count := frequencies[value[i]]
		if count < bestCount {
			best = value[i]
			bestCount = count
			if bestCount == 1 {
				return best
			}
		}
	}
	return best
}

func bestSharedIndex(values []string, reverse bool) int {
	bestIndex := 0
	bestDistinct := 0
	maxLen := shortestLength(values)
	if maxLen > 32 {
		maxLen = 32
	}
	for index := 0; index < maxLen; index++ {
		var seen [256]bool
		distinct := 0
		for _, value := range values {
			if len(value) <= index {
				continue
			}
			pos := index
			if reverse {
				pos = len(value) - 1 - index
			}
			key := value[pos]
			if seen[key] {
				continue
			}
			seen[key] = true
			distinct++
		}
		if distinct > bestDistinct {
			bestIndex = index
			bestDistinct = distinct
		}
	}
	return bestIndex
}

func shortestLength(values []string) int {
	if len(values) == 0 {
		return 0
	}
	shortest := len(values[0])
	for _, value := range values[1:] {
		if len(value) < shortest {
			shortest = len(value)
		}
	}
	return shortest
}

func normalize(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
