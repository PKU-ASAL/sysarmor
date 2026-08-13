package matcher

import (
	"fmt"
	"testing"
)

func BenchmarkPrefixMatcher(b *testing.B) {
	for _, strategy := range benchmarkStrategies() {
		b.Run(string(strategy), func(b *testing.B) {
			SetDefaultStrategy(strategy)
			b.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })
			for _, count := range []int{4, 16, 64, 256, 1024} {
				b.Run(fmt.Sprintf("patterns_%d_miss", count), func(b *testing.B) {
					m := NewPrefix(benchPrefixes(count))
					value := "/var/log/application/current/request.log"
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
				b.Run(fmt.Sprintf("patterns_%d_hit", count), func(b *testing.B) {
					m := NewPrefix(benchPrefixes(count))
					value := fmt.Sprintf("/bench/path/%04d/payload", count-1)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
			}
		})
	}
}

func BenchmarkExactMatcher(b *testing.B) {
	for _, strategy := range benchmarkStrategies() {
		b.Run(string(strategy), func(b *testing.B) {
			SetDefaultStrategy(strategy)
			b.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })
			for _, count := range []int{4, 16, 64, 256, 1024} {
				b.Run(fmt.Sprintf("patterns_%d", count), func(b *testing.B) {
					m := NewExact(benchPorts(count))
					value := fmt.Sprintf("%d", 10000+count-1)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
			}
		})
	}
}

func BenchmarkContainsMatcher(b *testing.B) {
	for _, strategy := range benchmarkStrategies() {
		b.Run(string(strategy), func(b *testing.B) {
			SetDefaultStrategy(strategy)
			b.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })
			for _, count := range []int{4, 16, 64, 256, 1024} {
				b.Run(fmt.Sprintf("patterns_%d_miss", count), func(b *testing.B) {
					m := NewContains(benchTokens(count))
					value := "/usr/bin/python app.py --serve"
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
				b.Run(fmt.Sprintf("patterns_%d_hit", count), func(b *testing.B) {
					m := NewContains(benchTokens(count))
					value := fmt.Sprintf("/bin/sh -c token-%04d", count-1)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
			}
		})
	}
}

func BenchmarkSuffixMatcher(b *testing.B) {
	for _, strategy := range benchmarkStrategies() {
		b.Run(string(strategy), func(b *testing.B) {
			SetDefaultStrategy(strategy)
			b.Cleanup(func() { SetDefaultStrategy(StrategyLinear) })
			for _, count := range []int{4, 16, 64, 256, 1024} {
				b.Run(fmt.Sprintf("patterns_%d_miss", count), func(b *testing.B) {
					m := NewSuffix(benchSuffixes(count))
					value := "/var/log/application/current/request.log"
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
				b.Run(fmt.Sprintf("patterns_%d_hit", count), func(b *testing.B) {
					m := NewSuffix(benchSuffixes(count))
					value := fmt.Sprintf("/tmp/payload.%04d", count-1)
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_ = m.Match(value)
					}
				})
			}
		})
	}
}

func benchmarkStrategies() []Strategy {
	return []Strategy{StrategyLinear, StrategyOptimized}
}

func benchPrefixes(count int) []string {
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		values = append(values, fmt.Sprintf("/bench/path/%04d/", i))
	}
	return values
}

func benchSuffixes(count int) []string {
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		values = append(values, fmt.Sprintf(".%04d", i))
	}
	return values
}

func benchPorts(count int) []string {
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		values = append(values, fmt.Sprintf("%d", 10000+i))
	}
	return values
}

func benchTokens(count int) []string {
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		values = append(values, fmt.Sprintf("token-%04d", i))
	}
	return values
}
