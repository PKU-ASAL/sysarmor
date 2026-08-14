package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestMergeReleaseContentPreservesUserConfig(t *testing.T) {
	existing := []byte(`agent:
  label.owner: platform
local:
  state_path: /custom/state
sensor:
  backend: tetragon
  mode: managed
  scope:
    type: container
    selector: exact-container
telemetry:
  max_batch_items: 17
  max_batch_bytes: 64KiB
  flush_interval: 3s
policy:
  path: /custom/policy.json
content:
  default_path: /old/default
  path: /custom/content
  trust_keys: "old=key"
`)
	release := []byte(`local:
  state_path: /var/lib/sysarmor/agent
sensor:
  backend: tetragon
  mode: managed
policy:
  path: /etc/sysarmor/agent/policy.json
content:
  default_path: /opt/sysarmor/agent/content/default
  path: /var/lib/sysarmor/agent/content
  trust_keys: "release=new-key"
`)

	merged, err := MergeReleaseContent(existing, release)
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range [][]byte{[]byte("label.owner: platform"), []byte("selector: exact-container"), []byte("max_batch_items: 17"), []byte(`path: "/custom/content"`)} {
		if !bytes.Contains(merged, preserved) {
			t.Fatalf("merged config missing preserved value %q:\n%s", preserved, merged)
		}
	}
	for _, replaced := range [][]byte{[]byte(`default_path: "/opt/sysarmor/agent/content/default"`), []byte(`trust_keys: "release=new-key"`)} {
		if !bytes.Contains(merged, replaced) {
			t.Fatalf("merged config missing release value %q:\n%s", replaced, merged)
		}
	}
	if bytes.Contains(merged, []byte("old=key")) || bytes.Count(merged, []byte("content:\n")) != 1 {
		t.Fatalf("merged content block is not replaced exactly once:\n%s", merged)
	}
}

func TestMergeReleaseContentRejectsDuplicateContentSections(t *testing.T) {
	existing := []byte("local:\n  state_path: /var/lib/sysarmor/agent\nsensor:\n  backend: tetragon\n  mode: managed\npolicy:\n  path: /etc/sysarmor/agent/policy.json\ncontent:\n  trust_keys: first=key\ncontent:\n  trust_keys: second=key\n")
	release := []byte("local:\n  state_path: /var/lib/sysarmor/agent\nsensor:\n  backend: tetragon\n  mode: managed\npolicy:\n  path: /etc/sysarmor/agent/policy.json\ncontent:\n  default_path: /opt/sysarmor/agent/content/default\n  trust_keys: release=key\n")
	if _, err := MergeReleaseContent(existing, release); err == nil || !strings.Contains(err.Error(), "duplicate section") {
		t.Fatalf("MergeReleaseContent() error = %v, want duplicate section", err)
	}
}
