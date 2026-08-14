package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryExampleConfigLoads(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "..", "..", "..", "configs", "agent.example.yaml"))
	if err != nil {
		t.Fatalf("LoadFile(agent.example.yaml) error = %v", err)
	}
	if cfg.Manager.Transport != "" || cfg.Local.StatePath != "/var/lib/sysarmor/agent" {
		t.Fatalf("example is not standalone: manager=%+v agent=%+v", cfg.Manager, cfg.Agent)
	}
	if cfg.Sensor.EventSource != "" {
		t.Fatalf("example event_source = %q, want managed mode empty source", cfg.Sensor.EventSource)
	}
	if cfg.Sensor.TetraPath == "" || cfg.Sensor.TetragonPath == "" {
		t.Fatalf("example managed tetragon paths missing: %+v", cfg.Sensor)
	}
	if cfg.Runtime.FeatureFlags.MatcherStrategy != "linear" {
		t.Fatalf("example matcher strategy = %q, want linear", cfg.Runtime.FeatureFlags.MatcherStrategy)
	}
}

func TestLoadFileParsesConvergedRuntimeConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	write(t, path, `
local:
  state_path: /var/lib/sysarmor/agent
  storage:
    max_bytes: 10GiB
    min_free_bytes: 2GiB
    segment_size: 64MiB
    signal_max_count: 100000
  export:
    retry_initial: 1s
    retry_max: 30s
    request_timeout: 10s
    max_inflight: 1
    wire_compression: none
telemetry:
  max_batch_items: 256
  max_batch_bytes: 256KiB
  flush_interval: 1s
sensor:
  backend: fake
policy:
  path: /etc/sysarmor/agent/policy.json
content:
  default_path: /opt/sysarmor/agent/content/default
  path: /var/lib/sysarmor/agent/content
`)
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Local.StatePath != "/var/lib/sysarmor/agent" || cfg.Local.Storage.SegmentSize != 64<<20 || cfg.Local.Export.MaxInflight != 1 {
		t.Fatalf("local config=%+v", cfg.Local)
	}
	if cfg.Telemetry.MaxBatchItems != 256 || cfg.Telemetry.MaxBatchBytes != 256<<10 || cfg.Policy.Path == "" {
		t.Fatalf("config=%+v", cfg)
	}
	if cfg.Sensor.PolicyPath != cfg.Policy.Path {
		t.Fatalf("sensor policy path = %q want %q", cfg.Sensor.PolicyPath, cfg.Policy.Path)
	}
	if cfg.Content.DefaultPath != "/opt/sysarmor/agent/content/default" || cfg.Content.Path != "/var/lib/sysarmor/agent/content" {
		t.Fatalf("content config = %+v", cfg.Content)
	}
}

func TestLoadFileRejectsLegacyRuntimeSections(t *testing.T) {
	for name, document := range map[string]string{
		"agent state path": "agent:\n  state_path: /tmp/state\n",
		"storage":          "storage:\n  max_bytes: 1GiB\n",
		"data plane":       "data_plane:\n  retry_initial: 1s\n",
		"telemetry name":   "telemetry:\n  batch_size: 10\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yaml")
			write(t, path, document)
			if _, err := LoadFile(path); err == nil {
				t.Fatal("legacy config accepted")
			}
		})
	}
}

func TestLoadFileRejectsLegacyCloudIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	write(t, path, `
agent:
  id: node-a
  host_id: node-a
  tenant_id: default
  token: dev-token

manager:
  address: 127.0.0.1:9443

sensor:
  backend: fake
  mode: managed
  policy_path: test/policies/collection.yaml

telemetry:
  max_batch_items: 256
  max_batch_bytes: 256KiB
  flush_interval: 1s

health:
  interval: 10s
`)
	if _, err := LoadFile(path); err == nil {
		t.Fatal("legacy cloud identity accepted")
	}
}

func TestSystemdUnitStartsAgentDaemon(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "deployments", "agent", "systemd", "sysarmor-agent.service"))
	if err != nil {
		t.Fatalf("ReadFile(systemd unit) error = %v", err)
	}
	unit := string(data)
	for _, want := range []string{
		"ExecStart=/opt/sysarmor/agent/bin/sysarmor-agent run --config /etc/sysarmor/agent/agent.yaml",
		"RuntimeDirectory=sysarmor/agent",
		"WorkingDirectory=/opt/sysarmor/agent",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("systemd unit missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "network-online.target") {
		t.Fatal("standalone service depends on network-online")
	}
}

func TestInstallCoreUsesUnifiedLayoutAndStartsService(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "..", "deployments", "agent")
	data, err := os.ReadFile(filepath.Join(root, "install-core.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installer := string(data)
	for _, want := range []string{
		`/etc/sysarmor/agent/agent.yaml`,
		`/etc/sysarmor/agent/policy.json`,
		`SYSARMOR_INSTALL_CTL_SOURCE`,
		`systemctl enable --now sysarmor-agent`,
		`wait_for_agent`,
	} {
		if !strings.Contains(installer, want) {
			t.Fatalf("installer missing %q", want)
		}
	}
	for _, name := range []string{"install-agent.sh", "install-release.sh"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "install-core.sh") {
			t.Fatalf("%s does not delegate to install-core.sh", name)
		}
	}
}

func TestReleaseBuilderPackagesAgentControlTool(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "deployments", "packages", "build-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	builder := string(data)
	for _, want := range []string{
		`CTL_BIN=`, `--ctl-bin "$CTL_BIN"`,
		`CONTENT_SIGNING_KEY=`, `--content-signing-key "$CONTENT_SIGNING_KEY"`, `--content-key-id "$CONTENT_KEY_ID"`,
	} {
		if !strings.Contains(builder, want) {
			t.Fatalf("release builder missing %q", want)
		}
	}
}

func TestStandaloneDeploymentConfigLoads(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "..", "..", "..", "deployments", "agent", "standalone.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Manager.Transport != "" || cfg.Local.Storage.MaxBytes != 10<<30 || cfg.Local.StatePath == "" {
		t.Fatalf("config=%+v", cfg)
	}
}
