package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func assign(cfg *Config, section, key, value string) error {
	switch section {
	case "agent":
		labelKey, ok := strings.CutPrefix(key, "label.")
		if !ok || strings.TrimSpace(labelKey) == "" {
			return unknown(section, key)
		}
		if cfg.Agent.Labels == nil {
			cfg.Agent.Labels = map[string]string{}
		}
		cfg.Agent.Labels[strings.TrimSpace(labelKey)] = value
	case "local":
		if key != "state_path" {
			return unknown(section, key)
		}
		cfg.Local.StatePath = value
	case "local.storage":
		return assignLocalStorage(&cfg.Local.Storage, key, value)
	case "local.export":
		return assignLocalExport(&cfg.Local.Export, key, value)
	case "manager":
		if key != "tls_insecure" {
			return unknown(section, key)
		}
		insecure, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("manager.tls_insecure: %w", err)
		}
		cfg.Manager.TLSInsecure = insecure
	case "control":
		switch key {
		case "socket_path":
			cfg.Control.SocketPath = value
		default:
			return unknown(section, key)
		}
	case "runtime.feature_flags":
		switch key {
		case "matcher_strategy":
			cfg.Runtime.FeatureFlags.MatcherStrategy = value
		default:
			return unknown(section, key)
		}
	case "sensor":
		switch key {
		case "backend":
			cfg.Sensor.Backend = value
		case "mode":
			cfg.Sensor.Mode = value
		case "version":
			cfg.Sensor.Version = value
		case "bundle_dir":
			cfg.Sensor.BundleDir = value
		case "install_dir":
			cfg.Sensor.InstallDir = value
		case "tetra_path":
			cfg.Sensor.TetraPath = value
		case "tetragon_path":
			cfg.Sensor.TetragonPath = value
		case "event_transport":
			cfg.Sensor.EventTransport = value
		case "server_address":
			cfg.Sensor.ServerAddress = value
		case "cgroup_rate":
			cfg.Sensor.CgroupRate = value
		case "pprof_address":
			cfg.Sensor.PprofAddress = value
		case "gops_address":
			cfg.Sensor.GopsAddress = value
		case "process_cache_size":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("sensor.process_cache_size: %w", err)
			}
			cfg.Sensor.ProcessCacheSize = v
		case "data_cache_size":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("sensor.data_cache_size: %w", err)
			}
			cfg.Sensor.DataCacheSize = v
		case "event_queue_size":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("sensor.event_queue_size: %w", err)
			}
			cfg.Sensor.EventQueueSize = v
		case "rb_queue_size":
			cfg.Sensor.RBQueueSize = value
		case "btf_path":
			cfg.Sensor.BTFPath = value
		case "bpffs_path":
			cfg.Sensor.BPFFSPath = value
		case "require_btf":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("sensor.require_btf: %w", err)
			}
			cfg.Sensor.RequireBTF = b
		case "require_bpffs":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("sensor.require_bpffs: %w", err)
			}
			cfg.Sensor.RequireBPFFS = b
		case "event_source":
			cfg.Sensor.EventSource = value
		case "fake_startup_events":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("sensor.fake_startup_events: %w", err)
			}
			cfg.Sensor.FakeStartupEvents = v
		case "observe_only":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("sensor.observe_only: %w", err)
			}
			cfg.Sensor.ObserveOnly = b
		case "restart":
			cfg.Sensor.Restart = value
		case "max_restarts":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("sensor.max_restarts: %w", err)
			}
			cfg.Sensor.MaxRestarts = v
		case "max_parse_errors":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("sensor.max_parse_errors: %w", err)
			}
			cfg.Sensor.MaxParseErrors = v
		case "max_dropped_events":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("sensor.max_dropped_events: %w", err)
			}
			cfg.Sensor.MaxDroppedEvents = v
		case "restart_window":
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("sensor.restart_window: %w", err)
			}
			cfg.Sensor.RestartWindow = d
		default:
			return unknown(section, key)
		}
	case "sensor.scope":
		switch key {
		case "type":
			cfg.Sensor.Scope.Type = value
		case "selector":
			cfg.Sensor.Scope.Selector = value
		default:
			return unknown(section, key)
		}
	case "telemetry":
		switch key {
		case "max_batch_items":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("telemetry.max_batch_items: %w", err)
			}
			cfg.Telemetry.MaxBatchItems = v
		case "max_batch_bytes":
			v, err := parseByteSize(value)
			if err != nil {
				return fmt.Errorf("telemetry.max_batch_bytes: %w", err)
			}
			cfg.Telemetry.MaxBatchBytes = int(v)
		case "flush_interval":
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("telemetry.flush_interval: %w", err)
			}
			cfg.Telemetry.FlushInterval = d
		default:
			return unknown(section, key)
		}
	case "health":
		switch key {
		case "interval":
			d, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("health.interval: %w", err)
			}
			cfg.Health.Interval = d
		default:
			return unknown(section, key)
		}
	case "policy":
		switch key {
		case "path":
			cfg.Policy.Path = value
		default:
			return unknown(section, key)
		}
	case "content":
		switch key {
		case "default_path":
			cfg.Content.DefaultPath = value
		case "path":
			cfg.Content.Path = value
		case "trust_keys":
			cfg.Content.TrustKeys = value
		default:
			return unknown(section, key)
		}
	case "learning":
		switch key {
		case "model_path":
			cfg.Learning.ModelPath = value
		case "trust_keys":
			cfg.Learning.TrustKeys = value
		default:
			return unknown(section, key)
		}
	case "resource":
		switch key {
		case "max_active_cep_groups":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("resource.max_active_cep_groups: %w", err)
			}
			cfg.Resource.MaxActiveCEPGroups = v
		case "max_event_refs_per_signal":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("resource.max_event_refs_per_signal: %w", err)
			}
			cfg.Resource.MaxEventRefsPerSignal = v
		default:
			return unknown(section, key)
		}
	default:
		return fmt.Errorf("unknown section %q", section)
	}
	return nil
}

func parseByteSize(raw string) (int64, error) {
	units := []struct {
		suffix     string
		multiplier int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}
	for _, unit := range units {
		if strings.HasSuffix(raw, unit.suffix) {
			value := strings.TrimSpace(strings.TrimSuffix(raw, unit.suffix))
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed <= 0 {
				return 0, fmt.Errorf("invalid byte size %q", raw)
			}
			return parsed * unit.multiplier, nil
		}
	}
	return 0, fmt.Errorf("byte size %q requires B, KiB, MiB, or GiB", raw)
}

func assignLocalStorage(storage *LocalStorageConfig, key, raw string) error {
	if key == "signal_max_count" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("local.storage.signal_max_count: %w", err)
		}
		storage.SignalMaxCount = value
		return nil
	}
	value, err := parseByteSize(raw)
	if err != nil {
		return fmt.Errorf("local.storage.%s: %w", key, err)
	}
	switch key {
	case "max_bytes":
		storage.MaxBytes = value
	case "min_free_bytes":
		storage.MinFreeBytes = value
	case "segment_size":
		storage.SegmentSize = value
	default:
		return unknown("local.storage", key)
	}
	return nil
}

func assignLocalExport(export *LocalExportConfig, key, raw string) error {
	if key == "max_inflight" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("local.export.max_inflight: %w", err)
		}
		export.MaxInflight = value
		return nil
	}
	if key == "wire_compression" {
		export.WireCompression = raw
		return nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("local.export.%s: %w", key, err)
	}
	switch key {
	case "retry_initial":
		export.RetryInitial = value
	case "retry_max":
		export.RetryMax = value
	case "request_timeout":
		export.RequestTimeout = value
	default:
		return unknown("local.export", key)
	}
	return nil
}

func unknown(section, key string) error {
	return fmt.Errorf("unknown config key %s.%s", section, key)
}
