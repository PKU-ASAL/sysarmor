package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSensorConfigHasNoLegacyScopeFields(t *testing.T) {
	typeOfConfig := reflect.TypeOf(SensorConfig{})
	for _, field := range []string{"ScopeType", "ScopeSelector", "ContainerIDPrefix"} {
		if _, ok := typeOfConfig.FieldByName(field); ok {
			t.Errorf("SensorConfig still exposes legacy field %s", field)
		}
	}
}

func TestLoadFileRejectsLegacyScopeKeys(t *testing.T) {
	for _, key := range []string{"scope_type", "scope_selector", "container_id_prefix"} {
		t.Run(key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yaml")
			write(t, path, "\nsensor:\n  backend: tetragon\n  mode: managed\n  "+key+": legacy\n")
			_, err := LoadFile(path)
			if err == nil || !strings.Contains(err.Error(), "unknown config key sensor."+key) {
				t.Fatalf("LoadFile() error = %v, want unknown legacy key", err)
			}
		})
	}
}
