package compiler_test

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/compiler"
)

func TestParseFieldAliasesShareCanonicalField(t *testing.T) {
	tests := []struct {
		canonical string
		alias     string
	}{
		{canonical: "event.id", alias: "id"},
		{canonical: "event.behavior", alias: "behavior"},
		{canonical: "lineage_id", alias: "lineage.id"},
		{canonical: "process.stable_id", alias: "process.id"},
		{canonical: "process.binary", alias: "binary"},
		{canonical: "process.binary_name", alias: "binary_name"},
		{canonical: "process.argv", alias: "argv"},
		{canonical: "process.uid", alias: "uid"},
		{canonical: "process.pid", alias: "pid"},
		{canonical: "parent.stable_id", alias: "parent.id"},
		{canonical: "file.path", alias: "object.file_path"},
		{canonical: "socket.addr", alias: "object.socket_addr"},
		{canonical: "container.id", alias: "container_id"},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			canonical := compiler.ParseField(tt.canonical)
			if canonical == compiler.FieldUnknown || compiler.ParseField(tt.alias) != canonical {
				t.Fatalf("ParseField(%q) = %v, want canonical %v", tt.alias, compiler.ParseField(tt.alias), canonical)
			}
		})
	}
}

func TestParseOperatorAliasesShareCanonicalOperator(t *testing.T) {
	tests := []struct {
		canonical string
		alias     string
	}{
		{canonical: "eq", alias: "equals"},
		{canonical: "neq", alias: "not_eq"},
		{canonical: "prefix", alias: "has_prefix"},
		{canonical: "suffix", alias: "has_suffix"},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			canonical := compiler.ParseOperator(tt.canonical)
			if canonical == compiler.OperatorUnknown || compiler.ParseOperator(tt.alias) != canonical {
				t.Fatalf("ParseOperator(%q) = %v, want canonical %v", tt.alias, compiler.ParseOperator(tt.alias), canonical)
			}
		})
	}
}
