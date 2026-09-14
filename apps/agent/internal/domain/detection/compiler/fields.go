package compiler

import "strings"

type Field uint8

const (
	FieldUnknown Field = iota
	FieldEventID
	FieldBehavior
	FieldLineageID
	FieldProcessStableID
	FieldProcessBinary
	FieldProcessBinaryName
	FieldProcessArgv
	FieldProcessSudoCommand
	FieldProcessUID
	FieldProcessPID
	FieldParentStableID
	FieldFilePath
	FieldSocketAddr
	FieldSocketPort
	FieldSocket
	FieldScopeType
	FieldScopeSelector
	FieldContainerID
	FieldCgroup
)

type Operator uint8

const (
	OperatorUnknown Operator = iota
	OperatorEqual
	OperatorNotEqual
	OperatorContains
	OperatorPrefix
	OperatorSuffix
	OperatorIn
	OperatorNotIn
	OperatorSameAs
	OperatorExists
	OperatorGreaterThan
	OperatorGreaterThanOrEqual
	OperatorLessThan
	OperatorLessThanOrEqual
)

func ParseField(field string) Field {
	switch strings.TrimSpace(field) {
	case "event.id", "id":
		return FieldEventID
	case "event.behavior", "behavior":
		return FieldBehavior
	case "lineage_id", "lineage.id":
		return FieldLineageID
	case "process.stable_id", "process.id":
		return FieldProcessStableID
	case "process.binary", "binary":
		return FieldProcessBinary
	case "process.binary_name", "binary_name":
		return FieldProcessBinaryName
	case "process.argv", "argv":
		return FieldProcessArgv
	case "process.sudo_command":
		return FieldProcessSudoCommand
	case "process.uid", "uid":
		return FieldProcessUID
	case "process.pid", "pid":
		return FieldProcessPID
	case "parent.stable_id", "parent.id":
		return FieldParentStableID
	case "file.path", "object.file_path":
		return FieldFilePath
	case "socket.addr", "object.socket_addr":
		return FieldSocketAddr
	case "socket.port":
		return FieldSocketPort
	case "socket":
		return FieldSocket
	case "scope.type":
		return FieldScopeType
	case "scope.selector":
		return FieldScopeSelector
	case "container.id", "container_id":
		return FieldContainerID
	case "cgroup":
		return FieldCgroup
	default:
		return FieldUnknown
	}
}

func ParseOperator(operator string) Operator {
	switch strings.ToLower(strings.TrimSpace(operator)) {
	case "", "eq", "equals":
		return OperatorEqual
	case "neq", "not_eq":
		return OperatorNotEqual
	case "contains":
		return OperatorContains
	case "prefix", "has_prefix":
		return OperatorPrefix
	case "suffix", "has_suffix":
		return OperatorSuffix
	case "in":
		return OperatorIn
	case "not_in":
		return OperatorNotIn
	case "same_as":
		return OperatorSameAs
	case "exists":
		return OperatorExists
	case "gt":
		return OperatorGreaterThan
	case "gte":
		return OperatorGreaterThanOrEqual
	case "lt":
		return OperatorLessThan
	case "lte":
		return OperatorLessThanOrEqual
	default:
		return OperatorUnknown
	}
}
