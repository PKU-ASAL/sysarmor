package contracts

import (
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func SensorCollectionIntent(value domainpolicy.CollectionIntent) contract.CollectionIntent {
	result := contract.CollectionIntent{
		Behaviors:          append([]string(nil), value.Behaviors...),
		MandatoryBehaviors: append([]string(nil), value.MandatoryBehaviors...),
		BinaryPrefixes:     append([]string(nil), value.BinaryPrefixes...),
		FilePrefixes:       append([]string(nil), value.FilePrefixes...),
		FileWriteExcludes:  append([]string(nil), value.FileWriteExcludes...),
		SocketFamilies:     append([]string(nil), value.SocketFamilies...),
		SocketAddrs:        append([]string(nil), value.SocketAddrs...),
		SocketPorts:        append([]string(nil), value.SocketPorts...),
		ScopeType:          value.ScopeType, ScopeSelector: value.ScopeSelector,
		ObserveOnly: value.ObserveOnly,
	}
	for _, filter := range value.BehaviorFilters {
		result.BehaviorFilters = append(result.BehaviorFilters, contract.CollectionBehaviorFilter{
			Behavior:       filter.Behavior,
			BinaryPrefixes: append([]string(nil), filter.BinaryPrefixes...),
			FilePrefixes:   append([]string(nil), filter.FilePrefixes...),
			SocketFamilies: append([]string(nil), filter.SocketFamilies...),
			SocketAddrs:    append([]string(nil), filter.SocketAddrs...),
			SocketPorts:    append([]string(nil), filter.SocketPorts...),
		})
	}
	return result
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}
