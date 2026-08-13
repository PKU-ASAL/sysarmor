package daemon

import (
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
)

func collectionContentSnapshot(snapshot agentcontent.Snapshot) agentpolicy.CollectionContentSnapshot {
	out := agentpolicy.CollectionContentSnapshot{
		ContextSets: make(map[string]agentpolicy.CollectionValueSet, len(snapshot.ContextSets)),
		IOCPacks:    make(map[string]agentpolicy.CollectionValueSet, len(snapshot.IOCPacks)),
	}
	for ref, set := range snapshot.ContextSets {
		out.ContextSets[ref] = collectionValueSet(set)
	}
	for ref, set := range snapshot.IOCPacks {
		out.IOCPacks[ref] = collectionValueSet(set)
	}
	return out
}

func collectionValueSet(set agentcontent.ValueSet) agentpolicy.CollectionValueSet {
	return agentpolicy.CollectionValueSet{
		Ref: set.Ref, Version: set.Version, Digest: set.Digest, ValueType: set.ValueType,
		Values: append([]string(nil), set.Values...),
	}
}
