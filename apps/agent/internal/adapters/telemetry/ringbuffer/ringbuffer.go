package ringbuffer

import (
	"fmt"
	"sync"
)

type Entry struct {
	Ref  string
	Data []byte
}

type Buffer struct {
	mu      sync.RWMutex
	next    uint64
	cap     int
	order   []string
	entries map[string]Entry
}

func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 1
	}
	return &Buffer{cap: capacity, entries: make(map[string]Entry)}
}

func (b *Buffer) Put(data []byte) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	ref := fmt.Sprintf("raw-%020d", b.next)
	b.putLocked(ref, data)
	return ref
}

func (b *Buffer) Remember(ref string, data []byte) string {
	if ref == "" {
		return b.Put(data)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.putLocked(ref, data)
	return ref
}

func (b *Buffer) Get(ref string) (Entry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	entry, ok := b.entries[ref]
	if !ok {
		return Entry{}, false
	}
	return Entry{Ref: entry.Ref, Data: append([]byte(nil), entry.Data...)}, true
}

func (b *Buffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

func (b *Buffer) putLocked(ref string, data []byte) {
	if _, exists := b.entries[ref]; !exists {
		b.order = append(b.order, ref)
	}
	b.entries[ref] = Entry{Ref: ref, Data: append([]byte(nil), data...)}
	for len(b.order) > b.cap {
		oldest := b.order[0]
		b.order = b.order[1:]
		delete(b.entries, oldest)
	}
}
