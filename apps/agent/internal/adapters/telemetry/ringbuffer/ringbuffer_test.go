package ringbuffer

import "testing"

func TestBufferRememberGetAndEvict(t *testing.T) {
	buf := New(2)
	buf.Remember("raw-a", []byte("a"))
	buf.Remember("raw-b", []byte("b"))
	buf.Remember("raw-c", []byte("c"))

	if _, ok := buf.Get("raw-a"); ok {
		t.Fatal("raw-a should be evicted")
	}
	entry, ok := buf.Get("raw-c")
	if !ok {
		t.Fatal("raw-c should exist")
	}
	if string(entry.Data) != "c" {
		t.Fatalf("raw-c data = %q, want c", string(entry.Data))
	}
	if got := buf.Len(); got != 2 {
		t.Fatalf("len = %d, want 2", got)
	}
}

func TestBufferPutAllocatesStableRef(t *testing.T) {
	buf := New(1)
	ref := buf.Put([]byte("line"))
	if ref == "" {
		t.Fatal("allocated ref is empty")
	}
	entry, ok := buf.Get(ref)
	if !ok || string(entry.Data) != "line" {
		t.Fatalf("entry = %#v ok=%v", entry, ok)
	}
}
