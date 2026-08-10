package telemetry

type Document []byte

type Index string

const (
	IndexEvents  Index = "events"
	IndexSignals Index = "signals"
)

type IndexedDocument struct {
	Index    Index
	Document Document
}

func (document Document) Clone() Document {
	return append(Document(nil), document...)
}
