package sqlite

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"time"

	"github.com/klauspost/compress/zstd"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/protobuf/proto"
)

const (
	segmentHeaderSize = 32
	recordFixedSize   = 20
	segmentVersion    = uint16(1)
	maxBatchBytes     = 16 << 20
)

var segmentMagic = [8]byte{'S', 'Y', 'S', 'A', 'S', 'E', 'G', '1'}
var crcTable = crc32.MakeTable(crc32.Castagnoli)

func encodeSegmentHeader(segmentID uint64, createdAt time.Time) []byte {
	header := make([]byte, segmentHeaderSize)
	copy(header[:8], segmentMagic[:])
	binary.BigEndian.PutUint16(header[8:10], segmentVersion)
	header[10] = 1
	binary.BigEndian.PutUint64(header[16:24], segmentID)
	binary.BigEndian.PutUint64(header[24:32], uint64(createdAt.UnixNano()))
	return header
}

func parseSegmentHeader(header []byte) (uint64, error) {
	if len(header) != segmentHeaderSize || string(header[:8]) != string(segmentMagic[:]) {
		return 0, fmt.Errorf("invalid segment header")
	}
	if binary.BigEndian.Uint16(header[8:10]) != segmentVersion || header[10] != 1 {
		return 0, fmt.Errorf("unsupported segment format")
	}
	return binary.BigEndian.Uint64(header[16:24]), nil
}

func encodeRecord(batch *dataplanev1.DataBatch) ([]byte, uint64, error) {
	raw, err := proto.Marshal(batch)
	if err != nil {
		return nil, 0, err
	}
	if len(raw) > maxBatchBytes {
		return nil, 0, fmt.Errorf("data batch exceeds %d bytes", maxBatchBytes)
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, 0, err
	}
	compressed := encoder.EncodeAll(raw, nil)
	encoder.Close()
	batchID := []byte(batch.GetHeader().GetBatchId())
	sequence := batchSequence(batch)
	total := recordFixedSize - 4 + len(batchID) + len(compressed) + 4
	record := make([]byte, 4+total)
	binary.BigEndian.PutUint32(record[:4], uint32(total))
	binary.BigEndian.PutUint32(record[4:8], uint32(len(raw)))
	binary.BigEndian.PutUint64(record[8:16], sequence)
	binary.BigEndian.PutUint16(record[16:18], uint16(len(batchID)))
	copy(record[20:], batchID)
	copy(record[20+len(batchID):], compressed)
	crcAt := len(record) - 4
	binary.BigEndian.PutUint32(record[crcAt:], crc32.Checksum(record[4:crcAt], crcTable))
	return record, sequence, nil
}

func decodeRecord(record []byte) (*dataplanev1.DataBatch, uint64, error) {
	if len(record) < recordFixedSize+4 {
		return nil, 0, fmt.Errorf("record is too short")
	}
	crcAt := len(record) - 4
	if crc32.Checksum(record[4:crcAt], crcTable) != binary.BigEndian.Uint32(record[crcAt:]) {
		return nil, 0, fmt.Errorf("record CRC mismatch")
	}
	rawLen := binary.BigEndian.Uint32(record[4:8])
	if rawLen > maxBatchBytes {
		return nil, 0, fmt.Errorf("record payload exceeds limit")
	}
	idLen := int(binary.BigEndian.Uint16(record[16:18]))
	if 20+idLen > crcAt {
		return nil, 0, fmt.Errorf("record batch id length is invalid")
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, 0, err
	}
	raw, err := decoder.DecodeAll(record[20+idLen:crcAt], make([]byte, 0, rawLen))
	decoder.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("decompress data batch: %w", err)
	}
	if len(raw) != int(rawLen) {
		return nil, 0, fmt.Errorf("decompressed data batch length %d, want %d", len(raw), rawLen)
	}
	batch := &dataplanev1.DataBatch{}
	if err := proto.Unmarshal(raw, batch); err != nil {
		return nil, 0, err
	}
	return batch, binary.BigEndian.Uint64(record[8:16]), nil
}

func batchSequence(batch *dataplanev1.DataBatch) uint64 {
	if batch.GetHeader().GetEventSeqStart() > 0 {
		return batch.GetHeader().GetEventSeqStart()
	}
	return batch.GetHeader().GetSignalSeqStart()
}
