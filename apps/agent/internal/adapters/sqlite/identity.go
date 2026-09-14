package sqlite

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

type DeviceIdentity struct {
	DeviceID  string
	HostID    string
	CreatedAt time.Time
}

func (s *Store) DeviceIdentity(ctx context.Context) (DeviceIdentity, error) {
	var identity DeviceIdentity
	var createdAt int64
	err := s.db.QueryRowContext(ctx, `SELECT device_id, host_id, created_at_ns FROM device_identity WHERE singleton = 1`).Scan(
		&identity.DeviceID, &identity.HostID, &createdAt,
	)
	identity.CreatedAt = time.Unix(0, createdAt).UTC()
	return identity, err
}

func (s *Store) ensureIdentity(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM device_identity").Scan(&count); err != nil {
		return fmt.Errorf("read device identity: %w", err)
	}
	if count > 0 {
		return nil
	}
	host, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read hostname: %w", err)
	}
	now := time.Now().UTC()
	deviceID, err := uuidV7(now)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_identity(singleton, device_id, host_id, created_at_ns) VALUES (1, ?, ?, ?)`, deviceID, host, now.UnixNano()); err != nil {
		return fmt.Errorf("create device identity: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO enrollment(singleton, state, updated_at_ns) VALUES (1, 'standalone', ?)`, now.UnixNano())
	return err
}

func uuidV7(now time.Time) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate device identity: %w", err)
	}
	millis := uint64(now.UnixMilli())
	value[0] = byte(millis >> 40)
	value[1] = byte(millis >> 32)
	value[2] = byte(millis >> 24)
	value[3] = byte(millis >> 16)
	value[4] = byte(millis >> 8)
	value[5] = byte(millis)
	value[6] = (value[6] & 0x0f) | 0x70
	value[8] = (value[8] & 0x3f) | 0x80
	a, b := binary.BigEndian.Uint64(value[:8]), binary.BigEndian.Uint64(value[8:])
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", uint32(a>>32), uint16(a>>16), uint16(a), uint16(b>>48), b&0xffffffffffff), nil
}
