package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/proto"
)

type SignalQuery struct {
	RuleID   string
	Severity string
	Since    time.Time
	Until    time.Time
	Limit    int
	Offset   int
}

func (s *Store) AppendSignals(ctx context.Context, frames []*dataplanev1.SignalFrame) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, frame := range frames {
		if err := appendSignal(ctx, tx, frame); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func appendSignal(ctx context.Context, tx *sql.Tx, frame *dataplanev1.SignalFrame) error {
	if frame == nil || frame.GetSignal() == nil || frame.GetSignal().GetId() == "" {
		return fmt.Errorf("signal frame and id are required")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, frame.GetObservedAt())
	if err != nil {
		return fmt.Errorf("parse signal observed_at: %w", err)
	}
	payload, err := proto.Marshal(frame.GetSignal())
	if err != nil {
		return fmt.Errorf("marshal signal: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO signals(sequence, signal_id, observed_at_ns, rule_id, severity, payload) VALUES (?, ?, ?, ?, ?, ?)`,
		frame.GetSequence(), frame.GetSignal().GetId(), observedAt.UnixNano(), frame.GetSignal().GetRuleId(), frame.GetSignal().GetSeverity(), payload)
	return err
}

func (s *Store) QuerySignals(ctx context.Context, query SignalQuery) ([]*dataplanev1.SignalFrame, error) {
	where, args := signalWhere(query)
	limit := query.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if query.Offset < 0 {
		return nil, fmt.Errorf("signal offset must be non-negative")
	}
	args = append(args, limit, query.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, observed_at_ns, payload FROM signals`+where+` ORDER BY sequence DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSignals(rows)
}

func signalWhere(query SignalQuery) (string, []any) {
	var clauses []string
	var args []any
	if query.RuleID != "" {
		clauses = append(clauses, "rule_id = ?")
		args = append(args, query.RuleID)
	}
	if query.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, query.Severity)
	}
	if !query.Since.IsZero() {
		clauses = append(clauses, "observed_at_ns >= ?")
		args = append(args, query.Since.UnixNano())
	}
	if !query.Until.IsZero() {
		clauses = append(clauses, "observed_at_ns <= ?")
		args = append(args, query.Until.UnixNano())
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func scanSignals(rows *sql.Rows) ([]*dataplanev1.SignalFrame, error) {
	var out []*dataplanev1.SignalFrame
	for rows.Next() {
		var sequence uint64
		var observedAt int64
		var payload []byte
		if err := rows.Scan(&sequence, &observedAt, &payload); err != nil {
			return nil, err
		}
		signal := &signalv1.Signal{}
		if err := proto.Unmarshal(payload, signal); err != nil {
			return nil, fmt.Errorf("unmarshal signal: %w", err)
		}
		out = append(out, &dataplanev1.SignalFrame{Sequence: sequence, ObservedAt: time.Unix(0, observedAt).UTC().Format(time.RFC3339Nano), Signal: signal})
	}
	return out, rows.Err()
}

func (s *Store) PruneSignals(ctx context.Context) (uint64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM signals WHERE sequence IN (SELECT sequence FROM signals ORDER BY sequence ASC LIMIT MAX((SELECT COUNT(*) FROM signals) - ?, 0))`, s.opts.SignalMaxCount)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	return uint64(removed), err
}
