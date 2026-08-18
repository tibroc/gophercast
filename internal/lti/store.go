package lti

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"ocng/internal/schemastep"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FlowStore holds the launch flow's ONE piece of real state: the single-use,
// TTL-bounded state and nonce values minted at login initiation and SPENT at
// launch validation. Spend semantics are the replay protection (IMS Security
// Framework §5.1.3: the nonce is validated as unused and then unavailable for
// reuse; OIDC Core §15.5.2): a value is good exactly once — "known" without
// "unspent" is not replay protection.
type FlowStore interface {
	// Mint records a fresh single-use value of the given kind with a TTL.
	Mint(ctx context.Context, kind, value string, ttl time.Duration) error
	// Spend consumes the value: true exactly once per Mint, false for
	// unknown, expired, or ALREADY-SPENT values.
	Spend(ctx context.Context, kind, value string) (bool, error)
}

// NewValue mints a 256-bit random URL-safe value for state/nonce.
func NewValue() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is not a recoverable condition
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- in-memory store (the in-repo suite; single-process dev) ---------------

type MemFlowStore struct {
	mu  sync.Mutex
	m   map[string]time.Time // key: kind+"\x00"+value → expiry
	Now func() time.Time     // injectable for expiry tests; default time.Now
}

func NewMemFlowStore() *MemFlowStore {
	return &MemFlowStore{m: map[string]time.Time{}}
}

func (s *MemFlowStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *MemFlowStore) Mint(_ context.Context, kind, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[kind+"\x00"+value] = s.now().Add(ttl)
	return nil
}

func (s *MemFlowStore) Spend(_ context.Context, kind, value string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := kind + "\x00" + value
	exp, ok := s.m[k]
	if !ok {
		return false, nil
	}
	delete(s.m, k) // spent — even if expired, it is gone either way
	return s.now().Before(exp), nil
}

// ---- Postgres store (the assembled binary: two core replicas share the
// flow, so login and launch may hit different processes — ADR-009) ----------

type PGFlowStore struct {
	Pool *pgxpool.Pool
}

// Migrate follows the per-package migration pattern: ledger step 0 under
// the shared advisory key (T2 Option A — this also gains lti the advisory
// serialisation its plain Exec never had).
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := schemastep.Run(ctx, pool, "lti", MigrationSteps())
	return err
}

func MigrationSteps() []schemastep.Step {
	return []schemastep.Step{schemastep.TxDDL(0, "baseline", `
		CREATE TABLE IF NOT EXISTS lti_flow (
			kind       text        NOT NULL,
			value      text        NOT NULL,
			expires_at timestamptz NOT NULL,
			PRIMARY KEY (kind, value)
		)`)}
}

func (s *PGFlowStore) Mint(ctx context.Context, kind, value string, ttl time.Duration) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO lti_flow (kind, value, expires_at) VALUES ($1, $2, now() + $3)`,
		kind, value, ttl)
	return err
}

// Spend deletes the row and reports whether it was live: the DELETE is the
// single-winner primitive (same posture as the engine's claim transition) —
// two concurrent launches replaying one nonce race on the row delete and
// exactly one can win.
func (s *PGFlowStore) Spend(ctx context.Context, kind, value string) (bool, error) {
	var live bool
	err := s.Pool.QueryRow(ctx,
		`DELETE FROM lti_flow WHERE kind = $1 AND value = $2 RETURNING expires_at > now()`,
		kind, value).Scan(&live)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return live, nil
}
