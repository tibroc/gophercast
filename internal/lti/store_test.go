package lti

// PGFlowStore semantics against a real Postgres (the two-replica shape needs
// the flow shared — ADR-009): mint→spend once true, spend again false,
// expired false. Skips when the e2e database (ocng-pg, the same default as
// e2e/) is not reachable.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPGFlowStoreSpendSemantics(t *testing.T) {
	url := os.Getenv("OCNG_E2E_PG")
	if url == "" {
		url = "postgres://ocng:ocng@127.0.0.1:15432/ocng"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("postgres not reachable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("postgres not reachable: %v", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	s := &PGFlowStore{Pool: pool}

	v := NewValue()
	if err := s.Mint(ctx, kindNonce, v, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Spend(ctx, kindNonce, v); err != nil || !ok {
		t.Fatalf("first spend: ok=%v err=%v", ok, err)
	}
	if ok, err := s.Spend(ctx, kindNonce, v); err != nil || ok {
		t.Fatalf("second spend must fail: ok=%v err=%v — replay protection is the spend", ok, err)
	}

	// unknown value
	if ok, err := s.Spend(ctx, kindNonce, NewValue()); err != nil || ok {
		t.Fatalf("unknown value spent: ok=%v err=%v", ok, err)
	}

	// expired: minted with a negative TTL is dead on arrival
	e := NewValue()
	if err := s.Mint(ctx, kindState, e, -time.Second); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Spend(ctx, kindState, e); err != nil || ok {
		t.Fatalf("expired value spent: ok=%v err=%v", ok, err)
	}

	// kinds are separate namespaces
	k := NewValue()
	if err := s.Mint(ctx, kindState, k, time.Minute); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Spend(ctx, kindNonce, k); ok {
		t.Fatal("a state value spent as a nonce")
	}
	if ok, _ := s.Spend(ctx, kindState, k); !ok {
		t.Fatal("the state value should still have been live in its own kind")
	}
}
