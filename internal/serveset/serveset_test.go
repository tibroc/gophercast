// The guard-as-structure proof (T2 done-condition 1): a pool connected as
// ocng_serve can read exactly the serve-read set — an out-of-set query
// fails AT THE DATABASE (42501), in every environment, not just in a test's
// parse of the source. The serve handler is then exercised end to end over
// that pool.
package serveset_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/mediapackage"
	"ocng/internal/migrate"
	"ocng/internal/serve"
	"ocng/internal/serveset"
)

// TestPassword is the fixed dev/test password for the ocng_serve role; the
// role is cluster-global in the shared test database, so every creator must
// agree on it (deploy/compose.yaml uses the same value for the dev stack).
const testPassword = "ocng_serve"

func pgURL() string {
	if url := os.Getenv("OCNG_E2E_PG"); url != "" {
		return url
	}
	return "postgres://ocng:ocng@127.0.0.1:15432/ocng"
}

func poolAs(t *testing.T, url, schemaName string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestServeRoleReadsExactlyTheSet(t *testing.T) {
	ctx := context.Background()
	schemaName := fmt.Sprintf("ocng_sr_%d", time.Now().UnixNano())
	admin := poolAs(t, pgURL(), schemaName)
	if _, err := admin.Exec(ctx, "create schema "+schemaName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "drop schema "+schemaName+" cascade") })

	// the tables serve reads (mediapackage owns three of them) + the
	// migrate-owned url map, so all four set members exist
	if err := mediapackage.Migrate(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Migrate(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if err := serveset.EnsureRole(ctx, admin, testPassword); err != nil {
		t.Fatal(err)
	}
	// idempotent second call (the every-boot path: reads only)
	if err := serveset.EnsureRole(ctx, admin, testPassword); err != nil {
		t.Fatalf("second EnsureRole: %v", err)
	}

	// a populated element + publication for the handler round-trip
	if _, err := admin.Exec(ctx, `
		insert into mediapackage (id, title) values ('11111111-1111-1111-1111-111111111111', 't');
		insert into mp_element (id, mediapackage_id, kind, flavor, sha256, size_bytes)
		values ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111',
		        'track', 'presenter/source', 'abc', 3);
		insert into publication (id, mediapackage_id, channel, acl_read, acl_state)
		values ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111', 'engage-player',
		        '{ROLE_ANONYMOUS}', 'POPULATED'); -- public pin: D-044 admits the anonymous listing
		insert into publication_element (publication_id, element_id)
		values ('33333333-3333-3333-3333-333333333333', '22222222-2222-2222-2222-222222222222')`); err != nil {
		t.Fatal(err)
	}

	serveURL := fmt.Sprintf("postgres://%s:%s@%s", serveset.Role, testPassword, hostPart(t, pgURL()))
	servePool := poolAs(t, serveURL, schemaName)

	// SELECT on every set table works
	for _, tbl := range serveset.Tables {
		if _, err := servePool.Exec(ctx, `select count(*) from `+tbl); err != nil {
			t.Errorf("ocng_serve must be able to read %s: %v", tbl, err)
		}
	}

	// SELECT outside the set fails at the database with 42501
	for _, tbl := range []string{"mediapackage", "mp_snapshot", "schema_migration"} {
		_, err := servePool.Exec(ctx, `select count(*) from `+tbl)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("ocng_serve reading off-set table %s must fail with 42501 (insufficient_privilege); got: %v", tbl, err)
		}
	}
	// and writes to set tables fail too — the role is read-only
	if _, err := servePool.Exec(ctx, `delete from publication_element`); err == nil {
		t.Error("ocng_serve must not be able to write serve-read-set tables")
	}

	// the real handler over the serve pool: the publication listing runs
	// its actual SQL, and an element miss proves GetElement's read path
	h := serve.Handler(servePool, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/publications/11111111-1111-1111-1111-111111111111", nil))
	if rec.Code != 200 {
		t.Fatalf("publications over ocng_serve: %d %s", rec.Code, rec.Body.String())
	}
	var pubs []serve.Publication
	if err := json.Unmarshal(rec.Body.Bytes(), &pubs); err != nil || len(pubs) != 1 || len(pubs[0].ElementIDs) != 1 {
		t.Fatalf("publication listing wrong over ocng_serve: %s (err %v)", rec.Body.String(), err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/elements/99999999-9999-9999-9999-999999999999", nil))
	if rec.Code != 404 {
		t.Fatalf("element miss over ocng_serve must be a clean 404 (the row lookup ran); got %d %s", rec.Code, rec.Body.String())
	}
}

// hostPart extracts "host:port/db" from the admin URL so the serve pool
// targets the same database with different credentials.
func hostPart(t *testing.T, url string) string {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s:%d/%s", cfg.ConnConfig.Host, cfg.ConnConfig.Port, cfg.ConnConfig.Database)
}
