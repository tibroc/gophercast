// Command ocng-migrate is increment 6: one migration run = one organisation
// into one ocng instance (ADR-010). It ships in the core image and runs as a
// one-shot container / K8s Job against the SAME database and CAS bucket the
// assembled ocng-core serves — migration lands in the operable system, not a
// harness.
//
// It reads the source through AUTHORITATIVE representations only (the
// snapshot column, the XACML attachments + EAV cross-check, the series and
// search ACL columns) and writes the target additively.
// It holds no credential that can write the source; ADR-008's zero-exception
// invariant is asserted by the e2e after-hash diff, not hoped.
//
//	OCNG_DB_URL             target postgres URL (required)
//	OCNG_CAS_ENDPOINT/KEY/SECRET/BUCKET  target CAS (required)
//	-source <dir>           fixture-layout source directory; a live-DB
//	                        source backend is deferred adopter work
//	-org <id>               the ONE organisation this run migrates
//
// Exit codes: 0 complete; 3 complete-with-HOLDs (per-record decisions await
// a human — the report names each); 1 failed.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ocng/internal/acl"
	"ocng/internal/cas"
	"ocng/internal/mediapackage"
	"ocng/internal/migrate"
	"ocng/internal/search"
)

func main() {
	source := flag.String("source", "", "source fixture directory (fixture layout)")
	org := flag.String("org", "", "the one organisation this run migrates")
	flag.Parse()
	if *source == "" || *org == "" {
		fmt.Fprintln(os.Stderr, "usage: ocng-migrate -source <dir> -org <id>")
		os.Exit(1)
	}
	if err := run(*source, *org); err != nil {
		fmt.Fprintln(os.Stderr, "ocng-migrate:", err)
		os.Exit(1)
	}
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintf(os.Stderr, "ocng-migrate: %s is required\n", k)
		os.Exit(1)
	}
	return v
}

func run(source, org string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, mustEnv("OCNG_DB_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := cas.New(ctx, mustEnv("OCNG_CAS_ENDPOINT"),
		mustEnv("OCNG_CAS_KEY"), mustEnv("OCNG_CAS_SECRET"), mustEnv("OCNG_CAS_BUCKET"))
	if err != nil {
		return err
	}

	for _, mig := range []func(context.Context, *pgxpool.Pool) error{
		mediapackage.Migrate, acl.Migrate, search.Migrate, migrate.Migrate,
	} {
		if err := mig(ctx, pool); err != nil {
			return err
		}
	}

	src := &migrate.FixtureSource{Dir: source, Org: org}
	res, err := migrate.Run(ctx, pool, store, src, org)
	if err != nil {
		return err
	}
	fmt.Printf("migration run %d complete: org=%s events=%d series=%d versions=%d cas-puts=%d holds=%d\n",
		res.RunID, org, res.Events, res.Series, res.Versions, res.Objects, res.Holds)
	printReport(ctx, pool, res.RunID)
	if res.Holds > 0 {
		fmt.Printf("%d record(s) ON HOLD — each has a migration_report line; a human decides, the tool does not work around\n", res.Holds)
		os.Exit(3)
	}
	return nil
}

func printReport(ctx context.Context, pool *pgxpool.Pool, runID int64) {
	rows, err := pool.Query(ctx, `
		select class, count(*) from migration_report
		where run_id=$1 group by class order by class`, runID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report summary:", err)
		return
	}
	defer rows.Close()
	fmt.Println("report (migration_report has the per-record lines):")
	for rows.Next() {
		var class string
		var n int
		if err := rows.Scan(&class, &n); err != nil {
			return
		}
		fmt.Printf("  %-40s %d\n", class, n)
	}
}
