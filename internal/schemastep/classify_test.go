// The T2 invariant made executable. The done-condition red case is
// TestCheckRejectsRewriteOnServeTable: the same statement is FORBIDDEN
// against a serve-read-set table and PERMITTED against an off-set table —
// the three-way §5.3 model, not a blanket no-DDL rule. Written before the
// classifier existed (red-first): this test defines the invariant, the
// classifier satisfies it.
//
// The Postgres lock-behaviour claims are verified executably by
// TestGuardedDDLRetries / TestSecondBootTakesNoLockOnServeSet in run_test.go
// (a held ACCESS SHARE actually blocking / not blocking the mechanism);
// this file verifies the CLASSIFICATION of statements against those claims.
package schemastep

import (
	"strings"
	"testing"
)

// The done-condition red case (§5.6 item 2): rewrite-AEL on the set is
// rejected; the SAME statement off the set is slow-but-safe and permitted.
func TestCheckRejectsRewriteOnServeTable(t *testing.T) {
	violating := []Step{TxDDL(0, "bad", `alter table mp_element alter column flavor type varchar(64)`)}
	err := Check(violating)
	if err == nil {
		t.Fatal("rewrite-AEL (ALTER TYPE in place) on mp_element must be REJECTED — it is in the serve-read set")
	}
	if !strings.Contains(err.Error(), "migration-discipline") {
		t.Errorf("rejection must point the author at docs/migration-discipline.md; got: %v", err)
	}

	permitted := []Step{TxDDL(0, "slow-but-safe", `alter table task alter column operation type varchar(64)`)}
	if err := Check(permitted); err != nil {
		t.Fatalf("the SAME statement against task (off-set) is unconstrained on duration and must be PERMITTED; got: %v", err)
	}
}

// Metadata-class AEL on a serve table is permitted ONLY as a guarded step.
func TestCheckMetadataAELNeedsGuard(t *testing.T) {
	stmt := `alter table publication add column if not exists acl_read text[] not null default '{}'`
	if err := Check([]Step{TxDDL(0, "unguarded", stmt)}); err == nil {
		t.Fatal("metadata-AEL on a serve table in a plain tx-ddl step must be rejected (needs the lock_timeout guard)")
	}
	if err := Check([]Step{GuardedDDL(0, "guarded", stmt)}); err != nil {
		t.Fatalf("the same statement as a guarded step must pass; got: %v", err)
	}
	// off the set, no guard needed
	if err := Check([]Step{TxDDL(0, "off-set", `alter table workflow add column note text`)}); err != nil {
		t.Fatalf("metadata-AEL off the set needs no guard; got: %v", err)
	}
}

// A statement the classifier cannot separate cleanly must FAIL on (or
// possibly-on) the set — surface, don't guess (stop-and-surface rule).
func TestCheckUnknownFailsClosed(t *testing.T) {
	if err := Check([]Step{TxDDL(0, "opaque", `do $$ begin perform 1; end $$`)}); err == nil {
		t.Fatal("an unclassifiable statement with no derivable target must fail closed")
	}
	if err := Check([]Step{TxDDL(0, "weird-alter", `alter table mp_element set (fillfactor = 70)`)}); err == nil {
		t.Fatal("an unclassified ALTER form against a serve table must fail closed")
	}
}

// Every classification claim, statement by statement.
func TestClassifyStatements(t *testing.T) {
	cases := []struct {
		sql   string
		class StmtClass
		table string
	}{
		// rewrite-AEL (the ratified §5.3 forbidden list)
		{`alter table mp_element alter column flavor type varchar(64)`, ClassRewriteAEL, "mp_element"},
		{`alter table publication add column big text not null default gen_random_uuid()::text`, ClassRewriteAEL, "publication"},
		{`alter table mp_element alter column mimetype set not null`, ClassRewriteAEL, "mp_element"},
		{`cluster mp_element using mp_element_pkey`, ClassRewriteAEL, "mp_element"},
		{`vacuum full publication`, ClassRewriteAEL, "publication"},
		{`truncate publication_element`, ClassRewriteAEL, "publication_element"},
		{`alter table mp_element drop column source_url`, ClassRewriteAEL, "mp_element"},
		{`alter table mp_element rename column flavor to flavour`, ClassRewriteAEL, "mp_element"},
		{`drop table migration_url_map`, ClassRewriteAEL, "migration_url_map"},
		{`alter table publication add constraint c check (channel <> '')`, ClassRewriteAEL, "publication"},

		// metadata-AEL (brief; guarded-step territory on the set)
		{`alter table mp_element add column if not exists tech jsonb`, ClassMetadataAEL, "mp_element"},
		{`alter table publication add column if not exists acl_state text not null default 'ABSENT'
		    check (acl_state in ('ABSENT','EMPTY','POPULATED'))`, ClassMetadataAEL, "publication"},
		{`alter table publication add constraint c check (channel <> '') not valid`, ClassMetadataAEL, "publication"},
		{`alter table publication drop constraint c`, ClassMetadataAEL, "publication"},
		{`alter table mp_element alter column mimetype set default 'video/mp4'`, ClassMetadataAEL, "mp_element"},
		{`drop trigger task_terminal_guard on task`, ClassMetadataAEL, "task"},

		// reader-safe (never conflicts with ACCESS SHARE, or touches no live rel)
		{`create table if not exists mp_element (id uuid primary key)`, ClassReaderSafe, "mp_element"},
		{`create index if not exists x on mp_element (sha256)`, ClassReaderSafe, "mp_element"},
		{`create index concurrently x on mp_element (sha256)`, ClassReaderSafe, "mp_element"},
		{`alter table publication validate constraint c`, ClassReaderSafe, "publication"},
		{`alter table mp_element add constraint fk foreign key (mediapackage_id) references mediapackage(id)`, ClassReaderSafe, "mp_element"},
		{`create or replace function f() returns trigger as $$ begin return new; end $$ language plpgsql`, ClassReaderSafe, ""},
		{`create trigger tg before update on task for each row execute function f()`, ClassReaderSafe, "task"},
		{`create extension if not exists pg_trgm`, ClassReaderSafe, ""},
		{`update mp_element set size_bytes = size_bytes where false`, ClassReaderSafe, "mp_element"},
		{`grant select on mp_element to ocng_serve`, ClassReaderSafe, "mp_element"},

		// unknown — fail-closed material
		{`do $$ begin perform 1; end $$`, ClassUnknown, ""},
		{`alter table mp_element set (fillfactor = 70)`, ClassUnknown, "mp_element"},
	}
	for _, c := range cases {
		class, table := ClassifyStatement(c.sql)
		if class != c.class || table != c.table {
			t.Errorf("classify %q:\n got (%v, %q)\nwant (%v, %q)", c.sql, class, table, c.class, c.table)
		}
	}
}

// The statement splitter must survive the real baselines: dollar-quoted
// function bodies with semicolons (engine), comments, multi-line DDL.
func TestSplitStatements(t *testing.T) {
	sql := `-- comment; with semicolon
	create table a (id int); /* block; comment */
	create function f() returns trigger as $$
	begin
	    if old.state = 'X' then raise exception 'no'; end if;
	    return new;
	end
	$$ language plpgsql;
	create table b (s text default ';');
	`
	got := SplitStatements(sql)
	if len(got) != 3 {
		t.Fatalf("want 3 statements, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[1], "raise exception") {
		t.Errorf("dollar-quoted body must stay one statement: %q", got[1])
	}
	if !strings.Contains(got[2], "';'") {
		t.Errorf("quoted semicolon must not split: %q", got[2])
	}
}

// Every shipped baseline must pass Check under its declared step kind — the
// mechanism must refuse nothing it itself ships (and mediapackage's
// baseline, which takes metadata-AEL on serve tables via ADD COLUMN IF NOT
// EXISTS, must be shipped guarded).
func TestShippedBaselinesPass(t *testing.T) {
	// filled in by run_test.go's boot list — see TestAllPackagesCheckClean there.
}
