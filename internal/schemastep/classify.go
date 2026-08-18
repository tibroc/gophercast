// The T2 blocking-lock check: a migration is a list of typed steps, and
// Check is a pure function over them enforcing the ratified three-way
// invariant (internal/serveset/READSET.md, 2026-08-17):
//
//   - rewrite-class ACCESS EXCLUSIVE on a serve-read-set table: FORBIDDEN.
//   - metadata-class AEL on a serve-read-set table: permitted only as a
//     guarded step (SET lock_timeout + bounded retry — even a brief AEL
//     queues behind a long reader and stalls serve SELECTs behind it).
//   - anything off the set: unconstrained on duration (slow-but-safe).
//
// Statements the classifier cannot separate cleanly FAIL CLOSED when they
// target (or may target) the set — surface, don't guess. Lock-class claims
// are the PostgreSQL documented semantics; the runner tests exercise them
// against a live server (a held ACCESS SHARE really blocking a guarded
// ALTER, really not blocking a ledger-skipped boot).
package schemastep

import (
	"fmt"
	"regexp"
	"strings"

	"ocng/internal/serveset"
)

type StmtClass int

const (
	// ClassReaderSafe never conflicts with ACCESS SHARE: CREATE TABLE/INDEX
	// (SHARE blocks writes, not reads), CREATE INDEX CONCURRENTLY, VALIDATE
	// CONSTRAINT, ADD FOREIGN KEY (SHARE ROW EXCLUSIVE), triggers-on-create,
	// functions, extensions, grants, DML.
	ClassReaderSafe StmtClass = iota
	// ClassMetadataAEL takes ACCESS EXCLUSIVE briefly (no scan/rewrite):
	// nullable or constant-default ADD COLUMN, ADD CONSTRAINT ... NOT VALID,
	// DROP CONSTRAINT, SET/DROP DEFAULT, DROP TRIGGER.
	ClassMetadataAEL
	// ClassRewriteAEL holds ACCESS EXCLUSIVE for a scan or rewrite: in-place
	// ALTER TYPE, volatile-default ADD COLUMN, SET NOT NULL (full-table
	// scan under AEL), unvalidated ADD CHECK/UNIQUE/PK, CLUSTER, VACUUM
	// FULL, TRUNCATE, DROP/RENAME of live columns, DROP TABLE.
	ClassRewriteAEL
	// ClassUnknown: the classifier cannot prove a lock class. Fails closed
	// on or possibly-on the serve-read set.
	ClassUnknown
)

func (c StmtClass) String() string {
	switch c {
	case ClassReaderSafe:
		return "reader-safe"
	case ClassMetadataAEL:
		return "metadata-AEL"
	case ClassRewriteAEL:
		return "rewrite-AEL"
	}
	return "unknown"
}

// SplitStatements splits a DDL script on top-level semicolons, honouring
// line comments, block comments, single-quoted strings and dollar-quoting
// (the engine baseline's plpgsql body carries semicolons).
func SplitStatements(sql string) []string {
	var out []string
	var buf strings.Builder
	i := 0
	for i < len(sql) {
		rest := sql[i:]
		switch {
		case strings.HasPrefix(rest, "--"):
			nl := strings.IndexByte(rest, '\n')
			if nl < 0 {
				i = len(sql)
				continue
			}
			i += nl // keep the newline as whitespace
		case strings.HasPrefix(rest, "/*"):
			end := strings.Index(rest[2:], "*/")
			if end < 0 {
				i = len(sql)
				continue
			}
			i += 2 + end + 2
		case rest[0] == '\'':
			j := 1
			for j < len(rest) {
				if rest[j] == '\'' {
					if j+1 < len(rest) && rest[j+1] == '\'' { // escaped ''
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			buf.WriteString(rest[:j])
			i += j
		case rest[0] == '$':
			if tag := dollarTag(rest); tag != "" {
				end := strings.Index(rest[len(tag):], tag)
				if end < 0 { // unterminated: take the rest
					buf.WriteString(rest)
					i = len(sql)
					continue
				}
				n := len(tag) + end + len(tag)
				buf.WriteString(rest[:n])
				i += n
			} else {
				buf.WriteByte('$')
				i++
			}
		case rest[0] == ';':
			if s := strings.TrimSpace(buf.String()); s != "" {
				out = append(out, s)
			}
			buf.Reset()
			i++
		default:
			buf.WriteByte(rest[0])
			i++
		}
	}
	if s := strings.TrimSpace(buf.String()); s != "" {
		out = append(out, s)
	}
	return out
}

var dollarTagRe = regexp.MustCompile(`^\$[A-Za-z_]*\$`)

func dollarTag(s string) string { return dollarTagRe.FindString(s) }

var (
	reAlterTable = regexp.MustCompile(`(?is)^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+(.*)$`)
	reTableWord  = regexp.MustCompile(`(?is)^(truncate(?:\s+table)?|cluster|vacuum\s+full|drop\s+table(?:\s+if\s+exists)?)\s+(?:only\s+)?([\w."]+)`)
	reCreateTbl  = regexp.MustCompile(`(?is)^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?([\w."]+)`)
	reCreateIdx  = regexp.MustCompile(`(?is)^create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?[\w."]*\s*on\s+(?:only\s+)?([\w."]+)`)
	reCreateTrig = regexp.MustCompile(`(?is)^create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+.*?\son\s+([\w."]+)`)
	reDropTrig   = regexp.MustCompile(`(?is)^drop\s+trigger\s+(?:if\s+exists\s+)?[\w."]+\s+on\s+([\w."]+)`)
	reDML        = regexp.MustCompile(`(?is)^(?:insert\s+into|update|delete\s+from|merge\s+into)\s+(?:only\s+)?([\w."]+)`)
	reGrant      = regexp.MustCompile(`(?is)^(?:grant|revoke)\b.*?\bon\s+(?:table\s+)?([\w."]+)`)
	// constant defaults: literals only — numbers, quoted strings, true/false/
	// null, and array/row literals written as strings. A parenthesis after an
	// identifier means a function call → volatile-suspect → rewrite.
	reConstDefault = regexp.MustCompile(`(?is)\bdefault\s+(?:-?\d|'|true\b|false\b|null\b)`)
	reAnyDefault   = regexp.MustCompile(`(?is)\bdefault\b`)
)

// unqualify returns the last dotted component, unquoted, lowercased.
func unqualify(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(strings.Trim(name, `"`))
}

// ClassifyStatement returns the lock class of one SQL statement and the
// unqualified table it targets ("" when no single target is derivable).
func ClassifyStatement(stmt string) (StmtClass, string) {
	s := strings.TrimSpace(stmt)
	low := strings.ToLower(s)

	if m := reAlterTable.FindStringSubmatch(s); m != nil {
		table := unqualify(m[1])
		return classifyAlterAction(strings.ToLower(strings.TrimSpace(m[2]))), table
	}
	if m := reTableWord.FindStringSubmatch(s); m != nil {
		return ClassRewriteAEL, unqualify(m[2])
	}
	if m := reCreateTbl.FindStringSubmatch(s); m != nil {
		return ClassReaderSafe, unqualify(m[1])
	}
	if m := reCreateIdx.FindStringSubmatch(s); m != nil {
		return ClassReaderSafe, unqualify(m[1])
	}
	if m := reCreateTrig.FindStringSubmatch(s); m != nil {
		return ClassReaderSafe, unqualify(m[1]) // SHARE ROW EXCLUSIVE
	}
	if m := reDropTrig.FindStringSubmatch(s); m != nil {
		return ClassMetadataAEL, unqualify(m[1]) // brief AEL on the table
	}
	if m := reDML.FindStringSubmatch(s); m != nil {
		return ClassReaderSafe, unqualify(m[1])
	}
	if m := reGrant.FindStringSubmatch(s); m != nil {
		return ClassReaderSafe, unqualify(m[1])
	}
	switch {
	case strings.HasPrefix(low, "create or replace function"),
		strings.HasPrefix(low, "create function"),
		strings.HasPrefix(low, "create extension"),
		strings.HasPrefix(low, "create sequence"),
		strings.HasPrefix(low, "create schema"),
		strings.HasPrefix(low, "create type"),
		strings.HasPrefix(low, "comment on"),
		strings.HasPrefix(low, "drop index concurrently"),
		strings.HasPrefix(low, "select"),
		strings.HasPrefix(low, "with"),
		strings.HasPrefix(low, "set "):
		return ClassReaderSafe, ""
	}
	return ClassUnknown, ""
}

var (
	reAlterType      = regexp.MustCompile(`(?is)\balter\s+column\s+[\w"]+\s+(?:set\s+data\s+)?type\b`)
	reSetNotNull     = regexp.MustCompile(`(?is)\bset\s+not\s+null\b`)
	reDropColumn     = regexp.MustCompile(`(?is)\bdrop\s+column\b`)
	reValidate       = regexp.MustCompile(`(?is)\bvalidate\s+constraint\b`)
	reAddFK          = regexp.MustCompile(`(?is)\badd\s+(?:constraint\s+[\w"]+\s+)?foreign\s+key\b`)
	reAddScanConstr  = regexp.MustCompile(`(?is)\badd\s+(?:constraint\s+[\w"]+\s+)?(?:check|unique|primary\s+key|exclude)\b`)
	reNotValid       = regexp.MustCompile(`(?is)\bnot\s+valid\b`)
	reUsingIndex     = regexp.MustCompile(`(?is)\busing\s+index\b`)
	reAddColumn      = regexp.MustCompile(`(?is)^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?[\w"]+\s`)
	reDropConstraint = regexp.MustCompile(`(?is)\bdrop\s+constraint\b`)
	reSetDropDefault = regexp.MustCompile(`(?is)\balter\s+column\s+[\w"]+\s+(?:set|drop)\s+default\b`)
)

// classifyAlterAction maps the action part of an ALTER TABLE to a class.
// Order matters: the definite rewrite shapes and constraint forms are
// checked before the bare `ADD name type` fallback (Go regexp has no
// lookahead to exclude `ADD CONSTRAINT` there).
func classifyAlterAction(action string) StmtClass {
	switch {
	case reAlterType.MatchString(action):
		return ClassRewriteAEL // in-place type change
	case reSetNotNull.MatchString(action):
		return ClassRewriteAEL // full-table scan under AEL (no valid-constraint proof derivable here)
	case reDropColumn.MatchString(action):
		return ClassRewriteAEL // ratified list: dropping a live column breaks readers
	case strings.HasPrefix(action, "rename"):
		return ClassRewriteAEL // renaming a live column/table breaks readers
	case reValidate.MatchString(action):
		return ClassReaderSafe // SHARE UPDATE EXCLUSIVE
	case reAddFK.MatchString(action):
		return ClassReaderSafe // SHARE ROW EXCLUSIVE on the referencing side
	case reAddScanConstr.MatchString(action):
		if reNotValid.MatchString(action) || reUsingIndex.MatchString(action) {
			return ClassMetadataAEL
		}
		return ClassRewriteAEL // AEL held for the validation scan / index build
	case reAddColumn.MatchString(action):
		if reAnyDefault.MatchString(action) && !reConstDefault.MatchString(action) {
			return ClassRewriteAEL // non-constant default: table rewrite
		}
		return ClassMetadataAEL // nullable or constant default: metadata only [PG11+]
	case reDropConstraint.MatchString(action):
		return ClassMetadataAEL
	case reSetDropDefault.MatchString(action):
		return ClassMetadataAEL
	}
	return ClassUnknown
}

// Check enforces the invariant over a plan. The runner refuses to execute a
// plan that fails Check, and the classifier red-case test in
// classify_test.go is the done-condition proof.
func Check(steps []Step) error {
	for _, st := range steps {
		switch st.Kind {
		case KindBatchedDML:
			// Go-code steps carry no SQL to classify. Their contract is
			// batched reader-safe DML only (docs/migration-discipline.md) —
			// an honest hole in the static check, covered structurally by
			// the ocng_serve role for the serve path.
			continue
		case KindConcurrentIndex:
			for _, stmt := range SplitStatements(st.SQL) {
				if !regexp.MustCompile(`(?is)^create\s+(?:unique\s+)?index\s+concurrently\s`).MatchString(stmt) {
					return fmt.Errorf("schemastep: step %d %q: a concurrent-index step may contain only CREATE INDEX CONCURRENTLY, got %q", st.N, st.Name, firstLine(stmt))
				}
			}
			continue
		}
		for _, stmt := range SplitStatements(st.SQL) {
			class, table := ClassifyStatement(stmt)
			inSet := table != "" && serveset.Contains(table)
			switch class {
			case ClassReaderSafe:
				// fine anywhere
			case ClassMetadataAEL:
				if table == "" {
					return fmt.Errorf("schemastep: step %d %q: cannot determine the table a metadata-AEL statement targets — cannot prove it is off the serve-read set: %q (see docs/migration-discipline.md)", st.N, st.Name, firstLine(stmt))
				}
				if inSet && st.Kind != KindGuardedDDL {
					return fmt.Errorf("schemastep: step %d %q: metadata-AEL on serve-read-set table %s is permitted only as a guarded step (SET lock_timeout + retry) — use GuardedDDL (see docs/migration-discipline.md)", st.N, st.Name, table)
				}
			case ClassRewriteAEL:
				if table == "" {
					return fmt.Errorf("schemastep: step %d %q: cannot determine the table a rewrite-AEL statement targets: %q (see docs/migration-discipline.md)", st.N, st.Name, firstLine(stmt))
				}
				if inSet {
					return fmt.Errorf("schemastep: step %d %q: rewrite-class ACCESS EXCLUSIVE on serve-read-set table %s is FORBIDDEN — plane-1 reads would stall for the rewrite duration; evolve via nullable-add + backfill + NOT VALID/VALIDATE instead (see docs/migration-discipline.md): %q", st.N, st.Name, table, firstLine(stmt))
				}
				// off the set: unconstrained on duration (slow-but-safe)
			default: // ClassUnknown
				if table == "" || inSet {
					return fmt.Errorf("schemastep: step %d %q: cannot classify the lock class of %q — refusing to guess against the serve-read set; classify it (or move it off the set) and see docs/migration-discipline.md", st.N, st.Name, firstLine(stmt))
				}
				// unknown but provably off the set: permitted (the relaxation)
			}
		}
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	if len(s) > 120 {
		s = s[:120] + " …"
	}
	return s
}
