// CAS tests against real MinIO — the store IS the S3 API plus a hash; a
// mock would test the mock.
package cas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	endpoint := os.Getenv("OCNG_E2E_MINIO")
	if endpoint == "" {
		endpoint = "127.0.0.1:19000"
	}
	s, err := New(context.Background(), endpoint, "ocng", "ocng-secret",
		fmt.Sprintf("ocng-cas-test-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("minio: %v", err)
	}
	return s
}

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPutGetRoundtrip(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	content := "increment-1 bytes"
	want := sha256.Sum256([]byte(content))
	wantHex := hex.EncodeToString(want[:])

	sum, err := s.PutFile(ctx, write(t, content))
	if err != nil {
		t.Fatal(err)
	}
	if sum != wantHex {
		t.Fatalf("PutFile sha = %s, want %s", sum, wantHex)
	}

	ok, err := s.Exists(ctx, sum)
	if err != nil || !ok {
		t.Fatalf("Exists(%s) = %v, %v", sum, ok, err)
	}

	r, err := s.Get(ctx, sum)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("Get = %q, want %q", got, content)
	}
}

func TestDedupSameBytesOneObject(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	a, err := s.PutFile(ctx, write(t, "same bytes"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.PutFile(ctx, write(t, "same bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("same content, different keys: %s vs %s", a, b)
	}
}

func TestGetMissingFailsLoudly(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	missing := sha256.Sum256([]byte("never stored"))
	if _, err := s.Get(ctx, hex.EncodeToString(missing[:])); err == nil {
		t.Fatal("Get of a missing object returned a reader, want error at call time")
	}
	ok, err := s.Exists(ctx, hex.EncodeToString(missing[:]))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("Exists true for never-stored object")
	}
}
