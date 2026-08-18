package cas

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// The source of truth for storage behaviour is the S3 API CONTRACT, not the
// dev backend's observed behaviour (MinIO is a deprecated dev/test stand-in).
// This test asserts the contract — a ranged GET returns exactly the
// requested bytes, and a missing object errors at call time — against
// whatever backend OCNG_E2E_MINIO points at; it must hold unchanged on
// AWS S3 / Ceph RGW.
func TestGetRangeHonoursOffsets(t *testing.T) {
	ctx := context.Background()
	s, err := New(ctx, "127.0.0.1:19000", "ocng", "ocng-secret", fmt.Sprintf("probe-%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	tmp, _ := os.CreateTemp("", "probe")
	data := bytes.Repeat([]byte("0123456789"), 100)
	tmp.Write(data)
	tmp.Close()
	sum, err := s.PutFile(ctx, tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.GetRange(ctx, sum, 10, 19)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data[10:20]) {
		t.Fatalf("range mismatch")
	}

	// a missing object must error at GetRange time, not on first Read —
	// the serve layer relies on this to 404 before writing 206 headers
	absent := "0000000000000000000000000000000000000000000000000000000000000000"
	if r, err := s.GetRange(ctx, absent, 0, 9); err == nil {
		r.Close()
		t.Fatalf("GetRange on an absent object returned a reader, want an error at call time")
	}
}
