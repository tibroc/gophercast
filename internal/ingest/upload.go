package ingest

import (
	"context"
	"fmt"
	"io"
	"os"

	"ocng/internal/cas"
)

// stashUpload streams an upload into CAS: spool to a temp file (the content
// must be fully known before its hash — and the hash IS the key — so a spool
// is unavoidable; it is disk, never memory), then store via the same
// cas.PutFile the loader and worker use. Returns the sha256 and size.
//
// The storage contract here is the S3 API itself, not any particular dev
// backend: bytes stored must equal bytes uploaded and
// be retrievable by hash, asserted by TestStashUploadStoresExactBytes
// against whatever backend is configured.
func stashUpload(ctx context.Context, store *cas.Store, r io.Reader) (sha string, size int64, err error) {
	tmp, err := os.CreateTemp("", "ocng-ingest-*")
	if err != nil {
		return "", 0, fmt.Errorf("ingest: %w", err)
	}
	defer os.Remove(tmp.Name())
	size, err = io.Copy(tmp, r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, fmt.Errorf("ingest: spooling upload: %w", err)
	}
	sha, err = store.PutFile(ctx, tmp.Name())
	if err != nil {
		return "", 0, err
	}
	return sha, size, nil
}
