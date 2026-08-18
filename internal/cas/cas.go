// Package cas is the ADR-008 content-addressed store: SHA-256-keyed
// immutable objects behind the S3 API. Deliberately no filesystem backend —
// one access path, no fast/slow pair for a misconfiguration to select
// silently. put/get/exists plus the two primitives the
// mark-sweep collector needs (List, Delete — internal/gc, T4); reclaim
// policy lives entirely in the collector, never here (deferred mark-sweep,
// never inline refcounting).
package cas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Store struct {
	mc     *minio.Client
	bucket string
}

// New connects to an S3-compatible endpoint and ensures the bucket exists.
// Increment 1 is dev-scoped: plain HTTP to a local MinIO; TLS and real S3
// credentials are deployment configuration, not a second code path.
func New(ctx context.Context, endpoint, accessKey, secretKey, bucket string) (*Store, error) {
	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	if err != nil {
		return nil, fmt.Errorf("cas: %w", err)
	}
	ok, err := mc.BucketExists(ctx, bucket)
	if err != nil {
		return nil, fmt.Errorf("cas: bucket check: %w", err)
	}
	if !ok {
		if err := mc.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("cas: make bucket: %w", err)
		}
	}
	return &Store{mc: mc, bucket: bucket}, nil
}

func objectKey(sha256hex string) string {
	// two-level fanout, the conventional CAS layout
	return "sha256/" + sha256hex[:2] + "/" + sha256hex
}

// PutFile stores the file's bytes under their SHA-256 and returns the hex
// digest. The content is hashed BEFORE upload (the key is the content, so
// the content must be known first), and storing bytes that already exist is
// a no-op — deduplication by construction, the property ADR-004 leans on
// for file-output idempotency.
func (s *Store) PutFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cas: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", fmt.Errorf("cas: hashing %s: %w", path, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	exists, err := s.Exists(ctx, sum)
	if err != nil {
		return "", err
	}
	if exists {
		return sum, nil // dedup: same bytes, same object
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("cas: %w", err)
	}
	_, err = s.mc.PutObject(ctx, s.bucket, objectKey(sum), f, size,
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return "", fmt.Errorf("cas: put %s: %w", sum, err)
	}
	return sum, nil
}

// Get streams the object with the given digest. The caller owns the reader.
func (s *Store) Get(ctx context.Context, sha256hex string) (io.ReadCloser, error) {
	obj, err := s.mc.GetObject(ctx, s.bucket, objectKey(sha256hex), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("cas: get %s: %w", sha256hex, err)
	}
	// GetObject is lazy; force the first read so a missing object errors
	// here, not at the caller's first Read
	if _, err := obj.Stat(); err != nil {
		obj.Close()
		return nil, fmt.Errorf("cas: get %s: %w", sha256hex, err)
	}
	return obj, nil
}

// GetRange streams object bytes [start, end] (inclusive, per HTTP Range
// semantics) — the serve layer's 206 path. The caller owns the reader.
func (s *Store) GetRange(ctx context.Context, sha256hex string, start, end int64) (io.ReadCloser, error) {
	opts := minio.GetObjectOptions{}
	if err := opts.SetRange(start, end); err != nil {
		return nil, fmt.Errorf("cas: range %d-%d: %w", start, end, err)
	}
	// Existence is checked with a SEPARATE StatObject call so a missing
	// object errors HERE, before the serve layer writes 206 headers —
	// never via Stat() on the lazy Object: minio-go's request loop
	// deletes the Range header when the first operation is a Stat and
	// again on the follow-up offset-0 read, so the caller's SetRange is
	// silently discarded and the full object streams back. That is SDK
	// CLIENT behaviour (api-get-object.go:152-156,215-218 @ v7.2.1),
	// identical against any S3 backend — NOT a MinIO-server quirk, so
	// this stays under the "implement to the S3 contract, not to MinIO"
	// rule. TestGetRangeHonoursOffsets guards the contract.
	if _, err := s.mc.StatObject(ctx, s.bucket, objectKey(sha256hex), minio.StatObjectOptions{}); err != nil {
		return nil, fmt.Errorf("cas: get %s: %w", sha256hex, err)
	}
	obj, err := s.mc.GetObject(ctx, s.bucket, objectKey(sha256hex), opts)
	if err != nil {
		return nil, fmt.Errorf("cas: get %s: %w", sha256hex, err)
	}
	return obj, nil
}

// GetToFile downloads an object to a local path (the worker's
// download-process-upload access pattern, ADR-008).
func (s *Store) GetToFile(ctx context.Context, sha256hex, path string) error {
	r, err := s.Get(ctx, sha256hex)
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("cas: download %s: %w", sha256hex, err)
	}
	return nil
}

// List streams every stored object's digest to fn, in unspecified order —
// the sweep's enumeration primitive. Bounded memory: objects are visited as
// the S3 listing pages arrive, never collected into one slice.
func (s *Store) List(ctx context.Context, fn func(sha256hex string) error) error {
	for obj := range s.mc.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix: "sha256/", Recursive: true,
	}) {
		if obj.Err != nil {
			return fmt.Errorf("cas: list: %w", obj.Err)
		}
		// key layout is sha256/<2-char fanout>/<digest> (objectKey)
		sha := obj.Key
		if i := strings.LastIndexByte(sha, '/'); i >= 0 {
			sha = sha[i+1:]
		}
		if err := fn(sha); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes one object. ONLY the mark-sweep collector may call this —
// every other consumer treats objects as immutable and permanent (ADR-008).
func (s *Store) Delete(ctx context.Context, sha256hex string) error {
	if err := s.mc.RemoveObject(ctx, s.bucket, objectKey(sha256hex), minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("cas: delete %s: %w", sha256hex, err)
	}
	return nil
}

func (s *Store) Exists(ctx context.Context, sha256hex string) (bool, error) {
	_, err := s.mc.StatObject(ctx, s.bucket, objectKey(sha256hex), minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if resp := minio.ToErrorResponse(err); resp.Code == "NoSuchKey" {
		return false, nil
	}
	return false, fmt.Errorf("cas: stat %s: %w", sha256hex, err)
}
