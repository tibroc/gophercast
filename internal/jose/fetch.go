package jose

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Fetcher resolves signing keys from a JWKS URL with a small cache. Rotation
// tolerance: an unknown kid forces ONE refetch before failing — the pattern
// every provider's key rollover assumes (new key published at the same URL).
// Shared by both trust models: the LTI platform registry hands it per-platform
// jwks_uri values; OIDC (step 4) hands it the one operated issuer's.
type Fetcher struct {
	TTL    time.Duration // cache lifetime per URL (default 5m)
	Client *http.Client  // default http.DefaultClient

	mu    sync.Mutex
	cache map[string]cachedSet
}

type cachedSet struct {
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// Key returns the RSA public key for kid as published at jwksURL.
func (f *Fetcher) Key(ctx context.Context, jwksURL, kid string) (*rsa.PublicKey, error) {
	ttl := f.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]cachedSet{}
	}
	set, ok := f.cache[jwksURL]
	f.mu.Unlock()

	if ok && time.Since(set.fetched) < ttl {
		if k, ok := set.keys[kid]; ok {
			return k, nil
		}
	}
	// miss, stale, or unknown kid → refetch once
	keys, err := f.fetch(ctx, jwksURL)
	if err != nil {
		// a live cached key beats a dead endpoint, but only for known kids
		if ok {
			if k, kOK := set.keys[kid]; kOK {
				return k, nil
			}
		}
		return nil, err
	}
	f.mu.Lock()
	f.cache[jwksURL] = cachedSet{keys: keys, fetched: time.Now()}
	f.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("jose: kid %q not in JWKS at %s", kid, jwksURL)
}

func (f *Fetcher) fetch(ctx context.Context, url string) (map[string]*rsa.PublicKey, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jose: fetching JWKS %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jose: JWKS %s answered %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseJWKS(body)
}
