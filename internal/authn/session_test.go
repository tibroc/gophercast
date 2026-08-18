package authn

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ocng/internal/jose"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// The cookie carries the BOUNDED principal — the T1 keystone through the
// stateless path (serve-auth Phase B).
func TestSessionCodec(t *testing.T) {
	c := &SessionCodec{Secret: testSecret}

	val, err := c.Mint("user-42", []string{"ROLE_LTI_USER", "ROLE_LTI_CONTEXT_COURSE_7"})
	if err != nil {
		t.Fatal(err)
	}
	p, info, ok := c.Validate(val)
	if !ok || info.Method != "lti" || info.Username != "user-42" ||
		len(p.Roles) != 2 || p.Roles[0] != "ROLE_LTI_USER" {
		t.Fatalf("round-trip: ok=%v info=%+v roles=%v", ok, info, p.Roles)
	}

	// mint-side bound: a role outside ROLE_LTI_* is a loud refusal
	if _, err := c.Mint("user-42", []string{"ROLE_LTI_USER", "ROLE_ADMIN"}); err == nil {
		t.Error("mint accepted ROLE_ADMIN (T1 keystone breach)")
	}
	if _, err := c.Mint("user-42", []string{"ROLE_EPISODE_x_WRITE"}); err == nil {
		t.Error("mint accepted an episode synthetic")
	}

	// validate-side bound: a cookie SIGNED WITH THE REAL KEY but carrying
	// an out-of-bound role is rejected whole — even key compromise cannot
	// widen authority through this path.
	forged, err := jose.SignHS256(map[string]any{
		"sub": "attacker", "roles": []any{"ROLE_LTI_USER", "ROLE_ADMIN"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.Validate(forged); ok {
		t.Error("validate accepted a real-key session carrying ROLE_ADMIN")
	}

	// tampered cookie rejected
	parts := strings.Split(val, ".")
	tampered := parts[0] + "." + parts[1][:len(parts[1])-2] + "AA" + "." + parts[2]
	if _, _, ok := c.Validate(tampered); ok {
		t.Error("tampered cookie validated")
	}

	// expired → rejected (Now injected past the TTL + skew)
	late := &SessionCodec{Secret: testSecret,
		Now: func() time.Time { return time.Now().Add(DefaultSessionTTL + time.Hour) }}
	if _, _, ok := late.Validate(val); ok {
		t.Error("expired session validated")
	}

	// empty role set carries no authority: rejected
	empty, err := jose.SignHS256(map[string]any{
		"sub": "user-42", "roles": []any{},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.Validate(empty); ok {
		t.Error("roleless session validated")
	}
}

// Resolve chain link 2: a valid session resolves; a presented-but-invalid
// session is a HARD anonymous — never a fallthrough to the dev seam (the
// bearer posture, applied to the cookie).
func TestResolveSessionLink(t *testing.T) {
	codec := &SessionCodec{Secret: testSecret}
	a := New(Config{Session: codec, DevSeam: true})

	val, err := codec.Mint("user-42", []string{"ROLE_LTI_CONTEXT_COURSE_7", "ROLE_LTI_USER"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/elements/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: val})
	p, info, ok := a.Resolve(req)
	if !ok || info.Method != "lti" || p.Roles[0] != "ROLE_LTI_CONTEXT_COURSE_7" {
		t.Fatalf("session resolve: ok=%v info=%+v roles=%v", ok, info, p.Roles)
	}

	// tampered session + dev-seam X-Roles: the cookie DECIDES (hard
	// anonymous); the seam must not rescue a failed credential
	req = httptest.NewRequest("GET", "/elements/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: val + "x"})
	req.Header.Set("X-Roles", "ROLE_ADMIN")
	if p, _, ok := a.Resolve(req); ok || len(p.Roles) != 1 || p.Roles[0] != "ROLE_ANONYMOUS" {
		t.Fatalf("invalid session must be hard anonymous, got ok=%v roles=%v", ok, p.Roles)
	}

	// no cookie at all: the seam still works (dev/test shape unchanged)
	req = httptest.NewRequest("GET", "/elements/x", nil)
	req.Header.Set("X-Roles", "ROLE_COURSE_7")
	if p, _, ok := a.Resolve(req); !ok || p.Roles[0] != "ROLE_COURSE_7" {
		t.Fatalf("dev seam without cookie: ok=%v roles=%v", ok, p.Roles)
	}
}
