package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func holderJWK(key ed25519.PrivateKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(key.Public().(ed25519.PublicKey))}
}

// present has the holder reveal the named disclosures and sign the key binding, as a wallet does.
func present(t *testing.T, issued string, holder ed25519.PrivateKey, reveal func(disclosure string) bool) string {
	t.Helper()
	parts := strings.Split(strings.TrimSuffix(issued, "~"), "~")
	out := parts[0] + "~"
	for _, d := range parts[1:] {
		if reveal(d) {
			out += d + "~"
		}
	}
	kb := jwt.MapClaims{"aud": "redirect_uri:https://verifier.test/response", "nonce": "nonce-1", "iat": now.Unix(), "sd_hash": digest(out)}
	return out + sign(t, holder, kb, "kb+jwt")
}

func issueOptions() Options {
	return Options{Keys: DIDKey{}, Audience: "redirect_uri:https://verifier.test/response", Nonce: "nonce-1", Now: func() time.Time { return now }}
}

func newIssued(t *testing.T) (issued string, issuer string, holder ed25519.PrivateKey) {
	t.Helper()
	pub, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ = ed25519.GenerateKey(rand.Reader)
	issued, err := Issue(issuerKey, Credential{
		Type: "Employee", HolderKey: holderJWK(holder), ExpiresAt: now.Add(24 * time.Hour), Now: func() time.Time { return now },
		Claims:      map[string]any{"organisation": "Gemeente Utrecht"},
		Disclosable: map[string]any{"email": "jerry@example.com", "department": "Parkeren", "roles": []any{"hr", "admin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued, DIDKeyFromEd25519(pub), holder
}

func TestIssuedCredentialVerifiesWithEveryDisclosure(t *testing.T) {
	issued, issuer, holder := newIssued(t)
	v, err := Verify(present(t, issued, holder, func(string) bool { return true }), issueOptions())
	if err != nil {
		t.Fatal(err)
	}
	if v.Issuer != issuer || v.Type != "Employee" {
		t.Fatalf("issuer %q type %q", v.Issuer, v.Type)
	}
	if v.Claims["email"] != "jerry@example.com" || v.Claims["department"] != "Parkeren" || v.Claims["organisation"] != "Gemeente Utrecht" {
		t.Fatalf("claims %v", v.Claims)
	}
	if roles, _ := v.Claims["roles"].([]any); len(roles) != 2 {
		t.Fatalf("roles %v", v.Claims["roles"])
	}
}

func TestIssuedCredentialHidesWhatTheHolderKeeps(t *testing.T) {
	issued, _, holder := newIssued(t)
	onlyEmail := func(d string) bool { return strings.Contains(decode(t, d), `"email"`) }
	v, err := Verify(present(t, issued, holder, onlyEmail), issueOptions())
	if err != nil {
		t.Fatal(err)
	}
	if v.Claims["email"] != "jerry@example.com" {
		t.Fatalf("claims %v", v.Claims)
	}
	if _, ok := v.Claims["department"]; ok {
		t.Fatal("department was not disclosed")
	}
	if strings.Contains(issued, "Parkeren") || strings.Contains(strings.SplitN(issued, "~", 2)[0], "jerry") {
		t.Fatal("disclosable values appear in the signed token")
	}
}

func TestIssuedCredentialWithoutDisclosablesHasNoTrailingGap(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	issued, err := Issue(key, Credential{Type: "Plain", HolderKey: holderJWK(holder), Claims: map[string]any{"a": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(issued, "~") || strings.HasSuffix(issued, "~~") || strings.Count(issued, "~") != 1 {
		t.Fatalf("token %q", issued)
	}
}

func TestIssueRejectsBadInput(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	good := func() Credential { return Credential{Type: "T", HolderKey: holderJWK(holder)} }
	cases := map[string]func(*Credential){
		"no type":            func(c *Credential) { c.Type = "" },
		"no holder key":      func(c *Credential) { c.HolderKey = nil },
		"reserved visible":   func(c *Credential) { c.Claims = map[string]any{"cnf": 1} },
		"reserved disclosed": func(c *Credential) { c.Disclosable = map[string]any{"_sd": 1} },
		"both":               func(c *Credential) { c.Claims = map[string]any{"a": 1}; c.Disclosable = map[string]any{"a": 2} },
	}
	for name, edit := range cases {
		c := good()
		edit(&c)
		if _, err := Issue(key, c); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func decode(t *testing.T, d string) string {
	t.Helper()
	raw, err := base64URL(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func base64URL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
