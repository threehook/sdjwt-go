package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestStatusListRoundTrip(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	list := NewStatusList(10)
	if err := list.SetRevoked(3, true); err != nil {
		t.Fatal(err)
	}
	if err := list.SetRevoked(40, true); err != nil { // grows
		t.Fatal(err)
	}
	token, err := SignStatusList(key, "https://issuer.test/status/1", list, time.Minute, now.Add(time.Hour), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyStatusList(token, DIDKey{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != DIDKeyFromEd25519(pub) || got.URI != "https://issuer.test/status/1" || got.TTL != time.Minute || !got.ExpiresAt.Equal(now.Add(time.Hour).Truncate(time.Second)) {
		t.Fatalf("token %+v", got)
	}
	for i, want := range map[int]bool{0: false, 3: true, 4: false, 40: true, 41: false} {
		if r, err := got.List.Revoked(i); err != nil || r != want {
			t.Fatalf("index %d: revoked %v err %v, want %v", i, r, err, want)
		}
	}
	if _, err := got.List.Revoked(got.List.Len()); err == nil {
		t.Fatal("an index beyond the list must be an error")
	}
}

func TestStatusListRejectsExpiredAndTampered(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	token, _ := SignStatusList(key, "https://issuer.test/status/1", NewStatusList(8), 0, now.Add(time.Hour), func() time.Time { return now })
	if _, err := VerifyStatusList(token, DIDKey{}, func() time.Time { return now.Add(2 * time.Hour) }); err == nil {
		t.Fatal("expired list accepted")
	}
	parts := strings.Split(token, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA"
	if _, err := VerifyStatusList(strings.Join(parts, "."), DIDKey{}, func() time.Time { return now }); err == nil {
		t.Fatal("tampered list accepted")
	}
}

func TestStatusListIsNotACredential(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	token, _ := SignStatusList(key, "https://issuer.test/status/1", NewStatusList(8), 0, time.Time{}, func() time.Time { return now })
	if _, err := Verify(token+"~kb", issueOptions()); err == nil {
		t.Fatal("a status list verified as a credential")
	}
}

func TestCredentialStatusReachesVerified(t *testing.T) {
	pub, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	issued, err := Issue(issuerKey, Credential{
		Type: "Employee", HolderKey: holderJWK(holder), Now: func() time.Time { return now },
		Status:      &StatusReference{Index: 7, URI: "https://issuer.test/status/1"},
		Disclosable: map[string]any{"email": "jerry@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(present(t, issued, holder, func(string) bool { return true }), issueOptions())
	if err != nil {
		t.Fatal(err)
	}
	if v.Issuer != DIDKeyFromEd25519(pub) || v.Status == nil || *v.Status != (StatusReference{Index: 7, URI: "https://issuer.test/status/1"}) {
		t.Fatalf("status %+v", v.Status)
	}
	issued, _, holder = newIssued(t)
	v, err = Verify(present(t, issued, holder, func(string) bool { return true }), issueOptions())
	if err != nil || v.Status != nil {
		t.Fatalf("no status claim: %+v %v", v, err)
	}
}

func TestIssueRejectsStatusAsClaimName(t *testing.T) {
	_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	_, err := Issue(issuerKey, Credential{Type: "Employee", HolderKey: holderJWK(holder), Claims: map[string]any{"status": "x"}})
	if err == nil {
		t.Fatal("status must be reserved")
	}
}
