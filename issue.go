package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Credential is what an issuer puts in an SD-JWT VC.
type Credential struct {
	// Type is the credential type (the `vct` claim).
	Type string
	// HolderKey is the holder's public key as a JWK; the credential is bound to it (`cnf.jwk`).
	HolderKey map[string]any
	// ExpiresAt is optional.
	ExpiresAt time.Time
	// Claims are always visible; Disclosable ones are only revealed when the holder includes their disclosure.
	Claims      map[string]any
	Disclosable map[string]any
	// Now defaults to time.Now.
	Now func() time.Time
}

var reservedClaims = []string{"iss", "iat", "exp", "vct", "cnf", "_sd", "_sd_alg", "..."}

// Issue signs the credential with an Ed25519 key and returns `<issuer-signed JWT>~<disclosure>~...~`, the form a holder stores.
// The issuer is the key's `did:key`.
func Issue(key ed25519.PrivateKey, c Credential) (string, error) {
	if c.Type == "" {
		return "", errors.New("credential has no type")
	}
	holderClaims := map[string]any{"jwk": c.HolderKey}
	if _, err := holderKeyOf(jwt.MapClaims{"cnf": holderClaims}); err != nil {
		return "", err
	}
	for name := range c.Claims {
		if err := checkName(name); err != nil {
			return "", err
		}
	}
	for name := range c.Disclosable {
		if err := checkName(name); err != nil {
			return "", err
		}
		if _, dup := c.Claims[name]; dup {
			return "", fmt.Errorf("claim %q is both visible and disclosable", name)
		}
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	issuer := DIDKeyFromEd25519(key.Public().(ed25519.PublicKey))

	payload := jwt.MapClaims{"iss": issuer, "iat": now().Unix(), "vct": c.Type, "cnf": holderClaims, "_sd_alg": sdAlgSHA256}
	if !c.ExpiresAt.IsZero() {
		payload["exp"] = c.ExpiresAt.Unix()
	}
	for name, v := range c.Claims {
		payload[name] = v
	}

	var disclosures, digests []string
	for name, v := range c.Disclosable {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		raw, err := json.Marshal([]any{base64.RawURLEncoding.EncodeToString(salt), name, v})
		if err != nil {
			return "", fmt.Errorf("claim %q: %w", name, err)
		}
		d := base64.RawURLEncoding.EncodeToString(raw)
		disclosures = append(disclosures, d)
		digests = append(digests, digest(d))
	}
	if len(digests) > 0 {
		sort.Strings(digests) // the order must not reveal which claim is which
		payload["_sd"] = digests
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, payload)
	token.Header["typ"] = typeCredential
	token.Header["kid"] = issuer + "#" + strings.TrimPrefix(issuer, "did:key:")
	signed, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	out := signed + "~"
	for _, d := range disclosures {
		out += d + "~"
	}
	return out, nil
}

func checkName(name string) error {
	for _, r := range reservedClaims {
		if name == r {
			return fmt.Errorf("claim name %q is reserved", name)
		}
	}
	return nil
}
