package sdjwt

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const typeStatusList = "statuslist+jwt"

// maxStatusListBytes bounds the decompressed list so a hostile list cannot exhaust memory.
const maxStatusListBytes = 16 << 20

// StatusReference points a credential to its bit in a status list (draft-ietf-oauth-status-list): the `status.status_list` claim.
type StatusReference struct {
	// Index is the credential's position in the list.
	Index int
	// URI is where the list is published; it is the `sub` of the list's token.
	URI string
}

// StatusList holds one bit per credential; a set bit means revoked.
type StatusList struct {
	bits []byte
}

// NewStatusList returns a list with room for size credentials, none revoked.
func NewStatusList(size int) *StatusList {
	return &StatusList{bits: make([]byte, (size+7)/8)}
}

// Len is the number of positions the list holds (a multiple of 8).
func (l *StatusList) Len() int { return len(l.bits) * 8 }

// Revoked reports whether the bit at index is set. An index beyond the list is an error.
func (l *StatusList) Revoked(index int) (bool, error) {
	if index < 0 || index >= l.Len() {
		return false, fmt.Errorf("status index %d is outside the list of %d", index, l.Len())
	}
	return l.bits[index/8]&(1<<(index%8)) != 0, nil
}

// SetRevoked sets or clears the bit at index, growing the list when needed.
func (l *StatusList) SetRevoked(index int, revoked bool) error {
	if index < 0 {
		return errors.New("negative status index")
	}
	for index/8 >= len(l.bits) {
		l.bits = append(l.bits, 0)
	}
	if revoked {
		l.bits[index/8] |= 1 << (index % 8)
	} else {
		l.bits[index/8] &^= 1 << (index % 8)
	}
	return nil
}

// StatusListToken is a verified status list token.
type StatusListToken struct {
	Issuer string
	// URI is the token's `sub`: where the list claims to be published.
	URI  string
	List *StatusList
	// ExpiresAt is zero when the token has no `exp`; TTL is zero when it has no `ttl`.
	ExpiresAt time.Time
	TTL       time.Duration
}

// SignStatusList signs the list as a `statuslist+jwt` for uri. A zero ttl or expiresAt leaves that claim out.
func SignStatusList(key ed25519.PrivateKey, uri string, list *StatusList, ttl time.Duration, expiresAt time.Time, now func() time.Time) (string, error) {
	if uri == "" {
		return "", errors.New("status list has no uri")
	}
	if now == nil {
		now = time.Now
	}
	var packed bytes.Buffer
	zw, err := zlib.NewWriterLevel(&packed, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(list.bits); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	issuer := DIDKeyFromEd25519(key.Public().(ed25519.PublicKey))
	claims := jwt.MapClaims{
		"iss": issuer, "sub": uri, "iat": now().Unix(),
		"status_list": map[string]any{"bits": 1, "lst": base64.RawURLEncoding.EncodeToString(packed.Bytes())},
	}
	if ttl > 0 {
		claims["ttl"] = int64(ttl / time.Second)
	}
	if !expiresAt.IsZero() {
		claims["exp"] = expiresAt.Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = typeStatusList
	token.Header["kid"] = issuer + "#" + strings.TrimPrefix(issuer, "did:key:")
	return token.SignedString(key)
}

// VerifyStatusList checks the signature (through keys), `typ` and `exp` of a status list token and decodes it.
// It does not compare the issuer or the uri with the credential's: the caller does.
func VerifyStatusList(token string, keys KeyResolver, now func() time.Time) (*StatusListToken, error) {
	if now == nil {
		now = time.Now
	}
	claims := jwt.MapClaims{}
	var issuer string
	_, err := jwt.NewParser(jwt.WithValidMethods(issuerAlgs), jwt.WithLeeway(leeway), jwt.WithTimeFunc(now)).
		ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
			if typ, _ := t.Header["typ"].(string); typ != typeStatusList {
				return nil, fmt.Errorf("unexpected status list typ %q", typ)
			}
			issuer, _ = claims["iss"].(string)
			if issuer == "" {
				return nil, errors.New("status list has no issuer")
			}
			return keys.Key(issuer, t.Header)
		})
	if err != nil {
		return nil, fmt.Errorf("status list signature: %w", err)
	}
	uri, _ := claims["sub"].(string)
	if uri == "" {
		return nil, errors.New("status list has no sub")
	}
	sl, _ := claims["status_list"].(map[string]any)
	if bits, _ := sl["bits"].(float64); bits != 1 {
		return nil, fmt.Errorf("unsupported status list bits %v", sl["bits"])
	}
	lst, _ := sl["lst"].(string)
	packed, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		return nil, errors.New("status list is not base64url")
	}
	zr, err := zlib.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil, errors.New("status list is not zlib data")
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxStatusListBytes+1))
	if err != nil || len(raw) > maxStatusListBytes {
		return nil, errors.New("status list is corrupt or too large")
	}
	out := &StatusListToken{Issuer: issuer, URI: uri, List: &StatusList{bits: raw}}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		out.ExpiresAt = exp.Time
	}
	if ttl, ok := claims["ttl"].(float64); ok && ttl > 0 {
		out.TTL = time.Duration(ttl) * time.Second
	}
	return out, nil
}

// statusOf reads the `status.status_list` claim; nil means the credential has none.
func statusOf(claims map[string]any) (*StatusReference, error) {
	raw, ok := claims["status"]
	if !ok {
		return nil, nil
	}
	status, _ := raw.(map[string]any)
	ref, _ := status["status_list"].(map[string]any)
	idx, okIdx := ref["idx"].(float64)
	uri, _ := ref["uri"].(string)
	if !okIdx || idx < 0 || idx != float64(int(idx)) || uri == "" {
		return nil, errors.New("credential has an invalid status claim")
	}
	return &StatusReference{Index: int(idx), URI: uri}, nil
}
