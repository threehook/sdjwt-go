# sdjwt-go

Go library to issue and verify SD-JWT VC credentials ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)) with holder key binding.
Issuers identify themselves with an Ed25519 `did:key`, so verifying needs no network and no registry.

```sh
go get github.com/threehook/sdjwt-go
```

## Issue

The credential is bound to the holder's public key (a JWK). `Claims` are always visible; `Disclosable` claims are only revealed
when the holder includes their disclosure.

```go
_, issuerKey, _ := ed25519.GenerateKey(rand.Reader)

credential, err := sdjwt.Issue(issuerKey, sdjwt.Credential{
	Type:      "Employee",
	HolderKey: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "..."},
	ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	Claims:    map[string]any{"organisation": "Gemeente Utrecht"},
	Disclosable: map[string]any{
		"email":      "jerry@example.com",
		"department": "Parkeren",
	},
})
// credential is "<issuer-signed JWT>~<disclosure>~<disclosure>~", the form a holder stores.
// The issuer is the did:key of issuerKey.
```

## Verify

A presentation is `<issuer-signed JWT>~<disclosure>~...~<key-binding JWT>`. The key-binding JWT ties it to one request of one verifier.

```go
v, err := sdjwt.Verify(presentation, sdjwt.Options{
	Keys:     sdjwt.DIDKey{},
	Audience: "redirect_uri:https://verifier.example/response",
	Nonce:    nonceOfThisRequest,
})
if err != nil {
	// not a valid presentation
}
// v.Issuer, v.Type (the vct) and v.Claims: the visible and the disclosed claims only.
```

`Verify` checks the issuer signature, `typ`, `exp` and `nbf`, that every disclosure is referenced exactly once, and the key-binding JWT:
its signature with `cnf.jwk`, `aud`, `nonce`, `sd_hash` over the presentation, and an `iat` no older than `KeyBindingMaxAge` (5 minutes by default).

It never decides whether an issuer is trusted. It reports who the issuer is and the caller decides. To resolve issuers another way
(a web DID, a certificate), implement `KeyResolver`:

```go
type KeyResolver interface {
	Key(issuer string, header map[string]any) (crypto.PublicKey, error)
}
```

## Revocation

An issuer sets `Credential.Status` (index and list URI) and publishes a signed status list
([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)), one bit per credential, 1 = revoked.
`Verify` returns the reference in `Verified.Status`; checking the bit is up to the caller, who fetches the list.

```go
list := sdjwt.NewStatusList(1024)
list.SetRevoked(7, true)
token, err := sdjwt.SignStatusList(issuerKey, "https://issuer.example/status/1", list, 5*time.Minute, time.Now().Add(time.Hour), nil)

st, err := sdjwt.VerifyStatusList(token, sdjwt.DIDKey{}, nil)
// st.Issuer, st.URI (compare with v.Issuer and v.Status.URI), st.TTL, st.ExpiresAt
revoked, err := st.List.Revoked(v.Status.Index)
```

## Limits

- Status lists use 1 bit per credential.
- Digest algorithm `sha-256` only.
- Issuing signs with Ed25519. Verifying accepts EdDSA and ES256, for the issuer and for the holder.
- Holder keys in `cnf.jwk` are Ed25519 or P-256.
- Issuing makes object-property disclosures, without decoy digests or nested disclosures.
- `Verify` checks presentations, so key binding is required; it does not check a credential on its own.

MIT. Made for [Attesta](https://github.com/threehook/attesta), with no dependency on it.
