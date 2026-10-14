# sdjwt-go

Go library for SD-JWT VC (RFC 9901): issue a credential bound to a holder key, and verify a presentation (issuer signature, disclosures, key binding). Issuers are Ed25519 `did:key`.

```go
credential, err := sdjwt.Issue(issuerKey, sdjwt.Credential{Type: "Employee", HolderKey: jwk, Disclosable: map[string]any{"email": "a@b.nl"}})

v, err := sdjwt.Verify(presentation, sdjwt.Options{Keys: sdjwt.DIDKey{}, /* audience, nonce, ... */})
```

Part of [Attesta](https://github.com/threehook/attesta); it has no dependency on it. MIT.
