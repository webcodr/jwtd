# Feature ideas

Feature suggestions for `jwtd`, grounded in the current architecture and its
fail-closed, single-binary, security-first design. Grouped from quick ergonomic
wins to larger additions and deliberate scope expansions.

---

## High-impact daily-driver ergonomics (low effort)

### 1. Strip `Authorization: Bearer ` prefix and surrounding quotes

`main.go` (`sanitizeToken`)

`sanitizeToken` currently strips whitespace only, so pasting
`Authorization: Bearer eyJ...`, `Bearer eyJ...`, or `"eyJ..."` from browser
DevTools, `curl -v`, or logs fails as malformed. Stripping an optional
case-insensitive `Authorization:` / `Bearer` prefix and matching surrounding
quotes removes a common copy-paste paper cut with zero risk to valid compact
tokens.

### 2. Additional claim validation flags

`claims.go` (`claimChecks`, `validateClaimsSet`)

Claim validation currently supports `--verify-claims`, `--aud`, and `--iss`
with zero clock-skew leeway. Several high-value options are already supported by
`golang-jwt/jwt/v5` or hook directly into existing helpers:

- `--leeway <duration>` (e.g. `30s`) for clock skew (`jwt.WithLeeway`)
- `--sub <subject>` to assert the `sub` claim (`jwt.WithSubject`)
- `--require-exp` to fail when `exp` is absent (`jwt.WithExpirationRequired`)
- `--alg <alg>` to pin the expected JWS/JWE algorithm (e.g. reject `RS256` when only `EdDSA` is allowed)
- `--at <rfc3339|unix>` to evaluate `exp`/`nbf` at a specific historical or future timestamp (hooks straight into `timeNow` in `output.go` for debugging incident logs)

### 3. Quiet / check-only mode (`-q` / `--quiet`)

`main.go`

Suppress stdout and rely solely on the exit code for scripting and CI checks
(e.g. `jwtd -q -k pub.pem --verify-claims "$TOKEN"`).

### 4. Local timezone display and additional OIDC timestamp claims

`output.go` (`representableTime`, `isTimestampClaim`)

`representableTime` always renders UTC, and `isTimestampClaim` only annotates
`iat`, `exp`, and `nbf`. Adding an opt-in `--local` / `--tz` flag for local
time display and recognizing OIDC timestamp claims (`auth_time`, optionally
`updated_at`) makes human inspection easier without touching `--json` output.

### 5. JWK Set disambiguation by `use` and `alg`

`keys.go` (`parseJWK`)

When multiple entries in a JWK Set share a `kid` (for example, one with
`use: "sig"` and another with `use: "enc"`, or different `alg` values),
`parseJWK` currently selects `matches[0]`. Filtering matching entries by `use`
(`sig` for JWS, `enc` for JWE) and header `alg` before falling back to the
first match prevents avoidable key-selection mismatches against real-world IdP
JWK Sets.

---

## Real-world verification & JWE workflows (medium effort)

### 6. Opt-in remote JWKS / OIDC discovery (`--jwks` / `--oidc`)

`keys.go`, `main.go`

Verifying tokens from Auth0, Okta, Cognito, Keycloak, Google, or GitHub Actions
currently requires downloading the provider's JWKS manually first. An explicit
`--jwks <https-url>` flag — and optionally `--oidc <issuer>` to resolve
`<issuer>/.well-known/openid-configuration` → `jwks_uri` — removes that step.

**Security constraints:**
- Strictly opt-in via explicit flags; never auto-follow untrusted `jku` or `iss` URLs from a token (prevents SSRF).
- HTTPS-only by default, with strict request timeouts and response size caps.

### 7. Separate decryption and verification keys for nested tokens (JWE → JWS)

`jwe.go`, `output.go` (`printDecryptedPayload`, `renderNested`), `main.go`

Currently `printDecryptedPayload` forwards the outer `--key` to any nested
token, and `main.go` skips `--verify-claims` / `--aud` / `--iss` on JWEs. In
practice, signed-then-encrypted tokens (such as encrypted OIDC ID tokens) are
decrypted with the recipient's private key and verified with the issuer's
public key.

Adding a dedicated `--verify-key` (or `--decrypt-key`) flag and applying claim
validation to decrypted nested JWTs would make JWE+JWS support end-to-end
complete.

### 8. Native OpenSSH public key support

`keys.go` (`isSSHPublicKey`, `unsupportedKeyError`)

`keys.go` already detects OpenSSH public keys and prints a `ssh-keygen -e -m PKCS8`
conversion hint (which does not support Ed25519 keys). Parsing OpenSSH RSA,
ECDSA, and Ed25519 public keys natively lets users verify directly against
`~/.ssh/id_*.pub` while keeping the fail-closed symmetric-secret boundary
intact.

### 9. Section and claim extraction (`--header`, `--payload`, `--claim`)

`main.go`, `jsonout.go`

Allow printing a single section or extracting a specific claim value directly
(e.g. `jwtd --claim sub "$TOKEN"` or `jwtd --payload "$TOKEN"`) for quick shell
pipelines when `jq` is unavailable or unnecessary.

---

## Deeper token inspection & modern standards (medium–larger effort)

### 10. Token diffing (`jwtd diff <tokenA> <tokenB>`)

New subcommand

Compare two tokens side by side or as a unified colored diff of header and
payload claims — useful when comparing before/after token refreshes, staging
vs. production tokens, or two users' roles/scopes — including human-readable
timestamp deltas.

### 11. SD-JWT (Selective Disclosure JWT, RFC 9901)

New parser / renderer

Decode tilde-separated SD-JWTs (`<issuer-jwt>~<disclosure1>~...~<kb-jwt>`),
verify `_sd` digest bindings, show which claims were selectively disclosed, and
render any attached Key Binding JWT.

### 12. Inspect embedded `x5c` certificate chains

`output.go` / `keys.go`

Decode embedded `x5c` X.509 certificates in JWS/JWE headers into readable
summaries (subject, issuer, validity window, SANs, SHA-256 thumbprint) instead
of opaque base64 strings — inline or behind a flag such as `--inspect-certs`.

### 13. JWS / JWE JSON Serialization (RFC 7515 / RFC 7516)

`main.go`, `jwe.go`

Support Flattened and General JSON Serialization in addition to compact
dot-separated tokens, as well as raw non-JSON JWS payloads permitted by
RFC 7515.

### 14. Batch / stream and looping interactive mode

`main.go` (`readToken`, `readInteractive`)

Accept multiple newline-delimited tokens over stdin (e.g. scanning log streams,
optionally emitting NDJSON with `--json`) and/or allow interactive mode to
decode multiple tokens in a session instead of exiting after one.

---

## Scope-expanding ideas (deliberate product decisions)

### 15. Security lint / audit mode (`--lint` or `--audit`)

Flag common JWT/JWE pitfalls without breaking normal decode: `alg: none`,
deprecated JWE key algorithms (`RSA1_5`), missing `exp`, unusually long token
lifetimes, remote header pointers (`jku`, `x5u`), or token sizes exceeding
common HTTP header/cookie limits (4 KB / 8 KB).

### 16. Token creation and re-signing (`jwtd encode` / `jwtd sign`)

Craft test tokens or edit a decoded token's claims and re-sign with a local
development key. Frequently requested for local dev workflows, though it
expands `jwtd` beyond a strictly read/inspect/verify/decrypt tool — worth
weighing against keeping the CLI's focused scope.
