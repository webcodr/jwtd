# Security Audit: jwtd (application code)

**Date:** 2026-07-22
**Scope:** `main.go`, `jwe.go`, `keys.go`, `output.go` + dependency behavior (jwt v5.3.1, go-jose v4.1.4). Excluded: release/CI config, packaging, website.
**Method:** code review + empirical verification against the real binary (crafted tokens/JWEs/keys), dependency source inspection, `go test`, `go vet`, `govulncheck`.

## Verdict: no vulnerabilities found

The codebase is defensively written and its security-relevant claims hold up under testing. All findings below are low-severity or informational hardening opportunities.

## Attack surfaces verified safe (with evidence)

### Algorithm confusion (JWS)

`validMethodsForKey` restricts accepted `alg` values to the loaded key's type, applied *after* private-to-public extraction. Verified end-to-end:

- HS256 token + RSA public key (file *and* inline base64) → `INVALID`
- RS256 token + HMAC secret → `INVALID`
- `alg:none` → `INVALID`
- Exit code 1 on invalid signatures

jwt v5.3.1 additionally enforces ECDSA curve/alg match. The classic "use the public key as HMAC secret" attack is not possible: anything that parses as structured key material can never degrade into `[]byte` (guarded by `isStructuredKeyData`).

### Terminal escape injection

Every output path was traced and fuzzed with crafted inputs:

- **JWT signature segment** is base64url-validated by `ParseUnverified` (jwt v5.3.1 decodes it) before being printed raw → safe charset only.
- **Header/claims/JWE protected header** are re-encoded through `encoding/json` + `escapeFormattedJSONControls` (DEL, C1, bidi). A JWE header containing ESC/CSI/OSC/DEL/U+202E rendered fully escaped (verified at byte level).
- **Decrypted raw payloads** go through `escapeTerminalText` (C0 incl. ESC/BEL, DEL, C1, bidi, invalid UTF-8). An OSC 52 clipboard-hijack payload decrypted successfully but emitted zero raw control bytes.
- **Error messages** only echo attacker data via `%q`/`%#v` quoting or validated-base64url segments.

### Denial of service

All bounded:

- **`big.Rat` in `formatTimestamps`**: suspected exponent amplification (`{"exp":1e999999999}` → ~415 MB allocation from a 67-byte token). **Not exploitable** — Go's `Rat.SetString` caps decimal exponents at 1e6 and rejects larger in <1 µs (verified empirically).
- **JSON nesting**: capped at 10,000 by `encoding/json` (verified).
- **JWE zip bombs**: go-jose v4.1.4 caps inflate at max(250 KB, 10x compressed size).
- **PBES2**: go-jose caps `p2c` at 1,000,000 iterations.

### Dependencies

`govulncheck`: **0 vulnerabilities in called code**. jwt 5.3.1 and go-jose 4.1.4 are current and include all known fixes (PBES2 DoS, token-split DoS). The tool performs no network access, no subprocess execution, no file writes, no temp files — it only reads argv/stdin/key file and writes stdout/stderr.

### Fail-closed behavior

- Unknown key types → no alg restriction applied, but jwt rejects the key-type mismatch → `INVALID`.
- JWK Set with an unparseable first key → `INVALID`.
- Broken structured key material misclassified by the heuristics → becomes an HMAC key → `INVALID`.

## Findings (hardening opportunities only)

| # | Severity | Finding |
|---|----------|---------|
| L1 | Low | **Key-argument ambiguity.** `-k mysecret` is silently base64-decoded (derived key `[155 43 30 114 183 173]`, verified), not taken literally. Documented in the flag help and `raw:` exists as escape hatch; failure direction is safe (false INVALID, never false VALID). Consider a stderr hint when the arg isn't an existing file and lacks `raw:` ("interpreted as base64"). |
| L2 | Info | **JWK Set: only first key used** (documented in `parseJWK`). No `kid` matching — a multi-key JWKS where the signer's key isn't first yields false INVALID. Fail-closed, but potentially confusing. |
| L3 | Info | **RSA1_5 accepted for JWE decryption.** Legacy algorithm (Bleichenbacher); impractical against a one-shot CLI, and go-jose implements RFC 3218 countermeasures. Acceptable for a decoder. |
| L4 | Info | **`JWTD_KEY` env var** exposes key material via `/proc/<pid>/environ` to same-user processes. Standard practice, documented. |
| L5 | Info | **Build toolchain Go 1.26.1 has stdlib CVEs** (x509 hostname parsing, net CNAME, os.Root). govulncheck confirms none are reachable from jwtd's code, but release binaries should be built with Go >=1.26.5. |
| L6 | Info | No ssh-style permission warning when reading private key files. Optional nicety. |

## Particularly good

- Strict JSON decoding everywhere (exact `json.Number`, trailing-data rejection) — display can't be desynced from what was parsed.
- The `isStructuredKeyData`/`hasJWKMember` heuristics exist specifically to prevent structured-keys-degrading-to-HMAC-bytes, and the failure direction is always closed.
- The test suite already includes adversarial tests for alg-confusion, BOM/escaped-JWK detection, and escaping — matching these findings.
- Nested JWT/JWE recursion is depth-bounded by design (nested tokens are decoded without a key, so no recursion).

**Bottom line:** No changes required. The only suggestion worth acting on is the L1 stderr hint; everything else is documentation-grade.
