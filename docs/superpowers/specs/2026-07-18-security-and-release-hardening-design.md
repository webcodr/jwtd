# Security and Release Hardening Design

## Goal

Resolve all findings from the repository review without changing jwtd's single-package architecture or removing supported opaque symmetric-key files.

The changes must prevent asymmetric key material from being reinterpreted as an HMAC secret, make failed verification observable through the process exit status, preserve JSON number fidelity, make raw decrypted output terminal-safe, display complete JWE protected headers, and ensure releases are tested and bound to the commit they identify.

## Compatibility Decisions

- Invalid JWS signatures print the existing `Signature: INVALID` diagnostic and return a nonzero exit status.
- X.509 PEM and DER certificates are supported as verification keys by extracting their public key.
- Recognizable structured key data that cannot be parsed is rejected.
- Opaque text and binary key files remain supported as symmetric key material.
- Manual releases are restricted to `main`.
- The existing release matrix, archive names, and Homebrew publishing flow remain unchanged.

## Runtime Design

Production code remains in `main.go`. New helpers are introduced only where they isolate a security boundary or make behavior directly testable.

### Key Loading

`loadKey` continues to support `raw:`, file paths, standard base64, and raw base64url inputs. File and decoded inline data pass through structured parsing before any symmetric-key fallback.

Structured parsing supports:

- Single JWK and JWK Set input.
- PEM-encoded PKCS#1, PKCS#8, SEC 1, and PKIX keys.
- DER-encoded PKCS#1, PKCS#8, SEC 1, and PKIX keys.
- PEM- or DER-encoded X.509 certificates, which resolve to `certificate.PublicKey`.

If input has a recognizable structured envelope, such as a PEM block, JSON object, or syntactically valid ASN.1 DER sequence, a parsing failure is returned to the caller. It must not fall through to `[]byte`. Only data with no recognizable structured envelope uses the existing raw symmetric-key fallback. Text key files continue to have trailing CR and LF bytes trimmed; binary files remain byte-exact.

This preserves documented symmetric-key files while preventing public certificates, malformed PEM, or malformed JWK data from becoming attacker-known HMAC keys.

### Signature Verification

Introduce a package-level sentinel error for cryptographic verification failure. `verifySignature` retains the current valid/invalid output and detailed invalid reason, but returns the sentinel error after an invalid result. Key loading and output failures remain distinguishable errors.

The Cobra command suppresses usage text for runtime failures. Consequently, an invalid signature prints the invalid result and reason, then exits with status 1 without appending command usage. Valid signatures, including expired tokens with a correct signature, exit successfully.

### Number Fidelity

JWT parsing uses `jwt.WithJSONNumber()` so arbitrary numeric claims are not rounded through `float64`. Decrypted JSON uses a `json.Decoder` with `UseNumber` for both objects and arrays.

`formatTimestamps` accepts `json.Number` and existing numeric values. It preserves the original numeric text in parentheses. Integral NumericDate values keep the existing RFC3339 output; fractional values retain their fraction and format the corresponding subsecond time without truncation. Invalid or out-of-range timestamp values remain unchanged rather than being replaced with a misleading date.

### Terminal-Safe Plaintext

The non-JSON decrypted payload path escapes terminal control characters before writing output. Newlines and tabs remain readable. C0 controls, carriage returns, ESC, BEL, DEL, and invalid UTF-8 bytes are rendered as `\xNN`; C1 and targeted bidi control runes are rendered as `\uNNNN`. The output must not contain active ANSI, OSC, or other terminal control sequences originating from plaintext.

Formatted JSON uses its own sanitizer for C1, DEL, and the same targeted bidi controls; it does not pass through the raw-text escaper.

### Complete JWE Protected Headers

After go-jose successfully parses the compact JWE, the first compact segment is base64url-decoded into a display-only `map[string]any` using `UseNumber`. This map is printed as the protected header, preserving all fields, including `x5c` and future extension fields.

go-jose remains authoritative for algorithm allowlisting, structural validation, and decryption. The display decoder does not influence cryptographic behavior.

## Release Workflow Design

Add a validation job before matrix builds. It must:

- Fail unless `github.ref` is `refs/heads/main`.
- Validate the supplied version as SemVer 2.0 without a leading `v`, including correct numeric identifier, prerelease, and build-metadata rules.
- Check formatting, run `go vet ./...`, and run `go test ./...` against the dispatch SHA.

The version input is assigned to an environment variable and referenced only as quoted `"$VERSION"` shell data. GitHub expression interpolation is not placed directly in shell scripts.

Every build depends on validation, and per-version concurrency serializes release reconciliation. If the version tag is absent, the release job creates its Git ref at `GITHUB_SHA` through the Git refs API; it then freshly force-fetches and peels the tag and requires the resulting commit to equal `GITHUB_SHA`. Release creation uses `gh release create --verify-tag` to create an assetless draft. Creation conflicts trigger a bounded release re-query and state reload. Draft assets are uploaded deterministically, downloaded, and byte-verified before publication; an existing published release is treated as immutable and its complete asset set must byte-match the current artifacts. The Homebrew formula uses the same validated version variable. Existing platforms, archive names, checksums, and tap publication remain unchanged.

## Error Handling

- Invalid signatures are expected verification failures: print the invalid result, return the sentinel error, and exit nonzero.
- Malformed structured keys return a key-loading error with the underlying format failure wrapped.
- Invalid display-only protected-header decoding returns a parsing error because a successfully parsed compact JWE must have a valid protected header.
- Writer, JSON formatting, decryption, and workflow failures continue to propagate immediately.
- Runtime errors do not print Cobra usage text.

## Test Strategy

Implementation follows test-driven development. Each behavior receives a failing regression test before production changes.

### Key Tests

- Load X.509 PEM and DER certificates and assert that their public keys are returned.
- Sign an HS256 token with public certificate bytes and assert verification fails with the sentinel error.
- Reject malformed PEM and malformed JWK files instead of returning `[]byte`.
- Reject recognizable unsupported structured DER.
- Preserve existing opaque text and binary symmetric-key file behavior.
- Preserve RSA, ECDSA, Ed25519, HMAC, and JWE key-loading coverage.

### Verification Tests

- Invalid signatures and algorithm/key mismatches print `INVALID` and return the sentinel error.
- Valid signatures return nil.
- Expired but correctly signed tokens remain cryptographically valid.
- Cobra execution returns an error for an invalid signature without emitting usage text.

### Formatting Tests

- Values above JavaScript's safe integer limit retain their exact decimal representation.
- Fractional NumericDate values retain their source value and subsecond time.
- Out-of-range and malformed NumericDate values remain unchanged.
- Decrypted JSON objects and arrays preserve large numbers.

### Output Tests

- Raw plaintext containing ANSI CSI, OSC, BEL, carriage return, DEL, C1 controls, invalid UTF-8, and targeted bidi controls contains no active control sequences in output.
- Formatted JSON sanitizes C1, DEL, and targeted bidi controls without applying the raw C0/invalid-UTF-8 path.
- Safe text, newlines, and tabs remain readable.
- A compact JWE protected header containing `x5c` and custom fields displays every field.

### Workflow Verification

- Run `actionlint` when available.
- Inspect the workflow to confirm all release jobs depend on validation; per-version concurrency is enabled; a missing tag is established at `GITHUB_SHA`, freshly fetched, peeled, and proven equal; release creation verifies that tag; conflicts re-query release state; and draft or immutable published assets are byte-verified.
- Run `go test -race ./...`, `go vet ./...`, `gofmt -l .`, and `go build ./...`.
- Cross-build all six release `GOOS` and `GOARCH` combinations.

## Documentation

Update `README.md` and `AGENTS.md` to document:

- X.509 certificate key support.
- Rejection of malformed recognizable structured key data.
- Continued raw symmetric-key file support for opaque files.
- Nonzero exit status when supplied-key signature verification fails.

## Non-Goals

- Splitting the package or production source into multiple files.
- Changing supported JWS or JWE algorithms.
- Adding remote JWKS retrieval or changing the documented first-key JWK Set behavior.
- Adding claims validation; verification continues to report cryptographic signature validity independently of expiry and other claims.
- Changing release artifact names or supported platforms.
