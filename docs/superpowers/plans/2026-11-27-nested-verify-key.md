# Separate Verification Key and Nested Claims Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--verify-key`/`JWTD_VERIFY_KEY`, so a signed-then-encrypted token is decrypted with one key and verified with another. Claim checks move to the innermost claims set in the human, `--json`, and extraction modes.

**Architecture:** A new `layers.go` opens a token once into a chain of `tokenLayer`s. All decryption and verification happens there, under the key table in the spec, before any output. The human printer, `--json`, and extraction then become renderers over that chain.

**Tech Stack:** Go, Cobra, golang-jwt/jwt v5, go-jose v4.

**Spec:** `docs/superpowers/specs/2026-11-27-nested-verify-key-design.md`

## Global Constraints

- Every existing human-output case stays byte-identical. The existing `decodeAndPrint`/`decodeAndPrintJWE` tests are the oracle and keep today's signatures, `(w io.Writer, tokenStr, keyStr string) error`, as wrappers over `tokenKeys{decrypt: keyStr}`.
- Existing hard-error texts are unchanged: `signature verification: %w`, `signature verification: error loading key: %w`, `loading decryption key: %w`, `decrypting JWE: %w`.
- `--alg` checks the outermost header only, before any key is loaded.
- An explicit `--verify-key` is never skipped. A failure to use it on a nested JWS is a hard error.
- Unreachable claims give exactly one of these reasons: `the JWE payload is encrypted; pass --key to decrypt it`, `a nested JWE could not be decrypted`, `the decrypted payload is not a JSON claims set`.
- The error for a verification key that verified nothing is `--verify-key was given but no JWS signature was reached`, with ` (pass --key to decrypt the JWE first)` appended when the outer token is a JWE and no `--key` was given.
- Package `main`. Tests mirror sources (`layers.go` ↔ `layers_test.go`). Conventional Commits.

## Review Focus

1. **The motivating case:** an RSA recipient key wrapping an RS256 JWS signed by a different RSA key. `--key recipient --verify-key issuer` must give `Signature: VALID` and exit 0. With only `--key`, today's `INVALID` stays. The tests go in Tasks 1 and 2.
2. **A JWK Set `--verify-key` whose `kid` misses a nested JWS** must be a hard error, not a keyless retry. The same JWK Set passed as `--key` (fallback) gives no verdict, as today. The test goes in Task 1.
3. **A JWE without `--key` plus `--verify-claims`** used to exit 0 with a note. It now gives `Claims: INVALID` and a nonzero exit. The test goes in Task 3.
4. **`JWTD_VERIFY_KEY` set globally while decoding a plain JWT:** the env key verifies it, and a global `JWTD_KEY` alongside it is not an error. The test goes in Task 3.
5. **Extraction on JWE→JWS with a bad inner signature** must keep stdout empty. The test goes in Task 5.

---

### Task 1: Open a token into layers

**Files:**
- Create: `layers.go`
- Test: `layers_test.go`

**Interfaces:**
- Consumes: `parseUnverifiedJWT`, `parseJWE`, `headerKID`, `loadKeyForToken`, `keySelector`, `verifyLoadedKeySignature`, `decodeJSON`, `isJWEBytes`, `isJWTBytes`.
- Produces:
  - `type tokenKeys struct { decrypt, verify string }` with `func (k tokenKeys) verification() (keyStr string, explicit bool)`: returns `verify, true` when it is set, otherwise `decrypt, false`.
  - `type verdict struct { valid bool; reason string }`
  - `type tokenLayer struct { jws *parsedJWT; sig *verdict; jweToken string; jwe *jose.JSONWebEncryption; header map[string]any; plaintext []byte; decrypted bool; nested *tokenLayer }`. Exactly one of `jws` and `jwe` is set. `header` is the JWE protected header (a JWS keeps its header in `jws.header`).
  - `func openJWT(p *parsedJWT, keys tokenKeys, nested bool) (*tokenLayer, error)`
  - `func openJWE(token string, jwe *jose.JSONWebEncryption, header map[string]any, keys tokenKeys, nested bool) (*tokenLayer, error)`
  - `func openToken(token string, keys tokenKeys) (*tokenLayer, error)`: parses the token and dispatches with `nested=false`.
  - `func (l *tokenLayer) innermost() *tokenLayer`
  - `func (l *tokenLayer) claimsTarget() (jwt.MapClaims, string)`: returns the claims, or nil plus one of the three spec reasons.
  - `func (l *tokenLayer) signatureFailure() *verdict`: the outermost invalid verdict, or nil.
  - `func (l *tokenLayer) hasJWS() bool`

- [ ] **Step 1: Write the failing tests** in `layers_test.go` (table-driven where the shape repeats):

```go
func TestOpenToken_TopLevel(t *testing.T)
// plain JWT, no key → jws != nil, sig == nil
// HS256 JWT, keys{decrypt: secretArg} → sig.valid (fallback)
// HS256 JWT, keys{decrypt: wrongArg, verify: secretArg} → sig.valid (verify wins)
// HS256 JWT, keys{decrypt: "raw:"} → err contains "signature verification: error loading key"
// JWE, no key → jwe != nil, !decrypted
// JWE {"sub":"x"}, keys{decrypt: keyPath} → decrypted, plaintext == `{"sub":"x"}`, nested == nil
// JWE, keys{decrypt: otherKeyPath} → err contains "decrypting JWE"

func TestOpenToken_SignedThenEncrypted(t *testing.T)
// inner := signJWT(t, issuerKey, {"sub":"alice"}); outer := encryptJWE(t, recipientKey, inner)
// keys{decrypt: recipientPath, verify: writeRSAPublicKeyFile(issuer)} → nested.jws != nil, nested.sig.valid
// keys{decrypt: recipientPath} → nested.sig != nil && !nested.sig.valid   (today's fallback, pinned)
// keys{decrypt: recipientPath, verify: issuerJWKSetWithKID("other")} with inner kid "nope" → err contains "nested JWT signature verification"
// keys{decrypt: same JWK-set-shaped recipient key, inner kid "nope"} → nested.sig == nil (fallback keyless retry)

func TestOpenToken_NestedJWEUndecryptable(t *testing.T)
// outer := encryptJWE(t, keyA, encryptJWE(t, keyB, `{"sub":"x"}`)); keys{decrypt: keyAPath}
// → nested.jwe != nil, !nested.decrypted

func TestTokenLayer_ClaimsTarget(t *testing.T)
// JWT → its claims, ""
// JWE no key → nil, "the JWE payload is encrypted; pass --key to decrypt it"
// JWE {"sub":"x"} with key → map with sub, ""
// JWE "text" with key → nil, "the decrypted payload is not a JSON claims set"
// JWE wrapping undecryptable JWE → nil, "a nested JWE could not be decrypted"
// JWE wrapping JWS → the JWS claims
```

For the fallback no-verdict row, the decryption key has to load for the JWE but fail to load for the inner JWS. Use a JWK Set holding the recipient key and no `kid`-matching entry for the inner JWS's `kid: "nope"`. Sign the inner token with `signJWTWithHMACHeader`, or an RSA variant with a `kid` header; add an RSA header helper to `helpers_test.go` if needed.

- [ ] **Step 2: Run them to see them fail.** Run `go test -run 'TestOpenToken|TestTokenLayer' ./...`. Expected: FAIL to compile.
- [ ] **Step 3: Implement `layers.go`.**
  - `openJWT`: take the key from `keys.verification()`. With no key, return no verdict.
    - At the top level, a `headerKID` or key-load error becomes the existing `signature verification: ...` text.
    - For a nested layer with an explicit key, the same failures become `nested JWT signature verification: ...`.
    - For a nested layer in fallback mode, they give `sig = nil`.
    - Once a key is loaded, the verdict is `verifyLoadedKeySignature` with `reason.Error()`.
  - `openJWE`: with no decrypt key, return the layer undecrypted. Otherwise headerKID, load (use `enc`) and decrypt, with the existing error texts at the top level. In a nested layer, any of those failures returns the layer undecrypted. After decrypting, `nested` comes from the plaintext: `isJWEBytes` → `parseJWE` → `openJWE(…, true)`, else `isJWTBytes` → `parseUnverifiedJWT` → `openJWT(…, true)`. A parse failure leaves `nested` nil. A hard error from the nested open propagates.
- [ ] **Step 4: Run the tests to see them pass.** Same command. Expected: PASS.
- [ ] **Step 5: Commit** with `feat: open tokens into verified layers`.

### Task 2: Human renderer over layers

**Files:**
- Modify: `main.go` (`decodeAndPrint`, `printParsedJWT`, `decodeParsedJWTHuman`), `jwe.go` (`decodeAndPrintJWE`, `decodeParsedJWEHuman`), `output.go` (remove `printDecryptedPayload` and `renderNested`, add the renderer)
- Test: `output_test.go` / `jwe_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces: `func renderLayerHuman(w io.Writer, f *jsonFormatter, l *tokenLayer) error`. It returns `errInvalidSignature` (wrapped as today) when any layer's verdict is invalid. The output reproduces today's sections exactly: JWS Header/Payload (via a `formatTimestamps` clone)/Signature plus an optional verdict; JWE Protected Header, then encrypted parts, or `Decrypted Payload (nested JWE|JWT)` with the nested render, or the JSON/raw payload. `decodeAndPrint`, `decodeAndPrintJWE`, and `printParsedJWT` keep their signatures and become wrappers that open and then render.

- [ ] **Step 1: Write the failing test** `TestDecodeAndPrintJWE_SeparateVerifyKey`. It renders the Task 1 signed-then-encrypted token through `renderLayerHuman` after `openToken` with both keys. The stripped output contains `Decrypted Payload (nested JWT)` and `Signature: VALID`, and the error is nil.
- [ ] **Step 2: Run it to see it fail.** Run `go test -run TestDecodeAndPrintJWE_SeparateVerifyKey ./...`. Expected: FAIL (`renderLayerHuman` undefined).
- [ ] **Step 3: Implement the renderer** and rewire the wrappers. Delete `printDecryptedPayload` and `renderNested`, whose logic now lives in `openJWE`.
- [ ] **Step 4: Run the full suite.** Run `go test -count=1 ./...`. Expected: PASS, with every existing human-output test unchanged. A failing existing test means the output drifted, so fix the renderer, not the test.
- [ ] **Step 5: Commit** with `refactor: render human output from opened layers`.

### Task 3: `--verify-key` flag and innermost claims (human)

**Files:**
- Modify: `main.go` (`newRootCommand`, `run`, `printKeyInterpretation`, `decodeParsedJWTHuman`)
- Test: `main_test.go`

**Interfaces:**
- Consumes: Tasks 1 and 2, plus `printClaimsVerdict`.
- Produces: the `--verify-key` flag; `printKeyInterpretation(w io.Writer, keyStr, origin string, fromFlag bool)` (callers pass `--key`/`JWTD_KEY` or `--verify-key`/`JWTD_VERIFY_KEY`); and `func decodeLayerHuman(w io.Writer, l *tokenLayer, checks claimChecks) error`, which renders and then prints the claims verdict over `claimsTarget()` (an unreachable target gives `printVerdict(w, "Claims", false, reason)` plus `errInvalidClaims`).

- [ ] **Step 1: Write the failing CLI tests** (use `runRootCommand`):

```go
func TestRun_VerifyKeyNestedJWS(t *testing.T)            // --key recipient --verify-key issuerPub <jwe> → stdout has "Signature: VALID", err nil
func TestRun_VerifyKeyFromEnv(t *testing.T)              // t.Setenv("JWTD_VERIFY_KEY", secretFile); t.Setenv("JWTD_KEY", otherSecretFile); plain HS256 JWT → "Signature: VALID", err nil
func TestRun_VerifyKeyUnused(t *testing.T)               // --verify-key pub <jwe> (no --key) → err == spec text with the "(pass --key ...)" suffix, stdout ""
func TestRun_ClaimsOnNestedJWS(t *testing.T)             // pinTime; inner exp in the past; --key r --verify-key i --verify-claims <jwe> → "Claims: INVALID", errors.Is(err, errInvalidClaims)
func TestRun_ClaimsOnJWEWithoutKey(t *testing.T)         // --verify-claims <jwe> → "Claims: INVALID" + "pass --key to decrypt it", errors.Is(err, errInvalidClaims)
func TestRun_ClaimsOnEncryptedClaimsSet(t *testing.T)    // JWE plaintext {"sub":"x","aud":"a"} --key k --aud a → "Claims: VALID", err nil
func TestRun_VerifyKeyInterpretationNote(t *testing.T)   // --verify-key raw:s <jwt> → stderr contains "--verify-key used as a literal symmetric secret"
```

- [ ] **Step 2: Run them to see them fail.** Run `go test -run 'TestRun_(VerifyKey|ClaimsOn)' ./...`. Expected: FAIL (unknown flag `--verify-key`).
- [ ] **Step 3: Implement.** Add the flag ("key for JWS signature verification, top level or nested inside a JWE; defaults to --key"). Resolve `JWTD_VERIFY_KEY` the same way `JWTD_KEY` is resolved. In `run`, after the `--alg` check, call `openJWT`/`openJWE`. Then:
  - Check that the verification key reached a signature (with `hasJWS()` and the spec error).
  - Dispatch the human path to `decodeLayerHuman`.
  - Delete the "skipped for JWE" note.
  - Leave the #9 JWE-selector refusal in place until Task 5.
- [ ] **Step 4: Run the full suite.** Run `go test -count=1 ./...`. Expected: PASS. Any existing test that asserted the removed note or the exit 0 for claim flags on a keyless JWE must be updated to the new fail-closed behaviour; ledger each one as a ruling.
- [ ] **Step 5: Commit** with `feat: add --verify-key and validate innermost claims`.

### Task 4: `--json` over layers

**Files:**
- Modify: `jsonout.go`
- Test: `jsonout_test.go`

**Interfaces:**
- Consumes: Tasks 1 and 3.
- Produces:
  - `jweJSON` gains `Nested any \`json:"nested,omitempty"\`` and `ClaimsValid *bool \`json:"claimsValid,omitempty"\``.
  - `func layerJSON(l *tokenLayer) any` returns a `jwtJSON` or `jweJSON`, recursing into `nested`, with no `claimsValid`.
  - `func decodeLayerJSON(w io.Writer, l *tokenLayer, checks claimChecks) error` sets `claimsValid` on the top-level object, writes it, and returns the sentinel (signature first).
  - `decodeJWTJSON`/`decodeJWEJSON` keep their signatures as wrappers.

- [ ] **Step 1: Write the failing tests.**
  - `TestDecodeJWEJSON_Nested`: for the signed-then-encrypted token with both keys, `out["nested"].(map)["signatureValid"] == true`, `out["nested"].(map)["payload"].(map)["sub"] == "alice"`, and `decryptedPayload` is still the compact string.
  - `TestDecodeJWEJSON_ClaimsValid`: for a JWE claims set with `--aud` mismatching, `out["claimsValid"] == false` and `errors.Is(err, errInvalidClaims)`.
- [ ] **Step 2: Run them to see them fail.** Run `go test -run 'TestDecodeJWEJSON_(Nested|ClaimsValid)' ./...`. Expected: FAIL.
- [ ] **Step 3: Implement** and route `run`'s `--json` branch through `decodeLayerJSON`.
- [ ] **Step 4: Run the full suite.** Run `go test -count=1 ./...`. Expected: PASS.
- [ ] **Step 5: Commit** with `feat: recurse into nested tokens in --json output`.

### Task 5: Extraction over layers

**Files:**
- Modify: `extract.go` (replace `extractJWT`/`extractJWE` with one `extractLayer`), `main.go` (remove the #9 JWE-selector refusal)
- Test: `extract_test.go`, `main_test.go`

**Interfaces:**
- Consumes: Tasks 1 and 3, plus `writeSelected`.
- Produces: `func extractLayer(w, errw io.Writer, l *tokenLayer, checks claimChecks, sel selection, jsonOut bool) error`.
  - Before any output, print every failing verdict to `errw`: the outermost invalid signature, then the claims (an unreachable target counts as invalid when checks are requested).
  - Header: the outermost header. A JWE needs no key, but a given key has already been used, during open.
  - Payload: the innermost layer. A JWS gives its claims; a decrypted JWE gives the JSON value or the text, as #9 does; an undecrypted JWE gives the #9 `requires --key` error.
  - Claim: `claimsTarget()`. An unreachable target is an error using its reason, and a missing claim gives `claim %q not present`.

- [ ] **Step 1: Update and add the tests.** Move the existing `TestExtractJWT_*`/`TestExtractJWE` cases onto `extractLayer`, keeping their assertions. Change the `claim on nested token` case to expect the inner claim. Add:
  - `TestExtractLayer_NestedBadSignatureWithholds`: both keys, but the inner token is signed by a third key. Stdout is empty, `errors.Is(err, errInvalidSignature)`, and stderr has `Signature: INVALID`.
  - `TestExtractLayer_PayloadIsInnermost`: `--payload --json` on the signed-then-encrypted token gives `{"sub":"alice"}`.
  - In `main_test.go`, change `TestRun_JWEExtractionRefusesClaimFlags` to `TestRun_JWEExtractionValidatesClaims`: `--aud mine` against `aud: other` gives stdout empty, `errInvalidClaims`, and stderr `Claims: INVALID`.
- [ ] **Step 2: Run them to see them fail.** Run `go test -run 'TestExtract|TestRun_JWEExtraction' ./...`. Expected: FAIL.
- [ ] **Step 3: Implement** and route `run`'s selector branch through `extractLayer`.
- [ ] **Step 4: Run the full suite.** Run `go test -count=1 ./...`. Expected: PASS.
- [ ] **Step 5: Commit** with `feat: extract from the innermost layer of nested tokens`.

### Task 6: Documentation

**Files:**
- Modify: `AGENTS.md` (overview, a `layers.go` section, the `output.go`/`jwe.go`/`jsonout.go`/`extract.go` entries that describe removed functions, the file count, and Conventions), `README.md`, `site/index.html`, `site_test.go`, `docs/feature-ideas.md` (#7 status)

- [ ] **Step 1: Pin the site copy.** Add `"verify key workflow": "jwtd --key /path/to/private-key.pem --verify-key /path/to/issuer-public-key.pem"` to `TestWebsiteCopyContract`, run it, and expect FAIL.
- [ ] **Step 2: Write the docs.** They must state the key table, fail-closed claims, the `--json` `nested` field, `--payload` meaning the innermost payload, and the `--key`-only false `INVALID` with `--verify-key` as the fix.
- [ ] **Step 3: Run the checks.** Run `go test -count=1 ./...` and `gofmt -l .`. Expected: PASS and no output.
- [ ] **Step 4: Commit** with `docs: document --verify-key and nested claim validation`.
