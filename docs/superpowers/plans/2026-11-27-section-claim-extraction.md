# Section and Claim Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--header`, `--payload`, and `--claim <name>`, which print one part of a token to stdout. A part that failed a requested check is never printed.

**Architecture:** A new `extract.go` renders the selected part after `run()` has parsed the token and applied `--alg`. It reuses `verifyJWTSignature`, `validateClaimsSet`, and the JWE key loading, so extraction verifies exactly the way the normal output does. A failing verdict goes to stderr and stdout stays empty.

**Tech Stack:** Go, Cobra, golang-jwt/jwt v5, go-jose v4.

**Spec:** `docs/superpowers/specs/2026-11-27-section-claim-extraction-design.md`

## Global Constraints

- Single package `main`. Tests mirror source files (`extract.go` ↔ `extract_test.go`).
- Claim names are top-level only. Do not interpret dots or paths.
- Output is the raw parse (`p.claims`, the decoded header), never the `formatTimestamps` display copy.
- A selector with a failing signature or claim check writes nothing to stdout, writes the failing verdict to stderr via `printVerdict`, and returns `errInvalidSignature` (which takes precedence) or `errInvalidClaims`.
- Missing claim error text: `claim "<name>" not present`.
- `--header`, `--payload`, and `--claim` are mutually exclusive. `--claim ""` is rejected before the token is read.
- Commit messages follow Conventional Commits.

## Review Focus

1. **A claim string with control or escape bytes** (`"sub":"\u001b[31mx"`) printed bare must not reach the terminal raw. Pass it through `escapeTerminalText`. The test goes in Task 1.
2. **`--claim` with a key and an invalid signature** must leave stdout empty even when the claim exists, which is the anti-goal case. The test goes in Task 1.
3. **A JSON `null` claim value** (`"x":null`) is present, not missing: it prints `null`. The test goes in Task 1.
4. **A JWE with `--payload` but no key**, including a key given only through `JWTD_KEY`, must be treated as having a key. The test goes in Task 3.
5. **`--claim` on a JWE whose plaintext is a nested JWT** gives the "not supported yet" error, not a confusing "not a JSON object". The test goes in Task 2.

---

### Task 1: JWT extraction core

**Files:**
- Create: `extract.go`
- Test: `extract_test.go`

**Interfaces:**
- Consumes: `parsedJWT`, `verifyJWTSignature(p, keyStr) (valid bool, reason error, err error)`, `validateClaimsSet(claims, checks) (bool, error)`, `claimReason(error) string`, `printVerdict`, `newFormatter`, `writeFormattedJSON`, `escapeTerminalText`.
- Produces:
  - `type selectionKind int` with `selectNone`, `selectHeader`, `selectPayload`, `selectClaim`
  - `type selection struct { kind selectionKind; claim string }` with `func (s selection) active() bool`
  - `func extractJWT(w, errw io.Writer, p *parsedJWT, keyStr string, checks claimChecks, sel selection, jsonOut bool) error`
  - `func writeSelected(w io.Writer, v any, sel selection, jsonOut bool) error`, shared with Task 2: header/payload without `--json` go through the formatter and `writeFormattedJSON`, otherwise they are encoded compactly. A claim prints a bare string (escaped) without `--json`, otherwise it is encoded compactly.
  - `func writeCompactJSON(w io.Writer, v any) error`, which is `json.NewEncoder(w).Encode(v)` with the error wrapped as in `writeJSON`.

- [ ] **Step 1: Write the failing tests** (table-driven where the shape repeats; set `color.NoColor = true` for the test duration)

```go
func TestExtractJWT_Selections(t *testing.T)
// token: makeJWT(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"u1","n":12345678901234567890,"roles":["a","b"],"x":null,"exp":1700000000}`, "sig")
// cases (sel, jsonOut) → exact stdout:
//   {selectClaim,"sub"}, false  → "u1\n"
//   {selectClaim,"sub"}, true   → "\"u1\"\n"
//   {selectClaim,"n"},   false  → "12345678901234567890\n"   (exact json.Number)
//   {selectClaim,"roles"},false → "[\"a\",\"b\"]\n"
//   {selectClaim,"x"},   false  → "null\n"
//   {selectClaim,"exp"}, false  → "1700000000\n"            (raw, not humanized)
//   {selectHeader},      true   → "{\"alg\":\"HS256\",\"typ\":\"JWT\"}\n"
//   {selectPayload},     false  → output parses with json.Valid and contains "1700000000", not "UTC"

func TestExtractJWT_MissingClaim(t *testing.T)
// err.Error() == `claim "nope" not present`; stdout empty

func TestExtractJWT_EscapesBareClaimString(t *testing.T)
// payload `{"sub":"\u001b[31mx"}`: stdout has no 0x1b byte

func TestExtractJWT_InvalidSignatureWithholdsValue(t *testing.T)
// signJWTWithHMAC with key A, keyStr = symmetricKeyArg(t, keyB), sel {selectClaim,"sub"}
// errors.Is(err, errInvalidSignature); stdout == ""; stripANSI(stderr) contains "Signature: INVALID"

func TestExtractJWT_InvalidClaimsWithholdsValue(t *testing.T)
// pinTime(t, 2000000000); exp 1700000000; checks{verify:true}; no key
// errors.Is(err, errInvalidClaims); stdout == ""; stderr contains "Claims: INVALID"

func TestExtractJWT_ValidChecksPrintNothingToStderr(t *testing.T)
// correct HMAC key + checks{verify:true}, unexpired: stdout "u1\n", stderr == ""
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test -run 'TestExtractJWT' ./...`
Expected: FAIL to compile (`extractJWT` undefined).

- [ ] **Step 3: Implement `extract.go`**

`extractJWT`: if `keyStr != ""`, call `verifyJWTSignature`. A hard `err` returns `fmt.Errorf("signature verification: %w", err)`, and an invalid result prints the verdict to `errw` with `reason.Error()`. If `checks.requested()`, call `validateClaimsSet` and print a failing verdict to `errw` with `claimReason`. If either failed, return the sentinel wrapped like `decodeParsedJWTJSON` does, signature first, and write nothing to `w`. Otherwise select: header → `p.header`; payload → `map[string]any(p.claims)`; claim → look up with `v, ok := p.claims[name]`, and if it is absent return the missing-claim error. Then `writeSelected`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test -run 'TestExtractJWT' ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add extract.go extract_test.go
git commit -m "feat: add jwt section and claim extraction core"
```

### Task 2: JWE extraction

**Files:**
- Modify: `extract.go`
- Test: `extract_test.go`

**Interfaces:**
- Consumes: `writeSelected`, `selection` (Task 1), `headerKID`, `loadKeyForToken(keyStr, keySelector{kid, use: "enc", alg})`, `decodeJSON`, `isJWEBytes`, `isJWTBytes`, `escapeTerminalText`.
- Produces: `func extractJWE(w io.Writer, jwe *jose.JSONWebEncryption, header map[string]any, keyStr string, sel selection, jsonOut bool) error`

- [ ] **Step 1: Write the failing tests**

```go
func TestExtractJWE(t *testing.T)
// key := generateRSAKey(t); keyPath := writeKeyFile(t, key)
// cases → expectation:
//   header, no key, plaintext {"sub":"j1"}, jsonOut  → stdout parses as JSON object with "alg"
//   payload, no key                                  → err contains "requires --key to decrypt"
//   claim "sub", no key                              → err contains "requires --key to decrypt"
//   payload, key, plaintext {"sub":"j1"}, jsonOut    → "{\"sub\":\"j1\"}\n"
//   payload, key, plaintext "hello\x1b"              → stdout has no 0x1b and contains "hello"
//   claim "sub", key, plaintext {"sub":"j1"}         → "j1\n"
//   claim "sub", key, plaintext [1,2]                → err == "decrypted payload is not a JSON object"
//   claim "sub", key, plaintext = a compact HS256 JWT → err contains "nested token" and "not supported"
//   claim "nope", key, plaintext {"sub":"j1"}        → err == `claim "nope" not present`
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test -run 'TestExtractJWE' ./...`
Expected: FAIL to compile (`extractJWE` undefined).

- [ ] **Step 3: Implement `extractJWE`**

Header: `writeSelected(w, header, ...)` with no key needed. Payload or claim without a key: return `fmt.Errorf("--%s requires --key to decrypt the JWE", flagName)`, where flagName is `payload` or `claim`. Otherwise load the key and decrypt using the same steps and error wrapping as `decodeParsedJWEJSON`. For a claim, a nested token (`isJWEBytes || isJWTBytes`) fails with `errors.New("--claim on a nested token is not supported yet")`. The plaintext must then `decodeJSON` into `map[string]any`; if it does not, the error is `decrypted payload is not a JSON object`. For a payload: if `decodeJSON` into `any` succeeds, use `writeSelected`; otherwise `fmt.Fprintln(w, escapeTerminalText(plaintext))`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test -run 'TestExtractJWE' ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add extract.go extract_test.go
git commit -m "feat: add jwe section and claim extraction"
```

### Task 3: CLI wiring

**Files:**
- Modify: `main.go` (`newRootCommand`, `run`)
- Test: `main_test.go`

**Interfaces:**
- Consumes: `selection`, `extractJWT`, `extractJWE`.
- Produces: the `--header`, `--payload`, and `--claim` flags.

- [ ] **Step 1: Write the failing tests** (drive `newRootCommand()` with `SetOut`/`SetErr`/`SetArgs`, as the existing `TestRun_*` tests do)

```go
func TestRun_ClaimExtraction(t *testing.T)            // --claim sub <hs256 token> → stdout "u1\n"
func TestRun_SelectorsMutuallyExclusive(t *testing.T) // --header --payload <tok> → err contains "none of the others can be"
func TestRun_EmptyClaimRejectedBeforeToken(t *testing.T) // args {"--claim", ""} with no token → err contains "--claim requires a claim name", not errNoToken
func TestRun_ClaimExtractionWithholdsOnBadSignature(t *testing.T) // wrong raw: key → stdout "", errors.Is(err, errInvalidSignature), stderr contains "Signature: INVALID"
func TestRun_JWEPayloadUsesEnvKey(t *testing.T)       // t.Setenv("JWTD_KEY", keyPath); --payload <jwe> → decrypted JSON on stdout
func TestRun_QuietWithSelector(t *testing.T)          // -q --claim sub → stdout "", err nil
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test -run 'TestRun_(ClaimExtraction|Selectors|EmptyClaim|JWEPayload|QuietWith)' ./...`
Expected: FAIL (unknown flag `--claim`).

- [ ] **Step 3: Wire the flags**

Add `Bool("header")` ("print only the token header (the protected header for a JWE)"), `Bool("payload")` ("print only the payload (the decrypted plaintext for a JWE)"), and `String("claim")` ("print only the value of this top-level claim; strings are printed bare"). Then call `rootCmd.MarkFlagsMutuallyExclusive("header", "payload", "claim")`. In `run`, before `readToken`, build the `selection`; if `Changed("claim")` and the value is empty, return `errors.New("--claim requires a claim name")`. After the existing `--alg` check, a `sel.active()` dispatches to `extractJWE(w, jwe, header, keyStr, sel, jsonOut)` or `extractJWT(w, cmd.ErrOrStderr(), p, keyStr, checks, sel, jsonOut)` instead of the decode handlers. The existing JWE claim-flag note stays.

- [ ] **Step 4: Run the full suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: add --header, --payload, and --claim flags"
```

### Task 4: Documentation

**Files:**
- Modify: `AGENTS.md` (Project Overview flag list, a new `extract.go` architecture entry, the "split across six source files" count and Conventions file list), `README.md` (usage), `site/index.html` (usage workflow and FAQ), `site_test.go` (pin the new workflow command), `docs/feature-ideas.md` (status: items 1–5 and 9 implemented)

- [ ] **Step 1: Pin the site copy first.** Add `"claim extraction workflow": "jwtd --claim sub"` to `TestWebsiteCopyContract`. Run `go test -run TestWebsiteCopyContract ./...` and expect FAIL.
- [ ] **Step 2: Write the docs.** Each mention of the feature must state the withholding rule: a failing check prints nothing to stdout.
- [ ] **Step 3: Run `go test ./...` and `gofmt -l .`.** Expect PASS and no output.
- [ ] **Step 4: Commit** with `docs: document section and claim extraction`.
