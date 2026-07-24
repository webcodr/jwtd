# Security Audit: jwtd (application, supply chain, website)

**Date:** 2026-07-24
**Scope:** `main.go`, `jwe.go`, `keys.go`, `output.go`; `.github/workflows/*`; `.goreleaser.yaml`, `.mise.toml`, `Formula/`, `aur/`, `copr/`, `flake.nix`; `site/`.
**Method:** code review, dependency source inspection, `go vet`, `go test`, `govulncheck`, and empirical exploitation against a binary built from `7adfab7`.

This audit extends [`security-audit-2026-07-22.md`](security-audit-2026-07-22.md), which covered the application code only. Its findings were re-verified rather than inherited; one of its conclusions is corrected below (see H1).

## Verdict

Two exploitable weaknesses of the same class (**H1**, **H2**) that let an attacker obtain `Signature: VALID` on a forged token. Both are **fixed** in `keys.go` with regression tests; everything else is hardening or informational.

## H1 — Unparseable public-key material silently becomes an HMAC secret

**Severity:** High (forged-token acceptance) · **Location:** `keys.go:22-67`, `isStructuredKeyData` `keys.go:69-85` · **Status: fixed**

When `loadKey` cannot parse key data as JWK/PEM/DER and `isStructuredKeyData` does not recognise it as structured, the bytes are used verbatim as a symmetric HMAC key. Public keys in formats jwtd does not support fall into that path. Since public keys are *public*, an attacker who knows which key file the victim uses can sign an `HS256` token with the file's contents and jwtd will report it as authentic.

`validMethodsForKey` does not help here: by the time it runs, the key is already a `[]byte`, so it *permits* `HS256`.

### Demonstrated variants (all print `Signature: VALID`, exit 0)

| Key material | Why it falls through |
|---|---|
| OpenSSH public key (`ssh-ed25519 AAAA… user@host`) | not PEM/JWK/DER; printable ASCII |
| RFC4716 / SSH2 (`---- BEGIN SSH2 PUBLIC KEY ----`) | `hasPEMMarker` requires **five** dashes; RFC4716 uses four |
| Base64 of a DER public key **saved to a file** (e.g. a JWKS `x5c` entry, or a PEM body with the header lines stripped) | file contents are never base64-decoded |

Reproduction (OpenSSH case):

```sh
ssh-keygen -t ed25519 -N '' -f victim -C victim@host   # victim.pub is published, e.g. github.com/<user>.keys
# attacker signs HS256 with the public key file's bytes (trailing newline trimmed)
jwtd -k victim.pub "$forged_token"
# → Signature: VALID
```

The third variant also exposes an internal inconsistency: the *same bytes* are parsed as a real RSA public key when passed inline (`-k <base64>`) but become an HMAC secret when read from a file — inline input is base64-decoded before parsing, file input is not.

```sh
jwtd -k "$(cat rsa.pub.b64)" "$forged"   # Signature: INVALID  (parsed as RSA)
jwtd -k rsa.pub.b64          "$forged"   # Signature: VALID    (used as HMAC secret)
```

**This corrects the prior audit**, which stated that misclassified key material always fails closed and that "anything that parses as structured key material can never degrade into `[]byte`". That holds for *recognised-but-broken* structured data; it does not hold for key formats jwtd does not recognise at all.

**Preconditions:** the victim points `--key`/`JWTD_KEY` at an unsupported public-key file and inspects an attacker-supplied token. No network position or local access is needed — only knowledge of the (public) key file's bytes.

### Recommended fix

Minimal and dependency-free — treat these as structured key material so they fail closed with an error instead of degrading to HMAC:

1. In `hasPEMMarker`, also match the four-dash RFC4716 marker (`---- BEGIN `).
2. In `isStructuredKeyData`, return `true` for content whose first token is an SSH key type (`ssh-rsa`, `ssh-ed25519`, `ssh-dss`, `ecdsa-sha2-*`, `sk-ssh-*`, `sk-ecdsa-*`), with an error message pointing at `ssh-keygen -e -m PKCS8`.
3. For file input, attempt base64 decoding of printable-ASCII contents before falling back to raw bytes, mirroring the inline path.

Stronger, and worth considering given the failure mode: require symmetric secrets to be *explicit* (`raw:`, or a `--key-type` flag), so no file can ever become an HMAC key by accident. Supporting OpenSSH keys properly would need `golang.org/x/crypto/ssh`, which is a larger dependency call than this project's minimal style has taken so far.

### Remediation (applied)

All three changes landed in `keys.go`, plus the H2 fix below:

- `isSSHPublicKey` recognises OpenSSH one-line keys, `authorized_keys` option prefixes, and RFC 4716 armor. Detection confirms the SSH wire-format type prefix inside the base64 blob, so a secret that merely begins with `ssh-rsa` is not misclassified. `isStructuredKeyData` returns `true` for these, and `parseKeyData` returns a targeted error naming the supported formats. (The conversion hint is scoped to RSA and ECDSA: `ssh-keygen -e -m PKCS8` rejects Ed25519 keys, which is worth knowing before writing that hint into a message.)
- `decodeBase64Key` decodes whitespace-tolerantly and is now used for text key files as well as inline arguments, so identical bytes yield an identical key either way. Encoded data only wins if it parses as a key or looks structured, so opaque base64-looking secrets stay literal.
- Regression tests: `TestLoadKey_RejectsSSHPublicKeyFile` (7 formats), `TestLoadKey_RejectsBase64EncodedSSHPublicKey`, `TestLoadKey_Base64KeyMaterialInFileParsesAsKey`, `TestLoadKey_Base64LookingSecretFileStaysLiteral`, and end-to-end forgery coverage in `TestVerifySignature_RejectsForgedHMACFromPublishedKeyFile`. All 21 new subtests were confirmed to fail against the unfixed code.

## H2 — Empty key material is accepted as an HMAC secret

**Severity:** High (forged-token acceptance) · **Location:** `keys.go` symmetric fallback · **Status: fixed**

Found while remediating H1. A zero-byte key file was read, failed every parser, and fell through to the symmetric fallback as an empty `[]byte`. The empty HMAC secret is known to everyone, so *any* attacker could forge a token that jwtd reports as `Signature: VALID` with exit 0 — no knowledge of the victim's keys required.

The realistic trigger is a botched key conversion: `ssh-keygen -e -m PKCS8 -f id_ed25519.pub > key.pem` fails on Ed25519 and the shell redirect leaves a zero-byte `key.pem` behind. That is exactly how this was found — the failed conversion was an artifact of testing the H1 fix's own error-message hint.

**Fix:** a `symmetricKey` helper now gates every path that returns opaque bytes (`raw:`, text files, binary files, inline base64) and rejects empty key material; empty files are reported with the file path. Covered by `TestLoadKey_RejectsEmptyKeyMaterial` and an end-to-end subtest.

## Findings — supply chain

| # | Severity | Finding |
|---|----------|---------|
| S1 | Low | **Unpinned `pip install copr-cli`** (`release.yml:705`) runs in the job holding `COPR_API_TOKEN`. A compromised `copr-cli` release or transitive dependency could exfiltrate the token and publish arbitrary RPMs that Fedora users install via `dnf`. Pin an exact version, ideally with `--require-hashes` and a `requirements.txt`. Every other tool in the pipeline is version-pinned; this is the one that is not. |
| S2 | Low | **Go toolchain pinned to 1.26.1** (`.mise.toml`), which is four patch releases behind and carries known stdlib advisories (`crypto/x509`, `net`, `os`). `govulncheck` symbol analysis confirms **0 reachable** from jwtd's code, and no token-controlled data reaches `crypto/x509` (key material comes only from `--key`/`JWTD_KEY`), so exposure is theoretical — but the pin ships in every released binary. Bump to ≥1.26.5. Unchanged since the 2026-07-22 audit (L5). |
| S3 | Info | **SBOMs are neither checksummed nor signed** — deliberate, and documented in `AGENTS.md` (including them would break byte-for-byte verification of the signed `checksums.txt`). The consequence is that the six SBOMs are verified only by presence and count, so an actor with release-write could alter them undetected. The binaries themselves remain covered. |
| S4 | Info | **No `mise.lock`.** Tools are version-pinned but not checksum-pinned. A lockfile would close the gap between "same version" and "same bytes". |
| S5 | Info | `test.yml` runs on `pull_request` from forks and executes fork-controlled `.mise.toml` and `.goreleaser.yaml` (arbitrary tool download + build hooks). Bounded correctly: read-only `GITHUB_TOKEN`, no secrets in that workflow, no `pull_request_target`. Noted for awareness, not a defect. |

### Supply chain verified sound

- Every third-party action is pinned by commit SHA; workflow-level `permissions: contents: read` with per-job elevation only where needed (`id-token: write` for keyless signing, `contents: write` only in `release`, `pages: write` only in `deploy`).
- Release is `workflow_dispatch`-only, must run from `main`, and validates the version against a strict semver regex **before** checkout. That regex is also what makes the `sed -e "s/VERSION/$VERSION/g"` template rendering safe in the Homebrew/AUR/COPR jobs: it admits no `/`, `&`, or `\`.
- Version input reaches shell only via the `VERSION` env var, never via `${{ }}` interpolation into a script body — no expression injection.
- GoReleaser cannot publish: `release.disable`, `skip_upload`, `--skip=publish`, and no write-capable token in the build job.
- Downstream package hashes are taken from the Cosign-signed `checksums.txt`, never re-hashed, so Homebrew/Scoop/AUR/COPR can only point at the exact archives this release published and verified. Placeholder-residue checks fail closed.
- Release assets are verified byte-for-byte after upload, with an exact asset count and `cosign verify-blob` against a certificate-identity regex bound to this repo's workflow. Manifests travel in a separate artifact so a downstream manifest can never become a release asset.
- AUR host key is pinned (no TOFU); all three downstream jobs carry `Gem::Version` downgrade guards and run only for stable releases.
- No secrets or key material in the repository or its git history; test keys are generated at runtime.

## Findings — application (beyond H1)

| # | Severity | Finding |
|---|----------|---------|
| A1 | Low | **Inline key material appears in `argv`.** `jwtd -k raw:<secret>` / `-k <base64>` puts the secret in `/proc/<pid>/cmdline`, which is world-readable to other local users by default (unlike `/proc/<pid>/environ`, which is owner-only) — and in shell history. `JWTD_KEY` and file paths are the safer forms. Worth one line in the README's key section; the prior audit's L4 flagged the env var but not the strictly worse argv case. |
| A2 | Low | Key-argument ambiguity (prior L1, unchanged): `-k mysecret` is silently base64-decoded rather than taken literally. Fails safe (false INVALID), `raw:` is the escape hatch. A stderr hint would help — and would also surface H1 if the message named the interpretation actually chosen. |
| A3 | Info | JWK Set uses the first key only, with no `kid` matching (prior L2). Fail-closed. If `Keys[0].Key` is `nil`, `validMethodsForKey` returns `nil` and the algorithm restriction is dropped, but verification still fails on the key-type assertion. |
| A4 | Info | `RSA1_5` is accepted for JWE decryption (prior L3). No practical oracle in a one-shot CLI. |
| A5 | Info | `readToken` reads stdin unbounded, and `sanitizeToken` copies it. Self-inflicted only. |

### Application behaviour verified safe (re-tested)

- **Terminal escape injection:** ESC in a claim string, a header value, and an OSC 52 clipboard payload all render fully escaped (``, `‮`). ESC in the signature segment is rejected outright — `ParseUnverified` base64-decodes `parts[2]` (`parser.go:196`) before `printSignature` prints it, so the prior audit's claim holds.
- **Algorithm confusion:** HS256 forged with an RSA public key → INVALID, both as a file and inline base64; `alg:none` → INVALID; exit 1 in each case. (This is exactly the attack H1 reopens through a different door.)
- **DoS bounds:** `{"exp":1e999999999}` is rejected by `Rat.SetString` instantly; worst permitted case (three claims at `1e999999`) is ~100 ms/token. 200 000-deep JSON nesting is rejected by `encoding/json`'s depth cap. go-jose 4.1.4 caps PBES2 at 1 000 000 iterations (`symmetric.go:435`) and inflate at max(250 kB, 10×) (`encoding.go:103`).
- **Nested tokens** are decoded without a key, so recursion cannot continue past one level.
- `go vet` clean, full test suite passes, `govulncheck` reports 0 reachable vulnerabilities.

## Findings — website

The site is static, self-contained, and served from GitHub Pages.

- CSP meta tag is strict and correct: `default-src 'none'`, no `unsafe-inline`, `object-src`/`base-uri`/`form-action` all `'none'`. No external resources are loaded, so the policy is actually satisfiable.
- `script.js` uses no `innerHTML`, `eval`, or `document.write`; all writes go through `textContent`. The `location.hash` handler is regex-validated (`/^#install-([a-z]+)$/`) and cross-checked against known tabs — no DOM XSS.
- No `target="_blank"` links, so no reverse-tabnabbing exposure.
- Install commands download over HTTPS from GitHub releases; no `curl | sh` pattern anywhere.
- **Info:** `frame-ancestors` cannot be set via a meta CSP and GitHub Pages cannot send headers, so clickjacking is unmitigated. Irrelevant for a static page with no interactive state.
- **Info:** `pages.yml:29-30` interpolates the latest tag name into `sed`. Tag names are maintainer-created and the release workflow constrains them to `v<semver>`; a manually created tag containing `/` would break the build rather than inject. Using a placeholder-safe substitution would remove the sharp edge.

## Remaining work

1. **S1** — pin `copr-cli`.
2. **S2** — bump the Go pin to ≥1.26.5.
3. **A2** — stderr hint naming how the key argument was interpreted.

**H1** and **H2** are fixed. **A1** is addressed in the README's key-formats section.
