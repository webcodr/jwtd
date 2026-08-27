# AGENTS.md

## Project Overview

jwtd is a CLI tool written in Go that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output. It can also verify JWS signatures and decrypt JWEs when given a key via `--key`/`-k` or the `JWTD_KEY` environment variable. `--verify-claims` (plus `--aud`/`--iss`) opts into RFC 7519 claim validation with a nonzero exit on failure, independent of the signature check. `--json` emits a machine-readable object instead of the colored sections, and `--color=auto|always|never` overrides TTY-based color detection.

## Architecture

All functionality lives in package `main`, split across six source files:

### `main.go` - CLI, token input, and the JWT/JWS path

- `main()` / `newRootCommand()` - Build and execute the Cobra root command with the `--key`/`-k`, `--json`, and `--color` flags; suppress Cobra's automatic usage/error output so runtime errors are rendered once, while invalid-signature details are not duplicated
- `run()` / `readToken()` / `decodeJWTHuman()` - Resolves the token from arguments, stdin pipe, or interactive readline prompt; falls back to `JWTD_KEY` when `--key` is not set; applies the color mode, then dispatches to the JWT/JWE handler or, under `--json`, to the JSON handler. `decodeJWTHuman` wraps `decodeAndPrint` and, when claim validation was requested, prints a Claims section after it; both the signature and claim checks run so their sections show together, and the command exits nonzero if either fails (the signature verdict takes precedence for the returned sentinel). Claim flags on a JWE emit a stderr note and are otherwise skipped
- `applyColorMode()` - Maps `--color` onto `fatih/color`'s global `NoColor`: `auto` leaves TTY/`NO_COLOR` detection untouched, `always` forces color, `never` disables it; `--json` always forces color off
- `headerKID()` - Extracts the token's `kid` header (or `""`) so JWK Set verification/decryption selects the key the token names
- `printKeyInterpretation()` - Notes on stderr how a key argument was read when it was not read as a file, so precedence-based detection cannot silently take a value the user meant one way and use it another; adds the process-list exposure warning for `--key` values, which `JWTD_KEY` does not carry (`/proc/<pid>/cmdline` is world-readable, `/proc/<pid>/environ` is owner-only). Diagnostics go to stderr so stdout stays parseable
- `readInteractive()` - Prompts for a token interactively using `chzyer/readline`
- `decodeAndPrint()` - Parses the JWT with `golang-jwt/jwt` (`ParseUnverified`) and orchestrates output; verifies the signature when a key is provided
- `parseUnverifiedJWT()` / `decodeJSON()` - Strictly decode the header, claims, and other displayed JSON with exact `json.Number` values and reject malformed or trailing JSON data
- `verifyJWTSignature()` / `verifySignature()` - `verifyJWTSignature` does the cryptographic check without printing, with `jwt.WithoutClaimsValidation()` so the result reflects only the signature, not expiry; it returns `valid`, an invalid-signature `reason`, and a separate hard `err` (unparseable token/unusable key). `verifySignature` renders `Signature: VALID`/`INVALID` from it and returns the `errInvalidSignature` sentinel on failure so the CLI exits nonzero; the `--json` path reuses the same core
- `publicKeyForVerification()` - Extracts the public key from RSA/ECDSA/Ed25519 private keys

### `jsonout.go` - Machine-readable `--json` output

- `decodeJWTJSON()` / `decodeJWEJSON()` - Emit one JSON object per token. A JWT carries `header`, `payload`, `signature`, and (with a key) `signatureValid`; an invalid signature still writes the JSON and then returns `errInvalidSignature` for the exit code. A JWE carries `protectedHeader` plus either encrypted part sizes (no key) or `decryptedPayload` (with a key)
- `jsonPayloadValue()` / `base64URLLen()` / `writeJSON()` - Decode a decrypted payload as structured JSON when possible (else a string); report part sizes; and encode with `encoding/json`, which preserves `json.Number` exactly and escapes control characters including ESC. Timestamps are left as raw numeric claim values here — `formatTimestamps` is intentionally not applied — so consumers do their own date math

### `claims.go` - Opt-in claim validation

- `claimChecks` / `requested()` - Holds the `--verify-claims`, `--aud`, and `--iss` flag values. The zero value requests nothing, so the default stays decode-only and the exit code keeps reflecting the signature alone; `requested()` treats an expected audience or issuer as implying validation, so those flags work without also passing `--verify-claims`
- `validateClaimsSet()` - Runs the requested RFC 7519 checks against the already-parsed claims via `jwt.NewValidator` with `jwt.WithTimeFunc(timeNow)` (so the verdict shares the display clock and is deterministic under `pinTime`), returning `valid` plus a reason. Temporal claims (`exp`, `nbf`) that are present are always checked; an expected `aud`/`iss` is additionally required to be present and match. A missing `exp` is not treated as expired. No signature verification happens here — the human and `--json` paths share this core
- `verifyClaims()` / `claimReason()` - `verifyClaims` parses the token, calls the core, and renders `Claims: VALID`/`INVALID` with the reason, returning the `errInvalidClaims` sentinel on failure (and a hard error on an unparseable token). `claimReason` flattens the validator's newline-joined multi-error onto one `; `-separated line so the dim reason and wrapped error stay readable

**Claim validation is display-and-exit-code only, and deliberately separate from signature verification.** It performs no cryptography and runs whether or not a key is given, so `--verify-claims` on an unverified token still reports expiry — the two verdicts (`Signature:` and `Claims:`) are shown independently and either failing exits nonzero. This keeps the pre-existing invariant that a bare decode never fails on expiry intact: nothing validates claims unless a claim flag is passed.

### `jwe.go` - JWE parsing and decryption

- `isJWE()` / `isJWT()` - Detect JWE (5 dot-separated parts) and JWS/JWT (3 parts) compact serialization. Every token-shape dispatch goes through one of these two, so the shape rules are not restated inline
- `decodeAndPrintJWE()` / `jweProtectedHeaderMap()` - Parse a JWE with `go-jose` and decode every field in the compact protected header for display; without a key print encrypted part metadata, with a key decrypt and print the payload
- `jweEncryptedParts()` / `printEncryptedParts()` / `partSize()` - Encrypted part metadata shown when no key is provided. `jweEncryptedParts` splits the compact serialization into its five segments for both the human and `--json` paths; `partSize` renders `base64URLLen`'s count (or its `-1`) as display text, so measuring and formatting are not implemented twice

### `keys.go` - Key loading and format detection

- `loadKey()` / `loadKeyForKID()` / `parseKeyData()` / `parseAnyDER()` / `parseDERKey()` / `parseJWK()` - Resolve `raw:<secret>` and `hmac:<file>`, then an existing file path, then base64/base64url; parse loaded data as JWK/JWK Set, PEM, or DER (PKCS#1/PKCS#8/SEC 1/PKIX) keys and X.509 certificates, and error on anything else. `parseAnyDER` holds the one list of understood DER encodings, used both for raw DER and as `parseDERKey`'s fallback for an unrecognized PEM block type, so a format cannot be added to one and missed by the other. `parseKeyData` only detects formats: it never phrases a rejection, because `unsupportedKeyError` is the single place that knows the user-facing subject and the symmetric-form hint. Trailing newlines are trimmed only for ASCII `hmac:` files limited to printable bytes plus tab/CR/LF, while UTF-8/non-ASCII and other binary files remain byte-exact. `loadKeyForKID` threads the token's `kid` so a JWK Set selects the matching entry (`loadKey` is the `kid=""` wrapper); a `kid` that matches nothing returns the `errKIDNotFound` sentinel, which short-circuits the base64/unsupported-format fallbacks so a JWK Set miss fails closed with a clear message instead of degrading into other key material
- `unsupportedKeyError()` - Explains a rejection and names the explicit symmetric form to use, substituting the user's own path so the fix is copy-pasteable; SSH keys get a conversion hint instead
- `classifyKeyArg()` - Reports which reading `loadKey` will apply (`raw:` literal, `hmac:` secret file, existing file, base64, or unusable), mirroring its precedence so the CLI hint cannot drift from actual behavior; uses `Stat` rather than a read, so classifying never consumes the key source
- `decodeBase64Key()` / `symmetricKey()` - Decode whitespace-tolerant base64/base64url key material (applied to text key files as well as inline arguments, so the same bytes mean the same key either way) and gate symmetric secrets, rejecting empty key material
- `isTextKey()` / `isSSHPublicKey()` / `isSSHKeyType()` / `sshBlobHasType()` - Distinguish ASCII text from binary for newline trimming, and detect SSH public keys for the targeted error

**Symmetric secrets are explicit, and that is the security boundary.** Before 5.0.0, key material jwtd could not parse became an HMAC secret. Any *public* key reaching that path was forgeable: a public key is a published value, so an attacker who knew its bytes could sign an HS256 token that verified. Three formats hit it in practice (OpenSSH keys, RFC 4716 armor, base64 key material in a file), but the class was open to any format nobody had thought of. Unparseable material is now an error, so no new format can reopen it — verified against PKCS#12, which was never enumerated. `isSSHPublicKey()` exists only to give a better message; it covers OpenSSH one-line keys (verified through the SSH wire-format type prefix, so a secret merely starting with `ssh-rsa` is not misread), `authorized_keys` option prefixes, and RFC 4716 armor, whose four-dash BEGIN marker is not a PEM marker. Empty key material is rejected because the empty secret is known to everyone. `keys_test.go` and `TestVerifySignature_RejectsForgedHMACFromPublishedKeyFile` in `main_test.go` hold these properties down.

Removing the fallback deleted the heuristics that existed only to decide it (`isStructuredKeyData`, `hasPEMMarker`, `hasJWKMember`, `jsonStringEnd`, `isCompleteDER`) — about 100 lines of the most error-prone code in the package. Do not reintroduce a "looks like a secret" inference to make an unsupported format work; add a parser, or let the user say `hmac:`.

### `output.go` - Formatting, escaping, and colored printing

- `printDecryptedPayload()` / `escapeTerminalText()` / `escapeFormattedJSONControls()` - Recursively decode nested JWTs/JWEs and pretty-print JSON objects or arrays; raw plaintext escapes C0 controls except newline/tab, DEL, C1 controls, invalid UTF-8 bytes, and targeted bidi controls, while formatted JSON sanitizes C1, DEL, and the same targeted bidi controls
- `formatTimestamps()` / `timestampStatus()` / `humanizeDuration()` - Convert exact `iat`, `exp`, `nbf` Unix numeric values, including fractions, to RFC3339 strings (original value shown in parentheses); `exp` is annotated with the time remaining or elapsed (`expires in 14m` / `expired 2h ago`) and a future `nbf` with `not yet valid, in 5m` (an already-valid `nbf` gets no note). `humanizeDuration` renders the largest whole unit (s/m/h/d), truncating toward zero for deterministic output. This is display-only and never affects verification or the exit code; `timeNow` is a package variable so the annotations are testable. The `--json` path skips this entirely and keeps raw numeric claims
- `newFormatter()` - Creates a `go-prettyjson` formatter with the project color scheme
- `printSection()` / `printSignature()` / `printVerdict()` - Formatted output using `fatih/color`. `printSection` takes any JSON-marshalable value, so objects and arrays share one path; `printVerdict` renders the `<label>: VALID`/`INVALID` line with its dim reason, shared by the independent signature and claim verdicts so they cannot drift apart visually

### Release packaging

Cross-compilation, archive naming, checksums, SBOMs, and signing are owned by `.goreleaser.yaml` (pinned in `.mise.toml`); it selects the six linux/darwin/windows × amd64/arm64 targets, bakes `main.version` via ldflags, and produces binary-only `tar.gz` archives, two additional windows `.zip` archives (for `install.ps1`), `.deb`/`.rpm` packages for linux amd64/arm64, a `checksums.txt`, a per-`tar.gz` Syft SBOM, and keyless Cosign bundles over the checksum file (`checksums.txt.sigstore.json`) and over each SBOM.

The mise-pinned toolchain is checksum-locked: `.mise.toml` sets `lockfile = true` and `mise.lock` records a SHA256 per downloaded tool per platform (linux-x64 for CI, macos-arm64 for local work). Source-built `go:` tools (gopls) are the exception: mise installs them with `go install`, so there is no artifact to hash and the lockfile holds only their version and backend — their integrity comes from the Go module checksum database, and they are development-only, never part of the release path. `TestMiseLockInvariants` exempts them only when `.mise.toml` and `mise.lock` agree that the tool is source-built, so neither file alone can drop a downloaded tool out of checksum coverage. Regenerate the lockfile with `mise lock --platform linux-x64,macos-arm64` after changing any tool version, or `TestMiseLockInvariants` fails — a lockfile that disagrees with `.mise.toml` is worse than none, since it looks authoritative while the pins diverge.

There are two builds: `jwtd` (all six targets) and a windows-only `jwtd-windows` whose settings are identical, so its `jwtd.exe` is byte-for-byte the same binary as in the windows `tar.gz`. The `tar.gz` archives carry archive id `jwtd`; the windows zips carry id `jwtd-zip` (fed by `jwtd-windows`). The separate id exists so `scoops.ids: [jwtd]` can pin Scoop to the `tar.gz` archive — GoReleaser's scoop pipe errors if it sees more than one windows archive. `install.ps1` cannot consume `tar.gz` (PowerShell 5.1 ships `Expand-Archive` but no tar), which is the only reason the zips exist.

The `.deb`/`.rpm` packages also ship bash, zsh, and fish completions. A top-level `before.hooks` generates them with `go run . completion <shell> > completions/jwtd.<shell>`, and nfpm `contents` installs each at its shell's conventional path with mode `0644` and `mtime` pinned to the epoch. The completion scripts are static (no version or timestamp baked in), so the packages stay byte-reproducible in the strict tier. The **archives stay binary-only** — completions are not added to them — so the archive contract is unchanged; Homebrew instead calls `generate_completions_from_executable(bin/"jwtd", "completion")` at install time from the archived binary. AUR, COPR, and Scoop do not ship completions. `TestShellCompletionsPackaged` (nfpm contents + before-hooks) and the Homebrew check in `workflow_test.go` enforce this.

The nfpm packages share the `jwtd` build id with the archives, so `checksum.ids` covers them; the zips add id `jwtd-zip`. They all pin `mtime`/`builds_info.mtime` to the epoch and are byte-reproducible, which keeps them in the strict comparison tier. SBOMs are scoped to `sboms.ids: [jwtd]` (the `tar.gz` archives only): the windows zip wraps a binary already cataloged by the windows `tar.gz` SBOM, so a second SBOM would be redundant non-reproducible churn.

`checksum.ids` deliberately restricts `checksums.txt` to the archive ids (`jwtd`, `jwtd-zip`) and the nfpm packages (id `jwtd`). Syft SBOMs embed a random `documentNamespace` UUID and a creation timestamp, so including them would make the signed checksum file differ on every run and break byte-for-byte release verification. Consequently the release job verifies assets in two tiers: the eight archives (six `tar.gz` plus the two windows zips) and `checksums.txt` must match the build byte-for-byte, while the six SBOMs and the Cosign bundles are verified by presence, exact count, and `cosign verify-blob`. Because SBOMs cannot ride on `checksums.txt`, a second `signs` entry (`artifacts: sbom`) gives each one its own keyless bundle, so no published asset rests on a presence check alone — an actor with release-write cannot alter an SBOM without breaking its signature. `.github/workflows/release.yml` owns everything GoReleaser does not: version/ref validation, tag provenance (a local, unpushed tag drives GoReleaser's version discovery), draft release creation and reconciliation, byte-for-byte asset verification, semantic latest-release handling, and Homebrew tap publication. GoReleaser never publishes: `release.disable: true` in the config, `skip_upload: true` on the Scoop manifest, and `--skip=publish`/`--snapshot` at every invocation site all enforce this, and the GoReleaser build step never receives a write-capable token.

Homebrew is published as a **formula**, not a cask. Casks quarantine their downloaded binary, which macOS Gatekeeper blocks for jwtd's unsigned binaries (and Homebrew is deprecating casks that fail Gatekeeper); formulae do not quarantine and also work on Linux. The template lives in `Formula/jwtd.rb` with `VERSION`/`SHA256_*` placeholders; the `update-homebrew` job fills the four hashes from the signed `checksums.txt` (so the formula can only point at the exact archives this release published), renders `jwtd.rb`, pushes it to `Formula/jwtd.rb` in `webcodr/homebrew-tap`, and removes any superseded `Casks/jwtd.rb` (the 4.0.0 cask). GoReleaser's own `brews` generator is deprecated and fails `goreleaser check`, so the formula stays hand-templated.

Scoop is generated by GoReleaser: `scoops` renders `jwtd.json` with `skip_upload: true`, pinned to `ids: [jwtd]` so it uses the windows `tar.gz` (not the zip), and `update-scoop` cross-checks its hashes against `checksums.txt` before pushing to `webcodr/scoop-bucket`. `release.disable` means it needs an explicit `url_template`. Both downstream jobs run only for stable releases, after the release job succeeds.

**WinGet is not a distribution channel.** `WebCodr.jwtd` was published to `microsoft/winget-pkgs` up to 5.2.0; the manifest templates (`winget/`), the `update-winget` release job, and `TestWinGetInvariants` were removed afterwards, so releases no longer open a winget-pkgs PR. The already-merged manifests stay in winget-pkgs and simply stop receiving updates. Windows is served by `install.ps1` and Scoop. The windows `.zip` archives remain — `install.ps1` downloads them — so do not remove them along with any other WinGet leftovers.

Fedora is published to COPR (`webcodr/jwtd`) as a binary-repackage RPM, not a from-source build. `copr/jwtd.spec` carries a `VERSION`/`DATE`-placeholder spec that wraps the prebuilt linux archives (`Source0`/`Source1` per arch, selected with `%ifarch`), disables the debuginfo subpackage (`%global debug_package %{nil}`) since the Go binary is prebuilt, and ships the `LICENSE`. The `update-copr` job verifies the archives against the signed `checksums.txt`, renders the spec, builds a source RPM with `rpmbuild -bs` on the ubuntu runner (the SRPM step needs no Fedora macros), and submits it with `copr-cli build webcodr/jwtd <srpm> --nowait` authenticated by the base64-encoded `COPR_API_TOKEN` secret. COPR builds the SRPM in its Fedora chroots and signs the result with its own key. There is deliberately no version-downgrade guard: `dnf` resolves the highest EVR from the repo, so a re-submitted older version cannot downgrade users. `TestCOPRInvariants` enforces the binary-repackage contract and the gated job. Like the others, it runs only for stable releases after the release job.

AUR is published as `jwtd-bin`, a prebuilt-binary package that installs the released linux archive rather than compiling from source. Like Homebrew, it is hand-templated (GoReleaser is not involved at all, so `.goreleaser.yaml` is untouched): `aur/PKGBUILD` and `aur/.SRCINFO` carry `VERSION`/`SHA256_LINUX_AMD64`/`SHA256_LINUX_ARM64`/`SHA256_LICENSE` placeholders, and `update-aur` fills the two archive hashes from the signed `checksums.txt`, hashes the release-commit `LICENSE` itself (it is not a release archive, so not in `checksums.txt`, but is byte-identical to the tagged raw file the PKGBUILD downloads), renders both files, and pushes to `ssh://aur@aur.archlinux.org/jwtd-bin.git`. The archives have version-free names, so the PKGBUILD renames the downloads to include `${pkgver}` to avoid makepkg source-cache collisions across versions. The two templates must stay in sync: `aur/.SRCINFO` is byte-identical to `makepkg --printsrcinfo` run on the rendered PKGBUILD, so regenerate it that way after any PKGBUILD change. `update-aur` pins the AUR ED25519 host key in `known_hosts` (no trust-on-first-use), keeps the `Gem::Version` downgrade guard, authenticates with the `AUR_SSH_KEY` secret, and runs only for stable releases after the release job. `workflow_test.go`'s `TestAURInvariants` enforces these properties.

Artifacts cross the build/release job boundary as two separate uploads: `jwtd-release-assets` (everything published to the GitHub release) and `jwtd-manifests` (the Scoop manifest). The release job and `update-homebrew` download only the release assets; `update-scoop` downloads the manifests. So a downstream manifest can never become a release asset.

Release notes are auto-generated (`--generate-notes`), which lists only merged PR titles. `RELEASE_NOTES.md` holds hand-written prose for the next release: when present and non-empty it is prepended to the generated notes at release creation. Clear it after a release so its contents do not repeat on the following one.

### Install scripts

`install.sh` is a package-manager-free installer for macOS and Linux, served at `https://jwtd.sh/install.sh` (`curl -fsSL https://jwtd.sh/install.sh | sh`). It maps `uname -s`/`uname -m` onto the GoReleaser archive names (`jwtd-<os>-<arch>.tar.gz`, the four darwin/linux × amd64/arm64 targets), downloads that archive plus `checksums.txt` from the latest release — or from `--version <tag>` — extracts the binary, and installs it into `~/.local/bin` (overridable with `--dir`/`JWTD_INSTALL_DIR`). Windows is deliberately unreachable from this script: it is served by `install.ps1` and Scoop.

**Verification is not optional, and nothing is written before it passes.** The archive is always checked against its `checksums.txt` entry (`sha256sum`, falling back to `shasum -a 256`), and when `cosign` is on `PATH` the keyless bundle over `checksums.txt` is verified against the same certificate identity and issuer the README documents; a cosign failure aborts. cosign itself stays optional because most machines do not have it and the checksum already pins the bytes — but a present cosign is never advisory. The script runs under POSIX `sh` (it is piped into whatever `/bin/sh` the user has, not necessarily bash) and never calls `sudo`, so piping it into a shell is not a privilege decision.

The binary is copied into the install directory under a temporary name and then `mv`'d into place, so the replacement is a same-filesystem `rename(2)`: an upgrade cannot leave a half-written binary behind, and it does not fail with `ETXTBSY` when the running shell's own `jwtd` is being replaced. A cross-device `mv` straight from the temp directory would do both.

There is one copy of the script. `.github/workflows/pages.yml` copies the repository root file into the Pages artifact (`install -m 0755 install.sh site/install.sh`, which is git-ignored) so the hosted script is byte-identical to the reviewed one, and the workflow redeploys when `install.sh` changes. `install_test.go` holds down the contract: the archive naming against `.goreleaser.yaml`, verification ordering, the Cosign identity matching the README, `sh`/no-`sudo`, rejection of unsupported platforms (driven by a stubbed `uname`, so the test never touches the network), and the README/site one-liner.

`install.ps1` is the Windows counterpart, served at `https://jwtd.sh/install.ps1` (`irm https://jwtd.sh/install.ps1 | iex`), published by the same Pages step (`install -m 0644 install.ps1 site/install.ps1`) and git-ignored the same way. It keeps install.sh's contract — verify before writing anything, checksum always, a present `cosign` never advisory, the same certificate identity and issuer, no elevation — and differs only where Windows does:

- **It consumes the windows `.zip`, not the `.tar.gz`.** `Expand-Archive` ships with PowerShell 5.1; tar does not. The zips are covered by the signed `checksums.txt` like every other archive, so this adds no verification gap.
- **Errors `throw`, never `exit`.** The script is normally piped into `Invoke-Expression` in an interactive session, where `exit` would close the user's shell instead of aborting the installation. For the same reason `$ErrorActionPreference`/`$ProgressPreference` are set inside `Install-Jwtd` rather than at script scope: preference variables are dynamically scoped, and setting them at top level would leave them applied to the caller's session afterwards.
- **It edits the user PATH itself.** `install.sh` can only print a hint because it cannot know which shell profile to edit; Windows keeps the user PATH in one `HKCU:\Environment` value. It must be read with `DoNotExpandEnvironmentNames` and written back as `ExpandString` — `[Environment]::SetEnvironmentVariable` expands entries like `%USERPROFILE%` and writes the expanded text back as a plain string, silently rewriting parts of the PATH the installer never touched. `Publish-EnvironmentChange` broadcasts `WM_SETTINGCHANGE` (best-effort) so a newly opened terminal sees the change without a sign-out. `-NoModifyPath`/`JWTD_NO_MODIFY_PATH` opts out.
- **An upgrade renames the old binary aside.** Windows refuses to overwrite a running `.exe` but does allow renaming one, so the installer moves the installed binary to a temporary name, moves the new one into place, and then deletes the old file best-effort (the delete fails while an older `jwtd` is still running). This is the analogue of install.sh's stage-then-`rename(2)` handling of `ETXTBSY`.
- **Options come from environment variables.** `Invoke-Expression` cannot forward arguments, so `JWTD_VERSION`, `JWTD_INSTALL_DIR`, and `JWTD_NO_MODIFY_PATH` are the documented path; the `param()` block serves `& ([scriptblock]::Create((irm …))) -Version …`.
- **Architecture detection corrects for emulation.** An x64 PowerShell under emulation on an ARM64 machine reports X64, which would install the Intel binary; the machine-level `PROCESSOR_ARCHITECTURE` (and `PROCESSOR_ARCHITEW6432`) give the native architecture. This is the Rosetta check's counterpart.

`install_test.go` asserts the shape (archive naming against `.goreleaser.yaml`, verify-before-write ordering, the shared Cosign trust root, no `exit`, no elevation, the registry handling, the publication path); comment lines are stripped before the "must not call" assertions so a comment explaining why the script avoids an API cannot satisfy the check for it. The behaviour needs a real Windows host, so the `windows-installer` job in `.github/workflows/test.yml` installs the latest published release for real, reinstalls over it to exercise the upgrade path, checks that an unavailable release writes nothing, and verifies that the PATH edit adds the directory while leaving a seeded `%USERPROFILE%`-style entry verbatim and the value still `REG_EXPAND_SZ`.

### Open Graph card

`site/og.png` is the 1200×630 social card, rendered from `og/og.html` with headless Chromium at 2x and downsampled (the 2x pass is what keeps the small monospace text crisp). The source deliberately lives **outside** `site/`: the Pages artifact is that directory verbatim, so a generator kept there would be published as a page of its own. `og/og.html` carries the exact regeneration commands in a comment, and its palette is copied from `site/styles.css` — the two must be updated together, since nothing detects a card whose colors have drifted from the site.

The rendered PNG stays truecolor. Palette-quantizing it is less than half the bytes but dithers the ambient bloom into visible mottling, and 170 KB is far inside every platform's limit. The code sample on the card is a line-for-line subset of the hero specimen in `site/index.html`, so the card cannot advertise output the tool does not produce. `TestOpenGraphCard` pins the size against the `og:image:width`/`og:image:height` meta tags that hard-code it, and fails if the source reappears under `site/`.

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework (flags, help, argument handling) |
| `github.com/golang-jwt/jwt/v5` | JWT parsing via `ParseUnverified` and JWS signature verification |
| `github.com/go-jose/go-jose/v4` | JWE parsing/decryption and JWK/JWK Set key parsing |
| `github.com/hokaccha/go-prettyjson` | JSON pretty-printing with syntax highlighting |
| `github.com/fatih/color` | Terminal color output with automatic TTY detection |
| `github.com/chzyer/readline` | Interactive token input with line-editing support |

## Development

### Build

```sh
go build -o jwtd .
```

### Test

```sh
go test -v ./...
```

### Release packaging

```sh
mise install
goreleaser check
goreleaser release --snapshot --clean --skip=sign
```

`goreleaser check` validates `.goreleaser.yaml`; the snapshot build writes to the git-ignored `dist/` directory and publishes nothing. `--skip=sign` is required locally: signing is keyless and needs a GitHub Actions OIDC identity, so it can only run in the release workflow. CI runs the same commands on every push/PR and verifies the resulting `dist/artifacts.json` against the eight-archive (six `tar.gz` + two windows `.zip`) / one-checksum / six-SBOM contract.

### Nix flake

`flake.nix` builds jwtd from source with `buildGoModule` (not the release binaries), exposing `packages.default`, `apps.default` (so `nix run github:webcodr/jwtd` works), a `devShells.default` with Go and GoReleaser, and `nixfmt-rfc-style` as the formatter for `x86_64-linux`, `aarch64-linux`, and `aarch64-darwin` (nixpkgs unstable has dropped `x86_64-darwin`). The version is the git revision (`self.shortRev`), so source builds report the commit while tagged release binaries carry the semver via GoReleaser's ldflags. `flake.lock` pins nixpkgs.

`vendorHash` is the fixed-output hash of the Go module dependencies and must be updated whenever `go.mod`/`go.sum` change: set it to `pkgs.lib.fakeHash`, run `nix build`, and copy the `got:` hash from the mismatch error. The `nix` job in `.github/workflows/test.yml` runs `nix flake check --all-systems`, which builds the current-system package from source, so a stale `vendorHash` fails CI rather than rotting silently; `TestFlakeInvariants` guards the build-from-source contract (including that the hash is not the placeholder) and that the CI job exists.

### Usage

```sh
jwtd <token>
echo <token> | jwtd
jwtd                          # interactive prompt via readline
jwtd --key key.pem <token>    # verify JWS signature or decrypt JWE
JWTD_KEY=key.pem jwtd <token> # same, via environment variable
```

## Conventions

- **Single package.** All code stays in package `main`, split across topical files (`main.go`, `jwe.go`, `keys.go`, `output.go`, `jsonout.go`, `claims.go`).
- **Tests mirror the source files:** `main_test.go`, `jwe_test.go`, `keys_test.go`, `output_test.go`, `jsonout_test.go`, `claims_test.go`, with shared fixtures (key generation, token signing/encryption helpers) in `helpers_test.go` GoReleaser/release-workflow invariants in `workflow_test.go`, website/Pages invariants in `site_test.go`, and installer invariants in `install_test.go`. Use table-driven tests where multiple cases share the same structure.
- **Color scheme** is configured in `newFormatter()` via `go-prettyjson` and `fatih/color`. Colors auto-disable when stdout is not a TTY.
- **Error handling:** Return errors up the call stack with `fmt.Errorf` wrapping (`%w`). The root command suppresses Cobra's automatic error and usage output; `main()` renders non-signature errors and exits nonzero, while invalid signatures print their own details and return `errInvalidSignature`.
- **Formatting:** Use `gofmt`/`goimports` standard formatting. No special linter configuration.
- **Commit messages:** Use the [Conventional Commits](https://www.conventionalcommits.org/) format (e.g. `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`). Keep the subject line short and lowercase after the prefix.

## Color Scheme

| Token      | Color        | fatih/color attribute |
|------------|--------------|----------------------|
| Keys       | Bold blue    | `FgBlue, Bold`       |
| Strings    | Green        | `FgGreen`            |
| Numbers    | Yellow       | `FgYellow`           |
| Booleans   | Magenta      | `FgMagenta`          |
| Null       | Red          | `FgRed`              |
| Labels     | Bold cyan    | `FgCyan, Bold`       |
| Signature  | Dim          | `Faint`              |
