# AGENTS.md

## Project Overview

jwtd is a CLI tool written in Go that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output. It can also verify JWS signatures and decrypt JWEs when given a key via `--key`/`-k` or the `JWTD_KEY` environment variable.

## Architecture

All functionality lives in package `main`, split across four source files:

### `main.go` - CLI, token input, and the JWT/JWS path

- `main()` / `newRootCommand()` - Build and execute the Cobra root command with the `--key`/`-k` flag; suppress Cobra's automatic usage/error output so runtime errors are rendered once, while invalid-signature details are not duplicated
- `run()` / `readToken()` - Resolves the token from arguments, stdin pipe, or interactive readline prompt; falls back to `JWTD_KEY` when `--key` is not set; dispatches to JWT or JWE handling
- `printKeyInterpretation()` - Notes on stderr how a key argument was read when it was not read as a file, so precedence-based detection cannot silently take a value the user meant one way and use it another; adds the process-list exposure warning for `--key` values, which `JWTD_KEY` does not carry (`/proc/<pid>/cmdline` is world-readable, `/proc/<pid>/environ` is owner-only). Diagnostics go to stderr so stdout stays parseable
- `readInteractive()` - Prompts for a token interactively using `chzyer/readline`
- `decodeAndPrint()` - Parses the JWT with `golang-jwt/jwt` (`ParseUnverified`) and orchestrates output; verifies the signature when a key is provided
- `parseUnverifiedJWT()` / `decodeJSON()` - Strictly decode the header, claims, and other displayed JSON with exact `json.Number` values and reject malformed or trailing JSON data
- `verifySignature()` - Verifies a JWS signature with `jwt.WithoutClaimsValidation()` so the result reflects only the cryptographic signature, not expiry; prints `Signature: VALID`/`INVALID` and returns an `errInvalidSignature` sentinel on failure so the CLI exits nonzero
- `publicKeyForVerification()` - Extracts the public key from RSA/ECDSA/Ed25519 private keys

### `jwe.go` - JWE parsing and decryption

- `isJWE()` - Detects JWE compact serialization (5 dot-separated parts vs. 3 for a JWT)
- `decodeAndPrintJWE()` / `jweProtectedHeaderMap()` - Parse a JWE with `go-jose` and decode every field in the compact protected header for display; without a key print encrypted part metadata, with a key decrypt and print the payload
- `printEncryptedParts()` / `partSize()` - Encrypted part metadata shown when no key is provided

### `keys.go` - Key loading and format detection

- `loadKey()` / `parseKeyData()` / `parseDERKey()` / `parseJWK()` - Resolve `raw:<secret>`, then an existing file path, then base64/base64url; parse loaded data as JWK/JWK Set, PEM, or DER (PKCS#1/PKCS#8/SEC 1/PKIX) keys and X.509 certificates; reject recognizable structured parse failures and otherwise allow opaque raw symmetric bytes; trim trailing newlines only for ASCII text key files limited to printable bytes plus tab/CR/LF, while UTF-8/non-ASCII and other binary files remain byte-exact
- `classifyKeyArg()` - Reports which reading `loadKey` will apply (`raw:` literal, existing file, base64, or unusable), mirroring its precedence so the CLI hint cannot drift from actual behavior; uses `Stat` rather than a read, so classifying never consumes the key source
- `decodeBase64Key()` / `symmetricKey()` - Decode whitespace-tolerant base64/base64url key material (applied to text key files as well as inline arguments, so the same bytes mean the same key either way) and gate the symmetric fallback, which rejects empty key material
- `isStructuredKeyData()` / `hasPEMMarker()` / `hasJWKMember()` / `isCompleteDER()` / `isTextKey()` / `isSSHPublicKey()` - Heuristics distinguishing structured key material (PEM/JWK/DER/SSH) from opaque symmetric secrets

**The symmetric fallback is the security-critical path here.** Key material jwtd cannot parse becomes an HMAC secret, so any *public* key that reaches it is forgeable: an attacker who knows the published key bytes can sign an HS256 token that verifies. `isStructuredKeyData()` must therefore recognize every format a user might plausibly pass, even ones jwtd cannot parse, so they fail closed with an error. `isSSHPublicKey()` covers OpenSSH one-line keys (verified through the SSH wire-format type prefix, so a secret merely starting with `ssh-rsa` is not misread), `authorized_keys` option prefixes, and RFC 4716 armor, whose four-dash BEGIN marker is deliberately not a PEM marker. Empty key material is rejected for the same reason: the empty secret is known to everyone. `keys_test.go` and `TestVerifySignature_RejectsForgedHMACFromPublishedKeyFile` in `main_test.go` hold these properties down.

### `output.go` - Formatting, escaping, and colored printing

- `printDecryptedPayload()` / `escapeTerminalText()` / `escapeFormattedJSONControls()` - Recursively decode nested JWTs/JWEs and pretty-print JSON objects or arrays; raw plaintext escapes C0 controls except newline/tab, DEL, C1 controls, invalid UTF-8 bytes, and targeted bidi controls, while formatted JSON sanitizes C1, DEL, and the same targeted bidi controls
- `formatTimestamps()` - Converts exact `iat`, `exp`, `nbf` Unix numeric values, including fractions, to RFC3339 strings (original value shown in parentheses)
- `newFormatter()` - Creates a `go-prettyjson` formatter with the project color scheme
- `printSection()` / `printSignature()` - Formatted output using `fatih/color`

### Release packaging

Cross-compilation, archive naming, checksums, SBOMs, and signing are owned by `.goreleaser.yaml` (pinned in `.mise.toml`); it selects the six linux/darwin/windows × amd64/arm64 targets, bakes `main.version` via ldflags, and produces binary-only `tar.gz` archives, `.deb`/`.rpm` packages for linux amd64/arm64, a `checksums.txt`, a per-archive Syft SBOM, and keyless Cosign bundles over the checksum file (`checksums.txt.sigstore.json`) and over each SBOM.

The mise-pinned toolchain is checksum-locked: `.mise.toml` sets `lockfile = true` and `mise.lock` records a SHA256 per tool per platform (linux-x64 for CI, macos-arm64 for local work). Regenerate it with `mise lock --platform linux-x64,macos-arm64` after changing any tool version, or `TestMiseLockInvariants` fails — a lockfile that disagrees with `.mise.toml` is worse than none, since it looks authoritative while the pins diverge.

The nfpm packages share the `jwtd` build id with the archives, so `checksum.ids` covers both; they pin `mtime` to the epoch and are byte-reproducible, which keeps them in the strict comparison tier.

`checksum.ids` deliberately restricts `checksums.txt` to the `jwtd` id (archives and packages). Syft SBOMs embed a random `documentNamespace` UUID and a creation timestamp, so including them would make the signed checksum file differ on every run and break byte-for-byte release verification. Consequently the release job verifies assets in two tiers: the six archives and `checksums.txt` must match the build byte-for-byte, while the SBOMs and the Cosign bundles are verified by presence, exact count, and `cosign verify-blob`. Because SBOMs cannot ride on `checksums.txt`, a second `signs` entry (`artifacts: sbom`) gives each one its own keyless bundle, so no published asset rests on a presence check alone — an actor with release-write cannot alter an SBOM without breaking its signature. `.github/workflows/release.yml` owns everything GoReleaser does not: version/ref validation, tag provenance (a local, unpushed tag drives GoReleaser's version discovery), draft release creation and reconciliation, byte-for-byte asset verification, semantic latest-release handling, and Homebrew tap publication. GoReleaser never publishes: `release.disable: true` in the config, `skip_upload: true` on the Scoop manifest, and `--skip=publish`/`--snapshot` at every invocation site all enforce this, and the GoReleaser build step never receives a write-capable token.

Homebrew is published as a **formula**, not a cask. Casks quarantine their downloaded binary, which macOS Gatekeeper blocks for jwtd's unsigned binaries (and Homebrew is deprecating casks that fail Gatekeeper); formulae do not quarantine and also work on Linux. The template lives in `Formula/jwtd.rb` with `VERSION`/`SHA256_*` placeholders; the `update-homebrew` job fills the four hashes from the signed `checksums.txt` (so the formula can only point at the exact archives this release published), renders `jwtd.rb`, pushes it to `Formula/jwtd.rb` in `webcodr/homebrew-tap`, and removes any superseded `Casks/jwtd.rb` (the 4.0.0 cask). GoReleaser's own `brews` generator is deprecated and fails `goreleaser check`, so the formula stays hand-templated.

Scoop is generated by GoReleaser: `scoops` renders `jwtd.json` with `skip_upload: true`, and `update-scoop` cross-checks its hashes against `checksums.txt` before pushing to `webcodr/scoop-bucket`. `release.disable` means it needs an explicit `url_template`. Both downstream jobs run only for stable releases, after the release job succeeds.

Fedora is published to COPR (`webcodr/jwtd`) as a binary-repackage RPM, not a from-source build. `copr/jwtd.spec` carries a `VERSION`/`DATE`-placeholder spec that wraps the prebuilt linux archives (`Source0`/`Source1` per arch, selected with `%ifarch`), disables the debuginfo subpackage (`%global debug_package %{nil}`) since the Go binary is prebuilt, and ships the `LICENSE`. The `update-copr` job verifies the archives against the signed `checksums.txt`, renders the spec, builds a source RPM with `rpmbuild -bs` on the ubuntu runner (the SRPM step needs no Fedora macros), and submits it with `copr-cli build webcodr/jwtd <srpm> --nowait` authenticated by the base64-encoded `COPR_API_TOKEN` secret. COPR builds the SRPM in its Fedora chroots and signs the result with its own key. There is deliberately no version-downgrade guard: `dnf` resolves the highest EVR from the repo, so a re-submitted older version cannot downgrade users. `TestCOPRInvariants` enforces the binary-repackage contract and the gated job. Like the others, it runs only for stable releases after the release job.

AUR is published as `jwtd-bin`, a prebuilt-binary package that installs the released linux archive rather than compiling from source. Like Homebrew, it is hand-templated (GoReleaser is not involved at all, so `.goreleaser.yaml` is untouched): `aur/PKGBUILD` and `aur/.SRCINFO` carry `VERSION`/`SHA256_LINUX_AMD64`/`SHA256_LINUX_ARM64`/`SHA256_LICENSE` placeholders, and `update-aur` fills the two archive hashes from the signed `checksums.txt`, hashes the release-commit `LICENSE` itself (it is not a release archive, so not in `checksums.txt`, but is byte-identical to the tagged raw file the PKGBUILD downloads), renders both files, and pushes to `ssh://aur@aur.archlinux.org/jwtd-bin.git`. The archives have version-free names, so the PKGBUILD renames the downloads to include `${pkgver}` to avoid makepkg source-cache collisions across versions. The two templates must stay in sync: `aur/.SRCINFO` is byte-identical to `makepkg --printsrcinfo` run on the rendered PKGBUILD, so regenerate it that way after any PKGBUILD change. `update-aur` pins the AUR ED25519 host key in `known_hosts` (no trust-on-first-use), keeps the `Gem::Version` downgrade guard, authenticates with the `AUR_SSH_KEY` secret, and runs only for stable releases after the release job. `workflow_test.go`'s `TestAURInvariants` enforces these properties.

Artifacts cross the build/release job boundary as two separate uploads: `jwtd-release-assets` (everything published to the GitHub release) and `jwtd-manifests` (the Scoop manifest). The release job and `update-homebrew` download only the release assets; `update-scoop` downloads the manifests. So a downstream manifest can never become a release asset.

Release notes are auto-generated (`--generate-notes`), which lists only merged PR titles. `RELEASE_NOTES.md` holds hand-written prose for the next release: when present and non-empty it is prepended to the generated notes at release creation. Clear it after a release so its contents do not repeat on the following one.

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

`goreleaser check` validates `.goreleaser.yaml`; the snapshot build writes to the git-ignored `dist/` directory and publishes nothing. `--skip=sign` is required locally: signing is keyless and needs a GitHub Actions OIDC identity, so it can only run in the release workflow. CI runs the same commands on every push/PR and verifies the resulting `dist/artifacts.json` against the six-archive / one-checksum / six-SBOM contract.

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

- **Single package.** All code stays in package `main`, split across topical files (`main.go`, `jwe.go`, `keys.go`, `output.go`).
- **Tests mirror the source files:** `main_test.go`, `jwe_test.go`, `keys_test.go`, `output_test.go`, with shared fixtures (key generation, token signing/encryption helpers) in `helpers_test.go` and GoReleaser/release-workflow invariants in `workflow_test.go`. Use table-driven tests where multiple cases share the same structure.
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
