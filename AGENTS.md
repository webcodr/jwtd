# AGENTS.md

## Project Overview

jwtd is a CLI tool written in Go that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output. It can also verify JWS signatures and decrypt JWEs when given a key via `--key`/`-k` or the `JWTD_KEY` environment variable.

## Architecture

All functionality lives in package `main`, split across four source files:

### `main.go` - CLI, token input, and the JWT/JWS path

- `main()` / `newRootCommand()` - Build and execute the Cobra root command with the `--key`/`-k` flag; suppress Cobra's automatic usage/error output so runtime errors are rendered once, while invalid-signature details are not duplicated
- `run()` / `readToken()` - Resolves the token from arguments, stdin pipe, or interactive readline prompt; falls back to `JWTD_KEY` when `--key` is not set; dispatches to JWT or JWE handling
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
- `isStructuredKeyData()` / `hasPEMMarker()` / `hasJWKMember()` / `isCompleteDER()` / `isTextKey()` - Heuristics distinguishing structured key material (PEM/JWK/DER) from opaque symmetric secrets

### `output.go` - Formatting, escaping, and colored printing

- `printDecryptedPayload()` / `escapeTerminalText()` / `escapeFormattedJSONControls()` - Recursively decode nested JWTs/JWEs and pretty-print JSON objects or arrays; raw plaintext escapes C0 controls except newline/tab, DEL, C1 controls, invalid UTF-8 bytes, and targeted bidi controls, while formatted JSON sanitizes C1, DEL, and the same targeted bidi controls
- `formatTimestamps()` - Converts exact `iat`, `exp`, `nbf` Unix numeric values, including fractions, to RFC3339 strings (original value shown in parentheses)
- `newFormatter()` - Creates a `go-prettyjson` formatter with the project color scheme
- `printSection()` / `printSignature()` - Formatted output using `fatih/color`

### Release packaging

Cross-compilation, archive naming, checksums, SBOMs, and signing are owned by `.goreleaser.yaml` (pinned in `.mise.toml`); it selects the six linux/darwin/windows × amd64/arm64 targets, bakes `main.version` via ldflags, and produces binary-only `tar.gz` archives, `.deb`/`.rpm` packages for linux amd64/arm64, a `checksums.txt`, a per-archive Syft SBOM, and a keyless Cosign bundle (`checksums.txt.sigstore.json`) over the checksum file.

The nfpm packages share the `jwtd` build id with the archives, so `checksum.ids` covers both; they pin `mtime` to the epoch and are byte-reproducible, which keeps them in the strict comparison tier.

`checksum.ids` deliberately restricts `checksums.txt` to the `jwtd` id (archives and packages). Syft SBOMs embed a random `documentNamespace` UUID and a creation timestamp, so including them would make the signed checksum file differ on every run and break byte-for-byte release verification. Consequently the release job verifies assets in two tiers: the six archives and `checksums.txt` must match the build byte-for-byte, while the SBOMs and the Cosign bundle are verified by presence and exact count, with the bundle additionally checked via `cosign verify-blob`. `.github/workflows/release.yml` owns everything GoReleaser does not: version/ref validation, tag provenance (a local, unpushed tag drives GoReleaser's version discovery), draft release creation and reconciliation, byte-for-byte asset verification, semantic latest-release handling, and Homebrew tap publication. GoReleaser never publishes: `release.disable: true` in the config, `skip_upload: true` on the Homebrew cask, and `--skip=publish`/`--snapshot` at every invocation site all enforce this, and the GoReleaser build step never receives a write-capable token.

Homebrew metadata is generated by GoReleaser as a **cask** (`homebrew_casks`) and rendered into `dist/` without being pushed. Because `release.disable` is true, the cask needs an explicit `url.template`; without it GoReleaser fails with "cannot use default url_template". The `update-homebrew` job cross-checks every hash baked into the cask against `checksums.txt` before pushing it to `Casks/jwtd.rb` in `webcodr/homebrew-tap`, and removes the superseded `Formula/jwtd.rb` from the tap. Note that Homebrew casks are macOS-only, so Linux Homebrew installs are no longer supported; Linux users should use the `.deb`/`.rpm` packages or the archives.

Scoop works the same way: `scoops` renders `jwtd.json` with `skip_upload: true`, and `update-scoop` cross-checks its hashes against `checksums.txt` before pushing to `webcodr/scoop-bucket`. Note the field is `url_template` for scoop but nested `url.template` for casks. Both downstream jobs run only for stable releases, after the release job succeeds.

Artifacts cross the build/release job boundary as two separate uploads: `jwtd-release-assets` (everything published to the GitHub release) and `jwtd-manifests` (the cask and Scoop manifest). The release job downloads only the former, so a downstream manifest can never become a release asset.

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
