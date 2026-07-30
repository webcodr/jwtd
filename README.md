# jwtd

A CLI tool that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output.

## Features

- Decode any JWT and display its header, payload, and signature
- Decode and decrypt JWE tokens with automatic format detection
- JWS signature verification with `--key` flag
- Supports RSA, ECDSA, Ed25519, and HMAC signature algorithms
- Key loading from PEM/DER keys, X.509 certificates, JWK/JWK Sets, or base64-encoded input
- JWK Set key selection by the token's `kid` header (falls back to the first key when the token has none)
- Supports both private and public keys (private keys are auto-converted for verification)
- Invalid signatures produce a nonzero exit status when `--key`/`JWTD_KEY` is used
- Opt-in claim validation with `--verify-claims` (exp/nbf) plus `--aud`/`--iss` assertions, exiting nonzero when a check fails — independent of the signature check
- Nested token detection: JWT-inside-JWE and JWE-inside-JWE are decoded recursively
- `JWTD_KEY` environment variable for default key configuration
- Syntax-highlighted JSON output with a consistent color scheme
- Machine-readable output with `--json` for scripting and piping into tools like `jq`
- Automatic conversion of `iat`, `exp`, and `nbf` timestamps to human-readable RFC3339 dates, annotated with the time remaining or elapsed (`expires in 14m`, `expired 2h ago`, `not yet valid, in 5m`)
- Accepts tokens as arguments, from stdin pipes, or via an interactive prompt
- Colors auto-disable when output is not a TTY, or are controlled explicitly with `--color`
- Shell completions (bash, zsh, fish) shipped in the Homebrew formula and the `.deb`/`.rpm` packages

## Installation

### Install script (macOS and Linux)

```sh
curl -fsSL https://jwtd.sh/install.sh | sh
```

Downloads the release archive for the detected OS and architecture, verifies it against the release's `checksums.txt`, and installs the binary into `~/.local/bin` — no root privileges and no package manager required. When [Cosign](https://docs.sigstore.dev/) is installed, the keyless signature over `checksums.txt` is verified as well; without it the checksum verification still runs and a mismatch aborts the installation.

Pass options after `--`:

```sh
curl -fsSL https://jwtd.sh/install.sh | sh -s -- --version v5.3.0   # pin a release
curl -fsSL https://jwtd.sh/install.sh | sh -s -- --dir /usr/local/bin
```

`JWTD_VERSION` and `JWTD_INSTALL_DIR` set the same two values. Run the script with `--help` for the full list. The script is [`install.sh`](install.sh) in this repository; review it before piping it into a shell.

Windows is served by [WinGet](#winget-windows) and [Scoop](#scoop-windows) instead.

### Homebrew (macOS and Linux)

```sh
brew install webcodr/tap/jwtd
```

### Scoop (Windows)

```sh
scoop bucket add webcodr https://github.com/webcodr/scoop-bucket
scoop install jwtd
```

### WinGet (Windows)

Install with the built-in Windows Package Manager:

```sh
winget install WebCodr.jwtd
```

The manifest installs the same signed release binary as the other channels, packaged as a portable zip whose hashes are taken from the release's signed `checksums.txt`.

### AUR (Arch Linux)

Install the prebuilt-binary package from the [AUR](https://aur.archlinux.org/packages/jwtd-bin) with any AUR helper:

```sh
paru -S jwtd-bin
# or
yay -S jwtd-bin
```

The package installs the same signed release binary used by the other channels; its hashes are taken from the release's signed `checksums.txt`.

### Fedora (COPR)

Enable the COPR repository and install with `dnf`:

```sh
sudo dnf copr enable webcodr/jwtd
sudo dnf install jwtd
```

The COPR package repackages the same signed release binary used by the other channels, verified against the release's signed `checksums.txt`.

### Nix

The repository is a flake. Run jwtd without installing it:

```sh
nix run github:webcodr/jwtd -- <token>
```

Or install it into a profile:

```sh
nix profile install github:webcodr/jwtd
```

Flake builds compile from source and report the commit they were built from; tagged release binaries carry the semantic version.

### From source

Requires Go 1.26+.

```sh
go install github.com/webcodr/jwtd@latest
```

### From releases

Download a prebuilt binary from the [Releases](https://github.com/webcodr/jwtd/releases) page. Binaries are available for:

- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64, arm64)

Linux users can also install a `.deb` or `.rpm` package, which places the binary at `/usr/bin/jwtd`:

```sh
sudo dpkg -i jwtd-linux-amd64.deb    # Debian, Ubuntu
sudo rpm -i jwtd-linux-amd64.rpm     # Fedora, RHEL, openSUSE
```

Each release also includes a `checksums.txt` with SHA-256 hashes for every archive and Linux package; verify a download with `sha256sum --check checksums.txt`.

`checksums.txt` is signed with [Cosign](https://docs.sigstore.dev/) keyless signing. To verify that the checksums really came from this project's release workflow, download `checksums.txt.sigstore.json` alongside it and run:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/webcodr/jwtd/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Every `.tar.gz` archive also ships a [Syft](https://github.com/anchore/syft) SPDX SBOM named `<archive>.sbom.json`. Windows additionally ships a `.zip` archive (for WinGet) that wraps the same binary as the Windows `.tar.gz`.

## Usage

### Decode a JWT

Pass a token as an argument:

```sh
jwtd eyJhbGciOiJIUzI1NiIs...
```

Pipe a token from stdin:

```sh
echo eyJhbGciOiJIUzI1NiIs... | jwtd
```

Or run without arguments for an interactive prompt:

```sh
jwtd
Enter JWT/JWE: _
```

### Decode a JWE

JWE tokens (5 dot-separated parts) are automatically detected. Without a key, the protected header and encrypted part metadata are displayed:

```sh
jwtd eyJhbGciOiJSU0EtT0FF...
```

### Decrypt a JWE

Provide a decryption key with `--key` or `-k`:

```sh
jwtd --key /path/to/private-key.pem eyJhbGciOiJSU0EtT0FF...
jwtd -k /path/to/key.jwk eyJhbGciOiJSU0EtT0FF...
```

### Verify a JWT signature

Use the same `--key` flag to verify JWS signatures:

```sh
jwtd --key /path/to/public-key.pem eyJhbGciOiJSUzI1NiIs...
```

An invalid signature prints `Signature: INVALID` and exits with a nonzero status. Claim validity, including expiry, is not part of this cryptographic signature check.

### Validate claims

By default, claim validity never affects the exit code — expiry is shown only as a display annotation. Opt in to enforcement with `--verify-claims`, which validates the temporal claims (`exp`, `nbf`) and exits nonzero when the token is expired or not yet valid:

```sh
jwtd --verify-claims eyJhbGciOiJIUzI1NiIs...
```

Add `--aud` and/or `--iss` to also require a specific audience or issuer; either flag implies claim validation, so the temporal checks run too:

```sh
jwtd --aud my-api --iss https://issuer.example eyJhbGciOiJIUzI1NiIs...
```

The result is printed as a `Claims: VALID` / `Claims: INVALID` section (with the reason), and reported as `claimsValid` under `--json`. Claim validation is independent of the signature: it runs with or without `--key`, and when both are used the command exits nonzero if either check fails. A token with no `exp` is not treated as expired. The clock matches the displayed `expired` / `not yet valid` annotations, with no leeway. Claim validation applies to JWTs only; it is skipped (with a note) for JWEs.

### Key formats

The `--key` flag accepts:

- **PEM files**: RSA, EC, or Ed25519 keys (private or public), and X.509 certificates
- **DER files**: PKCS#1, PKCS#8, SEC 1, or PKIX encoded keys, and X.509 certificates
- **JWK files**: Single JSON Web Key or JWK Set (the entry matching the token's `kid` is used; the first key when the token has no `kid`)
- **Base64 strings**: Base64 or base64url encoded key material (PEM, DER, certificate, or JWK)
- **Symmetric key files**: `hmac:<file>` uses the file's bytes as a symmetric key
- **Literal secrets**: `raw:<secret>` uses the text after the prefix as a symmetric key verbatim

Key detection first honors the `raw:` and `hmac:` prefixes, then tries an existing file path, then standard base64 followed by base64url. File contents and decoded inline data are parsed as JWK/JWK Set, then PEM, then DER keys or X.509 certificates. Base64-encoded key material is decoded the same way whether it arrives inline or in a text file. For signature verification, jwtd extracts the public key from X.509 certificates. For `hmac:` files, trailing newlines are trimmed only when the content is printable ASCII text (with tab, CR, and LF allowed); UTF-8/non-ASCII and other binary files remain byte-exact.

**Symmetric secrets must be explicit.** Key material that does not parse as PEM, DER, JWK, or an X.509 certificate is an error, not a symmetric key. jwtd used to fall back to using such bytes as an HMAC secret, which made any unsupported key format forgeable: a public key is a published value, so anyone who knew its bytes could sign an HS256 token that verified against it. Pass symmetric secrets as `hmac:<file>` or `raw:<secret>` and the failure direction stays closed regardless of what format turns up.

SSH public keys (`id_*.pub`, `authorized_keys`, and RFC 4716 armor) are detected and reported with a conversion hint rather than a generic error. Convert RSA and ECDSA keys with `ssh-keygen -e -m PKCS8 -f <key>`. Empty key material is rejected: the empty secret is known to everyone.

```sh
jwtd --key raw:my-hmac-secret eyJhbGciOiJIUzI1NiIs...
jwtd --key hmac:/path/to/secret.key eyJhbGciOiJIUzI1NiIs...
```

Inline key material is visible to other local users through the process list and lands in shell history. Prefer a key file or `JWTD_KEY` for anything sensitive.

When a key argument is not an existing file, jwtd notes on stderr which reading it applied — literal secret or base64-decoded — so a value meant one way is never silently used another. Key files are the expected case and stay silent. The note goes to stderr, so piped stdout is unaffected.

### Machine-readable output

Use `--json` to emit a single JSON object instead of the colored sections, for scripting or piping into tools like `jq`:

```sh
jwtd --json eyJhbGciOiJIUzI1NiIs...
jwtd --json --key key.pem eyJhbGciOiJSUzI1NiIs... | jq .signatureValid
```

A JWT is emitted as `{ "header", "payload", "signature" }`, plus `"signatureValid"` when a key is provided and `"claimsValid"` when claim validation is requested. Timestamps stay as their raw numeric claim values (no RFC3339 conversion) so consumers can do their own date math, and numbers are preserved exactly. A JWE is emitted as `{ "protectedHeader", ... }` with either the encrypted part sizes (no key) or the decrypted payload (with a key). An invalid signature still prints the JSON and then exits nonzero.

### Color

Colors auto-disable when stdout is not a TTY. Override this with `--color`:

```sh
jwtd --color=always eyJhbGciOiJIUzI1NiIs... | less -R   # force color through a pager
jwtd --color=never  eyJhbGciOiJIUzI1NiIs...             # disable color
```

`--color` accepts `auto` (the default), `always`, or `never`. `--json` output is always plain, regardless of `--color`.

### Environment variable

Set `JWTD_KEY` to provide a default key without using `--key` on every invocation:

```sh
export JWTD_KEY=/path/to/key.pem
jwtd eyJhbGciOiJSU0EtT0FF...
```

The `--key` flag always takes precedence over `JWTD_KEY`.

## Output

jwtd prints sections with colored, indented JSON:

| Element    | Color      |
|------------|------------|
| Keys       | Bold blue  |
| Strings    | Green      |
| Numbers    | Yellow     |
| Booleans   | Magenta    |
| Null       | Red        |
| Labels     | Bold cyan  |
| Signature  | Dim        |

## Development

### Build

```sh
go build -o jwtd .
```

A Nix development shell with Go and GoReleaser is available via the flake:

```sh
nix develop
```

### Test

```sh
go test -v ./...
```

### Release packaging

Releases are cross-compiled and archived with [GoReleaser](https://goreleaser.com/), pinned in `.mise.toml`. Validate the configuration and produce a local snapshot build without publishing anything:

```sh
mise install
goreleaser check
goreleaser release --snapshot --clean --skip=sign
```

Snapshot artifacts are written to the git-ignored `dist/` directory. `--skip=sign` is required locally because signing is keyless and needs a GitHub Actions OIDC identity; the release workflow exercises the signing path. Production releases remain a manually dispatched GitHub Actions workflow; GoReleaser only builds, packages, and signs — it never publishes GitHub releases or Homebrew metadata.

## License

[MIT](LICENSE)
