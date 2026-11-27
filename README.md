# jwtd

A CLI tool that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output.

## Features

- Decode any JWT and display its header, payload, and signature
- Decode and decrypt JWE tokens with automatic format detection
- JWS signature verification with `--key` flag
- Signed-then-encrypted tokens (such as encrypted OIDC ID tokens): decrypt with `--key` and verify the inner signature with `--verify-key`
- Supports RSA, ECDSA, Ed25519, and HMAC signature algorithms
- Key loading from PEM/DER keys, X.509 certificates, JWK/JWK Sets, or base64-encoded input
- JWK Set key selection by the token's `kid` header, disambiguated by `use` (`sig`/`enc`) and `alg` (falls back to the first key when the token has no `kid`)
- Supports both private and public keys (private keys are auto-converted for verification)
- Invalid signatures produce a nonzero exit status when `--key`/`JWTD_KEY` is used
- Opt-in claim validation with `--verify-claims` (`exp`/`nbf`) plus `--aud`, `--iss`, `--sub`, `--leeway`, `--require-exp`, and `--at`, exiting nonzero when a check fails — independent of the signature check
- Algorithm pinning with `--alg` to require an exact JWS/JWE `alg` header
- Quiet mode (`-q`/`--quiet`) to suppress stdout and check status via exit code alone
- Section and claim extraction with `--header`, `--payload`, and `--claim <name>` for shell pipelines, printing nothing to stdout when a requested check fails
- Nested token detection: JWT-inside-JWE and JWE-inside-JWE are decoded recursively
- `JWTD_KEY` environment variable for default key configuration
- Syntax-highlighted JSON output with a consistent color scheme
- Machine-readable output with `--json` for scripting and piping into tools like `jq`
- Automatic conversion of `iat`, `exp`, `nbf`, `auth_time`, and `updated_at` timestamps to human-readable RFC3339 dates (UTC by default, or `--local`/`--tz`), with `exp`/`nbf` annotated with the time remaining or elapsed (`expires in 14m`, `expired 2h ago`, `not yet valid, in 5m`)
- Accepts tokens as arguments, from stdin pipes, or via an interactive prompt, stripping optional `Authorization: Bearer ` prefixes and surrounding quotes
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

### Install script (Windows)

```powershell
irm https://jwtd.sh/install.ps1 | iex
```

The same contract as the Unix installer: the release zip for the detected architecture is verified against the release's `checksums.txt` — and against the keyless Cosign signature when `cosign` is on `PATH` — before anything is written. The binary is installed into `%LOCALAPPDATA%\Programs\jwtd`, which is added to your user `PATH`; no administrator privileges are required.

`Invoke-Expression` cannot forward arguments, so the options are environment variables:

```powershell
$env:JWTD_VERSION = 'v5.3.0'        # pin a release
$env:JWTD_INSTALL_DIR = 'C:\tools'  # install somewhere else
$env:JWTD_NO_MODIFY_PATH = '1'      # leave PATH alone
irm https://jwtd.sh/install.ps1 | iex
```

To pass parameters directly instead, create the script block explicitly:

```powershell
& ([scriptblock]::Create((irm https://jwtd.sh/install.ps1))) -Version v5.3.0 -NoModifyPath
```

The script is [`install.ps1`](install.ps1) in this repository; review it before piping it into a shell.

### Homebrew (macOS and Linux)

```sh
brew install webcodr/tap/jwtd
```

### Scoop (Windows)

```sh
scoop bucket add webcodr https://github.com/webcodr/scoop-bucket
scoop install jwtd
```

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

Every `.tar.gz` archive also ships a [Syft](https://github.com/anchore/syft) SPDX SBOM named `<archive>.sbom.json`. Windows additionally ships a `.zip` archive (used by `install.ps1`) that wraps the same binary as the Windows `.tar.gz`.

## Usage

### Decode a JWT

Pass a token as an argument (an optional `Authorization: Bearer ` prefix and surrounding quotes are stripped automatically):

```sh
jwtd eyJhbGciOiJIUzI1NiIs...
jwtd "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
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

### Verify a signed-then-encrypted token

A token that is signed by an issuer and then encrypted to you (an encrypted OIDC ID token, for example) needs two keys: your private key to decrypt it, and the issuer's public key to verify the inner signature. Pass the second one with `--verify-key` (or `JWTD_VERIFY_KEY`):

```sh
jwtd --key /path/to/private-key.pem --verify-key /path/to/issuer-public-key.pem eyJhbGciOiJSU0EtT0FF...
```

`--key` decrypts every JWE layer, and `--verify-key` verifies every JWS layer, at the top level or nested. Without `--verify-key`, `--key` is offered for verification too, which is right when one key serves every layer. When the issuer signed with a different key than the one that decrypts — the normal case for an encrypted ID token — offering the recipient key to the inner signature reports `Signature: INVALID` (or, if the key cannot be used for it at all, leaves the signature unchecked), and a note on stderr says to pass `--verify-key`. A `--verify-key` flag is never skipped: if it cannot be used on a nested signature, that is an error, and if the token holds no signature at all, the command fails instead of passing a check that never ran. An empty `--verify-key` is rejected. A `JWTD_VERIFY_KEY` that meets no signature is standing configuration rather than a request about this token, so it only produces a note.

### Verify a JWT signature

Use the same `--key` flag to verify JWS signatures:

```sh
jwtd --key /path/to/public-key.pem eyJhbGciOiJSUzI1NiIs...
jwtd --alg EdDSA --key /path/to/public-key.pem eyJhbGciOiJFZERTQSIs...
```

An invalid signature prints `Signature: INVALID` and exits with a nonzero status. Claim validity, including expiry, is not part of this cryptographic signature check. Pass `--alg` to also require an exact `alg` header (for either JWT or JWE) and fail before verification/decryption if the token uses a different algorithm.

### Validate claims

By default, claim validity never affects the exit code — expiry is shown only as a display annotation. Opt in to enforcement with `--verify-claims`, which validates the temporal claims (`exp`, `nbf`) and exits nonzero when the token is expired or not yet valid:

```sh
jwtd --verify-claims eyJhbGciOiJIUzI1NiIs...
```

Add `--aud`, `--iss`, `--sub`, `--leeway`, and/or `--require-exp` to enforce additional constraints; each flag implies claim validation, so the temporal checks run too:

```sh
jwtd --aud my-api --iss https://issuer.example --sub user-123 --leeway 30s --require-exp eyJhbGciOiJIUzI1NiIs...
```

Use `--at` (RFC3339 or Unix seconds) to evaluate timestamps and claim validity at a specific instant, and `-q` / `--quiet` to suppress stdout when only the exit code is needed:

```sh
jwtd --at 2025-01-15T12:00:00Z --verify-claims eyJhbGciOiJIUzI1NiIs...
jwtd -q --key /path/to/public-key.pem --verify-claims eyJhbGciOiJIUzI1NiIs...
```

The result is printed as a `Claims: VALID` / `Claims: INVALID` section (with the reason), and reported as `claimsValid` under `--json`. Claim validation is independent of the signature: it runs with or without `--key`, and when both are used the command exits nonzero if either check fails. Without `--require-exp`, a token with no `exp` is not treated as expired. The clock matches the displayed `expired` / `not yet valid` annotations, with no leeway unless `--leeway` is given. For a JWE, the claims validated are the innermost claims set: the claims of a token nested inside it, or a decrypted plaintext that is a JSON object. If the claims cannot be reached — no `--key` to decrypt the JWE, a nested JWE that cannot be decrypted, or a plaintext that is not a JSON object — the result is `Claims: INVALID` with the reason, because a check that cannot run must not pass.

### Timestamp timezones

Human-readable timestamps (`iat`, `exp`, `nbf`, `auth_time`, `updated_at`) render in UTC by default. Pass `--local` for the system's local timezone or `--tz <IANA-zone>` for a specific zone (`--json` always keeps raw numeric timestamps):

```sh
jwtd --local eyJhbGciOiJIUzI1NiIs...
jwtd --tz America/New_York eyJhbGciOiJIUzI1NiIs...
```

### Key formats

The `--key` flag accepts:

- **PEM files**: RSA, EC, or Ed25519 keys (private or public), and X.509 certificates
- **DER files**: PKCS#1, PKCS#8, SEC 1, or PKIX encoded keys, and X.509 certificates
- **JWK files**: Single JSON Web Key or JWK Set (the entry matching the token's `kid` is used, disambiguated by `use` and `alg`; the first matching key when the token has no `kid`)
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

A JWT is emitted as `{ "header", "payload", "signature" }`, plus `"signatureValid"` when a key is provided and `"claimsValid"` when claim validation is requested. Timestamps stay as their raw numeric claim values (no RFC3339 conversion) so consumers can do their own date math, and numbers are preserved exactly. A JWE is emitted as `{ "protectedHeader", ... }` with either the encrypted part sizes (no key) or the decrypted payload (with a key). When the decrypted payload is itself a token, `"nested"` holds it in the same shape (with `"signatureValid"` when it was verified), and `"decryptedPayload"` keeps the compact string. `"claimsValid"` always sits on the top-level object. An invalid signature at any depth still prints the JSON and then exits nonzero.

### Extract a section or claim

Use `--header`, `--payload`, or `--claim <name>` to print only that part of the token, for example to capture a claim in a shell variable without `jq`:

```sh
sub=$(jwtd --key /path/to/public-key.pem --claim sub eyJhbGciOiJSUzI1NiIs...)
jwtd --payload eyJhbGciOiJIUzI1NiIs...
```

A string claim prints bare (like `jq -r`, escaped for the terminal) and any other value as compact JSON. `--header` and `--payload` print formatted JSON. Under `--json` every value is JSON-encoded on one line. Timestamps stay as their raw numeric values. `--claim` takes a top-level claim name literally, so a name containing dots (such as a URI) is not read as a path. A missing claim is an error.

Every requested check still runs: `--key`, the claim flags, and `--alg`. **If a check fails, nothing is printed to stdout.** The failing verdict goes to stderr and the exit status is nonzero, so a script that captures the output never receives a value that failed a check it asked for. For a JWE, `--header` needs no key, while `--payload` and `--claim` need `--key` to decrypt. A key that is given is always used, so a wrong key fails `--header` too instead of printing a header it could not authenticate. For a token nested inside a JWE, `--payload` and `--claim` read the innermost token, and an invalid signature at any depth withholds the value.

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
