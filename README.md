# jwtd

A CLI tool that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output.

## Features

- Decode any JWT and display its header, payload, and signature
- Decode and decrypt JWE tokens with automatic format detection
- JWS signature verification with `--key` flag
- Supports RSA, ECDSA, Ed25519, and HMAC signature algorithms
- Key loading from PEM/DER keys, X.509 certificates, JWK/JWK Sets, or base64-encoded input
- Supports both private and public keys (private keys are auto-converted for verification)
- Invalid signatures produce a nonzero exit status when `--key`/`JWTD_KEY` is used
- Nested token detection: JWT-inside-JWE and JWE-inside-JWE are decoded recursively
- `JWTD_KEY` environment variable for default key configuration
- Syntax-highlighted JSON output with a consistent color scheme
- Automatic conversion of `iat`, `exp`, and `nbf` timestamps to human-readable RFC3339 dates
- Accepts tokens as arguments, from stdin pipes, or via an interactive prompt
- Colors auto-disable when output is not a TTY

## Installation

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

Every archive also ships a [Syft](https://github.com/anchore/syft) SPDX SBOM named `<archive>.sbom.json`.

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

### Key formats

The `--key` flag accepts:

- **PEM files**: RSA, EC, or Ed25519 keys (private or public), and X.509 certificates
- **DER files**: PKCS#1, PKCS#8, SEC 1, or PKIX encoded keys, and X.509 certificates
- **JWK files**: Single JSON Web Key or JWK Set (first key is used)
- **Base64 strings**: Base64 or base64url encoded key material (PEM, DER, certificate, JWK, or raw symmetric key)
- **Literal secrets**: `raw:<secret>` uses the text after the prefix as a symmetric key verbatim

Key detection first honors the `raw:` prefix, then tries an existing file path, then standard base64 followed by base64url. File contents and decoded inline data are parsed as JWK/JWK Set, then PEM, then DER keys or X.509 certificates. For signature verification, jwtd extracts the public key from X.509 certificates. Recognizable structured data must parse successfully or jwtd returns an error; opaque unstructured data falls back to raw symmetric bytes. For key files, trailing newlines are trimmed only when the content is printable ASCII text (with tab, CR, and LF allowed). UTF-8/non-ASCII and other binary files remain byte-exact.

```sh
jwtd --key raw:my-hmac-secret eyJhbGciOiJIUzI1NiIs...
```

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
