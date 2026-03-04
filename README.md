# jwtd

A CLI tool that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output.

## Features

- Decode any JWT and display its header, payload, and signature
- Decode and decrypt JWE tokens with automatic format detection
- JWS signature verification with `--key` flag
- Supports RSA, ECDSA, Ed25519, and HMAC signature algorithms
- Key loading from PEM files, DER files, JWK/JWK Set, or base64-encoded input
- Supports both private and public keys (private keys are auto-converted for verification)
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

### Key formats

The `--key` flag accepts:

- **PEM files**: RSA, EC, or Ed25519 keys (private or public)
- **DER files**: PKCS#1, PKCS#8, or PKIX encoded keys
- **JWK files**: Single JSON Web Key or JWK Set (first key is used)
- **Base64 strings**: Base64 or base64url encoded key material (PEM, DER, JWK, or raw symmetric key)

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

### Test

```sh
go test -v ./...
```

## License

[MIT](LICENSE)
