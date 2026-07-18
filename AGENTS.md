# AGENTS.md

## Project Overview

jwtd is a CLI tool written in Go that decodes and pretty-prints JSON Web Tokens (JWTs) and JSON Web Encryption (JWE) tokens with syntax-highlighted JSON output. It can also verify JWS signatures and decrypt JWEs when given a key via `--key`/`-k` or the `JWTD_KEY` environment variable.

## Architecture

Single-file Go program (`main.go`) with all functionality in package `main`:

- `main()` - CLI entry point using Cobra; defines the root command and the `--key`/`-k` flag
- `run()` / `readToken()` - Resolves the token from arguments, stdin pipe, or interactive readline prompt; falls back to `JWTD_KEY` when `--key` is not set; dispatches to JWT or JWE handling
- `readInteractive()` - Prompts for a token interactively using `chzyer/readline`
- `isJWE()` - Detects JWE compact serialization (5 dot-separated parts vs. 3 for a JWT)
- `decodeAndPrint()` - Parses the JWT with `golang-jwt/jwt` (`ParseUnverified`) and orchestrates output; verifies the signature when a key is provided
- `verifySignature()` - Verifies a JWS signature with `jwt.WithoutClaimsValidation()` so the result reflects only the cryptographic signature, not expiry; prints `Signature: VALID`/`INVALID`
- `publicKeyForVerification()` - Extracts the public key from RSA/ECDSA/Ed25519 private keys
- `decodeAndPrintJWE()` - Parses a JWE with `go-jose`; without a key prints the protected header and encrypted part metadata, with a key decrypts and prints the payload
- `printDecryptedPayload()` - Pretty-prints decrypted JWE plaintext; recursively decodes nested JWTs/JWEs, falls back to JSON or raw text
- `loadKey()` / `parseKeyData()` / `parseDERKey()` / `parseJWK()` - Load a key from a file path or base64 string; supports PEM, DER (PKCS#1/PKCS#8/PKIX), JWK/JWK Set, and raw symmetric keys
- `formatTimestamps()` - Converts `iat`, `exp`, `nbf` Unix timestamps to RFC3339 strings (original epoch value shown in parentheses)
- `newFormatter()` - Creates a `go-prettyjson` formatter with the project color scheme
- `printSection()` / `printSignature()` / `printEncryptedParts()` - Formatted output using `fatih/color`

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

### Usage

```sh
jwtd <token>
echo <token> | jwtd
jwtd                          # interactive prompt via readline
jwtd --key key.pem <token>    # verify JWS signature or decrypt JWE
JWTD_KEY=key.pem jwtd <token> # same, via environment variable
```

## Conventions

- **Single package.** All code stays in package `main` unless complexity warrants splitting.
- **Tests live in `main_test.go`** alongside `main.go`. Use table-driven tests where multiple cases share the same structure.
- **Color scheme** is configured in `newFormatter()` via `go-prettyjson` and `fatih/color`. Colors auto-disable when stdout is not a TTY.
- **Error handling:** Return errors up the call stack with `fmt.Errorf` wrapping (`%w`). Cobra handles top-level error display and exit codes.
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
