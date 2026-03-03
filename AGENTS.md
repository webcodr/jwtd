# AGENTS.md

## Project Overview

jwtd is a zero-dependency CLI tool written in Go that decodes and pretty-prints JSON Web Tokens (JWTs) with syntax-highlighted JSON output.

## Architecture

Single-file Go program (`main.go`) with no external dependencies. All functionality lives in package `main`:

- `main()` / `readToken()` - CLI entry point; accepts a JWT as an argument or via stdin
- `decodeAndPrint()` - Orchestrates decoding and output of header, payload, and signature
- `decodeSegment()` - Base64url-decodes a JWT segment and parses it as JSON
- `colorize()` / `isJSONKey()` - ANSI syntax highlighting for JSON output
- `printSection()` / `printSignature()` - Formatted output with optional color
- `isTerminal()` - TTY detection; color is auto-disabled when piped

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
```

## Conventions

- **No external dependencies.** Use only the Go standard library.
- **Single package.** All code stays in package `main` unless complexity warrants splitting.
- **Tests live in `main_test.go`** alongside `main.go`. Use table-driven tests where multiple cases share the same structure.
- **ANSI color constants** are defined at the top of `main.go`. Colors auto-disable when stdout is not a TTY.
- **Error handling:** Return errors up the call stack with `fmt.Errorf` wrapping (`%w`). Print to stderr and exit non-zero in `main()` only.
- **Formatting:** Use `gofmt`/`goimports` standard formatting. No special linter configuration.
- **Commit messages:** Use the [Conventional Commits](https://www.conventionalcommits.org/) format (e.g. `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`). Keep the subject line short and lowercase after the prefix.

## Color Scheme

| Token      | Color        | ANSI Code   |
|------------|--------------|-------------|
| Keys       | Bold blue    | `\033[1;34m` |
| Strings    | Green        | `\033[0;32m` |
| Numbers    | Yellow       | `\033[0;33m` |
| Booleans   | Magenta      | `\033[0;35m` |
| Null       | Red          | `\033[0;31m` |
| Braces     | White        | `\033[0;37m` |
| Labels     | Bold cyan    | `\033[1;36m` |
| Signature  | Dim          | `\033[2m`    |
