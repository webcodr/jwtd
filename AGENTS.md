# AGENTS.md

## Project Overview

jwtd is a CLI tool written in Go that decodes and pretty-prints JSON Web Tokens (JWTs) with syntax-highlighted JSON output.

## Architecture

Single-file Go program (`main.go`) with all functionality in package `main`:

- `main()` - CLI entry point using Cobra; defines the root command
- `run()` / `readToken()` - Resolves the JWT from arguments, stdin pipe, or interactive readline prompt
- `readInteractive()` - Prompts for a token interactively using `chzyer/readline`
- `decodeAndPrint()` - Parses the JWT with `golang-jwt/jwt` and orchestrates output
- `formatTimestamps()` - Converts `iat`, `exp`, `nbf` Unix timestamps to RFC3339 strings
- `newFormatter()` - Creates a `go-prettyjson` formatter with the project color scheme
- `printSection()` / `printSignature()` - Formatted output using `fatih/color`

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework (flags, help, argument handling) |
| `github.com/golang-jwt/jwt/v5` | JWT parsing via `ParseUnverified` |
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
jwtd              # interactive prompt via readline
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
