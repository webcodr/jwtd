# jwtd

A CLI tool that decodes and pretty-prints JSON Web Tokens (JWTs) with syntax-highlighted JSON output.

## Features

- Decode any JWT and display its header, payload, and signature
- Syntax-highlighted JSON output with a consistent color scheme
- Automatic conversion of `iat`, `exp`, and `nbf` timestamps to human-readable RFC3339 dates
- Accepts tokens as arguments, from stdin pipes, or via an interactive prompt
- Colors auto-disable when output is not a TTY

## Installation

### From source

Requires Go 1.26+.

```sh
go install github.com/jwtd/jwtd@latest
```

### From releases

Download a prebuilt binary from the [Releases](https://github.com/jwtd/jwtd/releases) page. Binaries are available for:

- Linux (amd64)
- macOS (amd64, arm64)
- Windows (amd64)

## Usage

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
Enter JWT: _
```

## Output

jwtd prints three sections — **Header**, **Payload**, and **Signature** — with colored, indented JSON:

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
