# Section and claim extraction (`--header`, `--payload`, `--claim`)

Feature idea #9 in `docs/feature-ideas.md`. Small change.

## Intent

Print one piece of a token to stdout so shell pipelines can use it without
`jq`: `sub=$(jwtd -k pub.pem --claim sub "$TOKEN")`.

## Goals

- `--header` prints the JWT header (the protected header for a JWE).
- `--payload` prints the JWT claims, or the decrypted JWE plaintext.
- `--claim <name>` prints the value of one top-level claim.
- Checks that were requested still run (`--key`, the claim flags, `--alg`) and
  still set the exit code.

## Non-goals

- Dotted or JSONPath-style paths. Claim names are often URIs that contain dots
  (`https://example.com/roles`), so `a.b` would be ambiguous. Top-level only.
- Several selectors in one run.
- Extracting claims from a token nested inside a JWE. That is feature #7's
  territory (nested claim validation and separate keys).

## Anti-goals

- **Handing a script a value that failed a check it asked for.** If a
  requested signature or claim check fails, stdout stays empty, the verdict
  goes to stderr, and the exit code is nonzero. A script that captures the
  output with `$(...)` and forgets `set -e` still never receives an unverified
  value. This is the fail-closed design the rest of jwtd follows.

## Behaviour

| Selector | No `--json` | `--json` |
|----------|-------------|----------|
| `--header` | The header as formatted JSON (colored only on a TTY) | The header as compact JSON |
| `--payload` | The claims as formatted JSON, timestamps left raw | The claims as compact JSON |
| `--claim x` | String values bare (like `jq -r`); any other value as compact JSON | The value JSON-encoded |

- The output is always the raw parse (`p.claims`), never the display copy
  `formatTimestamps` rewrites, so `--payload` output is valid JSON that pipes
  anywhere.
- A missing claim is an error: `claim "x" not present`, exit 1.
- When a selector is set, the signature and claim verdicts are written to
  **stderr**, and only when they fail. The top-level printer silences
  `errInvalidSignature`/`errInvalidClaims` because the human output prints its
  own verdict, so extraction mode has to print the failing verdict itself or
  the failure would be silent.
- The selectors are mutually exclusive. `--claim ""` is rejected. Both are
  validated before the token is read, like the other flags.
- `-q` with a selector is allowed. It discards stdout the same way it does
  today, and the checks still drive the exit code.

### JWE

- `--header` works without a key.
- `--payload` and `--claim` need `--key`; without one they fail with an error
  saying a key is needed to decrypt.
- `--payload` with a key: a JSON plaintext prints as JSON (as in the table).
  Any other plaintext, a nested compact token included, prints as escaped text
  (`escapeTerminalText`), one line.
- `--claim` with a key: the plaintext must be a JSON object; otherwise the
  error says the payload is not a JSON object. A nested token is reported as
  not supported yet (#7).

## Approaches

1. **A selection step at the end of the existing paths (chosen).** `run()`
   parses and checks as it does today, then a new `extract.go` renders the
   selected part instead of calling the section printers. It reuses
   `parseUnverifiedJWT`, `verifyJWTSignature`, `validateClaimsSet`, and the JWE
   key loading, so extraction cannot verify differently from the normal
   output.
2. **A `jwtd get <part>` subcommand.** This reads well, but jwtd is a
   single-command CLI today, and a subcommand would have to duplicate or move
   every root flag. Rejected.
3. **Post-processing the `--json` output.** Simple, but the JWE `--json` path
   deliberately does not recurse, and it cannot keep failing checks off stdout
   without restructuring it anyway. Rejected.

## Left to the builder

- The exact function split inside `extract.go`, and the test layout
  (`extract_test.go`, following the convention that tests mirror sources).
- Updating `AGENTS.md`, `README.md`, the site usage copy and its pinned test,
  and marking #9 as implemented in `docs/feature-ideas.md`.
