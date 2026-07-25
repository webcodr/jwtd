## Highlights

Five additions from a review pass over jwtd. All are backward compatible — existing commands, output, and key handling are unchanged.

### JWK Set key selection by `kid`

When a key is a JWK Set, jwtd now selects the entry whose `kid` matches the token's header instead of always using the first key, so verification works against real JWKS files that rotate and carry several keys. A token with no `kid` still uses the first entry, and a `kid` that matches nothing fails closed with a clear error rather than verifying against the wrong key.

### Expired and not-yet-valid timestamps

`exp` and `nbf` claims are now annotated when they matter: an `exp` in the past reads `expired`, an `nbf` in the future reads `not yet valid`.

```
"exp": "2001-09-09T01:46:40Z (1000000000, expired)"
```

This is display-only. Signature verification and the exit code stay purely cryptographic, exactly as before.

### Machine-readable output with `--json`

`--json` emits one JSON object per token instead of the colored sections, for scripting or piping into tools like `jq`:

```sh
jwtd --json <token> | jq .payload
jwtd --json --key key.pem <token> | jq .signatureValid
```

Numbers are preserved exactly and timestamps stay as their raw claim values. A JWE is emitted with its protected header and either the encrypted part sizes or the decrypted payload. An invalid signature still prints the JSON and then exits nonzero.

### Color control with `--color`

`--color=auto|always|never` overrides the automatic TTY detection — force color through a pager, or turn it off entirely. `--json` output is always plain.

```sh
jwtd --color=always <token> | less -R
```

### Shell completions

The Homebrew formula and the `.deb` / `.rpm` packages now install bash, zsh, and fish completions.
