## Highlights

### Validate claims (opt-in)

jwtd can now enforce claim validity, not just display it. Pass `--verify-claims` to check the temporal claims and exit nonzero when a token is expired or not yet valid:

```
jwtd --verify-claims <token>
```

Add `--aud` and/or `--iss` to additionally require a specific audience or issuer (either flag implies validation):

```
jwtd --aud my-api --iss https://issuer.example <token>
```

The verdict prints as a `Claims: VALID` / `Claims: INVALID` section and is reported as `claimsValid` under `--json`. Claim validation is independent of signature verification: it runs with or without `--key`, and when both are used the command exits nonzero if either check fails. A token with no `exp` is not treated as expired, and the default behavior is unchanged — a bare decode still never fails on expiry.

### Relative timestamps

Decoded `exp`, `nbf`, and `iat` claims now show how long until — or since — they matter: `expires in 14m`, `expired 2h ago`, `not yet valid, in 5m`. This is display-only and never affects verification or the exit code, and the `--json` output keeps the raw numeric claim values.

### Fixes

- Reading a token from a closed or detached stdin no longer panics; jwtd falls back to the interactive prompt.
