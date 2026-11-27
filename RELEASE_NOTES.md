## Extraction and signed-then-encrypted tokens

This release adds single-value extraction for shell pipelines and end-to-end checking of signed-then-encrypted tokens such as encrypted OIDC ID tokens.

## What's new

**Section and claim extraction.** `--header`, `--payload`, and `--claim <name>` print one part of a token, so `sub=$(jwtd -k issuer.pem --claim sub "$TOKEN")` works without `jq`. String claims print bare, other values as compact JSON, and `--json` JSON-encodes every value. Every requested check still runs, and **if one fails, nothing is printed to stdout**: the verdict goes to stderr and the exit status is nonzero, so a script never receives a value that failed a check it asked for.

**A separate verification key.** `--verify-key` (or `JWTD_VERIFY_KEY`) verifies JWS signatures at any depth, while `--key` keeps decrypting every JWE layer. A token signed by an issuer and encrypted to you can now be checked in one command:

```sh
jwtd --key private-key.pem --verify-key issuer-public-key.pem "$TOKEN"
```

An explicit `--verify-key` is never skipped: if it cannot be used on a nested signature, or the token holds no signature at all, the command fails. An empty `--verify-key` is rejected.

**Claim validation and `--json` reach inside a JWE.** Claim flags now validate the innermost claims set: the claims of a token nested in the JWE, or a decrypted JSON payload. `--json` output for a JWE gains `nested` (the inner token, including its `signatureValid`) and `claimsValid`.

## Behaviour changes

- **Claim flags on a JWE are no longer skipped.** `jwtd --verify-claims <jwe>` used to print a note and exit 0. It now validates the innermost claims, and claims it cannot reach — no `--key` to decrypt, an undecryptable nested JWE, or a payload that is not a JSON object — are reported as `Claims: INVALID` with a nonzero exit.
- **`--json` now checks the inner signature of a nested token.** With only `--key`, the decryption key is offered to the inner signature, as the human output has always done. For an encrypted ID token signed with the issuer's own key, that reports `signatureValid: false` and exits nonzero where `--json` used to exit 0 without checking the inner signature at all. Pass `--verify-key` with the issuer's key; a stderr note says so whenever this happens.
- A top-level JWE that fails to decrypt is now reported before its protected header is printed.
