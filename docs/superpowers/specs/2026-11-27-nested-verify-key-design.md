# Separate verification key and nested claim validation

Feature idea #7 in `docs/feature-ideas.md`. A project-sized change. The user
picked approach A for the key flag and handed every other call to the builder.
The calls made on their behalf are marked **(call)**.

## Intent

Signed-then-encrypted tokens, such as encrypted OIDC ID tokens, are a JWS signed
by the issuer and then encrypted to the recipient. Checking one takes two keys:

- the recipient's private key, to decrypt the JWE;
- the issuer's public key, to verify the inner JWS.

jwtd should check such a token end to end: decrypt it, verify the inner
signature, and validate the inner claims. It should do this in all three output
modes (human, `--json`, and extraction).

## Today

- `--key` is threaded down the nesting (`renderNested`), so one key serves every
  layer.
- With two keys the output is actively wrong, not just limited:
  - If the recipient key and the issuer key are both RSA, the recipient key is
    tried on the inner signature. The result is `Signature: INVALID` and a
    nonzero exit for a valid token.
  - If the key types differ, the decode is retried keyless and no verdict is
    printed.
- Claim flags on a JWE print a stderr note and are skipped.
- The `--json` JWE path does not recurse: a nested token is reported as its
  compact string.
- Extraction (#9) refuses `--claim` on a nested token, and refuses claim flags
  with a JWE selector, until this feature lands.

## Goals

1. **`--verify-key <key>` / `JWTD_VERIFY_KEY`** verifies every JWS layer, top
   level or nested. It accepts the same key formats as `--key`, and the flag
   beats the environment variable.
2. **`--key` / `JWTD_KEY` decrypts every JWE layer.** It remains the
   verification key when no verification key is given (the "fallback"), so
   today's single-key behaviour does not change.
3. **Claim validation applies to the innermost claims set.** That is a nested
   JWS's claims at any depth, or a decrypted JWE plaintext that is a JSON object
   (an encrypted, unsigned JWT). This works in the human, `--json`, and
   extraction modes.
4. **`--json` recurses.** A JWE whose plaintext is a token gains a `nested`
   object (the same `jwtJSON`/`jweJSON` shape), and the top-level object gains
   `claimsValid` when checks are requested.
5. **Extraction lifts both #9 refusals.** `--claim` reads the innermost claims
   set, and claim flags work with JWE selectors, with the usual rule: if a check
   fails, nothing goes to stdout.

## Non-goals

- A repeatable `--key` that picks each key by its type or `use` (approach C,
  rejected: it is a "guess which key was meant" inference).
- Renaming `--key` to `--decrypt-key` (approach B, rejected: a breaking change).
- `--alg` pinning of nested layers. `--alg` keeps checking the outermost header
  only. **(call)**
- Per-layer claim validation. Only the innermost claims set is validated, because
  that is where an ID token's claims live. **(call)**

## Anti-goals

- A key the user named explicitly must never be silently skipped. If
  `--verify-key` is given and it cannot be used on a JWS it meets, that is an
  error, not a keyless retry.
- A requested check that cannot run must never pass. Claims that cannot be
  reached give `Claims: INVALID` with the reason. A `--verify-key` that never
  meets a signature is an error. Both happen before anything is printed where the
  outcome is known up front.

## Behaviour

### Keys

| Layer | Key used | If the key cannot be used |
|-------|----------|---------------------------|
| Top-level JWE | `--key` | Hard error, as today |
| Nested JWE | `--key` | Shown undecrypted (keyless retry), as today |
| Top-level JWS | `--verify-key`, else `--key` | Hard error, as today |
| Nested JWS, `--verify-key` given | `--verify-key` | **Hard error** (new) |
| Nested JWS, fallback to `--key` | `--key` | No verdict (keyless retry), as today |

An invalid signature at any depth is a verdict: it prints `Signature: INVALID`
and exits with `errInvalidSignature`, as it does today.

- **`--verify-key` that verified nothing** (call): if `--verify-key` (or
  `JWTD_VERIFY_KEY`) is set and no JWS layer was reached, that is a hard error
  before any output. This covers a JWE with JSON plaintext, and a JWE with no
  `--key` to decrypt it. Error: `--verify-key was given but no JWS signature was
  reached` plus, when the token is a JWE without `--key`, `(pass --key to
  decrypt the JWE first)`.
- **`--key` unused when `--verify-key` is set on a plain JWT** (call): this is
  silently fine. A global `JWTD_KEY` must not break JWT decoding.
- `printKeyInterpretation` narrates the verification key as well, naming
  `--verify-key` or `JWTD_VERIFY_KEY` as the origin.
- With only `--key`, the both-RSA false `INVALID` stays as it is today. The
  docs point to `--verify-key` as the fix. **(call: changing fallback
  behaviour would break the single-key case that works today.)**

### Claims

- The target is the innermost layer's claims: a JWS's `p.claims`, or a JWE
  plaintext that `decodeJSON` reads into a non-nil JSON object.
- When the target cannot be reached and checks were requested, the verdict is
  `Claims: INVALID`, and the reason is one of these:
  - `the JWE payload is encrypted; pass --key to decrypt it`
  - `a nested JWE could not be decrypted`
  - `the decrypted payload is not a JSON claims set`
- This replaces the "skipped for JWE" note. **This is a behaviour change**:
  `jwtd --verify-claims <jwe>` with no key used to exit 0 with a note, and now
  exits nonzero. **(call: fail closed.)**
- In the human output the claims verdict is printed last, after all the
  sections, as it is for a JWT today. Signature precedence for the returned
  sentinel is unchanged.

### `--json`

- `jweJSON` gains `nested` (`omitempty`) when the plaintext opened as a token,
  and `claimsValid` (`*bool`, `omitempty`). `decryptedPayload` is unchanged, and
  still the compact string for a nested token, so existing consumers keep
  working.
- A nested `jwtJSON` carries `signatureValid` when it was verified. It never
  carries `claimsValid`: the verdict lives on the top-level object only.

### Extraction

- `--header` prints the outermost header (unchanged).
- `--payload` prints the **innermost** payload: a nested JWS's claims, or the
  decrypted JSON or text plaintext. **(call: "payload" means claims for a
  JWT, so it does for a wrapped one too. #9 is unreleased, so nothing ships
  with the old meaning.)**
- `--claim` reads the innermost claims set, and a missing target is an error
  using the same reasons as above.
- Withholding covers every layer: any invalid signature at any depth, or
  invalid claims, means nothing goes to stdout and the verdicts go to stderr.

## Approaches

1. **Open once into layers, render three ways (chosen).** A new `layers.go`
   holds `tokenKeys` and `openToken(token, keys) (*tokenLayer, error)`. It does
   every decryption and verification, applies the key table above, and returns
   a chain of layers carrying parsed parts and verdicts. The human renderer,
   `--json`, and extraction become pure renderers over that chain. This follows
   the existing parse-once rule (`parsedJWT`). It lets fail-closed decisions
   such as "`--verify-key` verified nothing" happen before output. It also
   removes the three copies of the JWE decrypt sequence (review minor M4 on
   #9).
2. **Thread `tokenKeys` through today's recursive printers, and add a JSON
   walker and an extraction walker.** This is less churn up front, but it
   leaves three walkers that must apply the same key table, which is exactly
   the drift the #9 review flagged. Rejected.
3. **Only add `--verify-key` to `renderNested`.** This fixes the false
   `INVALID` but leaves claims, `--json`, and extraction where they are, which
   is the missing half of the feature. Rejected.

## Constraints

- **Human output for every existing case must stay byte-identical.** The
  existing `decodeAndPrint`/`decodeAndPrintJWE` tests (about 56) are the
  oracle, and those two functions remain as wrappers with today's signatures.
- Existing hard-error texts stay as they are: `signature verification: ...`,
  `loading decryption key: ...`, and `decrypting JWE: ...`.
- All code stays in package `main`; tests mirror the source files
  (`layers_test.go`).

## Left to the builder

- The exact fields of `tokenLayer` and the helper split.
- The text of the new hard error for an unusable explicit verification key on a
  nested JWS. It should be modelled on the existing
  `signature verification: error loading key: ...`.
- Updating `AGENTS.md`, `README.md`, the site, and `docs/feature-ideas.md`.
