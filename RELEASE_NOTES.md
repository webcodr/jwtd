## Faster decoding, no behavior change

This release is internal work. Nothing about the output changes, and on an ordinary token nothing about the speed is perceptible either: a `jwtd <token>` run takes about 0.9 ms, and roughly half of that is Go process startup that no amount of optimization touches.

What did change is the redundant work behind it. A run with `--key` decoded the token's header and claims three times over: once inside the JWT library's unverified parse (with a decoder that loses number precision, so every result was thrown away), once again strictly, and a third time when the signature check re-parsed the whole token just to reach the cryptography. Verification now works from the token already in hand.

On a 36 KB token with 500 claims, where it is actually measurable:

| | before | after |
|---|---|---|
| parse | 346 µs | 170 µs |
| signature verification | 196 µs | 19 µs |
| full `--key` decode | 1.15 ms | 0.74 ms |
| escaping a clean text payload | 287 MB/s | 4,053 MB/s |

The last row matters when you decrypt a large JWE whose payload is not JSON — that text is now returned as a single copy instead of being rebuilt character by character.

## One visible change

Four errors about malformed JSON inside a token now name the segment that failed. A payload that is not a JSON object reports `parsing JWT claims: json: cannot unmarshal array into Go value of type jwt.MapClaims` rather than the older, more roundabout `parsing JWT: token is malformed: could not JSON decode claim: ...`. The same tokens are accepted and rejected as before, with the same exit codes.

## On the algorithm allowlist

jwtd restricts the accepted JWS algorithms to those the supplied key type can carry, so an HS256 token cannot be verified against an RSA public key. That restriction previously came from the JWT library's parser; verifying from an already-parsed token makes it jwtd's own check, and it is now written out explicitly and covered by tests across RSA, ECDSA, Ed25519, and HMAC keys.
