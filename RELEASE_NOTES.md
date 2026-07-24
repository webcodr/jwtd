## Breaking: symmetric secrets must be explicit

A key file must now parse as PEM, DER, JWK, or an X.509 certificate. To use a file or string as a symmetric (HMAC) secret, say so:

```sh
jwtd --key hmac:/path/to/secret.key <token>   # a file of secret bytes
jwtd --key raw:my-hmac-secret <token>          # an inline literal secret
```

**Migration.** If you were verifying HS256 with a bare secret file (`--key secret.key`), add the `hmac:` prefix (`--key hmac:secret.key`). The error message names the exact replacement. `raw:` is unchanged. Structured keys — PEM/DER/JWK/certificates, from a file or inline base64 — are unchanged.

### Why

Previously, key material jwtd could not parse was used as an HMAC secret. A public key is a published value, so this let anyone who knew a key file's bytes sign an HS256 token that verified against it. Patching the formats we found (SSH keys, RFC 4716, base64 files) did not close the class — any unrecognized format was a latent repeat. Requiring symmetric secrets to be explicit closes it for every format, including ones nobody has enumerated.

SSH public keys are still detected and reported with a conversion hint (`ssh-keygen -e -m PKCS8 -f <key>` for RSA and ECDSA). Empty key material is rejected.
