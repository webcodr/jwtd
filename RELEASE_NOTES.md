## Security

Key material jwtd cannot parse is no longer used as a symmetric secret.

Public keys are published values, so this was forgeable: an OpenSSH public key, RFC 4716 armor, or base64 key material stored in a file could be used to sign an HS256 token that jwtd reported as `Signature: VALID`. Empty key files were worse still, since the empty secret is known to everyone. These inputs now fail with an error.

**If you pass an SSH public key, convert it first.** For RSA and ECDSA keys:

```sh
ssh-keygen -e -m PKCS8 -f <key>
```

Base64-encoded key material in a text file is now decoded the same way as an inline `--key` argument, so identical bytes mean the same key either way.

## Improvements

- Key arguments that are not an existing file now report on stderr which reading was applied, literal secret or base64-decoded, so a value meant one way is never silently used another. Key files stay silent, and the note goes to stderr so piped output is unaffected.
- The `--key` help text notes that inline key material is visible to other local users in the process list. Prefer a key file or `JWTD_KEY`.
- Release binaries are built with Go 1.26.5, which carries the current stdlib security fixes.
