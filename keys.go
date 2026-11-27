package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// errKIDNotFound marks a definitive failure: the material parsed as a JWK Set,
// but no entry matched the token's kid. It must not degrade into a generic
// "unsupported format" error or a base64/HMAC fallback attempt, so loadKeyForKID
// surfaces it as-is.
var errKIDNotFound = errors.New("kid not found in JWK Set")

// errEmptyKey marks empty symmetric key material. Like errKIDNotFound it is a
// definitive answer: the material parsed, it is simply unusable, so it must not
// degrade into a base64 retry or an "unsupported format" message that would
// point the user at a workaround for a key that is deliberately refused.
var errEmptyKey = errors.New("key is empty")

// finalKeyError reports whether a parse failure is a definitive verdict on the
// key material rather than a reason to try the next reading. Both sentinels
// mean the bytes were understood, so reinterpreting them can only pick a key
// the user did not mean.
func finalKeyError(err error) bool {
	return errors.Is(err, errKIDNotFound) || errors.Is(err, errEmptyKey)
}

// keySelector identifies which entry of a JWK Set matches the token being
// verified or decrypted. kid is the token's "kid" header ("" when absent), use
// is the expected JWK "use" ("sig" for JWS, "enc" for JWE), and alg is the
// token's "alg" header. Only JWK Set selection consults this; every other key
// form ignores it.
type keySelector struct {
	kid string
	use string
	alg string
}

// loadKeyForToken resolves a key argument, selecting the entry that matches
// sel when the material is a JWK Set.
//
// Symmetric secrets must be requested explicitly, with "raw:<secret>" for a
// literal or "hmac:<file>" for a file of secret bytes. Everything else must
// parse as structured key material: JWK/JWK Set, PEM, DER, or an X.509
// certificate, read from a file path or from inline base64.
//
// The explicit prefixes are the security boundary. Inferring "symmetric
// secret" from "did not parse" made every unsupported key format forgeable: a
// public key is a published value, so anyone who knew its bytes could sign an
// HS256 token that verified against it. Unparseable material is now an error,
// so the failure direction is always closed no matter what format shows up.
func loadKeyForToken(keyStr string, sel keySelector) (any, error) {
	// The precedence lives in classifyKeyArg and is applied here, so the
	// reading the CLI reports is by construction the reading that happens.
	switch classifyKeyArg(keyStr) {
	case keySourceLiteral:
		return symmetricKey([]byte(strings.TrimPrefix(keyStr, "raw:")))
	case keySourceSecretFile:
		return loadSymmetricKeyFile(strings.TrimPrefix(keyStr, "hmac:"))
	case keySourceFile:
		return loadKeyFile(keyStr, sel)
	case keySourceBase64:
		return loadInlineKey(keyStr, sel)
	case keySourceDirectory:
		return nil, fmt.Errorf("key path %q is a directory, not a key file", keyStr)
	default:
		return nil, fmt.Errorf("key is neither a valid file path nor base64-encoded data")
	}
}

// loadSymmetricKeyFile reads an explicit hmac: secret file. Keeping the secret
// bytes in a file rather than argv keeps them out of the process list, and
// covers binary secrets that cannot be passed as text.
func loadSymmetricKeyFile(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading symmetric key file %q: %w", path, err)
	}
	// Text secrets get the trailing newline editors typically add trimmed;
	// binary key material is used byte-exact.
	if isTextKey(data) {
		data = bytes.TrimRight(data, "\r\n")
	}
	return symmetricKey(data)
}

// loadKeyFile parses structured key material from a file, falling back to
// base64-decoding its contents so a text file holding encoded key material
// means the same key as that material passed inline.
func loadKeyFile(path string, sel keySelector) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("key file %q is empty", path)
	}

	key, err := parseKeyData(data, sel)
	if err == nil {
		return key, nil
	}
	// The file parsed as JWK material; a kid miss or an empty secret is final,
	// not a reason to try base64 or fall through to the unsupported-format
	// error.
	if finalKeyError(err) {
		return nil, err
	}

	if isTextKey(data) {
		if decoded, ok := decodeBase64Key(bytes.TrimRight(data, "\r\n")); ok {
			key, err := parseKeyData(decoded, sel)
			if err == nil {
				return key, nil
			}
			if finalKeyError(err) {
				return nil, err
			}
		}
	}
	return nil, unsupportedKeyError(data, fmt.Sprintf("key file %q", path), "hmac:"+path)
}

// loadInlineKey parses base64/base64url key material given directly on the
// command line or in JWTD_KEY.
func loadInlineKey(keyStr string, sel keySelector) (any, error) {
	// classifyKeyArg only returns keySourceBase64 after decoding this same
	// argument, so the decode cannot fail here.
	decoded, _ := decodeBase64Key([]byte(keyStr))
	key, err := parseKeyData(decoded, sel)
	if err != nil {
		if finalKeyError(err) {
			return nil, err
		}
		return nil, unsupportedKeyError(decoded, "inline key", "raw:<secret> or hmac:<file>")
	}
	return key, nil
}

// unsupportedKeyError explains why key material was rejected and names the
// explicit form to use for a symmetric secret. SSH keys get their own message
// because converting them, not re-flagging them, is the fix.
func unsupportedKeyError(data []byte, subject, symmetricForm string) error {
	if isSSHPublicKey(data) {
		// ssh-keygen's PKCS8 export covers RSA and ECDSA keys only, so the
		// hint does not promise it for Ed25519.
		return fmt.Errorf("%s is an SSH public key, which is not supported; supply it as PEM, DER, or JWK (for RSA and ECDSA keys: ssh-keygen -e -m PKCS8 -f <key>)", subject)
	}
	return fmt.Errorf("%s is not PEM, DER, JWK, or an X.509 certificate; if it holds a symmetric secret, pass it as %s", subject, symmetricForm)
}

// symmetricKey wraps opaque bytes used as a symmetric secret. Empty key
// material is rejected: it is never legitimate, and every attacker knows the
// empty secret, so accepting it would report forged HMAC tokens as valid.
func symmetricKey(data []byte) (any, error) {
	if len(data) == 0 {
		return nil, errEmptyKey
	}
	return data, nil
}

// keySource describes how a key argument is read. It drives loadKeyForKID's
// dispatch, and the CLI reports it when the reading is not the obvious one, so
// a key silently taken as something other than what the user meant becomes
// visible.
type keySource int

const (
	// keySourceFile is an existing file, the unsurprising case.
	keySourceFile keySource = iota
	// keySourceLiteral is a raw: prefixed literal secret.
	keySourceLiteral
	// keySourceSecretFile is an hmac: prefixed symmetric key file.
	keySourceSecretFile
	// keySourceBase64 is inline base64/base64url key material.
	keySourceBase64
	// keySourceDirectory is an existing path that is a directory. It can never
	// hold key material, and must not fall through to a base64 reading of its
	// own path text, which would report a nonsense interpretation of a path
	// the user clearly meant as a key file.
	keySourceDirectory
	// keySourceUnusable is none of these, and loadKeyForKID will reject it.
	keySourceUnusable
)

// classifyKeyArg decides how a key argument is read: the explicit prefixes
// first, then an existing file, then base64. loadKeyForKID dispatches on this
// and the CLI narrates it, so the reported reading is the reading that happens
// rather than a second copy of the ladder that could drift from it. Existence
// is checked with Stat rather than a read, so classifying never consumes the
// key source.
func classifyKeyArg(keyStr string) keySource {
	if strings.HasPrefix(keyStr, "raw:") {
		return keySourceLiteral
	}
	if strings.HasPrefix(keyStr, "hmac:") {
		return keySourceSecretFile
	}
	if info, err := os.Stat(keyStr); err == nil {
		if info.IsDir() {
			return keySourceDirectory
		}
		return keySourceFile
	}
	if _, ok := decodeBase64Key([]byte(keyStr)); ok {
		return keySourceBase64
	}
	return keySourceUnusable
}

// decodeBase64Key decodes base64 or base64url key material, tolerating the
// line wrapping and surrounding whitespace that encoded keys pick up when they
// are stored in files or pasted between tools.
func decodeBase64Key(data []byte) ([]byte, bool) {
	compact := string(bytes.Join(bytes.Fields(data), nil))
	if compact == "" {
		return nil, false
	}
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return decoded, true
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(compact); err == nil {
		return decoded, true
	}
	return nil, false
}

// isSSHPublicKey reports whether data holds an SSH public key: either the
// one-line OpenSSH format ("ssh-ed25519 AAAA... comment", as found in
// id_*.pub and authorized_keys) or the RFC 4716 armor, whose BEGIN marker
// uses four dashes and so is not a PEM marker.
func isSSHPublicKey(data []byte) bool {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("---- BEGIN ")) {
			return true
		}

		// authorized_keys entries may carry options before the key type, so
		// every adjacent field pair is considered.
		fields := bytes.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if isSSHKeyType(fields[i]) && sshBlobHasType(fields[i+1], fields[i]) {
				return true
			}
		}
	}
	return false
}

func isSSHKeyType(field []byte) bool {
	name := string(field)
	switch name {
	case "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448":
		return true
	}
	return strings.HasPrefix(name, "ecdsa-sha2-") ||
		strings.HasPrefix(name, "sk-ssh-") ||
		strings.HasPrefix(name, "sk-ecdsa-") ||
		strings.HasSuffix(name, "-cert-v01@openssh.com")
}

// sshBlobHasType reports whether a base64 SSH key blob opens with the given
// key type. The SSH wire format prefixes the type with its big-endian length,
// so this confirms the field pair really is a key rather than a secret that
// happens to start with a key-type word.
func sshBlobHasType(blob, keyType []byte) bool {
	decoded, err := base64.StdEncoding.DecodeString(string(blob))
	if err != nil || len(decoded) < 4 {
		return false
	}
	length := binary.BigEndian.Uint32(decoded[:4])
	if length > uint32(len(decoded)-4) {
		return false
	}
	return bytes.Equal(decoded[4:4+length], keyType)
}

// isTextKey reports whether key file content looks like a text secret
// (printable ASCII) rather than binary key material.
func isTextKey(data []byte) bool {
	for _, b := range data {
		if (b < 0x20 || b > 0x7e) && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// parseKeyData attempts to parse key data as JWK, JWK Set, PEM, or DER encoded
// key material. Supports both private and public keys. For a JWK Set, sel
// selects the matching key (kid first, then use/alg disambiguation).
func parseKeyData(data []byte, sel keySelector) (any, error) {
	// Try JWK / JWK Set (JSON-based formats).
	if key, err := parseJWK(data, sel); err == nil {
		return key, nil
	} else if finalKeyError(err) {
		// The data is valid JWK material: the kid simply did not match, or the
		// selected entry holds an empty secret. Either is a final answer, not
		// a reason to reinterpret the bytes as PEM/DER.
		return nil, err
	}

	// Try PEM decoding.
	block, _ := pem.Decode(data)
	if block != nil {
		return parseDERKey(block.Bytes, block.Type)
	}

	// Try raw DER parsing.
	if key, ok := parseAnyDER(data); ok {
		return key, nil
	}

	// The rejection is phrased by unsupportedKeyError, which is the single
	// place that knows the user-facing subject and the symmetric-form hint.
	return nil, fmt.Errorf("unrecognized key format")
}

// parseAnyDER tries every supported DER encoding, private keys first and then
// public ones, reporting whether any of them accepted the bytes. It backs both
// the raw-DER path and the fallback for an unrecognized PEM block type, so the
// set of understood encodings is defined once.
func parseAnyDER(der []byte) (any, bool) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, true
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, true
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, true
	}
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		return key, true
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return key, true
	}
	if cert, err := x509.ParseCertificate(der); err == nil {
		return cert.PublicKey, true
	}
	return nil, false
}

// parseDERKey parses DER-encoded key bytes based on the PEM block type.
// Supports both private and public key PEM block types.
func parseDERKey(der []byte, blockType string) (any, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(der)
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(der)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(der)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	default:
		if key, ok := parseAnyDER(der); ok {
			return key, nil
		}
		return nil, fmt.Errorf("unable to parse key from PEM block type %q", blockType)
	}
}

// parseJWK attempts to parse data as a JWK (JSON Web Key) or JWK Set. For a JWK
// Set, sel.kid selects the entries whose "kid" matches the token (a kid that
// matches nothing is an error rather than a silent fallback), and sel.use /
// sel.alg disambiguate when multiple entries remain.
func parseJWK(data []byte, sel keySelector) (any, error) {
	// Try single JWK.
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err == nil && jwk.Key != nil {
		return jwkKey(jwk)
	}

	// Try JWK Set ({"keys": [...]}).
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err == nil && len(jwks.Keys) > 0 {
		candidates := jwks.Keys
		if sel.kid != "" {
			candidates = jwks.Key(sel.kid)
			if len(candidates) == 0 {
				return nil, fmt.Errorf("%w (kid %q)", errKIDNotFound, sel.kid)
			}
		}
		return jwkKey(selectJWK(candidates, sel))
	}

	return nil, fmt.Errorf("not a valid JWK or JWK Set")
}

// selectJWK picks the best-matching entry from candidates (already filtered by
// kid when one was specified) by narrowing on use ("sig" / "enc") and then on
// the token's alg.
func selectJWK(candidates []jose.JSONWebKey, sel keySelector) jose.JSONWebKey {
	candidates = narrowJWKs(candidates, sel.use, func(k jose.JSONWebKey) string { return k.Use })
	candidates = narrowJWKs(candidates, sel.alg, func(k jose.JSONWebKey) string { return k.Algorithm })
	return candidates[0]
}

// narrowJWKs filters keys by one optional metadata attribute (such as use or
// alg) while preserving a deterministic fallback when only one key remains or
// no entry matches. Exact matches win; otherwise entries that omit the
// attribute are preferred over entries that explicitly carry a different one;
// otherwise the input slice is returned unchanged.
func narrowJWKs(keys []jose.JSONWebKey, want string, field func(jose.JSONWebKey) string) []jose.JSONWebKey {
	if want == "" || len(keys) <= 1 {
		return keys
	}
	var exact, compatible []jose.JSONWebKey
	for _, k := range keys {
		switch field(k) {
		case want:
			exact = append(exact, k)
		case "":
			compatible = append(compatible, k)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	if len(compatible) > 0 {
		return compatible
	}
	return keys
}

// jwkKey unwraps a parsed JWK into the key it holds. An "oct" JWK carries a
// symmetric secret, which go-jose hands back as a []byte, so it goes through
// symmetricKey like every other symmetric form: {"kty":"oct","k":""} otherwise
// yields an empty HMAC key, and the empty secret is known to everyone, so an
// HS256 token forged with it would verify. Every JWK path — single key,
// first-of-set, and the kid-selected entry — routes through here, so none of
// them can skip that gate.
func jwkKey(jwk jose.JSONWebKey) (any, error) {
	if secret, ok := jwk.Key.([]byte); ok {
		key, err := symmetricKey(secret)
		if err != nil {
			return nil, fmt.Errorf("oct JWK (kid %q): %w", jwk.KeyID, err)
		}
		return key, nil
	}
	return jwk.Key, nil
}
