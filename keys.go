package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// loadKey resolves a key argument. Symmetric secrets must be requested
// explicitly, with "raw:<secret>" for a literal or "hmac:<file>" for a file of
// secret bytes. Everything else must parse as structured key material: JWK/JWK
// Set, PEM, DER, or an X.509 certificate, read from a file path or from inline
// base64.
//
// The explicit prefixes are the security boundary. Inferring "symmetric
// secret" from "did not parse" made every unsupported key format forgeable: a
// public key is a published value, so anyone who knew its bytes could sign an
// HS256 token that verified against it. Unparseable material is now an error,
// so the failure direction is always closed no matter what format shows up.
func loadKey(keyStr string) (any, error) {
	// Explicit literal secret; no file or base64 detection.
	if secret, ok := strings.CutPrefix(keyStr, "raw:"); ok {
		return symmetricKey([]byte(secret))
	}

	// Explicit symmetric key file. Keeps secret bytes out of argv, where
	// other local users can read them, and covers binary secrets that cannot
	// be passed as text.
	if path, ok := strings.CutPrefix(keyStr, "hmac:"); ok {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading symmetric key file %q: %w", path, err)
		}
		// Text secrets get the trailing newline editors typically add
		// trimmed; binary key material is used byte-exact.
		if isTextKey(data) {
			data = bytes.TrimRight(data, "\r\n")
		}
		return symmetricKey(data)
	}

	// Try as file path first.
	if data, err := os.ReadFile(keyStr); err == nil {
		if len(data) == 0 {
			return nil, fmt.Errorf("key file %q is empty", keyStr)
		}
		if key, err := parseKeyData(data); err == nil {
			return key, nil
		}
		// A text file may hold base64-encoded key material just as an inline
		// key argument can, so the same bytes mean the same key either way.
		if isTextKey(data) {
			if decoded, ok := decodeBase64Key(bytes.TrimRight(data, "\r\n")); ok {
				if key, err := parseKeyData(decoded); err == nil {
					return key, nil
				}
			}
		}
		return nil, unsupportedKeyError(data, fmt.Sprintf("key file %q", keyStr), "hmac:"+keyStr)
	}

	// Try as base64-encoded key.
	decoded, ok := decodeBase64Key([]byte(keyStr))
	if !ok {
		return nil, fmt.Errorf("key is neither a valid file path nor base64-encoded data")
	}
	key, err := parseKeyData(decoded)
	if err != nil {
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
		return nil, fmt.Errorf("key is empty")
	}
	return data, nil
}

// keySource describes how loadKey will read a key argument. The CLI reports
// it when the reading is not the obvious one, so a key that is silently taken
// as something other than what the user meant becomes visible.
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
	// keySourceUnusable is neither, and loadKey will reject it.
	keySourceUnusable
)

// classifyKeyArg reports how loadKey will interpret keyStr, mirroring its
// precedence: the explicit prefixes, then an existing file, then base64.
// Existence is checked with Stat rather than a read, so classifying never
// consumes the key source.
func classifyKeyArg(keyStr string) keySource {
	if strings.HasPrefix(keyStr, "raw:") {
		return keySourceLiteral
	}
	if strings.HasPrefix(keyStr, "hmac:") {
		return keySourceSecretFile
	}
	if info, err := os.Stat(keyStr); err == nil && !info.IsDir() {
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
// key material. Supports both private and public keys.
func parseKeyData(data []byte) (any, error) {
	// Try JWK / JWK Set (JSON-based formats).
	if key, err := parseJWK(data); err == nil {
		return key, nil
	}

	// Try PEM decoding.
	block, _ := pem.Decode(data)
	if block != nil {
		return parseDERKey(block.Bytes, block.Type)
	}

	// Try raw DER parsing (private keys).
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	// Try raw DER parsing (public keys).
	if key, err := x509.ParsePKIXPublicKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return key, nil
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert.PublicKey, nil
	}

	if isSSHPublicKey(data) {
		// ssh-keygen's PKCS8 export covers RSA and ECDSA keys only, so the
		// hint does not promise it for Ed25519.
		return nil, fmt.Errorf("SSH public key format is not supported; supply the key as PEM, DER, or JWK (for RSA and ECDSA keys: ssh-keygen -e -m PKCS8 -f <key>)")
	}

	return nil, fmt.Errorf("unrecognized key format")
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
		// Try all parsers (private keys first, then public).
		if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKIXPublicKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
			return key, nil
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			return cert.PublicKey, nil
		}
		return nil, fmt.Errorf("unable to parse key from PEM block type %q", blockType)
	}
}

// parseJWK attempts to parse data as a JWK (JSON Web Key) or JWK Set.
// For a JWK Set, the first key is returned.
func parseJWK(data []byte) (any, error) {
	// Try single JWK.
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err == nil && jwk.Key != nil {
		return jwk.Key, nil
	}

	// Try JWK Set ({"keys": [...]}).
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err == nil && len(jwks.Keys) > 0 {
		return jwks.Keys[0].Key, nil
	}

	return nil, fmt.Errorf("not a valid JWK or JWK Set")
}
