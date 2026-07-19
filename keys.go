package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// loadKey reads a decryption key from either a file path or an inline base64 string.
// It auto-detects the format: if the value looks like a file path (exists on disk),
// it reads and parses the file; otherwise it treats it as a base64-encoded key.
// A "raw:" prefix bypasses detection and uses the remainder as a literal
// symmetric secret.
func loadKey(keyStr string) (any, error) {
	// Explicit literal secret; no file or base64 detection.
	if secret, ok := strings.CutPrefix(keyStr, "raw:"); ok {
		return []byte(secret), nil
	}

	// Try as file path first.
	if data, err := os.ReadFile(keyStr); err == nil {
		key, parseErr := parseKeyData(data)
		if parseErr == nil {
			return key, nil
		}
		if isStructuredKeyData(data) {
			return nil, fmt.Errorf("parsing key file %q: %w", keyStr, parseErr)
		}
		// File exists but doesn't parse as PEM/DER; use raw bytes as a
		// symmetric key. Text secrets get the trailing newline editors
		// typically add trimmed; binary key material is used as-is.
		if isTextKey(data) {
			return bytes.TrimRight(data, "\r\n"), nil
		}
		return data, nil
	}

	// Try as base64-encoded key.
	decoded, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		// Try base64url encoding.
		decoded, err = base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("key is neither a valid file path nor base64-encoded data")
		}
	}

	// Try parsing decoded bytes as PEM/DER key.
	key, parseErr := parseKeyData(decoded)
	if parseErr == nil {
		return key, nil
	}
	if isStructuredKeyData(decoded) {
		return nil, fmt.Errorf("parsing base64-encoded key: %w", parseErr)
	}

	// Use raw bytes as a symmetric key.
	return decoded, nil
}

func isStructuredKeyData(data []byte) bool {
	data = bytes.TrimSpace(data)
	if hasPEMMarker(data) {
		return true
	}
	jsonData := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(jsonData) > 0 && jsonData[0] == '{' {
		objectBody := bytes.TrimLeft(jsonData[1:], " \t\r\n")
		if json.Valid(jsonData) || len(objectBody) > 0 && objectBody[0] == '"' || hasJWKMember(jsonData) {
			return true
		}
	}

	var value asn1.RawValue
	rest, err := asn1.Unmarshal(data, &value)
	return err == nil && len(rest) == 0 && value.Tag == asn1.TagSequence && value.IsCompound && isCompleteDER(value.Bytes)
}

func hasPEMMarker(data []byte) bool {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		line = bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf})
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("-----BEGIN ")) {
			return true
		}
	}
	return false
}

func hasJWKMember(data []byte) bool {
	const (
		expectsMember = iota
		expectsValue
		afterValue
	)
	type container struct {
		kind  byte
		state int
	}

	var stack []container
	for i := 0; i < len(data); {
		switch data[i] {
		case ' ', '\t', '\r', '\n':
			i++
		case '"':
			end, ok := jsonStringEnd(data, i)
			if !ok {
				return false
			}

			if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
				state := stack[len(stack)-1].state
				next := end
				for next < len(data) && (data[next] == ' ' || data[next] == '\t' || data[next] == '\r' || data[next] == '\n') {
					next++
				}
				isRootMember := len(stack) == 1 && state == expectsMember
				isMissingCommaMember := len(stack) == 1 && state == afterValue && (next == len(data) || data[next] == ':')
				if isRootMember || isMissingCommaMember {
					var name string
					if err := json.Unmarshal(data[i:end], &name); err == nil && (name == "kty" || name == "keys") {
						return true
					}
				}
				stack[len(stack)-1].state = afterValue
			}
			i = end
		case '{', '[':
			if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
				stack[len(stack)-1].state = afterValue
			}
			stack = append(stack, container{kind: data[i], state: expectsMember})
			i++
		case '}', ']':
			if len(stack) > 0 && ((data[i] == '}' && stack[len(stack)-1].kind == '{') || (data[i] == ']' && stack[len(stack)-1].kind == '[')) {
				stack = stack[:len(stack)-1]
			}
			i++
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
				stack[len(stack)-1].state = expectsMember
			}
			i++
		case ':':
			if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
				stack[len(stack)-1].state = expectsValue
			}
			i++
		default:
			if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
				stack[len(stack)-1].state = afterValue
			}
			i++
		}
	}
	return false
}

func jsonStringEnd(data []byte, start int) (int, bool) {
	for i := start + 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
			if i >= len(data) {
				return 0, false
			}
		case '"':
			return i + 1, true
		}
	}
	return 0, false
}

func isCompleteDER(data []byte) bool {
	for len(data) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return false
		}
		if value.IsCompound && !isCompleteDER(value.Bytes) {
			return false
		}
		data = rest
	}
	return true
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
