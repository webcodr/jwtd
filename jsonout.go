package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
)

// jwtJSON is the machine-readable form of a decoded JWT. Numbers are preserved
// exactly via json.Number, and timestamps are left as their raw claim values
// so consumers can do their own date math. signatureValid is present only when
// a key was supplied.
type jwtJSON struct {
	Header         map[string]any `json:"header"`
	Payload        map[string]any `json:"payload"`
	Signature      string         `json:"signature"`
	SignatureValid *bool          `json:"signatureValid,omitempty"`
	ClaimsValid    *bool          `json:"claimsValid,omitempty"`
}

// jweJSON is the machine-readable form of a JWE. Without a key it reports the
// protected header and the byte sizes of the encrypted parts; with a key it
// reports the decrypted payload instead.
//
// DecryptedPayload is a pointer so presence and content stay separate: a
// payload that decodes to the JSON literal null is a nil interface, which
// omitempty on a plain any field would drop — leaving output with neither
// encrypted nor decryptedPayload. A non-nil pointer is always emitted, so a
// null plaintext renders as "decryptedPayload": null and the field is absent
// only when no key was given.
type jweJSON struct {
	ProtectedHeader  map[string]any `json:"protectedHeader"`
	Encrypted        *jweEncrypted  `json:"encrypted,omitempty"`
	DecryptedPayload *any           `json:"decryptedPayload,omitempty"`
}

type jweEncrypted struct {
	EncryptedKeyBytes int `json:"encryptedKeyBytes"`
	IVBytes           int `json:"ivBytes"`
	CiphertextBytes   int `json:"ciphertextBytes"`
	AuthTagBytes      int `json:"authTagBytes"`
}

// decodeJWTJSON writes a JWT as a single JSON object. When a key is supplied the
// signature is verified and reported in signatureValid; when claim validation is
// requested the verdict is reported in claimsValid. A failing check still emits
// the JSON and then returns a sentinel (errInvalidSignature or errInvalidClaims)
// so the exit code matches the human path; the signature verdict takes
// precedence when both fail, though either way the exit is nonzero.
func decodeJWTJSON(w io.Writer, tokenStr, keyStr string, checks claimChecks) error {
	p, err := parseUnverifiedJWT(tokenStr)
	if err != nil {
		return err
	}

	out := jwtJSON{
		Header:    p.header,
		Payload:   map[string]any(p.claims),
		Signature: p.parts[2],
	}

	var invalid error
	if keyStr != "" {
		valid, reason, verr := verifyJWTSignature(p, keyStr)
		if verr != nil {
			return fmt.Errorf("signature verification: %w", verr)
		}
		out.SignatureValid = &valid
		if !valid {
			invalid = fmt.Errorf("%w: %v", errInvalidSignature, reason)
		}
	}

	if checks.requested() {
		valid, reason := validateClaimsSet(p.claims, checks)
		out.ClaimsValid = &valid
		if !valid && invalid == nil {
			invalid = fmt.Errorf("%w: %s", errInvalidClaims, claimReason(reason))
		}
	}

	if err := writeJSON(w, out); err != nil {
		return err
	}
	return invalid
}

// decodeJWEJSON writes a JWE as a single JSON object, decrypting the payload
// when a key is supplied.
func decodeJWEJSON(w io.Writer, tokenStr, keyStr string) error {
	jwe, err := jose.ParseEncrypted(tokenStr, allKeyAlgorithms, allContentEncryptions)
	if err != nil {
		return fmt.Errorf("parsing JWE: %w", err)
	}

	header, err := jweProtectedHeaderMap(tokenStr)
	if err != nil {
		return err
	}
	out := jweJSON{ProtectedHeader: header}

	if keyStr == "" {
		if parts, ok := jweEncryptedParts(tokenStr); ok {
			out.Encrypted = &jweEncrypted{
				EncryptedKeyBytes: base64URLLen(parts[1]),
				IVBytes:           base64URLLen(parts[2]),
				CiphertextBytes:   base64URLLen(parts[3]),
				AuthTagBytes:      base64URLLen(parts[4]),
			}
		}
		return writeJSON(w, out)
	}

	kid, err := headerKID(header)
	if err != nil {
		return err
	}
	key, err := loadKeyForKID(keyStr, kid)
	if err != nil {
		return fmt.Errorf("loading decryption key: %w", err)
	}
	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return fmt.Errorf("decrypting JWE: %w", err)
	}

	payload := jsonPayloadValue(plaintext)
	out.DecryptedPayload = &payload
	return writeJSON(w, out)
}

// jsonPayloadValue decodes a decrypted payload as JSON when possible so it nests
// as structured data, preserving exact numbers; otherwise it is returned as a
// string. Nested tokens therefore appear as their compact string form.
func jsonPayloadValue(plaintext []byte) any {
	var v any
	if err := decodeJSON(plaintext, &v); err == nil {
		return v
	}
	return string(plaintext)
}

// base64URLLen returns the decoded byte length of a base64url part, or -1 when
// the part is not valid base64url.
//
// The length is derived from the encoded text rather than by decoding it: the
// ciphertext of a JWE is unbounded, and this only ever reports its size. The
// accepted input matches base64.RawURLEncoding.DecodeString exactly — the
// unpadded base64url alphabet, with CR and LF skipped the way the standard
// decoder skips them, and a remainder of one character rejected as corrupt.
// Trailing bits are not checked, because RawURLEncoding is not strict either.
// TestBase64URLLenMatchesDecode holds the two to the same answers.
func base64URLLen(s string) int {
	n := 0
	for i := range len(s) {
		switch c := s[i]; {
		case c == '\r' || c == '\n':
			// Skipped by encoding/base64, so skipped here too.
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
			n++
		default:
			return -1
		}
	}
	if n%4 == 1 {
		return -1
	}
	return base64.RawURLEncoding.DecodedLen(n)
}

// writeJSON encodes v as indented JSON. json.Number values are written as their
// exact numeric literal, and encoding/json escapes control characters
// (including ESC), so the output is safe to print and to pipe into other tools.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	return nil
}
