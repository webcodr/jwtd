package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// allKeyAlgorithms contains all JWE key management algorithms supported by go-jose.
var allKeyAlgorithms = []jose.KeyAlgorithm{
	jose.ED25519,
	jose.RSA1_5,
	jose.RSA_OAEP,
	jose.RSA_OAEP_256,
	jose.A128KW,
	jose.A192KW,
	jose.A256KW,
	jose.DIRECT,
	jose.ECDH_ES,
	jose.ECDH_ES_A128KW,
	jose.ECDH_ES_A192KW,
	jose.ECDH_ES_A256KW,
	jose.A128GCMKW,
	jose.A192GCMKW,
	jose.A256GCMKW,
	jose.PBES2_HS256_A128KW,
	jose.PBES2_HS384_A192KW,
	jose.PBES2_HS512_A256KW,
}

// allContentEncryptions contains all JWE content encryption algorithms supported by go-jose.
var allContentEncryptions = []jose.ContentEncryption{
	jose.A128CBC_HS256,
	jose.A192CBC_HS384,
	jose.A256CBC_HS512,
	jose.A128GCM,
	jose.A192GCM,
	jose.A256GCM,
}

// isJWE returns true if the token string looks like a JWE compact serialization
// (5 dot-separated parts) rather than a JWT (3 parts).
func isJWE(token string) bool {
	return strings.Count(token, ".") == 4
}

// decodeAndPrintJWE parses a JWE token and prints its contents.
// If keyStr is provided, the token is decrypted and the plaintext payload is displayed.
// Otherwise, only the protected header and encrypted part metadata are shown.
func decodeAndPrintJWE(w io.Writer, tokenStr, keyStr string) error {
	jwe, err := jose.ParseEncrypted(tokenStr, allKeyAlgorithms, allContentEncryptions)
	if err != nil {
		return fmt.Errorf("parsing JWE: %w", err)
	}

	f := newFormatter()

	header, err := jweProtectedHeaderMap(tokenStr)
	if err != nil {
		return err
	}
	if err := printSection(w, f, "Protected Header", header); err != nil {
		return err
	}

	if keyStr == "" {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		return printEncryptedParts(w, tokenStr)
	}

	key, err := loadKey(keyStr)
	if err != nil {
		return fmt.Errorf("loading decryption key: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return fmt.Errorf("decrypting JWE: %w", err)
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return printDecryptedPayload(w, f, plaintext)
}

// jweProtectedHeaderMap decodes every field in the compact JWE protected header
// for display. go-jose remains authoritative for parsing and cryptography.
func jweProtectedHeaderMap(token string) (map[string]any, error) {
	protected, _, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("JWE has no protected header segment")
	}

	data, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return nil, fmt.Errorf("decoding JWE protected header: %w", err)
	}

	var header map[string]any
	if err := decodeJSON(data, &header); err != nil {
		return nil, fmt.Errorf("parsing JWE protected header: %w", err)
	}
	if header == nil {
		return nil, fmt.Errorf("parsing JWE protected header: expected JSON object")
	}
	return header, nil
}

// printEncryptedParts displays metadata about the encrypted JWE parts.
func printEncryptedParts(w io.Writer, tokenStr string) error {
	parts := strings.SplitN(tokenStr, ".", 5)
	if len(parts) != 5 {
		return nil
	}

	if _, err := labelColor.Fprintln(w, "Encrypted Content"); err != nil {
		return err
	}
	if _, err := dimColor.Fprintf(w, "Encrypted Key : %s\n", partSize(parts[1])); err != nil {
		return err
	}
	if _, err := dimColor.Fprintf(w, "IV            : %s\n", partSize(parts[2])); err != nil {
		return err
	}
	if _, err := dimColor.Fprintf(w, "Ciphertext    : %s\n", partSize(parts[3])); err != nil {
		return err
	}
	if _, err := dimColor.Fprintf(w, "Auth Tag      : %s\n", partSize(parts[4])); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	_, err := dimColor.Fprintln(w, "Use --key/-k to provide a decryption key")
	return err
}

// partSize describes the decoded byte length of a base64url-encoded JWE part,
// flagging parts that are not valid base64url instead of reporting 0 bytes.
func partSize(s string) string {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "invalid base64url"
	}
	return fmt.Sprintf("%d bytes", len(data))
}
