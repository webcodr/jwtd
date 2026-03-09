package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hokaccha/go-prettyjson"
	"github.com/spf13/cobra"
)

var timestampKeyNames = []string{"iat", "exp", "nbf"}

// version is set at build time via -ldflags.
var version = "dev"

// Color definitions used for labels and signature output.
var (
	labelColor = color.New(color.FgCyan, color.Bold)
	dimColor   = color.New(color.Faint)
)

// newFormatter creates a prettyjson formatter matching the project color scheme.
func newFormatter() *prettyjson.Formatter {
	f := prettyjson.NewFormatter()
	f.KeyColor = color.New(color.FgBlue, color.Bold)
	f.StringColor = color.New(color.FgGreen)
	f.NumberColor = color.New(color.FgYellow)
	f.BoolColor = color.New(color.FgMagenta)
	f.NullColor = color.New(color.FgRed)
	f.Indent = 2
	return f
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "jwtd [token]",
		Short:   "Decode and pretty-print JSON Web Tokens",
		Long:    "jwtd decodes JWTs and JWEs and displays their contents with syntax-highlighted JSON output.",
		Args:    cobra.MaximumNArgs(1),
		Version: version,
		RunE:    run,
	}

	rootCmd.Flags().StringP("key", "k", "", "key for JWE decryption or JWS signature verification (file path, base64, or JWK)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	token, err := readToken(args)
	if err != nil {
		return err
	}

	keyStr, _ := cmd.Flags().GetString("key")
	if keyStr == "" {
		keyStr = os.Getenv("JWTD_KEY")
	}

	w := cmd.OutOrStdout()

	if isJWE(token) {
		return decodeAndPrintJWE(w, token, keyStr)
	}
	return decodeAndPrint(w, token, keyStr)
}

// readToken resolves the JWT string from arguments, stdin pipe, or interactive prompt.
func readToken(args []string) (string, error) {
	if len(args) > 0 {
		return strings.TrimSpace(args[0]), nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	return readInteractive()
}

// readInteractive prompts the user for a token using readline.
func readInteractive() (string, error) {
	rl, err := readline.New("Enter JWT/JWE: ")
	if err != nil {
		return "", fmt.Errorf("initializing readline: %w", err)
	}
	defer rl.Close()

	line, err := rl.Readline()
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}

	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("no token provided")
	}
	return token, nil
}

// isJWE returns true if the token string looks like a JWE compact serialization
// (5 dot-separated parts) rather than a JWT (3 parts).
func isJWE(token string) bool {
	return strings.Count(token, ".") == 4
}

// decodeAndPrint parses the JWT and prints header, payload, and signature.
// If keyStr is provided, the signature is verified against the given key.
func decodeAndPrint(w io.Writer, tokenStr, keyStr string) error {
	parser := jwt.NewParser()
	token, parts, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("unexpected claims type")
	}

	f := newFormatter()

	if err := printSection(w, f, "Header", token.Header); err != nil {
		return err
	}
	fmt.Fprintln(w)
	formatTimestamps(claims)
	if err := printSection(w, f, "Payload", claims); err != nil {
		return err
	}
	fmt.Fprintln(w)
	printSignature(w, parts[2])

	if keyStr != "" {
		fmt.Fprintln(w)
		verifySignature(w, tokenStr, keyStr)
	}

	return nil
}

// verifySignature verifies a JWT signature using the provided key and prints the result.
func verifySignature(w io.Writer, tokenStr, keyStr string) {
	key, err := loadKey(keyStr)
	if err != nil {
		dimColor.Fprintf(w, "Signature verification: error loading key: %v\n", err)
		return
	}

	// Extract the public key from private keys for verification.
	key = publicKeyForVerification(key)

	parser := jwt.NewParser()
	_, err = parser.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return key, nil
	})

	if err != nil {
		color.New(color.FgRed, color.Bold).Fprintln(w, "Signature: INVALID")
		dimColor.Fprintf(w, "  %v\n", err)
	} else {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "Signature: VALID")
	}
}

// publicKeyForVerification extracts the public key from asymmetric private keys.
// Symmetric keys ([]byte) and public keys are returned as-is.
func publicKeyForVerification(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return key
	}
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

	header := jweHeaderMap(jwe)
	if err := printSection(w, f, "Protected Header", header); err != nil {
		return err
	}

	if keyStr == "" {
		fmt.Fprintln(w)
		printEncryptedParts(w, tokenStr)
		return nil
	}

	key, err := loadKey(keyStr)
	if err != nil {
		return fmt.Errorf("loading decryption key: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return fmt.Errorf("decrypting JWE: %w", err)
	}

	fmt.Fprintln(w)
	return printDecryptedPayload(w, f, plaintext)
}

// jweHeaderMap extracts the protected header from a JWE object as a map.
func jweHeaderMap(jwe *jose.JSONWebEncryption) map[string]any {
	h := jwe.Header
	result := map[string]any{}

	if h.Algorithm != "" {
		result["alg"] = h.Algorithm
	}
	if h.KeyID != "" {
		result["kid"] = h.KeyID
	}
	if h.JSONWebKey != nil {
		result["jwk"] = h.JSONWebKey
	}

	for k, v := range h.ExtraHeaders {
		result[string(k)] = v
	}

	return result
}

// printEncryptedParts displays metadata about the encrypted JWE parts.
func printEncryptedParts(w io.Writer, tokenStr string) {
	parts := strings.SplitN(tokenStr, ".", 5)
	if len(parts) != 5 {
		return
	}

	labelColor.Fprintln(w, "Encrypted Content")
	dimColor.Fprintf(w, "Encrypted Key : %d bytes\n", decodedLen(parts[1]))
	dimColor.Fprintf(w, "IV            : %d bytes\n", decodedLen(parts[2]))
	dimColor.Fprintf(w, "Ciphertext    : %d bytes\n", decodedLen(parts[3]))
	dimColor.Fprintf(w, "Auth Tag      : %d bytes\n", decodedLen(parts[4]))
	fmt.Fprintln(w)
	dimColor.Fprintln(w, "Use --key/-k to provide a decryption key")
}

// decodedLen returns the byte length of a base64url-encoded string.
func decodedLen(s string) int {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0
	}
	return len(data)
}

// printDecryptedPayload formats and prints the decrypted JWE plaintext.
// If the plaintext is valid JSON, it is pretty-printed. If the plaintext
// is itself a JWT or JWE, it is decoded and printed recursively.
func printDecryptedPayload(w io.Writer, f *prettyjson.Formatter, plaintext []byte) error {
	text := string(plaintext)

	// Check if the decrypted payload is a nested JWE.
	if isJWE(text) {
		labelColor.Fprintln(w, "Decrypted Payload (nested JWE)")
		fmt.Fprintln(w)
		if err := decodeAndPrintJWE(w, text, ""); err == nil {
			return nil
		}
	}

	// Check if the decrypted payload is a nested JWT.
	if strings.Count(text, ".") == 2 {
		labelColor.Fprintln(w, "Decrypted Payload (nested JWT)")
		fmt.Fprintln(w)
		if err := decodeAndPrint(w, text, ""); err == nil {
			return nil
		}
	}

	// Try to parse as JSON object and pretty-print.
	var data map[string]any
	if err := json.Unmarshal(plaintext, &data); err == nil {
		formatTimestamps(data)
		return printSection(w, f, "Decrypted Payload", data)
	}

	// Try to parse as JSON array and pretty-print.
	var arr []any
	if err := json.Unmarshal(plaintext, &arr); err == nil {
		labelColor.Fprintln(w, "Decrypted Payload")
		pretty, err := f.Marshal(arr)
		if err != nil {
			return fmt.Errorf("formatting Decrypted Payload: %w", err)
		}
		fmt.Fprintln(w, string(pretty))
		return nil
	}

	// Fall back to raw text output.
	labelColor.Fprintln(w, "Decrypted Payload")
	fmt.Fprintln(w, text)
	return nil
}

// loadKey reads a decryption key from either a file path or an inline base64 string.
// It auto-detects the format: if the value looks like a file path (exists on disk),
// it reads and parses the file; otherwise it treats it as a base64-encoded key.
func loadKey(keyStr string) (any, error) {
	// Try as file path first.
	if data, err := os.ReadFile(keyStr); err == nil {
		if key, err := parseKeyData(data); err == nil {
			return key, nil
		}
		// File exists but doesn't parse as PEM/DER; use raw bytes as symmetric key.
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
	if key, err := parseKeyData(decoded); err == nil {
		return key, nil
	}

	// Use raw bytes as a symmetric key.
	return decoded, nil
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

// formatTimestamps converts numeric Unix timestamp values for known JWT claims
// into human-readable date strings. The map is modified in place.
func formatTimestamps(data map[string]any) {
	for key, val := range data {
		if !slices.Contains(timestampKeyNames, key) {
			continue
		}

		num, ok := val.(float64)
		if !ok {
			continue
		}
		t := time.Unix(int64(num), 0).UTC()
		data[key] = t.Format(time.RFC3339)
	}
}

// printSection outputs a labeled, pretty-printed JSON section.
func printSection(w io.Writer, f *prettyjson.Formatter, label string, data map[string]any) error {
	labelColor.Fprintln(w, label)

	pretty, err := f.Marshal(data)
	if err != nil {
		return fmt.Errorf("formatting %s: %w", label, err)
	}
	fmt.Fprintln(w, string(pretty))
	return nil
}

// printSignature outputs the raw signature string in dimmed text.
func printSignature(w io.Writer, sig string) {
	labelColor.Fprintln(w, "Signature")
	dimColor.Fprintln(w, sig)
}
