package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hokaccha/go-prettyjson"
	"github.com/spf13/cobra"
)

var timestampKeyNames = []string{"iat", "exp", "nbf"}

var errInvalidSignature = errors.New("invalid signature")

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
	rootCmd := newRootCommand()
	if err := rootCmd.Execute(); err != nil {
		_ = printExecutionError(rootCmd.ErrOrStderr(), err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "jwtd [token]",
		Short:         "Decode and pretty-print JSON Web Tokens",
		Long:          "jwtd decodes JWTs and JWEs and displays their contents with syntax-highlighted JSON output.",
		Args:          cobra.MaximumNArgs(1),
		Version:       version,
		RunE:          run,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.Flags().StringP("key", "k", "", "key for JWE decryption or JWS signature verification (file path, base64, JWK, or raw:<secret> for a literal symmetric key)")
	return rootCmd
}

func printExecutionError(w io.Writer, err error) error {
	if errors.Is(err, errInvalidSignature) {
		return nil
	}
	_, writeErr := fmt.Fprintf(w, "Error: %v\n", err)
	return writeErr
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
		return sanitizeToken(args[0]), nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return sanitizeToken(string(data)), nil
	}

	return readInteractive()
}

// sanitizeToken removes all whitespace from a token, so tokens that were
// wrapped across lines when copied from logs or emails still parse. Tokens
// never contain whitespace themselves.
func sanitizeToken(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// readInteractive prompts the user for a token using readline.
func readInteractive() (token string, err error) {
	rl, err := readline.New("Enter JWT/JWE: ")
	if err != nil {
		return "", fmt.Errorf("initializing readline: %w", err)
	}
	defer func() {
		if cerr := rl.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing readline: %w", cerr)
		}
	}()

	line, err := rl.Readline()
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}

	token = sanitizeToken(line)
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
	token, parts, claims, err := parseUnverifiedJWT(tokenStr)
	if err != nil {
		return err
	}

	f := newFormatter()

	if err := printSection(w, f, "Header", token.Header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	formatTimestamps(claims)
	if err := printSection(w, f, "Payload", claims); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if err := printSignature(w, parts[2]); err != nil {
		return err
	}

	if keyStr != "" {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if err := verifySignature(w, tokenStr, keyStr); err != nil {
			return err
		}
	}

	return nil
}

func parseUnverifiedJWT(tokenStr string) (*jwt.Token, []string, jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithJSONNumber())
	token, parts, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing JWT: %w", err)
	}

	payload, err := parser.DecodeSegment(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing JWT claims: decoding payload: %w", err)
	}

	claims := jwt.MapClaims{}
	if err := decodeJSON(payload, &claims); err != nil {
		return nil, nil, nil, fmt.Errorf("parsing JWT claims: %w", err)
	}
	return token, parts, claims, nil
}

// verifySignature verifies a JWT signature using the provided key and prints the result.
func verifySignature(w io.Writer, tokenStr, keyStr string) error {
	key, err := loadKey(keyStr)
	if err != nil {
		return fmt.Errorf("signature verification: error loading key: %w", err)
	}

	// Extract the public key from private keys for verification.
	key = publicKeyForVerification(key)
	if _, _, _, err := parseUnverifiedJWT(tokenStr); err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	// Claims validation is disabled so the result reflects only the
	// cryptographic signature, not token expiry. Accepted algorithms are
	// restricted to those compatible with the key type to rule out
	// algorithm confusion.
	opts := []jwt.ParserOption{jwt.WithoutClaimsValidation(), jwt.WithJSONNumber()}
	if methods := validMethodsForKey(key); methods != nil {
		opts = append(opts, jwt.WithValidMethods(methods))
	}
	parser := jwt.NewParser(opts...)
	_, err = parser.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return key, nil
	})

	if err != nil {
		if _, werr := color.New(color.FgRed, color.Bold).Fprintln(w, "Signature: INVALID"); werr != nil {
			return werr
		}
		if _, werr := dimColor.Fprintf(w, "  %v\n", err); werr != nil {
			return werr
		}
		return fmt.Errorf("%w: %v", errInvalidSignature, err)
	}
	_, werr := color.New(color.FgGreen, color.Bold).Fprintln(w, "Signature: VALID")
	return werr
}

// validMethodsForKey returns the JWS algorithm names compatible with the
// given verification key type, or nil for unknown key types.
func validMethodsForKey(key any) []string {
	switch key.(type) {
	case *rsa.PublicKey:
		return []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case *ecdsa.PublicKey:
		return []string{"ES256", "ES384", "ES512"}
	case ed25519.PublicKey:
		return []string{"EdDSA"}
	case []byte:
		return []string{"HS256", "HS384", "HS512"}
	default:
		return nil
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

// printDecryptedPayload formats and prints the decrypted JWE plaintext.
// If the plaintext is valid JSON, it is pretty-printed. If the plaintext
// is itself a JWT or JWE, it is decoded and printed recursively.
func printDecryptedPayload(w io.Writer, f *prettyjson.Formatter, plaintext []byte) error {
	text := string(plaintext)

	// Check if the decrypted payload is a nested JWE. The nested output is
	// buffered so nothing is printed if decoding fails and the payload falls
	// through to the JSON/raw handling below.
	if isJWE(text) {
		var nested bytes.Buffer
		if err := decodeAndPrintJWE(&nested, text, ""); err == nil {
			return printNestedPayload(w, "Decrypted Payload (nested JWE)", nested.Bytes())
		}
	}

	// Check if the decrypted payload is a nested JWT.
	if strings.Count(text, ".") == 2 {
		var nested bytes.Buffer
		if err := decodeAndPrint(&nested, text, ""); err == nil {
			return printNestedPayload(w, "Decrypted Payload (nested JWT)", nested.Bytes())
		}
	}

	// Try to parse as JSON object and pretty-print.
	var data map[string]any
	if err := decodeJSON(plaintext, &data); err == nil {
		formatTimestamps(data)
		return printSection(w, f, "Decrypted Payload", data)
	}

	// Try to parse as JSON array and pretty-print.
	var arr []any
	if err := decodeJSON(plaintext, &arr); err == nil {
		if _, err := labelColor.Fprintln(w, "Decrypted Payload"); err != nil {
			return err
		}
		pretty, err := f.Marshal(arr)
		if err != nil {
			return fmt.Errorf("formatting Decrypted Payload: %w", err)
		}
		_, err = fmt.Fprintln(w, escapeFormattedJSONControls(pretty))
		return err
	}

	// Fall back to raw text output.
	if _, err := labelColor.Fprintln(w, "Decrypted Payload"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, escapeTerminalText(plaintext))
	return err
}

func escapeTerminalText(text []byte) string {
	var escaped strings.Builder
	for len(text) > 0 {
		r, size := utf8.DecodeRune(text)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&escaped, `\x%02x`, text[0])
			text = text[1:]
			continue
		}

		switch {
		case r == '\n' || r == '\t':
			escaped.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&escaped, `\x%02x`, r)
		case r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&escaped, `\u%04x`, r)
		case isBidiControl(r):
			fmt.Fprintf(&escaped, `\u%04x`, r)
		default:
			escaped.WriteRune(r)
		}
		text = text[size:]
	}
	return escaped.String()
}

func escapeFormattedJSONControls(text []byte) string {
	var escaped strings.Builder
	for len(text) > 0 {
		r, size := utf8.DecodeRune(text)
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r) {
			fmt.Fprintf(&escaped, `\u%04x`, r)
		} else {
			escaped.Write(text[:size])
		}
		text = text[size:]
	}
	return escaped.String()
}

func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("invalid trailing JSON data: %w", err)
	}
	return nil
}

// printNestedPayload outputs a buffered, successfully decoded nested token
// under the given label.
func printNestedPayload(w io.Writer, label string, decoded []byte) error {
	if _, err := labelColor.Fprintln(w, label); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	_, err := w.Write(decoded)
	return err
}

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
// into human-readable date strings with the original value. The map is modified in place.
func formatTimestamps(data map[string]any) {
	for key, val := range data {
		if !slices.Contains(timestampKeyNames, key) {
			continue
		}

		var text string
		switch num := val.(type) {
		case json.Number:
			text = num.String()
		case float64:
			text = strconv.FormatFloat(num, 'f', -1, 64)
		default:
			continue
		}

		if len(text) == 0 || (text[0] != '-' && (text[0] < '0' || text[0] > '9')) || !json.Valid([]byte(text)) {
			continue
		}
		epoch, ok := new(big.Rat).SetString(text)
		if !ok {
			continue
		}

		seconds := new(big.Int).Quo(epoch.Num(), epoch.Denom())
		if !seconds.IsInt64() {
			continue
		}

		remainder := new(big.Rat).Sub(epoch, new(big.Rat).SetInt(seconds))
		nanoseconds := new(big.Rat).Mul(remainder, big.NewRat(int64(time.Second), 1))
		nanos := new(big.Int).Quo(nanoseconds.Num(), nanoseconds.Denom())
		if !nanos.IsInt64() {
			continue
		}

		t := time.Unix(seconds.Int64(), nanos.Int64()).UTC()
		if t.Year() < 0 || t.Year() > 9999 {
			continue
		}
		data[key] = fmt.Sprintf("%s (%s)", t.Format(time.RFC3339Nano), text)
	}
}

// printSection outputs a labeled, pretty-printed JSON section.
func printSection(w io.Writer, f *prettyjson.Formatter, label string, data map[string]any) error {
	if _, err := labelColor.Fprintln(w, label); err != nil {
		return err
	}

	pretty, err := f.Marshal(data)
	if err != nil {
		return fmt.Errorf("formatting %s: %w", label, err)
	}
	_, err = fmt.Fprintln(w, escapeFormattedJSONControls(pretty))
	return err
}

// printSignature outputs the raw signature string in dimmed text.
func printSignature(w io.Writer, sig string) error {
	if _, err := labelColor.Fprintln(w, "Signature"); err != nil {
		return err
	}
	_, err := dimColor.Fprintln(w, sig)
	return err
}
