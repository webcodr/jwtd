package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var errInvalidSignature = errors.New("invalid signature")

// version is set at build time via -ldflags.
var version = "dev"

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

	rootCmd.Flags().StringP("key", "k", "", "key for JWE decryption or JWS signature verification: a PEM/DER/JWK file or inline base64, hmac:<file> for a symmetric secret file, or raw:<secret> for a literal one (inline values are visible to other local users in the process list, so prefer a file or JWTD_KEY)")
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
	fromFlag := keyStr != ""
	if keyStr == "" {
		keyStr = os.Getenv("JWTD_KEY")
	}
	if keyStr != "" {
		printKeyInterpretation(cmd.ErrOrStderr(), keyStr, fromFlag)
	}

	w := cmd.OutOrStdout()

	if isJWE(token) {
		return decodeAndPrintJWE(w, token, keyStr)
	}
	return decodeAndPrint(w, token, keyStr)
}

// printKeyInterpretation notes on stderr how a key argument was read when it
// was not read as a file. Key detection is precedence-based, so a value meant
// as a literal secret can be taken as base64 or as a file; saying which
// applied turns a silent misreading into something the user can see. Inline
// key material also lands in the process list, where other local users can
// read it, so that is flagged for flag values.
//
// Writes are best effort: a failure here must not disturb decoding.
func printKeyInterpretation(w io.Writer, keyStr string, fromFlag bool) {
	origin := "JWTD_KEY"
	if fromFlag {
		origin = "--key"
	}

	var note string
	switch classifyKeyArg(keyStr) {
	case keySourceLiteral:
		note = fmt.Sprintf("Note: %s used as a literal symmetric secret.", origin)
	case keySourceBase64:
		note = fmt.Sprintf("Note: %s is not an existing file; decoded as base64 key material.", origin)
	default:
		// A file, including an hmac: secret file, is the expected reading,
		// and unusable values produce an error that speaks for itself.
		return
	}

	if fromFlag {
		note += "\n      Inline key material is visible to other local users in the process list."
	}
	_, _ = fmt.Fprintln(w, note)
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

	headerData, err := parser.DecodeSegment(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing JWT header: decoding header: %w", err)
	}

	// Re-decode the header for display with the same strictness as the
	// claims: exact json.Number values and no trailing data. ParseUnverified
	// decodes it with plain json.Unmarshal, which loses number precision.
	header := map[string]any{}
	if err := decodeJSON(headerData, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	token.Header = header

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
