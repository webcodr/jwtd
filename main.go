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
	"maps"
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
	rootCmd.Flags().Bool("json", false, "emit machine-readable JSON instead of colorized sections")
	rootCmd.Flags().String("color", "auto", "colorize output: auto (color only on a TTY), always, or never")
	rootCmd.Flags().Bool("verify-claims", false, "validate the temporal claims (exp, nbf) and exit nonzero if the token is expired or not yet valid")
	rootCmd.Flags().String("aud", "", "require this audience in the aud claim (implies --verify-claims)")
	rootCmd.Flags().String("iss", "", "require this issuer in the iss claim (implies --verify-claims)")
	return rootCmd
}

func printExecutionError(w io.Writer, err error) error {
	if errors.Is(err, errInvalidSignature) || errors.Is(err, errInvalidClaims) {
		return nil
	}
	_, writeErr := fmt.Fprintf(w, "Error: %v\n", err)
	return writeErr
}

func run(cmd *cobra.Command, args []string) error {
	jsonOut, _ := cmd.Flags().GetBool("json")
	colorMode, _ := cmd.Flags().GetString("color")
	if err := applyColorMode(colorMode, jsonOut); err != nil {
		return err
	}

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

	verifyClaimsFlag, _ := cmd.Flags().GetBool("verify-claims")
	aud, _ := cmd.Flags().GetString("aud")
	iss, _ := cmd.Flags().GetString("iss")
	checks := claimChecks{verify: verifyClaimsFlag, audience: aud, issuer: iss}

	w := cmd.OutOrStdout()

	if isJWE(token) {
		if checks.requested() {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Note: claim validation (--verify-claims/--aud/--iss) applies to JWTs only and is skipped for JWE.")
		}
		if jsonOut {
			return decodeJWEJSON(w, token, keyStr)
		}
		return decodeAndPrintJWE(w, token, keyStr)
	}

	if jsonOut {
		return decodeJWTJSON(w, token, keyStr, checks)
	}
	return decodeJWTHuman(w, token, keyStr, checks)
}

// decodeJWTHuman prints the decoded JWT and, when claim validation was
// requested, a Claims section after it. Both the signature check and the claim
// check run so their sections are shown together; the command exits nonzero if
// either fails, with the signature verdict taking precedence for the returned
// sentinel (both are suppressed by the top-level error printer).
func decodeJWTHuman(w io.Writer, tokenStr, keyStr string, checks claimChecks) error {
	p, err := parseUnverifiedJWT(tokenStr)
	if err != nil {
		return err
	}

	derr := printParsedJWT(w, p, keyStr)
	if derr != nil && !errors.Is(derr, errInvalidSignature) {
		return derr
	}

	var cerr error
	if checks.requested() {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		cerr = printClaimsVerdict(w, p.claims, checks)
		if cerr != nil && !errors.Is(cerr, errInvalidClaims) {
			return cerr
		}
	}

	if derr != nil {
		return derr
	}
	return cerr
}

// applyColorMode maps the --color flag onto fatih/color's global switch. "auto"
// leaves its default TTY and NO_COLOR detection untouched; "always" forces
// color even when piped; "never" disables it. --json output is plain JSON, so
// color is always off there regardless of the flag.
func applyColorMode(mode string, jsonOut bool) error {
	if jsonOut {
		color.NoColor = true
		return nil
	}
	switch mode {
	case "auto":
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	default:
		return fmt.Errorf("invalid --color value %q: use auto, always, or never", mode)
	}
	return nil
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

	// A nil FileInfo (Stat failed, e.g. a closed or detached stdin) is treated
	// as "no pipe" and falls through to the interactive prompt rather than
	// dereferencing nil.
	stat, err := os.Stdin.Stat()
	if err == nil && stat != nil && (stat.Mode()&os.ModeCharDevice) == 0 {
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
	p, err := parseUnverifiedJWT(tokenStr)
	if err != nil {
		return err
	}
	return printParsedJWT(w, p, keyStr)
}

// printParsedJWT renders an already-parsed token, so callers that also need the
// claims (claim validation) or the header (signature verification) parse once
// and share the result instead of decoding the same segments again.
func printParsedJWT(w io.Writer, p *parsedJWT, keyStr string) error {
	f := newFormatter()

	if err := printSection(w, f, "Header", p.token.Header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	// formatTimestamps rewrites claim values into display strings, so it runs
	// on a copy: p.claims stays the authoritative parse for validation.
	display := maps.Clone(p.claims)
	formatTimestamps(display)
	if err := printSection(w, f, "Payload", display); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if err := printSignature(w, p.parts[2]); err != nil {
		return err
	}

	if keyStr != "" {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if err := printSignatureVerdict(w, p, keyStr); err != nil {
			return err
		}
	}

	return nil
}

// parsedJWT is one strict decode of a compact JWT: the token with its
// display-decoded header, its three segments, and its claims. It is threaded
// through the decode, signature, and claim steps so a single run parses the
// token once rather than once per step.
type parsedJWT struct {
	raw    string
	token  *jwt.Token
	parts  []string
	claims jwt.MapClaims
}

func parseUnverifiedJWT(tokenStr string) (*parsedJWT, error) {
	parser := jwt.NewParser(jwt.WithJSONNumber())
	token, parts, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}

	headerData, err := parser.DecodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT header: decoding header: %w", err)
	}

	// Re-decode the header for display with the same strictness as the
	// claims: exact json.Number values and no trailing data. ParseUnverified
	// decodes it with plain json.Unmarshal, which loses number precision.
	header := map[string]any{}
	if err := decodeJSON(headerData, &header); err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	token.Header = header

	payload, err := parser.DecodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT claims: decoding payload: %w", err)
	}

	claims := jwt.MapClaims{}
	if err := decodeJSON(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}
	return &parsedJWT{raw: tokenStr, token: token, parts: parts, claims: claims}, nil
}

// printSignatureVerdict renders the signature verdict for an already-parsed
// token and returns the errInvalidSignature sentinel on failure so the CLI
// exits nonzero.
func printSignatureVerdict(w io.Writer, p *parsedJWT, keyStr string) error {
	valid, reason, err := verifyJWTSignature(p, keyStr)
	if err != nil {
		return fmt.Errorf("signature verification: %w", err)
	}

	if !valid {
		if werr := printVerdict(w, "Signature", false, reason.Error()); werr != nil {
			return werr
		}
		return fmt.Errorf("%w: %v", errInvalidSignature, reason)
	}
	return printVerdict(w, "Signature", true, "")
}

// verifyJWTSignature performs the cryptographic signature check and reports the
// outcome without printing anything, so both the human and --json paths share
// one verification. It returns valid=true on success; valid=false with a
// non-nil reason for a genuinely invalid signature; and a non-nil err only for
// hard failures (unparseable token, unusable key) that are not a verdict on the
// signature itself.
func verifyJWTSignature(p *parsedJWT, keyStr string) (valid bool, reason error, err error) {
	key, err := loadKeyForKID(keyStr, headerKID(p.token.Header))
	if err != nil {
		return false, nil, fmt.Errorf("error loading key: %w", err)
	}

	// Extract the public key from private keys for verification.
	key = publicKeyForVerification(key)

	// Claims validation is disabled so the result reflects only the
	// cryptographic signature, not token expiry. Accepted algorithms are
	// restricted to those compatible with the key type to rule out
	// algorithm confusion.
	opts := []jwt.ParserOption{jwt.WithoutClaimsValidation(), jwt.WithJSONNumber()}
	if methods := validMethodsForKey(key); methods != nil {
		opts = append(opts, jwt.WithValidMethods(methods))
	}
	parser := jwt.NewParser(opts...)
	if _, perr := parser.Parse(p.raw, func(*jwt.Token) (any, error) {
		return key, nil
	}); perr != nil {
		return false, perr, nil
	}
	return true, nil, nil
}

// headerKID returns the token's "kid" header as a string, or "" when it is
// absent or not a string. It selects the matching key from a JWK Set.
func headerKID(header map[string]any) string {
	if kid, ok := header["kid"].(string); ok {
		return kid
	}
	return ""
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
