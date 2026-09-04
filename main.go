package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var errInvalidSignature = errors.New("invalid signature")

// errNoToken is returned when stdin or the interactive prompt supplied nothing
// but whitespace, so an empty pipe is reported as such rather than as a
// malformed token.
var errNoToken = errors.New("no token provided")

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
	// The value is validated before --json is consulted, so a typo is
	// reported the same way whether or not JSON output is on.
	switch mode {
	case "auto", "always", "never":
	default:
		return fmt.Errorf("invalid --color value %q: use auto, always, or never", mode)
	}
	switch {
	case jsonOut, mode == "never":
		color.NoColor = true
	case mode == "always":
		color.NoColor = false
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
		token := sanitizeToken(string(data))
		if token == "" {
			return "", errNoToken
		}
		return token, nil
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
		return "", errNoToken
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

	if err := printSection(w, f, "Header", p.header); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	// formatTimestamps rewrites claim values into display strings, so it runs
	// on a copy: p.claims stays the authoritative parse for validation.
	display := maps.Clone(p.claims)
	formatTimestamps(display)
	// Converted to the plain map type: jwt.MapClaims is a named type, which the
	// formatter's fast path does not match.
	if err := printSection(w, f, "Payload", map[string]any(display)); err != nil {
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

// parsedJWT is one strict decode of a compact JWT: its three segments, the
// display-decoded header and claims, and the signing method and decoded
// signature bytes the verification step needs. It is threaded through the
// decode, signature, and claim steps so a single run parses the token once
// rather than once per step.
type parsedJWT struct {
	header    map[string]any
	parts     []string
	claims    jwt.MapClaims
	method    jwt.SigningMethod
	signature []byte
}

// parseUnverifiedJWT decodes a compact JWT without checking its signature.
//
// It does the segment work itself rather than calling jwt.ParseUnverified,
// which JSON-decodes the header and claims with plain json.Unmarshal — losing
// number precision and accepting trailing data — so every one of its decodes
// would be thrown away and redone strictly here. The remaining steps mirror
// ParseUnverified exactly, including its rejection of a token whose "alg" is
// missing or unknown, so the set of tokens jwtd decodes is unchanged.
func parseUnverifiedJWT(tokenStr string) (*parsedJWT, error) {
	parts, ok := splitCompactJWT(tokenStr)
	if !ok {
		return nil, fmt.Errorf("parsing JWT: %w: token contains an invalid number of segments", jwt.ErrTokenMalformed)
	}

	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT header: decoding header: %w", err)
	}

	// The header is decoded with the same strictness as the claims: exact
	// json.Number values and no trailing data.
	header := map[string]any{}
	if err := decodeJSON(headerData, &header); err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT claims: decoding payload: %w", err)
	}

	claims := jwt.MapClaims{}
	if err := decodeJSON(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	alg, ok := header["alg"].(string)
	if !ok {
		return nil, fmt.Errorf("parsing JWT: %w: signing method (alg) is unspecified", jwt.ErrTokenUnverifiable)
	}
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return nil, fmt.Errorf("parsing JWT: %w: signing method (alg) is unavailable", jwt.ErrTokenUnverifiable)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w: could not base64 decode signature: %w", jwt.ErrTokenMalformed, err)
	}

	return &parsedJWT{
		header:    header,
		parts:     parts,
		claims:    claims,
		method:    method,
		signature: signature,
	}, nil
}

// splitCompactJWT splits a compact serialization into its three segments,
// reporting false unless there are exactly two delimiters. A token carrying
// extra delimiters is rejected rather than truncated, matching
// jwt.ParseUnverified.
func splitCompactJWT(tokenStr string) ([]string, bool) {
	header, remain, ok := strings.Cut(tokenStr, ".")
	if !ok {
		return nil, false
	}
	claims, signature, ok := strings.Cut(remain, ".")
	if !ok || strings.Contains(signature, ".") {
		return nil, false
	}
	return []string{header, claims, signature}, true
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
	key, err := loadKeyForKID(keyStr, headerKID(p.header))
	if err != nil {
		return false, nil, fmt.Errorf("error loading key: %w", err)
	}

	// Extract the public key from private keys for verification.
	key = publicKeyForVerification(key)

	// Accepted algorithms are restricted to those compatible with the key type
	// to rule out algorithm confusion. This check is what jwt.WithValidMethods
	// would do inside jwt.Parse; verifying from the already-parsed token means
	// it has to be spelled out here, and it must stay ahead of the Verify call
	// below — without it an HS256 token signed with a published public key
	// verifies against that key.
	//
	// A key type with no JWS algorithms at all (an X25519 key, which is a
	// valid JWE key but can sign nothing) is rejected here as well, rather
	// than relying on every Verify implementation to refuse the Go type.
	alg := p.method.Alg()
	methods := validMethodsForKey(key)
	if len(methods) == 0 {
		return false, fmt.Errorf("%w: key type %T cannot verify a JWS", jwt.ErrTokenSignatureInvalid, key), nil
	}
	if !slices.Contains(methods, alg) {
		return false, fmt.Errorf("%w: signing method %v is invalid", jwt.ErrTokenSignatureInvalid, alg), nil
	}

	// Only the signature is checked here: the claims are never consulted, so
	// the verdict reflects the cryptography alone and not token expiry.
	signingInput := p.parts[0] + "." + p.parts[1]
	if verr := p.method.Verify(signingInput, p.signature, key); verr != nil {
		return false, fmt.Errorf("%w: %w", jwt.ErrTokenSignatureInvalid, verr), nil
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
// given verification key type. An unknown key type gets an empty list, which
// verifyJWTSignature treats as "verifies nothing": the allowlist fails closed
// instead of being skipped.
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

	// Nothing but JSON whitespace after the value is the ordinary case, and
	// deciding it here saves a second decode. Anything else is handed to the
	// decoder, which is what phrases the rejection.
	if isJSONWhitespace(data[decoder.InputOffset():]) {
		return nil
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

// isJSONWhitespace reports whether data is entirely JSON whitespace. The set is
// JSON's own four characters, not Unicode's: a vertical tab after a value is
// trailing data, and must reach the decoder that says so.
func isJSONWhitespace(data []byte) bool {
	for _, b := range data {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
	}
	return true
}
