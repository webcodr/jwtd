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
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	rootCmd.Flags().String("verify-key", "", "key for JWS signature verification, top level or nested inside a JWE; defaults to --key (same formats as --key; prefer a file or JWTD_VERIFY_KEY)")
	rootCmd.Flags().Bool("json", false, "emit machine-readable JSON instead of colorized sections")
	rootCmd.Flags().String("color", "auto", "colorize output: auto (color only on a TTY), always, or never")
	rootCmd.Flags().BoolP("quiet", "q", false, "suppress standard output and only report status via exit code")
	rootCmd.Flags().Bool("verify-claims", false, "validate the temporal claims (exp, nbf) and exit nonzero if the token is expired or not yet valid")
	rootCmd.Flags().String("aud", "", "require this audience in the aud claim (implies --verify-claims)")
	rootCmd.Flags().String("iss", "", "require this issuer in the iss claim (implies --verify-claims)")
	rootCmd.Flags().String("sub", "", "require this subject in the sub claim (implies --verify-claims)")
	rootCmd.Flags().Duration("leeway", 0, "clock-skew leeway for exp/nbf validation (e.g. 30s, 1m; implies --verify-claims)")
	rootCmd.Flags().Bool("require-exp", false, "require the exp claim to be present (implies --verify-claims)")
	rootCmd.Flags().String("alg", "", "require this exact alg header value (fails closed on mismatch for both JWT and JWE)")
	rootCmd.Flags().String("at", "", "evaluate timestamps and claim validity at this time (RFC3339 or Unix seconds)")
	rootCmd.Flags().Bool("local", false, "display formatted timestamps in the local timezone instead of UTC")
	rootCmd.Flags().String("tz", "", "display formatted timestamps in an IANA timezone (e.g. Europe/Berlin, America/New_York)")
	rootCmd.Flags().Bool("header", false, "print only the token header (the protected header for a JWE)")
	rootCmd.Flags().Bool("payload", false, "print only the payload (the decrypted plaintext for a JWE)")
	rootCmd.Flags().String("claim", "", "print only the value of this top-level claim; strings are printed bare (nothing is printed if a requested check fails)")
	rootCmd.MarkFlagsMutuallyExclusive("header", "payload", "claim")
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

	quiet, _ := cmd.Flags().GetBool("quiet")
	verifyClaimsFlag, _ := cmd.Flags().GetBool("verify-claims")
	aud, _ := cmd.Flags().GetString("aud")
	iss, _ := cmd.Flags().GetString("iss")
	sub, _ := cmd.Flags().GetString("sub")
	leeway, _ := cmd.Flags().GetDuration("leeway")
	if leeway < 0 {
		return fmt.Errorf("invalid --leeway value %v: must not be negative", leeway)
	}
	requireExp, _ := cmd.Flags().GetBool("require-exp")
	expectedAlg, _ := cmd.Flags().GetString("alg")
	atStr, _ := cmd.Flags().GetString("at")
	localTZ, _ := cmd.Flags().GetBool("local")
	tzName, _ := cmd.Flags().GetString("tz")

	sel, err := selectionFromFlags(cmd)
	if err != nil {
		return err
	}

	loc, err := resolveDisplayLocation(localTZ, tzName)
	if err != nil {
		return err
	}

	var hasAt bool
	var atTime time.Time
	if atStr != "" {
		atTime, err = parseAtTime(atStr)
		if err != nil {
			return err
		}
		hasAt = true
	}

	prevLoc := displayLocation
	displayLocation = loc
	defer func() { displayLocation = prevLoc }()

	if hasAt {
		prevNow := timeNow
		timeNow = func() time.Time { return atTime }
		defer func() { timeNow = prevNow }()
	}

	token, err := readToken(args)
	if err != nil {
		return err
	}

	keys := tokenKeys{
		decrypt: resolveKeyArg(cmd, "key", "JWTD_KEY"),
		verify:  resolveKeyArg(cmd, "verify-key", "JWTD_VERIFY_KEY"),
	}
	verifyKeyStr, _ := keys.verification()

	checks := claimChecks{
		verify:     verifyClaimsFlag,
		audience:   aud,
		issuer:     iss,
		subject:    sub,
		leeway:     leeway,
		requireExp: requireExp,
	}

	w := cmd.OutOrStdout()
	if quiet {
		w = io.Discard
	}

	if isJWE(token) {
		// Extraction promises that every requested check ran before a value is
		// printed. Claim validation does not run on a JWE yet, so a selector
		// with claim flags is refused rather than printing a value whose
		// claims were never checked; the stderr note below would not reach a
		// $(...) capture.
		if sel.active() && checks.requested() {
			return errors.New("claim validation (--verify-claims/--aud/--iss/--sub/--leeway/--require-exp) is not supported with --header/--payload/--claim on a JWE yet")
		}
		jwe, header, err := parseJWE(token)
		if err != nil {
			return err
		}
		alg, _ := header["alg"].(string)
		if err := checkExpectedAlg(alg, expectedAlg); err != nil {
			return err
		}
		l, err := openJWE(token, jwe, header, keys, false)
		if err != nil {
			return err
		}
		if err := checkVerifyKeyUsed(l, keys); err != nil {
			return err
		}
		if sel.active() {
			return extractJWE(w, jwe, header, keys.decrypt, sel, jsonOut)
		}
		if jsonOut {
			return decodeLayerJSON(w, l, checks)
		}
		return decodeLayerHuman(w, l, checks)
	}

	p, err := parseUnverifiedJWT(token)
	if err != nil {
		return err
	}
	if err := checkExpectedAlg(p.method.Alg(), expectedAlg); err != nil {
		return err
	}
	l, err := openJWT(p, keys, false)
	if err != nil {
		return err
	}
	if sel.active() {
		return extractJWT(w, cmd.ErrOrStderr(), p, verifyKeyStr, checks, sel, jsonOut)
	}
	if jsonOut {
		return decodeLayerJSON(w, l, checks)
	}
	return decodeLayerHuman(w, l, checks)
}

// resolveKeyArg reads a key flag, falling back to its environment variable, and
// narrates on stderr how a value that is not a key file was read.
func resolveKeyArg(cmd *cobra.Command, flag, env string) string {
	keyStr, _ := cmd.Flags().GetString(flag)
	fromFlag := keyStr != ""
	origin := "--" + flag
	if !fromFlag {
		keyStr = os.Getenv(env)
		origin = env
	}
	if keyStr != "" {
		printKeyInterpretation(cmd.ErrOrStderr(), keyStr, origin, fromFlag)
	}
	return keyStr
}

// checkVerifyKeyUsed fails when a verification key was given but the opened
// token holds no JWS for it: a signature check the user asked for that never
// ran must not pass silently. It runs before any output.
func checkVerifyKeyUsed(l *tokenLayer, keys tokenKeys) error {
	if keys.verify == "" || l.hasJWS() {
		return nil
	}
	if l.jwe != nil && keys.decrypt == "" {
		return fmt.Errorf("%w (pass --key to decrypt the JWE first)", errVerifyKeyUnused)
	}
	return errVerifyKeyUnused
}

// selectionFromFlags reads --header, --payload, and --claim. Cobra already
// rejects more than one of them; an empty --claim is rejected here, before the
// token is read, like every other invalid flag.
func selectionFromFlags(cmd *cobra.Command) (selection, error) {
	if header, _ := cmd.Flags().GetBool("header"); header {
		return selection{kind: selectHeader}, nil
	}
	if payload, _ := cmd.Flags().GetBool("payload"); payload {
		return selection{kind: selectPayload}, nil
	}
	if cmd.Flags().Changed("claim") {
		name, _ := cmd.Flags().GetString("claim")
		if name == "" {
			return selection{}, errors.New("--claim requires a claim name")
		}
		return selection{kind: selectClaim, claim: name}, nil
	}
	return selection{}, nil
}

func parseAtTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		rt, ok := representableTime(t)
		if !ok {
			return time.Time{}, fmt.Errorf("invalid --at value %q: timestamp out of representable range", s)
		}
		return rt, nil
	}
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		rt, ok := representableTime(time.Unix(sec, 0))
		if !ok {
			return time.Time{}, fmt.Errorf("invalid --at value %q: timestamp out of representable range", s)
		}
		return rt, nil
	}
	return time.Time{}, fmt.Errorf("invalid --at value %q: expected RFC3339 timestamp or Unix seconds", s)
}

func resolveDisplayLocation(local bool, tz string) (*time.Location, error) {
	if local && tz != "" {
		return nil, errors.New("--local and --tz cannot be used together")
	}
	if local {
		return time.Local, nil
	}
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("invalid --tz value %q: %w", tz, err)
		}
		return loc, nil
	}
	return time.UTC, nil
}

func checkExpectedAlg(actual, expected string) error {
	if expected != "" && actual != expected {
		return fmt.Errorf("token algorithm %q does not match expected --alg %q", actual, expected)
	}
	return nil
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
	return decodeParsedJWTHuman(w, p, keyStr, checks)
}

func decodeParsedJWTHuman(w io.Writer, p *parsedJWT, keyStr string, checks claimChecks) error {
	l, err := openJWT(p, tokenKeys{decrypt: keyStr}, false)
	if err != nil {
		return err
	}
	return decodeLayerHuman(w, l, checks)
}

// decodeLayerHuman renders an opened token and, when claim validation was
// requested, a Claims section after everything else. The claims checked are the
// innermost claims set (see claimsTarget), so a JWE wrapping a JWS is validated
// against the inner token's claims. Claims that cannot be reached are an
// INVALID verdict: a requested check that cannot run must not pass.
func decodeLayerHuman(w io.Writer, l *tokenLayer, checks claimChecks) error {
	derr := renderLayerHuman(w, newFormatter(), l)
	if derr != nil && !errors.Is(derr, errInvalidSignature) {
		return derr
	}

	var cerr error
	if checks.requested() {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		claims, reason := l.claimsTarget()
		if reason != "" {
			if err := printVerdict(w, "Claims", false, reason); err != nil {
				return err
			}
			cerr = fmt.Errorf("%w: %s", errInvalidClaims, reason)
		} else {
			cerr = printClaimsVerdict(w, claims, checks)
			if cerr != nil && !errors.Is(cerr, errInvalidClaims) {
				return cerr
			}
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
func printKeyInterpretation(w io.Writer, keyStr, origin string, fromFlag bool) {

	var note string
	switch classifyKeyArg(keyStr) {
	case keySourceLiteral:
		note = fmt.Sprintf("Note: %s used as a literal symmetric secret.", origin)
	case keySourceBase64:
		note = fmt.Sprintf("Note: %s is not an existing file; decoded as base64 key material.", origin)
	default:
		// A file, including an hmac: secret file, is the expected reading.
		// Directories and otherwise unusable values are rejected by
		// loadKeyForKID with an error that speaks for itself, so there is no
		// reading to narrate.
		return
	}

	if fromFlag {
		note += "\n      Inline key material is visible to other local users in the process list."
	}
	_, _ = fmt.Fprintln(w, note)
}

// maxStdinTokenBytes bounds how much of a piped stdin is read. A compact token
// is a few kilobytes at most, so the limit is generous; it exists so a stray
// pipe from an unbounded source (a log file, /dev/zero) fails with a clear
// message instead of being buffered whole into memory.
const maxStdinTokenBytes = 16 << 20 // 16 MiB

// readToken resolves the JWT string from arguments, stdin pipe, or interactive prompt.
func readToken(args []string) (string, error) {
	if len(args) > 0 {
		// An empty or whitespace-only argument carries no token, so it is
		// reported the same way an empty pipe is rather than as malformed.
		token := sanitizeToken(args[0])
		if token == "" {
			return "", errNoToken
		}
		return token, nil
	}

	// A nil FileInfo (Stat failed, e.g. a closed or detached stdin) is treated
	// as "no pipe" and falls through to the interactive prompt rather than
	// dereferencing nil.
	stat, err := os.Stdin.Stat()
	if err == nil && stat != nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		// One byte past the limit is read so exceeding it is detected rather
		// than silently truncating the token.
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinTokenBytes+1))
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		if len(data) > maxStdinTokenBytes {
			return "", fmt.Errorf("reading stdin: input exceeds the %d byte limit", maxStdinTokenBytes)
		}
		token := sanitizeToken(string(data))
		if token == "" {
			return "", errNoToken
		}
		return token, nil
	}

	return readInteractive()
}

// sanitizeToken strips an optional HTTP "Authorization:" header name,
// "Bearer" scheme prefix, surrounding matching quotes, and all whitespace from
// a token, so tokens copied from DevTools, curl output, logs, or emails still
// parse. Tokens never contain whitespace themselves.
func sanitizeToken(s string) string {
	s = stripMatchingQuotes(strings.TrimSpace(s))

	hadAuthHeader := false
	const authPrefix = "authorization"
	if len(s) >= len(authPrefix) && strings.EqualFold(s[:len(authPrefix)], authPrefix) {
		rest := strings.TrimLeft(s[len(authPrefix):], " \t")
		if afterColon, ok := strings.CutPrefix(rest, ":"); ok {
			hadAuthHeader = true
			s = stripMatchingQuotes(strings.TrimSpace(afterColon))
		}
	}

	const bearerPrefix = "bearer"
	if len(s) >= len(bearerPrefix) && strings.EqualFold(s[:len(bearerPrefix)], bearerPrefix) {
		afterBearer := s[len(bearerPrefix):]
		if afterBearer == "" {
			if hadAuthHeader {
				return ""
			}
		} else if r, _ := utf8.DecodeRuneInString(afterBearer); unicode.IsSpace(r) {
			s = stripMatchingQuotes(strings.TrimSpace(afterBearer))
		}
	}

	return strings.Join(strings.Fields(s), "")
}

func stripMatchingQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
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

// printParsedJWT renders an already-parsed token, so callers that also need the
// claims (claim validation) or the header (signature verification) parse once
// and share the result instead of decoding the same segments again.
func printParsedJWT(w io.Writer, p *parsedJWT, keyStr string) error {
	// Opening resolves and applies the key before anything is written, so a
	// bad key argument fails with an error alone instead of three decoded
	// sections followed by one.
	l, err := openJWT(p, tokenKeys{decrypt: keyStr}, false)
	if err != nil {
		return err
	}
	return renderLayerHuman(w, newFormatter(), l)
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
	// A literal "null" decodes without error and leaves the map nil, which
	// would otherwise be rendered as an empty object. The JWE header decoder
	// carries the same guard.
	if header == nil {
		return nil, fmt.Errorf("parsing JWT header: expected JSON object")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing JWT claims: decoding payload: %w", err)
	}

	claims := jwt.MapClaims{}
	if err := decodeJSON(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}
	if claims == nil {
		return nil, fmt.Errorf("parsing JWT claims: expected JSON object")
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

// verifyJWTSignature performs the cryptographic signature check and reports the
// outcome without printing anything, so both the human and --json paths share
// one verification. It returns valid=true on success; valid=false with a
// non-nil reason for a genuinely invalid signature; and a non-nil err only for
// hard failures (unparseable token, unusable key) that are not a verdict on the
// signature itself.
func verifyJWTSignature(p *parsedJWT, keyStr string) (valid bool, reason error, err error) {
	kid, err := headerKID(p.header)
	if err != nil {
		return false, nil, err
	}
	key, err := loadKeyForToken(keyStr, keySelector{kid: kid, use: "sig", alg: p.method.Alg()})
	if err != nil {
		return false, nil, fmt.Errorf("error loading key: %w", err)
	}
	valid, reason = verifyLoadedKeySignature(p, key)
	return valid, reason, nil
}

// verifyLoadedKeySignature is the verification core, taking a key that has
// already been loaded. Everything that can fail here is a verdict on the
// signature, so there is no separate hard error: the one hard failure, an
// unusable key argument, was decided by the caller that loaded it.
func verifyLoadedKeySignature(p *parsedJWT, key any) (valid bool, reason error) {
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
		return false, fmt.Errorf("%w: key type %T cannot verify a JWS", jwt.ErrTokenSignatureInvalid, key)
	}
	if !slices.Contains(methods, alg) {
		return false, fmt.Errorf("%w: signing method %v is invalid", jwt.ErrTokenSignatureInvalid, alg)
	}

	// Only the signature is checked here: the claims are never consulted, so
	// the verdict reflects the cryptography alone and not token expiry.
	signingInput := p.parts[0] + "." + p.parts[1]
	if verr := p.method.Verify(signingInput, p.signature, key); verr != nil {
		return false, fmt.Errorf("%w: %w", jwt.ErrTokenSignatureInvalid, verr)
	}
	return true, nil
}

// errNonStringKID rejects a "kid" header that is present but not a string.
var errNonStringKID = errors.New(`token header "kid" must be a string (RFC 7515)`)

// headerKID returns the token's "kid" header, which selects the matching entry
// from a JWK Set, or "" when the token carries none.
//
// A present but non-string "kid" is an error, not an absent one. RFC 7515
// requires the value to be a string, and treating {"kid":123} as "no kid
// named" would silently select the first JWK Set entry instead of the one the
// token points at — a key mismatch reported as a valid signature.
func headerKID(header map[string]any) (string, error) {
	raw, ok := header["kid"]
	if !ok {
		return "", nil
	}
	kid, ok := raw.(string)
	if !ok {
		return "", errNonStringKID
	}
	return kid, nil
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
