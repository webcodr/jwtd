package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var errInvalidClaims = errors.New("invalid claims")

// claimChecks describes the opt-in claim validations requested via flags. The
// zero value requests nothing, so the default behavior stays decode-only and
// the exit code keeps reflecting the signature alone.
type claimChecks struct {
	verify   bool   // --verify-claims: enforce the temporal claims (exp, nbf)
	audience string // --aud: require this audience in the aud claim
	issuer   string // --iss: require this issuer in the iss claim
}

// requested reports whether any claim validation was asked for. An expected
// audience or issuer implies validation, so those flags work without also
// passing --verify-claims.
func (c claimChecks) requested() bool {
	return c.verify || c.audience != "" || c.issuer != ""
}

// validateClaimsSet runs the requested RFC 7519 claim validations against the
// already-parsed claims without printing, so the human and --json paths share
// one implementation. It reports valid=true on success, or valid=false with a
// human-readable reason.
//
// Validation always covers the temporal claims (exp, nbf) that are present; an
// expected audience or issuer is additionally required to be present and to
// match. The clock is the shared timeNow, so the verdict agrees with the
// displayed expired / not-yet-valid annotations and is deterministic under
// test. This is purely a claims check and performs no signature verification.
func validateClaimsSet(claims jwt.MapClaims, c claimChecks) (bool, error) {
	opts := []jwt.ParserOption{jwt.WithTimeFunc(timeNow)}
	if c.audience != "" {
		opts = append(opts, jwt.WithAudience(c.audience))
	}
	if c.issuer != "" {
		opts = append(opts, jwt.WithIssuer(c.issuer))
	}
	if err := jwt.NewValidator(opts...).Validate(claims); err != nil {
		return false, err
	}
	return true, nil
}

// verifyClaims parses the token, runs the requested claim validations, and
// prints "Claims: VALID" or "Claims: INVALID" with the reason. It returns the
// errInvalidClaims sentinel (wrapping the reason) when a check fails so the CLI
// exits nonzero, mirroring signature verification; an unparseable token returns
// a hard error instead. Claim validation is independent of the signature: it
// runs with or without a key.
func verifyClaims(w io.Writer, tokenStr string, c claimChecks) error {
	_, _, claims, err := parseUnverifiedJWT(tokenStr)
	if err != nil {
		return err
	}

	valid, reason := validateClaimsSet(claims, c)
	if !valid {
		text := claimReason(reason)
		if werr := printVerdict(w, "Claims", false, text); werr != nil {
			return werr
		}
		return fmt.Errorf("%w: %s", errInvalidClaims, text)
	}
	return printVerdict(w, "Claims", true, "")
}

// claimReason flattens a validation error onto a single line. The jwt validator
// joins multiple failures with newlines (via errors.Join); collapsing them to a
// "; "-separated line keeps the dim reason and the wrapped error readable.
func claimReason(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}
