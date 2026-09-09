package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
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
	// The validator has to be shielded from timestamps it cannot convert: see
	// unrepresentableTimeClaim, which would otherwise silently invert the
	// verdict.
	if err := unrepresentableTimeClaim(claims); err != nil {
		return false, err
	}

	if err := jwt.NewValidator(opts...).Validate(claims); err != nil {
		return false, err
	}
	return true, nil
}

// printClaimsVerdict runs the requested checks against already-parsed claims
// and renders the verdict, so a caller that has parsed the token (the human
// decode path) does not parse it again just to validate it. The claims must be
// the raw parse, not the display copy formatTimestamps rewrites.
func printClaimsVerdict(w io.Writer, claims jwt.MapClaims, c claimChecks) error {
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

// temporalClaimKeys are the numeric date claims the validator consults, in a
// fixed order so the reported reason does not depend on map iteration.
var temporalClaimKeys = [...]string{"exp", "nbf", "iat"}

// unrepresentableTimeClaim reports the first temporal claim whose numeric value
// does not name a time jwtd can represent.
//
// It has to run before the validator. golang-jwt converts these claims with a
// Float64 whose error it discards and then casts to int64 (map_claims.go), so a
// value outside int64 range wraps - typically to math.MinInt64 - and the
// validator returns the opposite verdict: "exp":1e400 reads as long expired,
// "nbf":1e400 as long since valid. Neither is visible in the output, because
// claimTime declines to annotate a timestamp it cannot represent. Rejecting the
// value up front makes the verdict say what is actually wrong and keeps it
// agreeing with the displayed claims; the representability rule is claimTime's
// own, so the two cannot drift.
//
// Only numeric values are examined: a non-numeric temporal claim is not a
// timestamp at all, and the validator rejects it with its own message.
func unrepresentableTimeClaim(claims jwt.MapClaims) error {
	for _, key := range temporalClaimKeys {
		val, ok := claims[key]
		if !ok {
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

		if _, ok := claimTime(text); !ok {
			return fmt.Errorf("%s claim %s is not a representable timestamp", key, truncateClaimValue(text))
		}
	}
	return nil
}

// truncateClaimValue shortens a claim literal for an error message: a numeric
// claim comes from the token and can be arbitrarily long, while the reason is
// rendered on one line.
func truncateClaimValue(text string) string {
	const max = 32
	if len(text) <= max {
		return text
	}
	return text[:max] + "..."
}
