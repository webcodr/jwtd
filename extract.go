package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/go-jose/go-jose/v4"
)

// selectionKind names the one part of a token --header, --payload, or --claim
// asked for. selectNone is the zero value: the full decoded output.
type selectionKind int

const (
	selectNone selectionKind = iota
	selectHeader
	selectPayload
	selectClaim
)

// selection is the extraction request from the command line. claim is the
// top-level claim name for selectClaim. Names are taken literally, never as a
// path, because claim names are often URIs that contain dots.
type selection struct {
	kind  selectionKind
	claim string
}

func (s selection) active() bool {
	return s.kind != selectNone
}

// extractJWT prints only the selected part of an already-parsed JWT.
//
// Every requested check runs first, using the same signature and claim code as
// the normal output. If any check fails, nothing is written to w: the failing
// verdicts go to errw and the matching sentinel is returned, the signature
// verdict taking precedence. Extraction exists for `$(...)` capture in scripts,
// and a script that forgets `set -e` must still never receive a value that
// failed a check it asked for. The verdicts are printed here, not left to the
// top-level printer, because that printer deliberately silences the sentinels
// (the human output prints its own verdict).
func extractJWT(w, errw io.Writer, p *parsedJWT, keyStr string, checks claimChecks, sel selection, jsonOut bool) error {
	var invalid error
	if keyStr != "" {
		valid, reason, err := verifyJWTSignature(p, keyStr)
		if err != nil {
			return fmt.Errorf("signature verification: %w", err)
		}
		if !valid {
			if err := printVerdict(errw, "Signature", false, reason.Error()); err != nil {
				return err
			}
			invalid = fmt.Errorf("%w: %v", errInvalidSignature, reason)
		}
	}

	if checks.requested() {
		valid, reason := validateClaimsSet(p.claims, checks)
		if !valid {
			text := claimReason(reason)
			if err := printVerdict(errw, "Claims", false, text); err != nil {
				return err
			}
			if invalid == nil {
				invalid = fmt.Errorf("%w: %s", errInvalidClaims, text)
			}
		}
	}

	if invalid != nil {
		return invalid
	}

	switch sel.kind {
	case selectHeader:
		return writeSelected(w, p.header, sel, jsonOut)
	case selectPayload:
		// Converted to the plain map type for the formatter's fast path, as in
		// printParsedJWT. The raw parse is used, never the formatTimestamps
		// display copy, so the output stays valid JSON.
		return writeSelected(w, map[string]any(p.claims), sel, jsonOut)
	default:
		value, ok := p.claims[sel.claim]
		if !ok {
			return fmt.Errorf("claim %q not present", sel.claim)
		}
		return writeSelected(w, value, sel, jsonOut)
	}
}

// extractJWE prints only the selected part of an already-parsed JWE. The
// protected header needs no key; the payload and a claim need the plaintext, so
// they fail without one rather than printing nothing. A JWE carries no
// signature or claim verdict of its own, so there is nothing to withhold here
// beyond decryption itself failing.
func extractJWE(w io.Writer, jwe *jose.JSONWebEncryption, header map[string]any, keyStr string, sel selection, jsonOut bool) error {
	if sel.kind == selectHeader {
		return writeSelected(w, header, sel, jsonOut)
	}
	if keyStr == "" {
		flag := "payload"
		if sel.kind == selectClaim {
			flag = "claim"
		}
		return fmt.Errorf("--%s requires --key to decrypt the JWE", flag)
	}

	kid, err := headerKID(header)
	if err != nil {
		return err
	}
	alg, _ := header["alg"].(string)
	key, err := loadKeyForToken(keyStr, keySelector{kid: kid, use: "enc", alg: alg})
	if err != nil {
		return fmt.Errorf("loading decryption key: %w", err)
	}
	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return fmt.Errorf("decrypting JWE: %w", err)
	}

	if sel.kind == selectPayload {
		var value any
		if err := decodeJSON(plaintext, &value); err == nil {
			return writeSelected(w, value, sel, jsonOut)
		}
		_, err := fmt.Fprintln(w, escapeTerminalText(plaintext))
		return err
	}

	// Claims of a token nested inside the JWE are feature #7's territory: the
	// nested token may need a different key, and its claims may need
	// validating, neither of which extraction does yet.
	if isJWEBytes(plaintext) || isJWTBytes(plaintext) {
		return errors.New("--claim on a nested token is not supported yet")
	}
	var claims map[string]any
	if err := decodeJSON(plaintext, &claims); err != nil || claims == nil {
		return errors.New("decrypted payload is not a JSON object")
	}
	value, ok := claims[sel.claim]
	if !ok {
		return fmt.Errorf("claim %q not present", sel.claim)
	}
	return writeSelected(w, value, sel, jsonOut)
}

// writeSelected renders an extracted value. A header or payload is formatted
// JSON (colored only on a TTY) or, under --json, compact JSON. A claim value
// that is a string prints bare, like `jq -r`, escaped for the terminal; every
// other claim value, and any value under --json, prints as compact JSON.
func writeSelected(w io.Writer, v any, sel selection, jsonOut bool) error {
	if jsonOut {
		return writeCompactJSON(w, v)
	}
	if sel.kind == selectClaim {
		if s, ok := v.(string); ok {
			_, err := fmt.Fprintln(w, escapeTerminalText([]byte(s)))
			return err
		}
		return writeCompactJSON(w, v)
	}
	pretty, err := newFormatter().Marshal(v)
	if err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}
	return writeFormattedJSON(w, pretty)
}

// writeCompactJSON encodes v on one line. encoding/json writes json.Number
// exactly and escapes control characters, as writeJSON does for --json.
func writeCompactJSON(w io.Writer, v any) error {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	return nil
}
