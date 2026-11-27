package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// extractLayer prints only the selected part of an opened token.
//
// Every requested check has run by now: signatures at every depth while the
// token was opened, and the claims here, over the innermost claims set. If any
// check failed, nothing is written to w: the failing verdicts go to errw and
// the matching sentinel is returned, an invalid signature taking precedence.
// Extraction exists for `$(...)` capture in scripts, and a script that forgets
// `set -e` must still never receive a value that failed a check it asked for.
// The verdicts are printed here, not left to the top-level printer, because
// that printer deliberately silences the sentinels (the human output prints
// its own verdict).
func extractLayer(w, errw io.Writer, l *tokenLayer, checks claimChecks, sel selection, jsonOut bool) error {
	var invalid error
	if f := l.signatureFailure(); f != nil {
		if err := printVerdict(errw, "Signature", false, f.reason); err != nil {
			return err
		}
		invalid = fmt.Errorf("%w: %s", errInvalidSignature, f.reason)
	}

	if checks.requested() {
		claims, reason := l.claimsTarget()
		if reason == "" {
			if valid, verr := validateClaimsSet(claims, checks); !valid {
				reason = claimReason(verr)
			}
		}
		if reason != "" {
			if err := printVerdict(errw, "Claims", false, reason); err != nil {
				return err
			}
			if invalid == nil {
				invalid = fmt.Errorf("%w: %s", errInvalidClaims, reason)
			}
		}
	}

	if invalid != nil {
		return invalid
	}

	switch sel.kind {
	case selectHeader:
		// The outermost header. On a JWE a given key was already used while
		// opening, so a wrong key failed there instead of printing a header it
		// could not authenticate (the header is the AEAD's associated data).
		if l.jws != nil {
			return writeSelected(w, l.jws.header, sel, jsonOut)
		}
		return writeSelected(w, l.header, sel, jsonOut)
	case selectPayload:
		return writeInnermostPayload(w, l, sel, jsonOut)
	default:
		if l.jwe != nil && !l.decrypted {
			return errors.New("--claim requires --key to decrypt the JWE")
		}
		claims, reason := l.claimsTarget()
		if reason != "" {
			return errors.New(reason)
		}
		value, ok := claims[sel.claim]
		if !ok {
			return fmt.Errorf("claim %q not present", sel.claim)
		}
		return writeSelected(w, value, sel, jsonOut)
	}
}

// writeInnermostPayload prints the payload of the deepest layer: a JWS's claims,
// or a decrypted JWE's JSON value or text. "Payload" means the claims for a JWT,
// so it does for a JWT wrapped in a JWE too.
func writeInnermostPayload(w io.Writer, l *tokenLayer, sel selection, jsonOut bool) error {
	in := l.innermost()
	if in.jws != nil {
		// Converted to the plain map type for the formatter's fast path, as in
		// renderJWSHuman. The raw parse is used, never the formatTimestamps
		// display copy, so the output stays valid JSON.
		return writeSelected(w, map[string]any(in.jws.claims), sel, jsonOut)
	}
	if !in.decrypted {
		if in == l {
			return errors.New("--payload requires --key to decrypt the JWE")
		}
		return errors.New(reasonNestedUndecrypted)
	}
	var value any
	if err := decodeJSON(in.plaintext, &value); err == nil {
		return writeSelected(w, value, sel, jsonOut)
	}
	// A text plaintext is still JSON under --json, as jsonPayloadValue reports
	// it, so a --json consumer never receives raw text.
	if jsonOut {
		return writeCompactJSON(w, string(in.plaintext))
	}
	_, err := fmt.Fprintln(w, escapeTerminalText(in.plaintext))
	return err
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
		// encoding/json leaves C1 controls, DEL, and bidi overrides as raw
		// bytes inside strings. Rewriting them as \u escapes keeps the same JSON
		// value while keeping them off the terminal, as --payload does.
		var buf bytes.Buffer
		if err := writeCompactJSON(&buf, v); err != nil {
			return err
		}
		_, err := io.WriteString(w, escapeFormattedJSONControls(buf.Bytes()))
		return err
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
