package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/hokaccha/go-prettyjson"
)

var timestampKeyNames = []string{"iat", "exp", "nbf"}

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
