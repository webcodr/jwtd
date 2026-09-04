package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
)

// isTimestampClaim reports whether a claim name carries a Unix timestamp that
// is rewritten for display.
func isTimestampClaim(key string) bool {
	switch key {
	case "iat", "exp", "nbf":
		return true
	}
	return false
}

// timeNow returns the current time. It is a variable so tests can pin it and
// make the expired / not-yet-valid annotations deterministic.
var timeNow = time.Now

// The project color scheme. Every colored token in jwtd's output comes from one
// of these, so a color is described in exactly one place.
var (
	labelStyle   = newStyle(color.FgCyan, color.Bold)
	dimStyle     = newStyle(color.Faint)
	validStyle   = newStyle(color.FgGreen, color.Bold)
	invalidStyle = newStyle(color.FgRed, color.Bold)

	keyStyle    = newStyle(color.FgBlue, color.Bold)
	stringStyle = newStyle(color.FgGreen)
	numberStyle = newStyle(color.FgYellow)
	boolStyle   = newStyle(color.FgMagenta)
	nullStyle   = newStyle(color.FgRed)
)

// style is a color from the scheme, with the escape sequences it puts around
// text resolved once instead of on every use.
//
// fatih/color rebuilds both sequences with fmt.Sprintf on each call, which is
// affordable for a handful of labels but not for a token of JSON. The pair is
// derived from the color package itself rather than assembled here, so jwtd's
// output stays tied to its reset handling; only the caching is jwtd's.
type style struct {
	// escapes is memoized, and is derived from a color with EnableColor set,
	// so the sequences do not depend on when they were first resolved. Whether
	// they get used is decided per call against the current NoColor.
	escapes func() styleEscapes
}

// styleEscapes holds the sequences one color emits.
//
// There are two closing sequences because fatih/color uses two: the Sprint
// family closes with a reset per attribute, while the Fprintf family writes a
// plain reset around the whole write. Keeping both is what lets jwtd's output
// stay byte-identical to the calls it replaced.
type styleEscapes struct {
	prefix      string
	wrapSuffix  string
	resetSuffix string
}

// colorWrap is the escape sequence pair around one piece of colored text. The
// zero value is the no-color case, which keeps that output identical to the
// colored path minus the escapes.
type colorWrap struct {
	prefix, suffix string
}

func newStyle(attributes ...color.Attribute) *style {
	c := color.New(attributes...)
	c.EnableColor()
	return &style{escapes: sync.OnceValue(func() styleEscapes { return escapesFor(c) })}
}

// wrap returns the escape pair for text printed like color.Sprint: none when
// color is off.
func (s *style) wrap() colorWrap {
	if color.NoColor {
		return colorWrap{}
	}
	e := s.escapes()
	return colorWrap{prefix: e.prefix, suffix: e.wrapSuffix}
}

// printfWrap returns the escape pair for text printed like color.Fprintf.
func (s *style) printfWrap() colorWrap {
	if color.NoColor {
		return colorWrap{}
	}
	e := s.escapes()
	return colorWrap{prefix: e.prefix, suffix: e.resetSuffix}
}

// escapesFor reads a color's sequences by having it wrap a sentinel byte and
// splitting on it, which is the only way to get at sequences the color package
// keeps unexported — and the reason jwtd cannot drift from its reset handling.
func escapesFor(c *color.Color) styleEscapes {
	const sentinel = "\x00"

	var escapes styleEscapes
	wrapped := c.Sprint(sentinel)
	if i := strings.Index(wrapped, sentinel); i >= 0 {
		escapes.prefix = wrapped[:i]
		escapes.wrapSuffix = wrapped[i+len(sentinel):]
	}

	var printed strings.Builder
	if _, err := c.Fprintf(&printed, sentinel); err == nil {
		if i := strings.Index(printed.String(), sentinel); i >= 0 {
			escapes.resetSuffix = printed.String()[i+len(sentinel):]
		}
	}
	return escapes
}

// fprintln writes text in the style, followed by a newline.
//
// The newline stays outside the colored region, matching color.Fprintln: output
// truncated at the line break cannot leave the attribute active in the
// terminal.
func (s *style) fprintln(w io.Writer, text string) error {
	c := s.wrap()
	_, err := fmt.Fprintln(w, c.prefix+text+c.suffix)
	return err
}

// fprintf writes formatted text in the style. The escapes go around everything
// written, the trailing newline of the format included, matching
// color.Fprintf's set-writer / unset-writer ordering.
func (s *style) fprintf(w io.Writer, format string, a ...any) error {
	c := s.printfWrap()
	if _, err := io.WriteString(w, c.prefix); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, format, a...); err != nil {
		return err
	}
	_, err := io.WriteString(w, c.suffix)
	return err
}

// newFormatter creates a formatter matching the project color scheme.
func newFormatter() *jsonFormatter {
	return &jsonFormatter{
		KeyStyle:    keyStyle,
		StringStyle: stringStyle,
		NumberStyle: numberStyle,
		BoolStyle:   boolStyle,
		NullStyle:   nullStyle,
		Indent:      2,
	}
}

// printDecryptedPayload formats and prints the decrypted JWE plaintext.
// If the plaintext is valid JSON, it is pretty-printed. If the plaintext
// is itself a JWT or JWE, it is decoded and printed recursively.
func printDecryptedPayload(w io.Writer, f *jsonFormatter, plaintext []byte) error {
	// The shape checks run on the bytes, so a payload that is not a nested
	// token — the common case, and the one that can be large — is never copied
	// into a string just to be measured.

	// Check if the decrypted payload is a nested JWE. The nested output is
	// buffered so nothing is printed if decoding fails and the payload falls
	// through to the JSON/raw handling below.
	if isJWEBytes(plaintext) {
		var nested bytes.Buffer
		if err := decodeAndPrintJWE(&nested, string(plaintext), ""); err == nil {
			return printNestedPayload(w, "Decrypted Payload (nested JWE)", nested.Bytes())
		}
	}

	// Check if the decrypted payload is a nested JWT.
	if isJWTBytes(plaintext) {
		var nested bytes.Buffer
		if err := decodeAndPrint(&nested, string(plaintext), ""); err == nil {
			return printNestedPayload(w, "Decrypted Payload (nested JWT)", nested.Bytes())
		}
	}

	// Pretty-print JSON objects and arrays. The payload is decoded once and
	// dispatched on the decoded value, rather than re-parsing per shape.
	var value any
	if err := decodeJSON(plaintext, &value); err == nil {
		switch v := value.(type) {
		case map[string]any:
			formatTimestamps(v)
			return printSection(w, f, "Decrypted Payload", v)
		case []any:
			return printSection(w, f, "Decrypted Payload", v)
		}
	}

	// Fall back to raw text output.
	if err := labelStyle.fprintln(w, "Decrypted Payload"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, escapeTerminalText(plaintext))
	return err
}

func escapeTerminalText(text []byte) string {
	// Fast path: text that is entirely printable ASCII (plus the newline and
	// tab that pass through anyway) is returned as one copy instead of being
	// rebuilt rune by rune. A decrypted JWE payload can be arbitrarily large,
	// and this is the only path that prints one verbatim.
	if isPlainASCIIText(text) {
		return string(text)
	}

	var escaped strings.Builder
	escaped.Grow(len(text))
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
	// Every rune needsJSONEscape rewrites is DEL or above, so text whose bytes
	// are all below DEL is settled by a byte scan without decoding a single
	// rune; anything else falls through to the rune-level check.
	if isBelowDEL(text) {
		return string(text)
	}
	if !bytes.ContainsFunc(text, needsJSONEscape) {
		return string(text)
	}

	var escaped strings.Builder
	escaped.Grow(len(text))
	for len(text) > 0 {
		r, size := utf8.DecodeRune(text)
		if needsJSONEscape(r) {
			fmt.Fprintf(&escaped, `\u%04x`, r)
		} else {
			escaped.Write(text[:size])
		}
		text = text[size:]
	}
	return escaped.String()
}

// isPlainASCIIText reports whether text is entirely printable ASCII, plus the
// newline and tab escapeTerminalText passes through untouched. Such text needs
// no escaping, and deciding it byte by byte avoids decoding runes. Every case
// that escaper does rewrite — the other C0 controls, DEL, the C1 controls, the
// bidi controls, and invalid UTF-8 — has at least one byte outside that range,
// so a false result only ever costs a slow-path pass.
func isPlainASCIIText(text []byte) bool {
	for _, b := range text {
		if b >= 0x7f || (b < 0x20 && b != '\n' && b != '\t') {
			return false
		}
	}
	return true
}

// isBelowDEL reports whether every byte of text is below DEL, which is
// escapeFormattedJSONControls' fast path: everything it rewrites is DEL, a C1
// control, or a bidi control, and each of those has a byte at 0x7f or above.
//
// It deliberately admits the C0 controls that isPlainASCIIText rejects. The
// input here is JSON the formatter has already rendered, so when color is on it
// carries the ESC bytes of the formatter's own ANSI sequences — and reusing the
// stricter predicate would push every colored render, the interactive default,
// onto the rune-decoding pass over text that cannot contain anything to escape.
func isBelowDEL(text []byte) bool {
	for _, b := range text {
		if b >= 0x7f {
			return false
		}
	}
	return true
}

// needsJSONEscape reports whether a rune must be escaped in already-formatted
// JSON: DEL, the C1 controls, and the targeted bidi controls.
func needsJSONEscape(r rune) bool {
	return r == 0x7f || (r >= 0x80 && r <= 0x9f) || isBidiControl(r)
}

func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// printNestedPayload outputs a buffered, successfully decoded nested token
// under the given label.
func printNestedPayload(w io.Writer, label string, decoded []byte) error {
	if err := labelStyle.fprintln(w, label); err != nil {
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
		if !isTimestampClaim(key) {
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

		t, ok := claimTime(text)
		if !ok {
			continue
		}
		formatted := t.Format(time.RFC3339Nano) + " (" + text
		if status := timestampStatus(key, t); status != "" {
			formatted += ", " + status
		}
		data[key] = formatted + ")"
	}
}

// claimTime converts a numeric claim literal to the instant it denotes,
// reporting false for anything that is not a JSON number naming a
// representable time.
//
// A json.Number can be constructed with arbitrary text, so the value is
// re-validated as a JSON number literal first: big.Rat.SetString also accepts
// forms JSON does not (ratios, hex, binary exponents).
func claimTime(text string) (time.Time, bool) {
	// Whole seconds, which every ordinary token uses, are converted directly.
	// The literal is matched against the JSON integer grammar here rather than
	// handed to json.Valid, which would copy it to a []byte first; the forms
	// that grammar excludes still reach the full check below.
	if seconds, ok := jsonIntegerSeconds(text); ok {
		return representableTime(time.Unix(seconds, 0))
	}

	if len(text) == 0 || (text[0] != '-' && (text[0] < '0' || text[0] > '9')) || !json.Valid([]byte(text)) {
		return time.Time{}, false
	}

	// The big.Rat path exists for the fractional and exponent forms JSON also
	// permits, and costs roughly thirty allocations per claim.
	epoch, ok := new(big.Rat).SetString(text)
	if !ok {
		return time.Time{}, false
	}

	seconds := new(big.Int).Quo(epoch.Num(), epoch.Denom())
	if !seconds.IsInt64() {
		return time.Time{}, false
	}

	remainder := new(big.Rat).Sub(epoch, new(big.Rat).SetInt(seconds))
	nanoseconds := new(big.Rat).Mul(remainder, big.NewRat(int64(time.Second), 1))
	nanos := new(big.Int).Quo(nanoseconds.Num(), nanoseconds.Denom())
	if !nanos.IsInt64() {
		return time.Time{}, false
	}

	return representableTime(time.Unix(seconds.Int64(), nanos.Int64()))
}

// jsonIntegerSeconds parses a JSON integer literal as a second count.
//
// The accepted grammar is JSON's own for integers — an optional minus, then a
// single zero or a leading nonzero digit followed by digits — so what it admits
// is a strict subset of what json.Valid would. It reports false for every other
// form, including the fractional and exponent ones and an out-of-range value,
// which then take the exact big.Rat path.
func jsonIntegerSeconds(text string) (int64, bool) {
	digits := strings.TrimPrefix(text, "-")
	if digits == "" || (digits[0] == '0' && len(digits) > 1) {
		return 0, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}

	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return seconds, true
}

// representableTime rejects instants outside the four-digit year range
// RFC3339 can render.
func representableTime(t time.Time) (time.Time, bool) {
	t = t.UTC()
	if t.Year() < 0 || t.Year() > 9999 {
		return time.Time{}, false
	}
	return t, true
}

// timestampStatus returns an informational note describing a claim's time
// relative to now: an "exp" is annotated with how long ago it expired or how
// long until it does, and an "nbf" still in the future with how long until it
// becomes valid. An "nbf" already in the past is the ordinary active state and
// gets no note. It is display-only and never affects signature verification or
// the exit code, which stay purely cryptographic.
func timestampStatus(key string, t time.Time) string {
	now := timeNow()
	switch key {
	case "exp":
		if t.Before(now) {
			return "expired " + humanizeDuration(now.Sub(t)) + " ago"
		}
		return "expires in " + humanizeDuration(t.Sub(now))
	case "nbf":
		if now.Before(t) {
			return "not yet valid, in " + humanizeDuration(t.Sub(now))
		}
	}
	return ""
}

// humanizeDuration renders a non-negative approximation of d using its largest
// whole unit (seconds, minutes, hours, or days), truncating toward zero so the
// output is deterministic. It is meant for a compact at-a-glance annotation, not
// exact arithmetic; the raw epoch value stays alongside it for that.
func humanizeDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int64(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int64(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int64(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int64(d.Hours())/24)
	}
}

// printSection outputs a labeled, pretty-printed JSON section.
func printSection(w io.Writer, f *jsonFormatter, label string, data any) error {
	if err := labelStyle.fprintln(w, label); err != nil {
		return err
	}

	pretty, err := f.Marshal(data)
	if err != nil {
		return fmt.Errorf("formatting %s: %w", label, err)
	}
	return writeFormattedJSON(w, pretty)
}

// writeFormattedJSON writes already-formatted JSON, sanitized for the terminal.
// Output that needs no escaping — the ordinary case, and the one that can be
// megabytes — goes straight to the writer instead of through a second copy of
// itself.
func writeFormattedJSON(w io.Writer, pretty []byte) error {
	// escapeFormattedJSONControls decides the fast path itself, so the buffer
	// is scanned once here rather than once per function.
	escaped := escapeFormattedJSONControls(pretty)
	if _, err := io.WriteString(w, escaped); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// printVerdict renders a "<label>: VALID" / "<label>: INVALID" line, with the
// reason dimmed beneath a failure. The signature and claim checks are
// independent verdicts (see AGENTS.md) but share this rendering, so they cannot
// drift apart visually.
func printVerdict(w io.Writer, label string, valid bool, reason string) error {
	if valid {
		return validStyle.fprintln(w, label+": VALID")
	}
	if err := invalidStyle.fprintln(w, label+": INVALID"); err != nil {
		return err
	}
	return dimStyle.fprintf(w, "  %s\n", reason)
}

// printSignature outputs the raw signature string in dimmed text.
func printSignature(w io.Writer, sig string) error {
	if err := labelStyle.fprintln(w, "Signature"); err != nil {
		return err
	}
	return dimStyle.fprintln(w, sig)
}
