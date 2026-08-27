package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
)

// jsonFormatter renders a decoded JSON value as indented, syntax-highlighted
// text. It replaces go-prettyjson, whose output it reproduces byte for byte —
// TestFormatterMatchesPrettyJSON pins that against the library itself, which is
// kept as a test-only dependency for exactly that purpose.
//
// The library marshalled the value back to JSON and re-decoded it before
// formatting, then built the result by concatenating a string per token, each
// one passed through fmt.Sprintf and re-deriving its ANSI escapes. jwtd already
// holds the decoded value, so the round trip is pure overhead; this walks the
// value straight into one buffer with the escapes computed once per section.
type jsonFormatter struct {
	// The styles are the project scheme, applied per JSON token type.
	KeyStyle    *style
	StringStyle *style
	NumberStyle *style
	BoolStyle   *style
	NullStyle   *style

	// Indent is the number of spaces per nesting level.
	Indent int

	out bytes.Buffer

	// quoted is the scratch buffer quote writes through. Strings are quoted by
	// encoding/json itself rather than by a hand-rolled escaper, so the output
	// cannot drift from what the standard library produces for a JSON string.
	quoted  bytes.Buffer
	encoder *json.Encoder

	key, str, num, boolean, null colorWrap
}

// errUnformattableValue signals that the walk met a value outside the set of
// types a JSON decode produces, so the caller falls back to the round trip that
// normalizes it. It is never returned to callers of Marshal.
var errUnformattableValue = errors.New("value is not a decoded JSON value")

// Marshal formats a value as colored, indented JSON.
//
// Values produced by a JSON decode — the only kind jwtd formats in practice —
// are walked directly. Anything else (a float64, a named map type, a struct) is
// first marshalled and re-decoded so it arrives as one of those types, which is
// what go-prettyjson did unconditionally and is what makes the two agree on
// values the fast path cannot take.
func (f *jsonFormatter) Marshal(v any) ([]byte, error) {
	f.key = f.KeyStyle.wrap()
	f.str = f.StringStyle.wrap()
	f.num = f.NumberStyle.wrap()
	f.boolean = f.BoolStyle.wrap()
	f.null = f.NullStyle.wrap()

	f.out.Reset()
	f.quoted.Reset()
	if f.encoder == nil {
		f.encoder = json.NewEncoder(&f.quoted)
		f.encoder.SetEscapeHTML(false)
	}

	if err := f.write(v, 1); err == nil {
		return f.out.Bytes(), nil
	} else if !errors.Is(err, errUnformattableValue) {
		return nil, err
	}

	normalized, err := normalizeJSONValue(v)
	if err != nil {
		return nil, err
	}

	f.out.Reset()
	if err := f.write(normalized, 1); err != nil {
		return nil, err
	}
	return f.out.Bytes(), nil
}

// normalizeJSONValue marshals a value and decodes it again with exact
// json.Number values, so it comes back as the string / json.Number / bool /
// nil / map / slice set the walk understands.
func normalizeJSONValue(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func (f *jsonFormatter) write(v any, depth int) error {
	switch val := v.(type) {
	case nil:
		f.writeColored(f.null, "null")
	case string:
		return f.writeQuoted(f.str, val)
	case json.Number:
		f.writeColored(f.num, string(val))
	case bool:
		f.writeColored(f.boolean, strconv.FormatBool(val))
	case map[string]any:
		return f.writeMap(val, depth)
	case []any:
		return f.writeArray(val, depth)
	default:
		return errUnformattableValue
	}
	return nil
}

func (f *jsonFormatter) writeMap(m map[string]any, depth int) error {
	if len(m) == 0 {
		f.out.WriteString("{}")
		return nil
	}

	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	f.out.WriteString("{\n")
	for i, key := range keys {
		if i > 0 {
			f.out.WriteString(",\n")
		}
		f.writeIndent(depth)
		if err := f.writeQuoted(f.key, key); err != nil {
			return err
		}
		f.out.WriteString(": ")
		if err := f.write(m[key], depth+1); err != nil {
			return err
		}
	}
	f.out.WriteByte('\n')
	f.writeIndent(depth - 1)
	f.out.WriteByte('}')
	return nil
}

func (f *jsonFormatter) writeArray(a []any, depth int) error {
	if len(a) == 0 {
		f.out.WriteString("[]")
		return nil
	}

	f.out.WriteString("[\n")
	for i, val := range a {
		if i > 0 {
			f.out.WriteString(",\n")
		}
		f.writeIndent(depth)
		if err := f.write(val, depth+1); err != nil {
			return err
		}
	}
	f.out.WriteByte('\n')
	f.writeIndent(depth - 1)
	f.out.WriteByte(']')
	return nil
}

// writeQuoted writes a string as a colored JSON string literal, with HTML
// escaping disabled.
//
// The quoting is done by encoding/json rather than by a hand-rolled escaper, so
// the output cannot drift from what the standard library produces; the literal
// goes from the scratch buffer straight into the output, so a string costs no
// allocation of its own.
func (f *jsonFormatter) writeQuoted(c colorWrap, s string) error {
	// Strings that JSON quoting would copy verbatim are written with their
	// quotes and nothing else. Most claim values and every key are such
	// strings, and the encoder path costs an allocation per call.
	if isUnescapedJSONString(s) {
		f.out.WriteString(c.prefix)
		f.out.WriteByte('"')
		f.out.WriteString(s)
		f.out.WriteByte('"')
		f.out.WriteString(c.suffix)
		return nil
	}

	f.quoted.Reset()
	if err := f.encoder.Encode(s); err != nil {
		return err
	}
	// Encode appends a newline that is not part of the literal.
	literal := bytes.TrimSuffix(f.quoted.Bytes(), []byte("\n"))

	f.out.WriteString(c.prefix)
	f.out.Write(literal)
	f.out.WriteString(c.suffix)
	return nil
}

func (f *jsonFormatter) writeColored(c colorWrap, text string) {
	f.out.WriteString(c.prefix)
	f.out.WriteString(text)
	f.out.WriteString(c.suffix)
}

// indentSpaces is sliced for indentation, so nesting costs a copy rather than a
// strings.Repeat allocation per line. Depths past it fall back to a loop.
const indentSpaces = "                                                                "

func (f *jsonFormatter) writeIndent(depth int) {
	width := f.Indent * depth
	for width > len(indentSpaces) {
		f.out.WriteString(indentSpaces)
		width -= len(indentSpaces)
	}
	f.out.WriteString(indentSpaces[:width])
}

// isUnescapedJSONString reports whether a JSON string literal for s is exactly
// s in quotes.
//
// It admits only printable ASCII minus the two characters JSON always escapes,
// and minus the three encoding/json escapes when HTML escaping is on. Those
// three are excluded even though the formatter's encoder has HTML escaping off,
// so the fast path stays correct on its own terms rather than on that setting.
// Everything it rejects — including every multi-byte rune and every invalid
// byte — goes to encoding/json, which stays the only place quoting is decided.
func isUnescapedJSONString(s string) bool {
	for i := range len(s) {
		switch b := s[i]; {
		case b < 0x20 || b > 0x7e:
			return false
		case b == '"' || b == '\\':
			return false
		case b == '<' || b == '>' || b == '&':
			return false
		}
	}
	return true
}
