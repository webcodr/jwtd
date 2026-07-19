package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEscapeTerminalText(t *testing.T) {
	allC0 := make([]byte, 0x20)
	var escapedC0 strings.Builder
	for b := byte(0); b < 0x20; b++ {
		allC0[b] = b
		if b == '\t' || b == '\n' {
			escapedC0.WriteByte(b)
		} else {
			fmt.Fprintf(&escapedC0, `\x%02x`, b)
		}
	}

	var allC1 strings.Builder
	var escapedC1 strings.Builder
	for r := rune(0x80); r <= 0x9f; r++ {
		allC1.WriteRune(r)
		fmt.Fprintf(&escapedC1, `\u%04x`, r)
	}

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "safe UTF-8", input: []byte("plain cafe\u0301 世界"), want: "plain cafe\u0301 世界"},
		{name: "newline and tab", input: []byte("first\n\tsecond"), want: "first\n\tsecond"},
		{name: "carriage return", input: []byte("first\rsecond"), want: `first\x0dsecond`},
		{name: "all C0 controls", input: allC0, want: escapedC0.String()},
		{name: "DEL", input: []byte{'a', 0x7f, 'b'}, want: `a\x7fb`},
		{name: "all C1 controls", input: []byte(allC1.String()), want: escapedC1.String()},
		{name: "invalid UTF-8 bytes", input: []byte{'a', 0xff, 0x80, 0xc2, 'b'}, want: `a\xff\x80\xc2b`},
		{name: "invalid UTF-8 sequence", input: []byte{0xe2, '(', 0xa1}, want: `\xe2(\xa1`},
		{name: "overlong UTF-8", input: []byte{0xc0, 0xaf}, want: `\xc0\xaf`},
		{name: "zero width joiner remains safe", input: []byte("a\u200db"), want: "a\u200db"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeTerminalText(tt.input); got != tt.want {
				t.Errorf("escapeTerminalText(% x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTextEscapersEscapeBidiControls(t *testing.T) {
	controls := []rune{
		'\u061c', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069',
	}
	for _, control := range controls {
		t.Run(fmt.Sprintf("U+%04X", control), func(t *testing.T) {
			input := []byte("a" + string(control) + "b")
			want := fmt.Sprintf(`a\u%04xb`, control)
			if got := escapeTerminalText(input); got != want {
				t.Errorf("escapeTerminalText(%q) = %q, want %q", input, got, want)
			}
			if got := escapeFormattedJSONControls(input); got != want {
				t.Errorf("escapeFormattedJSONControls(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestEscapeFormattedJSONControls(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "trusted ANSI and C1",
			input: "\x1b[32mkey: value\u009b\u009d\u009c\x1b[0m",
			want:  "\x1b[32mkey: value\\u009b\\u009d\\u009c\x1b[0m",
		},
		{name: "DEL", input: "a\x7fb", want: `a\u007fb`},
		{name: "safe Unicode and zero width joiner", input: "cafe\u0301 \u200d 世界", want: "cafe\u0301 \u200d 世界"},
		{name: "already escaped controls", input: `\u007f \u009b \u061c \u202e \u2066`, want: `\u007f \u009b \u061c \u202e \u2066`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeFormattedJSONControls([]byte(tt.input)); got != tt.want {
				t.Errorf("escapeFormattedJSONControls(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- formatTimestamps --------------------------------------------------------

func TestFormatTimestamps_AllTimestampFields(t *testing.T) {
	data := map[string]any{
		"iat": float64(1516239022),
		"exp": float64(1716239022),
		"nbf": float64(1516239022),
	}

	formatTimestamps(data)

	expected := fmt.Sprintf("%s (%d)", time.Unix(1516239022, 0).UTC().Format(time.RFC3339), 1516239022)
	if data["iat"] != expected {
		t.Errorf("iat: expected %q, got %v", expected, data["iat"])
	}
	if data["nbf"] != expected {
		t.Errorf("nbf: expected %q, got %v", expected, data["nbf"])
	}

	expectedExp := fmt.Sprintf("%s (%d)", time.Unix(1716239022, 0).UTC().Format(time.RFC3339), 1716239022)
	if data["exp"] != expectedExp {
		t.Errorf("exp: expected %q, got %v", expectedExp, data["exp"])
	}
}

func TestFormatTimestamps_NonTimestampFieldsUnchanged(t *testing.T) {
	data := map[string]any{
		"sub":  "1234567890",
		"name": "John Doe",
		"num":  float64(42),
	}

	formatTimestamps(data)

	if data["sub"] != "1234567890" {
		t.Errorf("sub changed: %v", data["sub"])
	}
	if data["name"] != "John Doe" {
		t.Errorf("name changed: %v", data["name"])
	}
	if data["num"] != float64(42) {
		t.Errorf("num changed: %v", data["num"])
	}
}

func TestFormatTimestamps_MixedFields(t *testing.T) {
	data := map[string]any{
		"sub": "user123",
		"iat": float64(0),
		"exp": float64(1700000000),
	}

	formatTimestamps(data)

	if data["sub"] != "user123" {
		t.Errorf("sub changed: %v", data["sub"])
	}

	expectedIat := fmt.Sprintf("%s (%d)", time.Unix(0, 0).UTC().Format(time.RFC3339), 0)
	if data["iat"] != expectedIat {
		t.Errorf("iat: expected %q, got %v", expectedIat, data["iat"])
	}

	expectedExp := fmt.Sprintf("%s (%d)", time.Unix(1700000000, 0).UTC().Format(time.RFC3339), 1700000000)
	if data["exp"] != expectedExp {
		t.Errorf("exp: expected %q, got %v", expectedExp, data["exp"])
	}
}

func TestFormatTimestamps_NonNumericTimestampField(t *testing.T) {
	data := map[string]any{
		"iat": "not-a-number",
	}

	formatTimestamps(data)

	if data["iat"] != "not-a-number" {
		t.Errorf("non-numeric iat was modified: %v", data["iat"])
	}
}

func TestFormatTimestamps_EmptyMap(t *testing.T) {
	data := map[string]any{}
	formatTimestamps(data) // should not panic
	if len(data) != 0 {
		t.Errorf("empty map modified: %v", data)
	}
}

func TestFormatTimestamps_OutputFormat(t *testing.T) {
	data := map[string]any{
		"iat": float64(1516239022),
	}

	formatTimestamps(data)

	val, ok := data["iat"].(string)
	if !ok {
		t.Fatalf("iat should be a string after formatting, got %T", data["iat"])
	}

	if !strings.Contains(val, "2018-01-18T01:30:22Z") {
		t.Errorf("expected RFC3339 date in output, got %s", val)
	}

	if !strings.Contains(val, "1516239022") {
		t.Errorf("expected original epoch in output, got %s", val)
	}

	if val != "2018-01-18T01:30:22Z (1516239022)" {
		t.Errorf("expected '2018-01-18T01:30:22Z (1516239022)', got %s", val)
	}
}

func TestFormatTimestamps_JSONNumber(t *testing.T) {
	tests := []struct {
		name     string
		value    json.Number
		expected any
	}{
		{
			name:     "fractional",
			value:    json.Number("1516239022.75"),
			expected: "2018-01-18T01:30:22.75Z (1516239022.75)",
		},
		{
			name:     "negative fractional",
			value:    json.Number("-0.25"),
			expected: "1969-12-31T23:59:59.75Z (-0.25)",
		},
		{
			name:     "exponent",
			value:    json.Number("1.51623902275e9"),
			expected: "2018-01-18T01:30:22.75Z (1.51623902275e9)",
		},
		{
			name:     "out of RFC3339 range",
			value:    json.Number("253402300800"),
			expected: json.Number("253402300800"),
		},
		{
			name:     "overflows int64 seconds",
			value:    json.Number("1000000000000000000000000000000"),
			expected: json.Number("1000000000000000000000000000000"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"iat": tt.value}

			formatTimestamps(data)

			if data["iat"] != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, data["iat"])
			}
		})
	}
}

func TestFormatTimestamps_InvalidJSONNumbersUnchanged(t *testing.T) {
	tests := []struct {
		name  string
		value json.Number
	}{
		{name: "fraction", value: json.Number("1/2")},
		{name: "hexadecimal", value: json.Number("0x10")},
		{name: "binary exponent", value: json.Number("1p2")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{"iat": tt.value}

			formatTimestamps(data)

			got, ok := data["iat"].(json.Number)
			if !ok {
				t.Fatalf("expected unchanged json.Number, got %T (%v)", data["iat"], data["iat"])
			}
			if !bytes.Equal([]byte(got), []byte(tt.value)) {
				t.Errorf("expected unchanged text %q, got %q", tt.value, got)
			}
		})
	}
}

func TestFormatTimestamps_FractionalFloat64(t *testing.T) {
	data := map[string]any{"iat": float64(1516239022.75)}

	formatTimestamps(data)

	const expected = "2018-01-18T01:30:22.75Z (1516239022.75)"
	if data["iat"] != expected {
		t.Errorf("expected %q, got %q", expected, data["iat"])
	}
}

// --- newFormatter ------------------------------------------------------------

func TestNewFormatter_ReturnsFormatter(t *testing.T) {
	f := newFormatter()
	if f == nil {
		t.Fatal("newFormatter returned nil")
	}
	if f.Indent != 2 {
		t.Errorf("expected indent 2, got %d", f.Indent)
	}
}

func TestNewFormatter_MarshalContainsAllValues(t *testing.T) {
	f := newFormatter()
	data := map[string]any{
		"key":  "value",
		"num":  float64(42),
		"flag": true,
		"none": nil,
	}

	out, err := f.Marshal(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(string(out))

	checks := []string{`"key"`, `"value"`, "42", "true", "null"}
	for _, check := range checks {
		if !strings.Contains(plain, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestNewFormatter_IndentsOutput(t *testing.T) {
	f := newFormatter()
	data := map[string]any{
		"key": "value",
	}

	out, err := f.Marshal(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(string(out))
	if !strings.Contains(plain, "  ") {
		t.Error("output not indented")
	}
}

// --- printSection ------------------------------------------------------------

func TestPrintSection_ContainsLabelAndData(t *testing.T) {
	f := newFormatter()
	data := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}

	var buf bytes.Buffer
	printSection(&buf, f, "Header", data)

	plain := stripANSI(buf.String())

	if !strings.HasPrefix(plain, "Header\n") {
		t.Errorf("expected output to start with 'Header\\n', got: %q", plain[:min(len(plain), 20)])
	}
	if !strings.Contains(plain, `"alg"`) {
		t.Error("output missing alg field")
	}
	if !strings.Contains(plain, "HS256") {
		t.Error("output missing HS256 value")
	}
	if !strings.Contains(plain, `"typ"`) {
		t.Error("output missing typ field")
	}
}

func TestPrintSection_FormatsJSON(t *testing.T) {
	f := newFormatter()
	data := map[string]any{
		"a": float64(1),
		"b": "two",
	}

	var buf bytes.Buffer
	printSection(&buf, f, "Test", data)

	plain := stripANSI(buf.String())

	// Should be pretty-printed (multi-line with indentation)
	lines := strings.Split(strings.TrimSpace(plain), "\n")
	if len(lines) < 3 {
		t.Errorf("expected multi-line output, got %d lines", len(lines))
	}
}

// --- printSignature ----------------------------------------------------------

func TestPrintSignature_Output(t *testing.T) {
	var buf bytes.Buffer
	printSignature(&buf, "abc123sig")

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "Signature") {
		t.Error("missing Signature label")
	}
	if !strings.Contains(plain, "abc123sig") {
		t.Error("missing signature value")
	}
}

func TestPrintSignature_LabelsOnSeparateLines(t *testing.T) {
	var buf bytes.Buffer
	printSignature(&buf, "mysig")

	plain := stripANSI(buf.String())
	lines := strings.Split(strings.TrimSpace(plain), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if strings.TrimSpace(lines[0]) != "Signature" {
		t.Errorf("first line should be 'Signature', got %q", lines[0])
	}
	if strings.TrimSpace(lines[1]) != "mysig" {
		t.Errorf("second line should be 'mysig', got %q", lines[1])
	}
}
