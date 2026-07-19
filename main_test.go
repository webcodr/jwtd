package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

// helper to build a JWT from raw JSON header/payload and a signature string.
func makeJWT(headerJSON, payloadJSON, sig string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return h + "." + p + "." + sig
}

func makeHMACJWTWithRawPayload(t *testing.T, payload string, key []byte) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingString := header + "." + encodedPayload
	signature, err := jwt.SigningMethodHS256.Sign(signingString, key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signingString + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// stripANSI removes ANSI escape sequences from a string for easier assertion.
func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++ // skip the 'm'
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func assertEscapedControlRunes(t *testing.T, output []byte, controls ...rune) {
	t.Helper()
	for _, control := range controls {
		visible := fmt.Sprintf(`\u%04x`, control)
		if !bytes.Contains(output, []byte(visible)) {
			t.Errorf("output missing visible escape %q:\n%q", visible, output)
		}
		if encoded := []byte(string(control)); bytes.Contains(output, encoded) {
			t.Errorf("output contains literal UTF-8 control U+%04X (% x):\n%q", control, encoded, output)
		}
	}
}

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

// --- decodeAndPrint ----------------------------------------------------------

func TestDecodeAndPrint_ValidJWT(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		"test-signature",
	)

	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "Header") {
		t.Error("output missing Header label")
	}
	if !strings.Contains(plain, "Payload") {
		t.Error("output missing Payload label")
	}
	if !strings.Contains(plain, "Signature") {
		t.Error("output missing Signature label")
	}
	if !strings.Contains(plain, "test-signature") {
		t.Error("output missing signature value")
	}
	if !strings.Contains(plain, `"alg"`) {
		t.Error("output missing alg key")
	}
	if !strings.Contains(plain, "HS256") {
		t.Error("output missing HS256 value")
	}
	if !strings.Contains(plain, `"name"`) {
		t.Error("output missing name key")
	}
	if !strings.Contains(plain, "John Doe") {
		t.Error("output missing John Doe value")
	}
}

func TestDecodeAndPrint_WrongPartCount(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"no dots", "abcdef"},
		{"one dot", "abc.def"},
		{"three dots", "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := decodeAndPrint(&buf, tt.token, "")
			if err == nil {
				t.Fatal("expected error for wrong part count")
			}
		})
	}
}

func TestDecodeAndPrint_InvalidHeader(t *testing.T) {
	token := "!!!." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"123"}`)) +
		".sig"

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
}

func TestDecodeAndPrint_InvalidPayload(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) +
		".!!!." +
		"sig"

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

func TestDecodeAndPrint_EmptyToken(t *testing.T) {
	var buf bytes.Buffer
	err := decodeAndPrint(&buf, "", "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestDecodeAndPrint_TokenWithNestedObject(t *testing.T) {
	token := makeJWT(
		`{"alg":"RS256"}`,
		`{"data":{"nested":"value"},"arr":[1,2,3]}`,
		"sig",
	)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())
	if !strings.Contains(plain, "nested") {
		t.Error("output missing nested key")
	}
	if !strings.Contains(plain, "value") {
		t.Error("output missing nested value")
	}
}

func TestDecodeAndPrint_EscapesFormattedDELAndBidiControls(t *testing.T) {
	token := makeJWT(
		`{"alg":"none"}`,
		`{"key\u007f":"del","del":"\u007f","key\u061c":"bidi","lrm":"\u200e","rlm":"\u200f","override":"\u202e","isolate":"\u2066"}`,
		"",
	)

	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.Bytes()
	assertEscapedControlRunes(t, output, '\x7f', '\u061c', '\u200e', '\u200f', '\u202e', '\u2066')
	for _, visible := range []string{`key\u007f`, `key\u061c`} {
		if !bytes.Contains(output, []byte(visible)) {
			t.Errorf("output missing escaped key %q:\n%q", visible, output)
		}
	}
}

func TestDecodeAndPrint_PreservesLargeJSONNumber(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256"}`,
		`{"value":9007199254740993}`,
		"sig",
	)

	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())
	if !strings.Contains(plain, "9007199254740993") {
		t.Errorf("output did not preserve large JSON number:\n%s", plain)
	}
}

func TestDecodeAndPrint_RejectsTrailingJWTClaimsData(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "trailing junk", payload: `{"value":9007199254740993} trailing-junk`},
		{name: "second JSON value", payload: `{"value":9007199254740993} {"second":true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := makeJWT(`{"alg":"HS256"}`, tt.payload, "sig")

			var buf bytes.Buffer
			err := decodeAndPrint(&buf, token, "")
			if err == nil {
				t.Fatal("expected malformed JWT claims error")
			}
			if !strings.Contains(err.Error(), "parsing JWT claims") {
				t.Errorf("expected JWT claims parsing error, got: %v", err)
			}
			if output := stripANSI(buf.String()); strings.Contains(output, "Payload") {
				t.Errorf("malformed claims rendered as a normal payload:\n%s", output)
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

func TestDecodeJSON_UsesJSONNumberAndRejectsTrailingValues(t *testing.T) {
	var data map[string]any
	if err := decodeJSON([]byte(`{"value":9007199254740993}`), &data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := data["value"]; got != json.Number("9007199254740993") {
		t.Errorf("expected preserved json.Number, got %v (%T)", got, got)
	}

	if err := decodeJSON([]byte(`{"first":1} {"second":2}`), &data); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}

func TestDecodeAndPrint_TimestampsFormatted(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256"}`,
		`{"sub":"user1","iat":1516239022,"exp":1716239022,"nbf":1516239022}`,
		"sig",
	)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "2018-01-18T01:30:22Z") {
		t.Error("output missing formatted iat/nbf date")
	}
	if !strings.Contains(plain, "2024-05-20T") {
		t.Error("output missing formatted exp date")
	}
	if !strings.Contains(plain, "(1516239022)") {
		t.Error("output missing original iat/nbf epoch value")
	}
	if !strings.Contains(plain, "(1716239022)") {
		t.Error("output missing original exp epoch value")
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

// --- readToken ---------------------------------------------------------------

func TestReadToken_FromArgs(t *testing.T) {
	token, err := readToken([]string{"my.jwt.token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my.jwt.token" {
		t.Errorf("expected my.jwt.token, got %q", token)
	}
}

func TestReadToken_TrimsWhitespace(t *testing.T) {
	token, err := readToken([]string{"  my.jwt.token  \n"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my.jwt.token" {
		t.Errorf("expected my.jwt.token, got %q", token)
	}
}

func TestReadToken_StripsInternalWhitespace(t *testing.T) {
	token, err := readToken([]string{"my.\njwt\n.token\n"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my.jwt.token" {
		t.Errorf("expected my.jwt.token, got %q", token)
	}
}

func TestReadToken_FromStdinPipe_WrappedToken(t *testing.T) {
	origStdin := os.Stdin

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	go func() {
		fmt.Fprint(w, "header.\npayload.\nsignature\n")
		w.Close()
	}()

	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	token, err := readToken([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "header.payload.signature" {
		t.Errorf("expected header.payload.signature, got %q", token)
	}
}

func TestReadToken_FromStdinPipe(t *testing.T) {
	origStdin := os.Stdin

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	go func() {
		fmt.Fprint(w, "header.payload.signature\n")
		w.Close()
	}()

	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	token, err := readToken([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "header.payload.signature" {
		t.Errorf("expected header.payload.signature, got %q", token)
	}
}

// --- end-to-end via decodeAndPrint -------------------------------------------

func TestDecodeAndPrint_EndToEnd(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	checks := []string{
		`"alg"`,
		"HS256",
		`"typ"`,
		"JWT",
		`"sub"`,
		"1234567890",
		`"name"`,
		"John Doe",
		"2018-01-18T01:30:22Z",
		"Header",
		"Payload",
		"Signature",
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}
	for _, check := range checks {
		if !strings.Contains(plain, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestDecodeAndPrint_SectionOrder(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256"}`,
		`{"sub":"test"}`,
		"sig",
	)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	headerIdx := strings.Index(plain, "Header")
	payloadIdx := strings.Index(plain, "Payload")
	sigIdx := strings.Index(plain, "Signature")

	if headerIdx == -1 || payloadIdx == -1 || sigIdx == -1 {
		t.Fatal("missing one or more section labels")
	}
	if !(headerIdx < payloadIdx && payloadIdx < sigIdx) {
		t.Errorf("sections out of order: Header@%d, Payload@%d, Signature@%d",
			headerIdx, payloadIdx, sigIdx)
	}
}

// --- JWE helpers -------------------------------------------------------------

// generateRSAKey creates a fresh RSA key pair for testing.
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

// encryptJWE creates a JWE compact serialization token encrypting the given plaintext.
func encryptJWE(t *testing.T, key *rsa.PrivateKey, plaintext []byte) string {
	t.Helper()
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &key.PublicKey},
		nil,
	)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	jwe, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWE: %v", err)
	}
	return compact
}

// writeKeyFile writes an RSA private key to a temp PEM file and returns the path.
func writeKeyFile(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-key.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// generateECKey creates a fresh ECDSA P-256 key pair for testing.
func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	return key
}

// writeECKeyFile writes an ECDSA private key to a temp PEM file and returns the path.
func writeECKeyFile(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling EC key: %v", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-ec-key.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// writeSymmetricKeyFile writes raw symmetric key bytes to a temp file and returns the path.
func writeSymmetricKeyFile(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-sym-key.bin")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatalf("writing symmetric key file: %v", err)
	}
	return path
}

// encryptJWEGeneric creates a JWE compact serialization with the given algorithms and key.
func encryptJWEGeneric(t *testing.T, keyAlg jose.KeyAlgorithm, contentEnc jose.ContentEncryption, encryptionKey any, plaintext []byte) string {
	t.Helper()
	rcpt := jose.Recipient{Algorithm: keyAlg, Key: encryptionKey}
	enc, err := jose.NewEncrypter(contentEnc, rcpt, nil)
	if err != nil {
		t.Fatalf("creating encrypter (%s/%s): %v", keyAlg, contentEnc, err)
	}
	jwe, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting (%s/%s): %v", keyAlg, contentEnc, err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWE (%s/%s): %v", keyAlg, contentEnc, err)
	}
	return compact
}

// symmetricKeyForEnc returns a random symmetric key of the correct size for the
// given content encryption algorithm when used with direct key agreement.
func symmetricKeyForEnc(t *testing.T, enc jose.ContentEncryption) []byte {
	t.Helper()
	var size int
	switch enc {
	case jose.A128CBC_HS256:
		size = 32
	case jose.A192CBC_HS384:
		size = 48
	case jose.A256CBC_HS512:
		size = 64
	case jose.A128GCM:
		size = 16
	case jose.A192GCM:
		size = 24
	case jose.A256GCM:
		size = 32
	default:
		t.Fatalf("unknown content encryption: %s", enc)
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating symmetric key: %v", err)
	}
	return key
}

// --- isJWE -------------------------------------------------------------------

func TestIsJWE_FiveParts(t *testing.T) {
	if !isJWE("a.b.c.d.e") {
		t.Error("expected 5-part token to be detected as JWE")
	}
}

func TestIsJWE_ThreeParts(t *testing.T) {
	if isJWE("a.b.c") {
		t.Error("expected 3-part token to not be detected as JWE")
	}
}

func TestIsJWE_NoDots(t *testing.T) {
	if isJWE("abcdef") {
		t.Error("expected no-dot token to not be detected as JWE")
	}
}

// --- decodeAndPrintJWE -------------------------------------------------------

func TestDecodeAndPrintJWE_HeaderOnly(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"user1","name":"Jane"}`))

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "Protected Header") {
		t.Error("output missing Protected Header label")
	}
	if !strings.Contains(plain, "RSA-OAEP-256") {
		t.Error("output missing algorithm RSA-OAEP-256")
	}
	if !strings.Contains(plain, "A256GCM") {
		t.Error("output missing content encryption A256GCM")
	}
	if !strings.Contains(plain, "Encrypted Content") {
		t.Error("output missing Encrypted Content section")
	}
	if !strings.Contains(plain, "Encrypted Key") {
		t.Error("output missing Encrypted Key info")
	}
	if !strings.Contains(plain, "bytes") {
		t.Error("output missing byte size info")
	}
	if !strings.Contains(plain, "--key") {
		t.Error("output missing hint to use --key flag")
	}
}

func TestDecodeAndPrintJWE_DisplaysCompleteProtectedHeader(t *testing.T) {
	key := generateRSAKey(t)
	_, derPath, _ := writeRSACertificateFiles(t, key)
	certificateDER, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatalf("reading certificate: %v", err)
	}
	certificate := base64.StdEncoding.EncodeToString(certificateDER)
	custom := "custom-value\u009b\x7f\u061c\u202e\u2066"
	options := new(jose.EncrypterOptions).
		WithHeader(jose.HeaderKey("x5c"), []string{certificate}).
		WithHeader(jose.HeaderKey("custom"), custom).
		WithHeader(jose.HeaderKey("key\u200e"), "safe")
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &key.PublicKey},
		options,
	)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	encrypted, err := encrypter.Encrypt([]byte(`{"sub":"test"}`))
	if err != nil {
		t.Fatalf("encrypting payload: %v", err)
	}
	token, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWE: %v", err)
	}

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, ""); err != nil {
		t.Fatalf("decoding JWE: %v", err)
	}

	output := buf.Bytes()
	for _, want := range []string{`"x5c"`, certificate, `"custom"`, `custom-value\u009b\u007f\u061c\u202e\u2066`, `key\u200e`} {
		if !bytes.Contains(output, []byte(want)) {
			t.Errorf("protected header output missing %q:\n%q", want, output)
		}
	}
	assertEscapedControlRunes(t, output, '\u009b', '\x7f', '\u061c', '\u200e', '\u202e', '\u2066')
}

func TestDecodeAndPrintJWE_WithDecryption(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"user1","name":"Jane Doe"}`))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "Protected Header") {
		t.Error("output missing Protected Header label")
	}
	if !strings.Contains(plain, "Decrypted Payload") {
		t.Error("output missing Decrypted Payload label")
	}
	if !strings.Contains(plain, "Jane Doe") {
		t.Error("output missing decrypted name value")
	}
	if !strings.Contains(plain, `"sub"`) {
		t.Error("output missing decrypted sub key")
	}
}

func TestDecodeAndPrintJWE_WithTimestampFormatting(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"user1","iat":1516239022}`))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "2018-01-18T01:30:22Z") {
		t.Error("output missing formatted timestamp")
	}
	if !strings.Contains(plain, "(1516239022)") {
		t.Error("output missing original epoch value in formatted timestamp")
	}
}

func TestDecodeAndPrintJWE_PreservesLargeJSONNumberInObject(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"value":9007199254740993}`))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())
	if !strings.Contains(plain, "9007199254740993") {
		t.Errorf("output did not preserve large JSON number:\n%s", plain)
	}
}

func TestDecodeAndPrintJWE_InvalidToken(t *testing.T) {
	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, "a.b.c.d.e", "")
	if err == nil {
		t.Fatal("expected error for invalid JWE token")
	}
	if !strings.Contains(err.Error(), "parsing JWE") {
		t.Errorf("expected parsing error, got: %v", err)
	}
}

func TestDecodeAndPrintJWE_WrongKey(t *testing.T) {
	key := generateRSAKey(t)
	wrongKey := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"user1"}`))
	keyPath := writeKeyFile(t, wrongKey)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
	if !strings.Contains(err.Error(), "decrypting JWE") {
		t.Errorf("expected decrypting error, got: %v", err)
	}
}

func TestDecodeAndPrintJWE_NonJSONPayload(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte("plain text content, not JSON"))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "Decrypted Payload") {
		t.Error("output missing Decrypted Payload label")
	}
	if !strings.Contains(plain, "plain text content") {
		t.Error("output missing plaintext content")
	}
}

func TestDecodeAndPrintJWE_NonJSONPayloadEscapesTerminalControls(t *testing.T) {
	key := generateRSAKey(t)
	plaintext := []byte("before\x1b]0;unsafe title\x07after\rline\x1b[31mred c1:\u009d\u009c invalid:")
	plaintext = append(plaintext, 0xff, 0xc0, 0xaf)
	plaintext = append(plaintext, []byte(" bidi:\u061c\u200e\u200f\u202e\u2066 join:\u200d")...)
	token := encryptJWE(t, key, plaintext)
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.Bytes()
	escaped := `before\x1b]0;unsafe title\x07after\x0dline\x1b[31mred c1:\u009d\u009c invalid:\xff\xc0\xaf bidi:\u061c\u200e\u200f\u202e\u2066 join:` + "\u200d"
	if !bytes.Contains(output, []byte(escaped)) {
		t.Errorf("output missing visibly escaped plaintext %q:\n%q", escaped, output)
	}
	for _, control := range []byte{'\x1b', '\x07', '\r'} {
		if bytes.Contains(output, []byte{control}) {
			t.Errorf("output contains literal terminal control 0x%02x:\n%q", control, output)
		}
	}
	for _, unsafe := range [][]byte{[]byte("\u009d"), []byte("\u009c"), {0xff}, {0xc0, 0xaf}} {
		if bytes.Contains(output, unsafe) {
			t.Errorf("output contains literal unsafe bytes % x:\n%q", unsafe, output)
		}
	}
}

func TestDecodeAndPrintJWE_DottedTextPayload(t *testing.T) {
	key := generateRSAKey(t)
	// Two dots make this look like a nested JWT, but it is not one.
	token := encryptJWE(t, key, []byte("not.a.jwt"))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if strings.Contains(plain, "nested") {
		t.Errorf("output contains nested label for non-token payload:\n%s", plain)
	}
	if got := strings.Count(plain, "Decrypted Payload"); got != 1 {
		t.Errorf("expected exactly one Decrypted Payload label, got %d:\n%s", got, plain)
	}
	if !strings.Contains(plain, "not.a.jwt") {
		t.Error("output missing raw payload text")
	}
}

func TestDecodeAndPrintJWE_JSONArrayPayload(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`[{"id":1,"name":"first"},{"id":2,"name":"second"}]`))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	if !strings.Contains(plain, "Decrypted Payload") {
		t.Error("output missing Decrypted Payload label")
	}
	if !strings.Contains(plain, "first") {
		t.Error("output missing first array element value")
	}
	if !strings.Contains(plain, "second") {
		t.Error("output missing second array element value")
	}
	// Should be pretty-printed, not raw.
	if !strings.Contains(plain, `"id"`) {
		t.Error("output missing pretty-printed key")
	}
}

func TestDecodeAndPrintJWE_JSONObjectEscapesControls(t *testing.T) {
	key := generateRSAKey(t)
	plaintext := []byte(`{"csi":"\u009b","osc":"\u009d","st":"\u009c","del":"\u007f","bidi":"\u061c\u200e\u202e\u2066","key\u009b":"safe","key\u200f":"safe"}`)
	token := encryptJWE(t, key, plaintext)
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.Bytes()
	assertEscapedControlRunes(t, output, '\u009b', '\u009d', '\u009c', '\x7f', '\u061c', '\u200e', '\u200f', '\u202e', '\u2066')
	for _, visible := range []string{`key\u009b`, `key\u200f`} {
		if !bytes.Contains(output, []byte(visible)) {
			t.Errorf("output missing visibly escaped control in object key %q:\n%q", visible, output)
		}
	}
}

func TestDecodeAndPrintJWE_JSONArrayEscapesControls(t *testing.T) {
	key := generateRSAKey(t)
	plaintext := []byte(`["\u009b","\u009d","\u009c","\u007f","\u061c","\u202e","\u2066",{"key\u009d":"value\u009c","key\u200e":"value\u200f"}]`)
	token := encryptJWE(t, key, plaintext)
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.Bytes()
	assertEscapedControlRunes(t, output, '\u009b', '\u009d', '\u009c', '\x7f', '\u061c', '\u200e', '\u200f', '\u202e', '\u2066')
	for _, visible := range []string{`key\u009d`, `value\u009c`, `key\u200e`, `value\u200f`} {
		if !bytes.Contains(output, []byte(visible)) {
			t.Errorf("output missing %q from array object:\n%q", visible, output)
		}
	}
}

func TestDecodeAndPrintJWE_PreservesLargeJSONNumberInArray(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`[9007199254740993]`))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())
	if !strings.Contains(plain, "9007199254740993") {
		t.Errorf("output did not preserve large JSON number:\n%s", plain)
	}
}

// --- loadKey -----------------------------------------------------------------

func TestLoadKey_FromPEMFile(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaKey, ok := loaded.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", loaded)
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadKey_FromBase64SymmetricKey(t *testing.T) {
	// 32-byte symmetric key encoded in base64.
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(rawKey)

	loaded, err := loadKey(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if len(symKey) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(symKey))
	}
}

func TestLoadKey_InvalidInput(t *testing.T) {
	_, err := loadKey("not-a-file-and-not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid key input")
	}
}

func TestLoadKey_RawPrefix(t *testing.T) {
	loaded, err := loadKey("raw:my-literal-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if string(symKey) != "my-literal-secret" {
		t.Errorf("expected literal secret, got %q", symKey)
	}
}

func TestLoadKey_TextKeyFileTrimsTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("my-text-secret\n"), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if string(symKey) != "my-text-secret" {
		t.Errorf("expected trailing newline trimmed, got %q", symKey)
	}
}

func TestLoadKey_BinaryKeyFileKeepsTrailingNewlineByte(t *testing.T) {
	binKey := []byte{0x00, 0x01, 0xfe, 0xff, '\n'}
	keyPath := writeSymmetricKeyFile(t, binKey)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if !bytes.Equal(symKey, binKey) {
		t.Errorf("binary key modified: expected % x, got % x", binKey, symKey)
	}
}

// --- partSize ----------------------------------------------------------------

func TestPartSize_ValidBase64(t *testing.T) {
	data := base64.RawURLEncoding.EncodeToString([]byte("hello world"))
	if got := partSize(data); got != "11 bytes" {
		t.Errorf("expected 11 bytes, got %q", got)
	}
}

func TestPartSize_InvalidBase64(t *testing.T) {
	if got := partSize("!!!invalid!!!"); got != "invalid base64url" {
		t.Errorf("expected invalid base64url, got %q", got)
	}
}

func TestPartSize_Empty(t *testing.T) {
	if got := partSize(""); got != "0 bytes" {
		t.Errorf("expected 0 bytes for empty string, got %q", got)
	}
}

// --- jweProtectedHeaderMap ---------------------------------------------------

func TestJWEProtectedHeaderMap_PreservesAllFields(t *testing.T) {
	headerJSON := []byte(`{"alg":"dir","enc":"A256GCM","x5c":["certificate"],"custom":"custom-value","large":9007199254740993}`)
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + ".a.b.c.d"

	header, err := jweProtectedHeaderMap(token)
	if err != nil {
		t.Fatalf("decoding protected header: %v", err)
	}
	if got := header["alg"]; got != "dir" {
		t.Errorf("alg = %v (%T), want dir", got, got)
	}
	if got := header["enc"]; got != "A256GCM" {
		t.Errorf("enc = %v (%T), want A256GCM", got, got)
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) != 1 || x5c[0] != "certificate" {
		t.Errorf("x5c = %v (%T), want [certificate]", header["x5c"], header["x5c"])
	}
	if got := header["custom"]; got != "custom-value" {
		t.Errorf("custom = %v (%T), want custom-value", got, got)
	}
	large, ok := header["large"].(json.Number)
	if !ok {
		t.Fatalf("large = %v (%T), want json.Number", header["large"], header["large"])
	}
	if got := large.String(); got != "9007199254740993" {
		t.Errorf("large = %q, want 9007199254740993", got)
	}
}

func TestJWEProtectedHeaderMap_RejectsMalformedHeaders(t *testing.T) {
	encoded := func(data string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(data)) + ".a.b.c.d"
	}
	tests := []struct {
		name      string
		token     string
		wantError string
	}{
		{name: "missing dot", token: "protected", wantError: "no protected header segment"},
		{name: "invalid base64url", token: "%%%.a.b.c.d", wantError: "decoding JWE protected header"},
		{name: "non-object JSON", token: encoded(`["not","an","object"]`), wantError: "parsing JWE protected header"},
		{name: "null JSON", token: encoded(`null`), wantError: "parsing JWE protected header"},
		{name: "trailing JSON data", token: encoded(`{"alg":"dir"} {"enc":"A256GCM"}`), wantError: "parsing JWE protected header"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := jweProtectedHeaderMap(tt.token)
			if err == nil {
				t.Fatal("expected protected header error")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("error = %q, want context %q", err, tt.wantError)
			}
		})
	}
}

// --- printEncryptedParts -----------------------------------------------------

func TestPrintEncryptedParts_ShowsAllParts(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"test"}`))

	var buf bytes.Buffer
	printEncryptedParts(&buf, token)

	plain := stripANSI(buf.String())

	checks := []string{"Encrypted Key", "IV", "Ciphertext", "Auth Tag", "bytes"}
	for _, check := range checks {
		if !strings.Contains(plain, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestPrintEncryptedParts_InvalidBase64Part(t *testing.T) {
	var buf bytes.Buffer
	token := "aGVhZGVy.!!!not-base64!!!.aXY.Y2lwaGVy.dGFn"
	err := printEncryptedParts(&buf, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())
	if !strings.Contains(plain, "Encrypted Key : invalid base64url") {
		t.Errorf("expected invalid base64url marker, got:\n%s", plain)
	}
}

func TestPrintEncryptedParts_WrongPartCount(t *testing.T) {
	// Should not panic or produce output for non-5-part input.
	var buf bytes.Buffer
	printEncryptedParts(&buf, "a.b.c")
	if buf.String() != "" {
		t.Errorf("expected no output for 3-part input, got: %q", buf.String())
	}
}

// --- End-to-end JWE via decodeAndPrintJWE ------------------------------------

func TestDecodeAndPrintJWE_EndToEnd_HeaderOnly(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"e2e-test","role":"admin"}`))

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	// Should show header but NOT decrypted content.
	if !strings.Contains(plain, "Protected Header") {
		t.Error("output missing Protected Header")
	}
	if strings.Contains(plain, "e2e-test") {
		t.Error("output should NOT contain encrypted payload content without key")
	}
	if strings.Contains(plain, "admin") {
		t.Error("output should NOT contain encrypted payload content without key")
	}
}

func TestDecodeAndPrintJWE_EndToEnd_WithDecrypt(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"e2e-test","role":"admin","iat":1700000000}`))
	keyPath := writeKeyFile(t, key)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

	checks := []string{
		"Protected Header",
		"RSA-OAEP-256",
		"A256GCM",
		"Decrypted Payload",
		`"sub"`,
		"e2e-test",
		`"role"`,
		"admin",
	}
	for _, check := range checks {
		if !strings.Contains(plain, check) {
			t.Errorf("output missing %q", check)
		}
	}

	// Timestamp should be formatted with original epoch value.
	if !strings.Contains(plain, "(1700000000)") {
		t.Error("output missing original epoch value in formatted timestamp")
	}
}

// --- Algorithm coverage: key management algorithms ---------------------------

func TestDecodeAndPrintJWE_RSAKeyAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		keyAlg jose.KeyAlgorithm
		algStr string
	}{
		{"RSA-OAEP", jose.RSA_OAEP, "RSA-OAEP"},
		{"RSA-OAEP-256", jose.RSA_OAEP_256, "RSA-OAEP-256"},
		{"RSA1_5", jose.RSA1_5, "RSA1_5"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/header_only", func(t *testing.T) {
			key := generateRSAKey(t)
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, &key.PublicKey, []byte(`{"sub":"rsa-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, tt.algStr) {
				t.Errorf("output missing algorithm %q", tt.algStr)
			}
			if !strings.Contains(plain, "A128GCM") {
				t.Error("output missing content encryption A128GCM")
			}
			if !strings.Contains(plain, "Encrypted Content") {
				t.Error("output missing Encrypted Content section")
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			key := generateRSAKey(t)
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, &key.PublicKey, []byte(`{"sub":"rsa-test","role":"user"}`))
			keyPath := writeKeyFile(t, key)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "rsa-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "user") {
				t.Error("output missing decrypted role value")
			}
		})
	}
}

func TestDecodeAndPrintJWE_ECDHESKeyAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		keyAlg jose.KeyAlgorithm
		algStr string
	}{
		{"ECDH-ES", jose.ECDH_ES, "ECDH-ES"},
		{"ECDH-ES+A128KW", jose.ECDH_ES_A128KW, "ECDH-ES+A128KW"},
		{"ECDH-ES+A192KW", jose.ECDH_ES_A192KW, "ECDH-ES+A192KW"},
		{"ECDH-ES+A256KW", jose.ECDH_ES_A256KW, "ECDH-ES+A256KW"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/header_only", func(t *testing.T) {
			key := generateECKey(t)
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, &key.PublicKey, []byte(`{"sub":"ec-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, tt.algStr) {
				t.Errorf("output missing algorithm %q", tt.algStr)
			}
			if !strings.Contains(plain, "Encrypted Content") {
				t.Error("output missing Encrypted Content section")
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			key := generateECKey(t)
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, &key.PublicKey, []byte(`{"sub":"ec-test","data":"secret"}`))
			keyPath := writeECKeyFile(t, key)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "ec-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "secret") {
				t.Error("output missing decrypted data value")
			}
		})
	}
}

func TestDecodeAndPrintJWE_AESKWKeyAlgorithms(t *testing.T) {
	tests := []struct {
		name    string
		keyAlg  jose.KeyAlgorithm
		algStr  string
		keySize int
	}{
		{"A128KW", jose.A128KW, "A128KW", 16},
		{"A192KW", jose.A192KW, "A192KW", 24},
		{"A256KW", jose.A256KW, "A256KW", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/header_only", func(t *testing.T) {
			symKey := make([]byte, tt.keySize)
			if _, err := rand.Read(symKey); err != nil {
				t.Fatalf("generating key: %v", err)
			}
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, symKey, []byte(`{"sub":"aeskw-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, tt.algStr) {
				t.Errorf("output missing algorithm %q", tt.algStr)
			}
			if !strings.Contains(plain, "Encrypted Content") {
				t.Error("output missing Encrypted Content section")
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			symKey := make([]byte, tt.keySize)
			if _, err := rand.Read(symKey); err != nil {
				t.Fatalf("generating key: %v", err)
			}
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, symKey, []byte(`{"sub":"aeskw-test","msg":"hello"}`))
			b64Key := base64.StdEncoding.EncodeToString(symKey)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, b64Key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "aeskw-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "hello") {
				t.Error("output missing decrypted msg value")
			}
		})
	}
}

func TestDecodeAndPrintJWE_AESGCMKWKeyAlgorithms(t *testing.T) {
	tests := []struct {
		name    string
		keyAlg  jose.KeyAlgorithm
		algStr  string
		keySize int
	}{
		{"A128GCMKW", jose.A128GCMKW, "A128GCMKW", 16},
		{"A192GCMKW", jose.A192GCMKW, "A192GCMKW", 24},
		{"A256GCMKW", jose.A256GCMKW, "A256GCMKW", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/header_only", func(t *testing.T) {
			symKey := make([]byte, tt.keySize)
			if _, err := rand.Read(symKey); err != nil {
				t.Fatalf("generating key: %v", err)
			}
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A256GCM, symKey, []byte(`{"sub":"aesgcmkw-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, tt.algStr) {
				t.Errorf("output missing algorithm %q", tt.algStr)
			}
			if !strings.Contains(plain, "Encrypted Content") {
				t.Error("output missing Encrypted Content section")
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			symKey := make([]byte, tt.keySize)
			if _, err := rand.Read(symKey); err != nil {
				t.Fatalf("generating key: %v", err)
			}
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A256GCM, symKey, []byte(`{"sub":"aesgcmkw-test","status":"ok"}`))
			b64Key := base64.StdEncoding.EncodeToString(symKey)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, b64Key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "aesgcmkw-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "ok") {
				t.Error("output missing decrypted status value")
			}
		})
	}
}

func TestDecodeAndPrintJWE_DirectKeyAgreement(t *testing.T) {
	contentEncs := []struct {
		name   string
		enc    jose.ContentEncryption
		encStr string
	}{
		{"A128CBC-HS256", jose.A128CBC_HS256, "A128CBC-HS256"},
		{"A256CBC-HS512", jose.A256CBC_HS512, "A256CBC-HS512"},
		{"A128GCM", jose.A128GCM, "A128GCM"},
		{"A256GCM", jose.A256GCM, "A256GCM"},
	}

	for _, tt := range contentEncs {
		t.Run(tt.name+"/header_only", func(t *testing.T) {
			symKey := symmetricKeyForEnc(t, tt.enc)
			token := encryptJWEGeneric(t, jose.DIRECT, tt.enc, symKey, []byte(`{"sub":"dir-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, "dir") {
				t.Error("output missing algorithm 'dir'")
			}
			if !strings.Contains(plain, tt.encStr) {
				t.Errorf("output missing content encryption %q", tt.encStr)
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			symKey := symmetricKeyForEnc(t, tt.enc)
			token := encryptJWEGeneric(t, jose.DIRECT, tt.enc, symKey, []byte(`{"sub":"dir-test","val":"direct"}`))
			b64Key := base64.StdEncoding.EncodeToString(symKey)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, b64Key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "dir-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "direct") {
				t.Error("output missing decrypted val value")
			}
		})
	}
}

func TestDecodeAndPrintJWE_PBES2KeyAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		keyAlg jose.KeyAlgorithm
		algStr string
	}{
		{"PBES2-HS256+A128KW", jose.PBES2_HS256_A128KW, "PBES2-HS256+A128KW"},
		{"PBES2-HS384+A192KW", jose.PBES2_HS384_A192KW, "PBES2-HS384+A192KW"},
		{"PBES2-HS512+A256KW", jose.PBES2_HS512_A256KW, "PBES2-HS512+A256KW"},
	}

	for _, tt := range tests {
		password := []byte("test-password-for-jwtd")

		t.Run(tt.name+"/header_only", func(t *testing.T) {
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, password, []byte(`{"sub":"pbes2-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, tt.algStr) {
				t.Errorf("output missing algorithm %q", tt.algStr)
			}
			if !strings.Contains(plain, "Encrypted Content") {
				t.Error("output missing Encrypted Content section")
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			token := encryptJWEGeneric(t, tt.keyAlg, jose.A128GCM, password, []byte(`{"sub":"pbes2-test","auth":"pass"}`))
			// For PBES2, the "key" is the password passed as base64.
			b64Password := base64.StdEncoding.EncodeToString(password)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, b64Password)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "pbes2-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "pass") {
				t.Error("output missing decrypted auth value")
			}
		})
	}
}

// --- Algorithm coverage: content encryption algorithms -----------------------

func TestDecodeAndPrintJWE_ContentEncryptionAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		enc    jose.ContentEncryption
		encStr string
	}{
		{"A128CBC-HS256", jose.A128CBC_HS256, "A128CBC-HS256"},
		{"A192CBC-HS384", jose.A192CBC_HS384, "A192CBC-HS384"},
		{"A256CBC-HS512", jose.A256CBC_HS512, "A256CBC-HS512"},
		{"A128GCM", jose.A128GCM, "A128GCM"},
		{"A192GCM", jose.A192GCM, "A192GCM"},
		{"A256GCM", jose.A256GCM, "A256GCM"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/header_only", func(t *testing.T) {
			key := generateRSAKey(t)
			token := encryptJWEGeneric(t, jose.RSA_OAEP, tt.enc, &key.PublicKey, []byte(`{"sub":"enc-test"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Protected Header") {
				t.Error("output missing Protected Header")
			}
			if !strings.Contains(plain, tt.encStr) {
				t.Errorf("output missing content encryption %q", tt.encStr)
			}
			if !strings.Contains(plain, "RSA-OAEP") {
				t.Error("output missing algorithm RSA-OAEP")
			}
		})

		t.Run(tt.name+"/decrypt", func(t *testing.T) {
			key := generateRSAKey(t)
			token := encryptJWEGeneric(t, jose.RSA_OAEP, tt.enc, &key.PublicKey, []byte(`{"sub":"enc-test","enc_alg":"tested"}`))
			keyPath := writeKeyFile(t, key)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "enc-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "tested") {
				t.Error("output missing decrypted enc_alg value")
			}
		})
	}
}

// --- Cross-algorithm combinations --------------------------------------------

func TestDecodeAndPrintJWE_ECDHES_WithAllContentEncryptions(t *testing.T) {
	contentEncs := []struct {
		name string
		enc  jose.ContentEncryption
	}{
		{"A128CBC-HS256", jose.A128CBC_HS256},
		{"A256CBC-HS512", jose.A256CBC_HS512},
		{"A128GCM", jose.A128GCM},
		{"A256GCM", jose.A256GCM},
	}

	for _, tt := range contentEncs {
		t.Run("ECDH-ES+A256KW/"+tt.name, func(t *testing.T) {
			key := generateECKey(t)
			token := encryptJWEGeneric(t, jose.ECDH_ES_A256KW, tt.enc, &key.PublicKey,
				[]byte(`{"sub":"cross-test","msg":"combo"}`))
			keyPath := writeECKeyFile(t, key)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "cross-test") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "combo") {
				t.Error("output missing decrypted msg value")
			}
		})
	}
}

func TestDecodeAndPrintJWE_A256KW_WithAllContentEncryptions(t *testing.T) {
	contentEncs := []struct {
		name string
		enc  jose.ContentEncryption
	}{
		{"A128CBC-HS256", jose.A128CBC_HS256},
		{"A192CBC-HS384", jose.A192CBC_HS384},
		{"A256CBC-HS512", jose.A256CBC_HS512},
		{"A128GCM", jose.A128GCM},
		{"A192GCM", jose.A192GCM},
		{"A256GCM", jose.A256GCM},
	}

	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	b64Key := base64.StdEncoding.EncodeToString(symKey)

	for _, tt := range contentEncs {
		t.Run("A256KW/"+tt.name, func(t *testing.T) {
			token := encryptJWEGeneric(t, jose.A256KW, tt.enc, symKey,
				[]byte(`{"sub":"a256kw-combo","result":"success"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, b64Key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			plain := stripANSI(buf.String())
			if !strings.Contains(plain, "Decrypted Payload") {
				t.Error("output missing Decrypted Payload")
			}
			if !strings.Contains(plain, "a256kw-combo") {
				t.Error("output missing decrypted sub value")
			}
			if !strings.Contains(plain, "success") {
				t.Error("output missing decrypted result value")
			}
		})
	}
}

// --- loadKey with EC keys ----------------------------------------------------

func TestLoadKey_FromECPEMFile(t *testing.T) {
	key := generateECKey(t)
	keyPath := writeECKeyFile(t, key)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecKey, ok := loaded.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", loaded)
	}
	if ecKey.X.Cmp(key.X) != 0 || ecKey.Y.Cmp(key.Y) != 0 {
		t.Error("loaded EC key does not match original")
	}
}

func TestLoadKey_FromBase64EncodedPEM(t *testing.T) {
	key := generateRSAKey(t)
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	b64 := base64.StdEncoding.EncodeToString(pemBytes)

	loaded, err := loadKey(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaKey, ok := loaded.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", loaded)
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadKey_SymmetricKeyFromFile(t *testing.T) {
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyPath := writeSymmetricKeyFile(t, symKey)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Raw bytes that don't parse as PEM or DER should be returned as-is
	// (symmetric key fallback).
	if loaded == nil {
		t.Fatal("loaded key is nil")
	}
}

// --- public key loading ------------------------------------------------------

// writeRSAPublicKeyFile writes an RSA public key to a temp PEM file and returns the path.
func writeRSAPublicKeyFile(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshaling RSA public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-rsa-pub.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// writeECPublicKeyFile writes an ECDSA public key to a temp PEM file and returns the path.
func writeECPublicKeyFile(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshaling EC public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-ec-pub.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

func writeRSACertificateFiles(t *testing.T, key *rsa.PrivateKey) (pemPath, derPath string, pemBytes []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwtd test certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	dir := t.TempDir()
	pemPath = filepath.Join(dir, "test-cert.pem")
	derPath = filepath.Join(dir, "test-cert.der")
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(pemPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing PEM certificate: %v", err)
	}
	if err := os.WriteFile(derPath, der, 0600); err != nil {
		t.Fatalf("writing DER certificate: %v", err)
	}
	return pemPath, derPath, pemBytes
}

func TestLoadKey_RSAPublicKeyFromPEMFile(t *testing.T) {
	priv := generateRSAKey(t)
	keyPath := writeRSAPublicKeyFile(t, &priv.PublicKey)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaPub, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("loaded RSA public key does not match original")
	}
}

func TestLoadKey_ECPublicKeyFromPEMFile(t *testing.T) {
	priv := generateECKey(t)
	keyPath := writeECPublicKeyFile(t, &priv.PublicKey)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecPub, ok := loaded.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", loaded)
	}
	if ecPub.X.Cmp(priv.PublicKey.X) != 0 || ecPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Error("loaded EC public key does not match original")
	}
}

func TestLoadKey_RSAPublicKeyFromBase64(t *testing.T) {
	priv := generateRSAKey(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	b64 := base64.StdEncoding.EncodeToString(pemBytes)

	loaded, err := loadKey(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaPub, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("loaded RSA public key does not match original")
	}
}

func TestLoadKey_PKCS1RSAPublicKeyFromPEMFile(t *testing.T) {
	priv := generateRSAKey(t)
	der := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-rsa-pub-pkcs1.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaPub, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("loaded PKCS1 RSA public key does not match original")
	}
}

func TestLoadKey_X509Certificate(t *testing.T) {
	priv := generateRSAKey(t)
	pemPath, derPath, pemBytes := writeRSACertificateFiles(t, priv)
	tests := []struct {
		name  string
		input string
	}{
		{name: "PEM file", input: pemPath},
		{name: "DER file", input: derPath},
		{name: "base64 PEM", input: base64.StdEncoding.EncodeToString(pemBytes)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loaded, err := loadKey(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			publicKey, ok := loaded.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
			}
			if publicKey.N.Cmp(priv.PublicKey.N) != 0 || publicKey.E != priv.PublicKey.E {
				t.Error("loaded certificate public key does not match original")
			}
		})
	}
}

func TestLoadKey_RejectsMalformedStructuredData(t *testing.T) {
	unsupportedDER, err := asn1.Marshal(struct{ Value int }{Value: 1})
	if err != nil {
		t.Fatalf("marshaling unsupported DER: %v", err)
	}
	publicKey := generateRSAKey(t)
	publicJWK, err := json.Marshal(jose.JSONWebKey{Key: &publicKey.PublicKey})
	if err != nil {
		t.Fatalf("marshaling public JWK: %v", err)
	}
	publicJWKSet, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &publicKey.PublicKey}}})
	if err != nil {
		t.Fatalf("marshaling public JWK Set: %v", err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "malformed PEM", data: []byte("-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "malformed PEM after preamble", data: []byte("Bag Attributes\n    localKeyID: 01 00\n-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "indented malformed PEM after preamble", data: []byte("Bag Attributes\n    -----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "malformed PEM after BOM and preamble", data: []byte("\xef\xbb\xbfBag Attributes\n-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "malformed JWK JSON", data: []byte(`{"kty":"RSA","n":`)},
		{name: "malformed JWK with escaped kty", data: []byte(`{"\u006bty":"oct","k":`)},
		{name: "malformed JWK Set with escaped keys", data: []byte(`{"\u006b\u0065\u0079\u0073":[`)},
		{name: "escaped strings before escaped kty", data: []byte(`{"note":"escaped quote: \" and slash: \\","\u006bty":"oct","k":`)},
		{name: "literal kty after malformed value", data: []byte(`{"bad":truX,"kty":"RSA","n":"public"}`)},
		{name: "escaped kty after malformed value", data: []byte(`{"bad":truX,"\u006bty":"RSA","n":"public"}`)},
		{name: "literal kty after missing comma", data: []byte(`{"note":"x" "kty":"RSA","n":"public"}`)},
		{name: "escaped kty after missing comma", data: []byte(`{"note":"x" "\u006bty":"RSA","n":"public"}`)},
		{name: "literal keys after malformed value", data: []byte(`{"bad":truX,"keys":[`)},
		{name: "escaped keys after malformed value", data: []byte(`{"bad":truX,"\u006b\u0065\u0079\u0073":[`)},
		{name: "literal kty truncated before colon", data: []byte(`{"bad":truX,"kty"`)},
		{name: "escaped kty truncated before colon", data: []byte(`{"bad":truX,"\u006bty"`)},
		{name: "literal kty at EOF after missing comma", data: []byte(`{"note":"x" "kty"`)},
		{name: "escaped kty at EOF after malformed value", data: []byte(`{"bad":truX "\u006bty"`)},
		{name: "literal keys at EOF after missing comma", data: []byte(`{"note":"x" "keys"`)},
		{name: "escaped keys at EOF after malformed value", data: []byte(`{"bad":truX "\u006b\u0065\u0079\u0073"`)},
		{name: "literal kty with missing colon", data: []byte(`{"kty" "RSA","n":"public"}`)},
		{name: "escaped kty with missing colon", data: []byte(`{"\u006bty" "RSA","n":"public"}`)},
		{name: "literal keys with missing colon", data: []byte(`{"keys" [{"kty":"RSA"}]}`)},
		{name: "escaped keys with missing colon", data: []byte(`{"\u006b\u0065\u0079\u0073" [{"kty":"RSA"}]}`)},
		{name: "literal kty with replaced colon", data: []byte(`{"kty";"RSA","n":"public"}`)},
		{name: "escaped kty with replaced colon", data: []byte(`{"\u006bty";"RSA","n":"public"}`)},
		{name: "literal keys with replaced colon", data: []byte(`{"keys"=[{"kty":"RSA"}]}`)},
		{name: "escaped keys with replaced colon", data: []byte(`{"\u006b\u0065\u0079\u0073"=[{"kty":"RSA"}]}`)},
		{name: "truncated first member name", data: []byte(`{"kty`)},
		{name: "BOM-prefixed escaped truncated first member name", data: []byte("\xef\xbb\xbf \n{\t\"\\u006b")},
		{name: "malformed JWK fields without kty", data: []byte(`{"n":"public","e":"AQAB",`)},
		{name: "marker-like value followed by colon", data: []byte(`{"label":"kty":`)},
		{name: "escaped marker-like value followed by colon", data: []byte(`{"label":"\u006bty":`)},
		{name: "marker-like value followed by missing separator", data: []byte(`{"label":"keys" "opaque"`)},
		{name: "escaped marker-like value followed by replaced separator", data: []byte(`{"label":"\u006bty";opaque`)},
		{name: "escaped quote and backslash value", data: []byte(`{"label":"escaped quote: \" and slash: \\":`)},
		{name: "marker-like object value at EOF", data: []byte(`{"label":"kty"`)},
		{name: "marker-like nested array value", data: []byte(`{"values":["keys":`)},
		{name: "nested metadata kty member", data: []byte(`{"meta":{"kty":"custom"},"bad":truX}`)},
		{name: "marker in truncated value string", data: []byte(`{"label":"truncated kty`)},
		{name: "BOM-prefixed malformed JWK JSON", data: []byte("\xef\xbb\xbf{\"kty\":\"RSA\",\"n\":")},
		{name: "BOM-prefixed malformed JWK with escaped kty", data: []byte("\xef\xbb\xbf{\"\\u006bty\":\"oct\",\"k\":")},
		{name: "BOM-prefixed public JWK", data: append([]byte{0xef, 0xbb, 0xbf}, publicJWK...)},
		{name: "BOM-prefixed public JWK Set", data: append([]byte{0xef, 0xbb, 0xbf}, publicJWKSet...)},
		{name: "valid unsupported JSON object", data: []byte(`{"secret":"value"}`)},
		{name: "unsupported ASN.1 DER sequence", data: unsupportedDER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("file", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "structured-key")
				if err := os.WriteFile(path, tt.data, 0600); err != nil {
					t.Fatalf("writing structured key data: %v", err)
				}
				if loaded, err := loadKey(path); err == nil {
					t.Fatalf("expected parsing error, got %T", loaded)
				} else if !strings.Contains(err.Error(), path) {
					t.Fatalf("expected error to contain key path %q, got %v", path, err)
				}
			})

			t.Run("base64", func(t *testing.T) {
				encoded := base64.StdEncoding.EncodeToString(tt.data)
				if loaded, err := loadKey(encoded); err == nil {
					t.Fatalf("expected parsing error, got %T", loaded)
				}
			})
		})
	}
}

func TestLoadKey_OpaqueStructuredPrefixesRemainRaw(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "leading object brace", data: []byte("{opaque-symmetric-key")},
		{name: "lone object brace", data: []byte("{")},
		{name: "object brace followed by whitespace", data: []byte("{ \t")},
		{name: "BOM-prefixed object brace followed by opaque bytes", data: []byte("\xef\xbb\xbf \n{opaque-symmetric-key")},
		{name: "leading array bracket", data: []byte("[opaque-symmetric-key")},
		{name: "valid JSON array", data: []byte(`["opaque","symmetric","key"]`)},
		{name: "ASN.1 sequence with incomplete contents", data: []byte{0x30, 0x03, 0x02, 0x02, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []string{"file", "base64"} {
				t.Run(mode, func(t *testing.T) {
					input := base64.StdEncoding.EncodeToString(tt.data)
					if mode == "file" {
						input = filepath.Join(t.TempDir(), "opaque-key")
						if err := os.WriteFile(input, tt.data, 0600); err != nil {
							t.Fatalf("writing opaque key: %v", err)
						}
					}

					loaded, err := loadKey(input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					key, ok := loaded.([]byte)
					if !ok {
						t.Fatalf("expected []byte, got %T", loaded)
					}
					if !bytes.Equal(key, tt.data) {
						t.Fatalf("opaque key modified: expected % x, got % x", tt.data, key)
					}
				})
			}
		})
	}
}

// --- JWK key loading ---------------------------------------------------------

func TestLoadKey_RSAPrivateKeyFromJWKFile(t *testing.T) {
	priv := generateRSAKey(t)
	jwk := jose.JSONWebKey{Key: priv, KeyID: "test-rsa"}
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshaling JWK: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rsa-priv.jwk")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing JWK file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaKey, ok := loaded.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", loaded)
	}
	if rsaKey.N.Cmp(priv.N) != 0 {
		t.Error("loaded RSA private key does not match original")
	}
}

func TestLoadKey_RSAPublicKeyFromJWKFile(t *testing.T) {
	priv := generateRSAKey(t)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "test-rsa-pub"}
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshaling JWK: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rsa-pub.jwk")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing JWK file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaPub, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("loaded RSA public key does not match original")
	}
}

func TestLoadKey_ECPrivateKeyFromJWKFile(t *testing.T) {
	priv := generateECKey(t)
	jwk := jose.JSONWebKey{Key: priv, KeyID: "test-ec"}
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshaling JWK: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ec-priv.jwk")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing JWK file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecKey, ok := loaded.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", loaded)
	}
	if ecKey.X.Cmp(priv.X) != 0 || ecKey.Y.Cmp(priv.Y) != 0 {
		t.Error("loaded EC key does not match original")
	}
}

func TestLoadKey_JWKSetFirstKey(t *testing.T) {
	priv1 := generateRSAKey(t)
	priv2 := generateRSAKey(t)
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &priv1.PublicKey, KeyID: "key-1"},
			{Key: &priv2.PublicKey, KeyID: "key-2"},
		},
	}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshaling JWK Set: %v", err)
	}
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing JWK Set file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaPub, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	// Should return the first key from the set.
	if rsaPub.N.Cmp(priv1.PublicKey.N) != 0 {
		t.Error("loaded key does not match first key in JWK Set")
	}
}

func TestLoadKey_JWKFromBase64(t *testing.T) {
	priv := generateRSAKey(t)
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "test-b64"}
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshaling JWK: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(data)

	loaded, err := loadKey(b64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rsaPub, ok := loaded.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("loaded key from base64 JWK does not match original")
	}
}

// --- JWS signature verification -----------------------------------------------

// signJWT creates a signed JWT with the given claims and RSA private key.
func signJWT(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signed
}

// signJWTWithHMAC creates a signed JWT using HMAC-SHA256 with the given symmetric key.
func signJWTWithHMAC(t *testing.T, key []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signed
}

func TestVerifySignature_RejectsTrailingJWTClaimsData(t *testing.T) {
	key := []byte("a-random-looking-test-key-with-32b")
	tests := []struct {
		name    string
		payload string
	}{
		{name: "trailing junk", payload: `{"sub":"test"} trailing-junk`},
		{name: "second JSON value", payload: `{"sub":"test"} {"second":true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := makeHMACJWTWithRawPayload(t, tt.payload, key)

			var buf bytes.Buffer
			err := verifySignature(&buf, token, "raw:"+string(key))
			if err == nil {
				t.Fatal("expected malformed JWT claims error")
			}
			if errors.Is(err, errInvalidSignature) {
				t.Fatalf("malformed claims reported as an invalid signature: %v", err)
			}
			if !strings.Contains(err.Error(), "parsing JWT claims") {
				t.Errorf("expected JWT claims parsing error, got: %v", err)
			}
			output := stripANSI(buf.String())
			if strings.Contains(output, "Signature: VALID") {
				t.Errorf("malformed claims reported a valid signature:\n%s", output)
			}
			if strings.Contains(output, "Signature: INVALID") {
				t.Errorf("malformed claims reported an invalid signature:\n%s", output)
			}
		})
	}
}

func TestDecodeAndPrint_SignatureValid_RSA(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	claims := jwt.MapClaims{"sub": "test", "iss": "jwtd"}
	token := signJWT(t, key, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature message, got:\n%s", output)
	}
}

func TestDecodeAndPrint_SignatureValid_RSAPublicKey(t *testing.T) {
	key := generateRSAKey(t)
	pubKeyPath := writeRSAPublicKeyFile(t, &key.PublicKey)
	claims := jwt.MapClaims{"sub": "test", "iss": "jwtd"}
	token := signJWT(t, key, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, pubKeyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature message with public key, got:\n%s", output)
	}
}

func TestDecodeAndPrint_SignatureInvalid_WrongKey(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKey := generateRSAKey(t)
	wrongKeyPath := writeKeyFile(t, wrongKey)
	claims := jwt.MapClaims{"sub": "test"}
	token := signJWT(t, signingKey, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, wrongKeyPath)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: INVALID") {
		t.Errorf("expected invalid signature message, got:\n%s", output)
	}
}

func TestVerifySignature_InvalidOutputWriterErrors(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKeyPath := writeKeyFile(t, generateRSAKey(t))
	token := signJWT(t, signingKey, jwt.MapClaims{"sub": "test"})

	tests := []struct {
		name        string
		failedWrite int
	}{
		{name: "INVALID line", failedWrite: 1},
		{name: "reason", failedWrite: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writerErr := errors.New("writer failed")
			writer := &failOnWriteWriter{failedWrite: tt.failedWrite, err: writerErr}

			err := verifySignature(writer, token, wrongKeyPath)
			if !errors.Is(err, writerErr) {
				t.Fatalf("expected writer error, got: %v", err)
			}
			if errors.Is(err, errInvalidSignature) {
				t.Fatalf("expected writer error instead of invalid signature error, got: %v", err)
			}
		})
	}
}

type failOnWriteWriter struct {
	failedWrite int
	writes      int
	err         error
}

func (w *failOnWriteWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failedWrite {
		return 0, w.err
	}
	return len(p), nil
}

func TestDecodeAndPrint_SignatureInvalid_AlgKeyMismatch(t *testing.T) {
	// An HS256 token checked against an RSA public key must be rejected by
	// the algorithm restriction, not attempted as HMAC verification.
	rsaKey := generateRSAKey(t)
	pubKeyPath := writeRSAPublicKeyFile(t, &rsaKey.PublicKey)
	token := signJWTWithHMAC(t, []byte("shared-secret"), jwt.MapClaims{"sub": "test"})

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, pubKeyPath)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: INVALID") {
		t.Errorf("expected invalid signature for alg/key mismatch, got:\n%s", output)
	}
	if !strings.Contains(output, "signing method HS256 is invalid") {
		t.Errorf("expected signing method rejection reason, got:\n%s", output)
	}
}

func TestDecodeAndPrint_CertificateCannotBecomeHMACSecret(t *testing.T) {
	privateKey := generateRSAKey(t)
	certificatePath, _, certificatePEM := writeRSACertificateFiles(t, privateKey)
	token := signJWTWithHMAC(t, bytes.TrimSpace(certificatePEM), jwt.MapClaims{"sub": "test"})

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, certificatePath)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: INVALID") {
		t.Errorf("expected invalid signature for certificate/HMAC confusion, got:\n%s", output)
	}
}

func TestDecodeAndPrint_RejectsBOMPrefixedPublicJWKAsHMACSecret(t *testing.T) {
	rsaKey := generateRSAKey(t)
	jwkData, err := json.Marshal(jose.JSONWebKey{Key: &rsaKey.PublicKey})
	if err != nil {
		t.Fatalf("marshaling public JWK: %v", err)
	}
	jwkData = append([]byte{0xef, 0xbb, 0xbf}, jwkData...)
	keyPath := filepath.Join(t.TempDir(), "public.jwk")
	if err := os.WriteFile(keyPath, jwkData, 0600); err != nil {
		t.Fatalf("writing public JWK: %v", err)
	}
	token := signJWTWithHMAC(t, jwkData, jwt.MapClaims{"sub": "test"})

	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, keyPath); err == nil {
		t.Fatalf("expected BOM-prefixed public JWK to be rejected, got output:\n%s", stripANSI(buf.String()))
	}
	if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
		t.Fatalf("public JWK was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
	}
}

func TestDecodeAndPrint_RejectsEscapedJWKMemberAsHMACSecret(t *testing.T) {
	jwkData := []byte(`{"\u006bty":"oct","k":`)
	keyPath := filepath.Join(t.TempDir(), "malformed.jwk")
	if err := os.WriteFile(keyPath, jwkData, 0600); err != nil {
		t.Fatalf("writing malformed JWK: %v", err)
	}
	token := signJWTWithHMAC(t, jwkData, jwt.MapClaims{"sub": "test"})

	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, keyPath); err == nil {
		t.Fatalf("expected escaped JWK member to be rejected, got output:\n%s", stripANSI(buf.String()))
	}
	if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
		t.Fatalf("malformed JWK was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
	}
}

func TestDecodeAndPrint_RejectsLaterMalformedJWKMembersAsHMACSecrets(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "literal kty after malformed value", data: []byte(`{"bad":truX,"kty":"RSA","n":"public"}`)},
		{name: "escaped kty after malformed value", data: []byte(`{"bad":truX,"\u006bty":"RSA","n":"public"}`)},
		{name: "later keys", data: []byte(`{"bad":truX,"keys":[`)},
		{name: "kty truncated before colon", data: []byte(`{"bad":truX,"kty"`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "malformed.jwk")
			if err := os.WriteFile(keyPath, tt.data, 0600); err != nil {
				t.Fatalf("writing malformed JWK: %v", err)
			}
			token := signJWTWithHMAC(t, tt.data, jwt.MapClaims{"sub": "test"})

			var buf bytes.Buffer
			if err := decodeAndPrint(&buf, token, keyPath); err == nil {
				t.Fatalf("expected malformed JWK to be rejected, got output:\n%s", stripANSI(buf.String()))
			}
			if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
				t.Fatalf("malformed JWK was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
			}
		})
	}
}

func TestDecodeAndPrint_RejectsMissingCommaJWKMembersAsHMACSecrets(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		useBase64 bool
	}{
		{name: "literal kty", data: []byte(`{"note":"x" "kty":"RSA","n":"public"}`)},
		{name: "escaped kty", data: []byte(`{"note":"x" "\u006bty":"RSA","n":"public"}`)},
		{name: "literal kty at EOF", data: []byte(`{"note":"x" "kty"`)},
		{name: "escaped keys at EOF after malformed value via base64", data: []byte(`{"bad":truX "\u006b\u0065\u0079\u0073"`), useBase64: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyInput := base64.StdEncoding.EncodeToString(tt.data)
			if !tt.useBase64 {
				keyInput = filepath.Join(t.TempDir(), "malformed.jwk")
				if err := os.WriteFile(keyInput, tt.data, 0600); err != nil {
					t.Fatalf("writing malformed JWK: %v", err)
				}
			}
			token := signJWTWithHMAC(t, tt.data, jwt.MapClaims{"sub": "test"})

			var buf bytes.Buffer
			if err := decodeAndPrint(&buf, token, keyInput); err == nil {
				t.Fatalf("expected malformed JWK to be rejected, got output:\n%s", stripANSI(buf.String()))
			}
			if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
				t.Fatalf("malformed JWK was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
			}
		})
	}
}

func TestDecodeAndPrint_RejectsMalformedJWKMemberSeparatorsAsHMACSecrets(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		useBase64 bool
	}{
		{name: "literal kty with missing colon", data: []byte(`{"kty" "RSA","n":"public"}`)},
		{name: "escaped kty with replaced colon via base64", data: []byte(`{"\u006bty";"RSA","n":"public"}`), useBase64: true},
		{name: "literal keys with replaced colon", data: []byte(`{"keys"=[{"kty":"RSA"}]}`)},
		{name: "escaped keys with missing colon via base64", data: []byte(`{"\u006b\u0065\u0079\u0073" [{"kty":"RSA"}]}`), useBase64: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyInput := base64.StdEncoding.EncodeToString(tt.data)
			if !tt.useBase64 {
				keyInput = filepath.Join(t.TempDir(), "malformed.jwk")
				if err := os.WriteFile(keyInput, tt.data, 0600); err != nil {
					t.Fatalf("writing malformed JWK: %v", err)
				}
			}
			token := signJWTWithHMAC(t, tt.data, jwt.MapClaims{"sub": "test"})

			var buf bytes.Buffer
			if err := decodeAndPrint(&buf, token, keyInput); err == nil {
				t.Fatalf("expected malformed JWK to be rejected, got output:\n%s", stripANSI(buf.String()))
			}
			if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
				t.Fatalf("malformed JWK was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
			}
		})
	}
}

func TestDecodeAndPrint_RejectsIncompleteJSONObjectKeysAsHMACSecrets(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated kty member", data: []byte(`{"kty`)},
		{name: "malformed JWK fields without kty", data: []byte(`{"n":"public","e":"AQAB",`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []string{"file", "base64"} {
				t.Run(mode, func(t *testing.T) {
					keyInput := base64.StdEncoding.EncodeToString(tt.data)
					if mode == "file" {
						keyInput = filepath.Join(t.TempDir(), "malformed.jwk")
						if err := os.WriteFile(keyInput, tt.data, 0600); err != nil {
							t.Fatalf("writing malformed JWK: %v", err)
						}
					}
					token := signJWTWithHMAC(t, tt.data, jwt.MapClaims{"sub": "test"})

					var buf bytes.Buffer
					if err := decodeAndPrint(&buf, token, keyInput); err == nil {
						t.Fatalf("expected malformed JSON object key to be rejected, got output:\n%s", stripANSI(buf.String()))
					}
					if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
						t.Fatalf("malformed JSON object key was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
					}
				})
			}
		})
	}
}

func TestDecodeAndPrint_SignatureValid_HMACRawKey(t *testing.T) {
	secret := "plain-text-secret"
	claims := jwt.MapClaims{"sub": "test"}
	token := signJWTWithHMAC(t, []byte(secret), claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "raw:"+secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature with raw: key, got:\n%s", output)
	}
}

func TestDecodeAndPrint_SignatureValid_ExpiredToken(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(-time.Hour).Unix()}
	token := signJWT(t, key, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature for expired token, got:\n%s", output)
	}
}

func TestDecodeAndPrint_SignatureValid_HMAC(t *testing.T) {
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	b64Key := base64.StdEncoding.EncodeToString(symKey)
	claims := jwt.MapClaims{"sub": "test"}
	token := signJWTWithHMAC(t, symKey, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, b64Key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature message for HMAC, got:\n%s", output)
	}
}

// generateEd25519Key creates a fresh Ed25519 key pair for testing.
func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	return priv
}

// writeEd25519KeyFile writes an Ed25519 private key to a temp PEM file and returns the path.
func writeEd25519KeyFile(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling Ed25519 key: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-ed25519-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// signJWTWithEd25519 creates a signed JWT using Ed25519 with the given private key.
func signJWTWithEd25519(t *testing.T, key ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signed
}

func TestDecodeAndPrint_SignatureValid_Ed25519(t *testing.T) {
	key := generateEd25519Key(t)
	keyPath := writeEd25519KeyFile(t, key)
	claims := jwt.MapClaims{"sub": "test", "iss": "jwtd"}
	token := signJWTWithEd25519(t, key, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature message for Ed25519, got:\n%s", output)
	}
}

func TestDecodeAndPrint_SignatureValid_Ed25519PublicKey(t *testing.T) {
	key := generateEd25519Key(t)
	claims := jwt.MapClaims{"sub": "test", "iss": "jwtd"}
	token := signJWTWithEd25519(t, key, claims)

	// Write only the public key to a file.
	pub := key.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling Ed25519 public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	pubKeyPath := filepath.Join(t.TempDir(), "test-ed25519-pub.pem")
	if err := os.WriteFile(pubKeyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("writing public key file: %v", err)
	}

	var buf bytes.Buffer
	err = decodeAndPrint(&buf, token, pubKeyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature with Ed25519 public key, got:\n%s", output)
	}
}

func TestDecodeAndPrint_SignatureInvalid_WrongEd25519Key(t *testing.T) {
	signingKey := generateEd25519Key(t)
	wrongKey := generateEd25519Key(t)
	wrongKeyPath := writeEd25519KeyFile(t, wrongKey)
	claims := jwt.MapClaims{"sub": "test"}
	token := signJWTWithEd25519(t, signingKey, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, wrongKeyPath)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: INVALID") {
		t.Errorf("expected invalid signature message for wrong Ed25519 key, got:\n%s", output)
	}
}

func TestDecodeAndPrint_NoKeyNoVerification(t *testing.T) {
	key := generateRSAKey(t)
	claims := jwt.MapClaims{"sub": "test"}
	token := signJWT(t, key, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if strings.Contains(output, "Signature:") {
		t.Errorf("should not show verification when no key provided, got:\n%s", output)
	}
}

// --- nested JWE-in-JWE -------------------------------------------------------

func TestDecodeAndPrintJWE_NestedJWE(t *testing.T) {
	// Create inner JWE encrypted with innerKey.
	innerKey := make([]byte, 32)
	if _, err := rand.Read(innerKey); err != nil {
		t.Fatalf("generating inner key: %v", err)
	}
	innerJWE := encryptJWEGeneric(t, jose.A256KW, jose.A128CBC_HS256, innerKey, []byte(`{"secret":"nested"}`))

	// Create outer JWE that wraps the inner JWE.
	outerKey := generateRSAKey(t)
	outerJWE := encryptJWE(t, outerKey, []byte(innerJWE))

	outerKeyPath := writeKeyFile(t, outerKey)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, outerJWE, outerKeyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	// Should detect the nested JWE and display its header.
	if !strings.Contains(output, "nested JWE") {
		t.Errorf("expected nested JWE detection, got:\n%s", output)
	}
	// Should show the inner JWE's protected header (A256KW algorithm).
	if !strings.Contains(output, "A256KW") {
		t.Errorf("expected inner JWE algorithm in output, got:\n%s", output)
	}
}

// --- JWTD_KEY environment variable -------------------------------------------

func TestRun_JWTDKeyEnvVar_JWEDecryption(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	token := encryptJWE(t, key, []byte(`{"sub":"env-test"}`))

	t.Setenv("JWTD_KEY", keyPath)

	rootCmd := newRootCommand()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{token})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "env-test") {
		t.Errorf("expected decrypted payload with env key, got:\n%s", output)
	}
}

func TestRun_JWTDKeyEnvVar_JWSVerification(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	claims := jwt.MapClaims{"sub": "env-verify"}
	token := signJWT(t, key, claims)

	t.Setenv("JWTD_KEY", keyPath)

	rootCmd := newRootCommand()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{token})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected valid signature via env key, got:\n%s", output)
	}
}

func TestRun_KeyFlagOverridesEnvVar(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKey := generateRSAKey(t)
	signingKeyPath := writeKeyFile(t, signingKey)
	wrongKeyPath := writeKeyFile(t, wrongKey)
	claims := jwt.MapClaims{"sub": "override-test"}
	token := signJWT(t, signingKey, claims)

	// Set env var to the wrong key.
	t.Setenv("JWTD_KEY", wrongKeyPath)

	rootCmd := newRootCommand()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{token, "--key", signingKeyPath})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	// --key flag should take precedence over JWTD_KEY env var.
	if !strings.Contains(output, "Signature: VALID") {
		t.Errorf("expected --key flag to override env var, got:\n%s", output)
	}
}

func TestRun_InvalidSignatureReturnsErrorWithoutUsage(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKeyPath := writeKeyFile(t, generateRSAKey(t))
	token := signJWT(t, signingKey, jwt.MapClaims{"sub": "test"})

	rootCmd := newRootCommand()

	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{token, "--key", wrongKeyPath})

	err := rootCmd.Execute()
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected invalid signature error, got: %v", err)
	}
	if !rootCmd.SilenceUsage || !rootCmd.SilenceErrors {
		t.Fatalf("expected usage and error rendering to be silenced")
	}
	if strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("unexpected usage output:\n%s", stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected duplicate error output:\n%s", stderr.String())
	}
	output := stripANSI(stdout.String())
	if !strings.Contains(output, "Signature: INVALID") {
		t.Fatalf("expected invalid signature output, got:\n%s", output)
	}
	if got := strings.Count(output, "crypto/rsa: verification error"); got != 1 {
		t.Fatalf("expected verification reason exactly once, got %d occurrences:\n%s", got, output)
	}
}

func TestPrintExecutionError_PrintsOrdinaryErrorOnce(t *testing.T) {
	var stderr bytes.Buffer
	err := printExecutionError(&stderr, errors.New("ordinary failure"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := stderr.String(); got != "Error: ordinary failure\n" {
		t.Fatalf("expected one ordinary error, got %q", got)
	}
}

func TestPrintExecutionError_SuppressesInvalidSignature(t *testing.T) {
	var stderr bytes.Buffer
	err := printExecutionError(&stderr, fmt.Errorf("%w: verification details", errInvalidSignature))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no duplicate invalid signature error, got %q", stderr.String())
	}
}

// --- nested JWT inside JWE ---------------------------------------------------

func TestDecodeAndPrintJWE_NestedJWT(t *testing.T) {
	// Create a signed JWT.
	signingKey := generateRSAKey(t)
	claims := jwt.MapClaims{
		"sub": "nested-jwt-test",
		"iss": "jwtd",
		"iat": float64(time.Now().Unix()),
	}
	innerJWT := signJWT(t, signingKey, claims)

	// Encrypt the JWT inside a JWE.
	encKey := generateRSAKey(t)
	jweToken := encryptJWE(t, encKey, []byte(innerJWT))

	encKeyPath := writeKeyFile(t, encKey)

	var buf bytes.Buffer
	err := decodeAndPrintJWE(&buf, jweToken, encKeyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())

	// Should detect the nested JWT.
	if !strings.Contains(output, "nested JWT") {
		t.Errorf("expected 'nested JWT' label, got:\n%s", output)
	}

	// Should display the inner JWT header.
	if !strings.Contains(output, "RS256") {
		t.Errorf("expected inner JWT algorithm RS256, got:\n%s", output)
	}

	// Should display the inner JWT payload.
	if !strings.Contains(output, "nested-jwt-test") {
		t.Errorf("expected inner JWT subject claim, got:\n%s", output)
	}

	// Should display the inner JWT signature.
	if !strings.Contains(output, "Signature") {
		t.Errorf("expected inner JWT signature section, got:\n%s", output)
	}
}

func TestDecodeAndPrintJWE_NestedJWTEscapesC1Controls(t *testing.T) {
	innerJWT := makeJWT(
		`{"alg":"none"}`,
		`{"claim":"before\u009bafter","osc":"\u009d","st":"\u009c"}`,
		"",
	)
	encKey := generateRSAKey(t)
	jweToken := encryptJWE(t, encKey, []byte(innerJWT))
	encKeyPath := writeKeyFile(t, encKey)

	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, jweToken, encKeyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.Bytes()
	if !bytes.Contains(output, []byte("nested JWT")) {
		t.Fatalf("expected nested JWT output, got:\n%q", output)
	}
	assertEscapedControlRunes(t, output, '\u009b', '\u009d', '\u009c')
}

// releaseWorkflow models the subset of .github/workflows/release.yml needed
// to check the release security invariants.
type releaseWorkflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Jobs        map[string]struct {
		Needs yaml.Node `yaml:"needs"`
		Steps []struct {
			Name string `yaml:"name"`
			Uses string `yaml:"uses"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// workflowNeeds returns a job's needs as a list, accepting both the scalar
// and sequence YAML forms.
func workflowNeeds(t *testing.T, node yaml.Node) []string {
	t.Helper()
	switch node.Kind {
	case 0:
		return nil
	case yaml.ScalarNode:
		return []string{node.Value}
	case yaml.SequenceNode:
		var needs []string
		if err := node.Decode(&needs); err != nil {
			t.Fatalf("decoding needs list: %v", err)
		}
		return needs
	default:
		t.Fatalf("unexpected needs node kind %d", node.Kind)
		return nil
	}
}

// TestReleaseWorkflowSecurityInvariants checks the durable security
// properties of the release workflow: actions pinned to commit SHAs,
// least-privilege default permissions, workflow inputs reaching shell
// scripts only through environment variables, and every release job gated
// on the validate job.
func TestReleaseWorkflowSecurityInvariants(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}

	var wf releaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing release workflow: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("release workflow defines no jobs")
	}

	shaPinned := regexp.MustCompile(`@[0-9a-f]{40}$`)
	expression := regexp.MustCompile(`\$\{\{([^}]*)\}\}`)

	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = step.Uses
			}
			if step.Uses != "" && !shaPinned.MatchString(step.Uses) {
				t.Errorf("job %q step %q: action %q must be pinned to a full commit SHA", jobName, stepName, step.Uses)
			}
			for _, match := range expression.FindAllStringSubmatch(step.Run, -1) {
				if expr := strings.TrimSpace(match[1]); !strings.HasPrefix(expr, "matrix.") {
					t.Errorf("job %q step %q: run script interpolates %q; pass untrusted values through env instead", jobName, stepName, match[0])
				}
			}
		}
	}

	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Errorf("workflow permissions must be exactly {contents: read}, got %v", wf.Permissions)
	}

	if got, want := wf.Env["VERSION"], "${{ inputs.version }}"; got != want {
		t.Errorf("root env.VERSION must be %q so scripts read the version via env, got %q", want, got)
	}

	if _, ok := wf.Jobs["validate"]; !ok {
		t.Error("release workflow must define a validate job")
	}
	for jobName, job := range wf.Jobs {
		if jobName == "validate" {
			continue
		}
		if !slices.Contains(workflowNeeds(t, job.Needs), "validate") {
			t.Errorf("job %q must depend on the validate job", jobName)
		}
	}
}
