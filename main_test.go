package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// helper to build a JWT from raw JSON header/payload and a signature string.
func makeJWT(headerJSON, payloadJSON, sig string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return h + "." + p + "." + sig
}

// --- decodeSegment -----------------------------------------------------------

func TestDecodeSegment_Valid(t *testing.T) {
	raw := `{"alg":"HS256","typ":"JWT"}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))

	result, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["alg"] != "HS256" {
		t.Errorf("expected alg=HS256, got %v", result["alg"])
	}
	if result["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got %v", result["typ"])
	}
}

func TestDecodeSegment_AllTypes(t *testing.T) {
	raw := `{"s":"hello","n":42,"f":3.14,"b":true,"bf":false,"null_val":null}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(raw))

	result, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["s"] != "hello" {
		t.Errorf("expected s=hello, got %v", result["s"])
	}
	if result["n"] != float64(42) {
		t.Errorf("expected n=42, got %v", result["n"])
	}
	if result["f"] != float64(3.14) {
		t.Errorf("expected f=3.14, got %v", result["f"])
	}
	if result["b"] != true {
		t.Errorf("expected b=true, got %v", result["b"])
	}
	if result["bf"] != false {
		t.Errorf("expected bf=false, got %v", result["bf"])
	}
	if result["null_val"] != nil {
		t.Errorf("expected null_val=nil, got %v", result["null_val"])
	}
}

func TestDecodeSegment_InvalidBase64(t *testing.T) {
	_, err := decodeSegment("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "base64 decode") {
		t.Errorf("expected base64 decode error, got: %v", err)
	}
}

func TestDecodeSegment_InvalidJSON(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := decodeSegment(encoded)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "JSON parse") {
		t.Errorf("expected JSON parse error, got: %v", err)
	}
}

func TestDecodeSegment_EmptyObject(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	result, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

// --- decodeAndPrint ----------------------------------------------------------

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestDecodeAndPrint_ValidJWT(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
		"test-signature",
	)

	output := captureStdout(t, func() {
		if err := decodeAndPrint(token); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Should contain all sections (no color since stdout is piped)
	if !strings.Contains(output, "Header") {
		t.Error("output missing Header label")
	}
	if !strings.Contains(output, "Payload") {
		t.Error("output missing Payload label")
	}
	if !strings.Contains(output, "Signature") {
		t.Error("output missing Signature label")
	}
	if !strings.Contains(output, "test-signature") {
		t.Error("output missing signature value")
	}
	if !strings.Contains(output, `"alg"`) {
		t.Error("output missing alg key")
	}
	if !strings.Contains(output, `"HS256"`) {
		t.Error("output missing HS256 value")
	}
	if !strings.Contains(output, `"name"`) {
		t.Error("output missing name key")
	}
	if !strings.Contains(output, `"John Doe"`) {
		t.Error("output missing John Doe value")
	}
}

func TestDecodeAndPrint_WrongPartCount(t *testing.T) {
	tests := []struct {
		name  string
		token string
		parts int
	}{
		{"no dots", "abcdef", 1},
		{"one dot", "abc.def", 2},
		{"three dots", "a.b.c.d", 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := decodeAndPrint(tt.token)
			if err == nil {
				t.Fatal("expected error for wrong part count")
			}
			expected := fmt.Sprintf("got %d", tt.parts)
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("expected error containing %q, got: %v", expected, err)
			}
		})
	}
}

func TestDecodeAndPrint_InvalidHeader(t *testing.T) {
	token := "!!!." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"123"}`)) +
		".sig"

	err := decodeAndPrint(token)
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
	if !strings.Contains(err.Error(), "decoding header") {
		t.Errorf("expected header decode error, got: %v", err)
	}
}

func TestDecodeAndPrint_InvalidPayload(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) +
		".!!!." +
		"sig"

	err := decodeAndPrint(token)
	if err == nil {
		t.Fatal("expected error for invalid payload")
	}
	if !strings.Contains(err.Error(), "decoding payload") {
		t.Errorf("expected payload decode error, got: %v", err)
	}
}

// --- isJSONKey ---------------------------------------------------------------

func TestIsJSONKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pos      int
		expected bool
	}{
		{
			name:     "simple key",
			input:    `"key": "value"`,
			pos:      0,
			expected: true,
		},
		{
			name:     "string value",
			input:    `"key": "value"`,
			pos:      7,
			expected: false,
		},
		{
			name:     "key with spaces before colon",
			input:    `"key"  : "val"`,
			pos:      0,
			expected: true,
		},
		{
			name:     "key with escaped quote",
			input:    `"k\"y": "val"`,
			pos:      0,
			expected: true,
		},
		{
			name:     "value after escaped quote key",
			input:    `"k\"y": "val"`,
			pos:      8,
			expected: false,
		},
		{
			name:     "last value no colon",
			input:    `"value"`,
			pos:      0,
			expected: false,
		},
		{
			name:     "unclosed string",
			input:    `"unclosed`,
			pos:      0,
			expected: false,
		},
		{
			name:     "key followed by newline then colon",
			input:    "\"key\"\n:",
			pos:      0,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJSONKey(tt.input, tt.pos)
			if got != tt.expected {
				t.Errorf("isJSONKey(%q, %d) = %v, want %v", tt.input, tt.pos, got, tt.expected)
			}
		})
	}
}

// --- colorize ----------------------------------------------------------------

func TestColorize_Keys(t *testing.T) {
	input := `{"alg": "HS256"}`
	result := colorize(input)

	if !strings.Contains(result, colorKey+`"alg"`+colorReset) {
		t.Error("key 'alg' not colorized with key color")
	}
}

func TestColorize_StringValues(t *testing.T) {
	input := `{"alg": "HS256"}`
	result := colorize(input)

	if !strings.Contains(result, colorString+`"HS256"`+colorReset) {
		t.Error("string value 'HS256' not colorized with string color")
	}
}

func TestColorize_Numbers(t *testing.T) {
	input := `{"iat": 1516239022}`
	result := colorize(input)

	if !strings.Contains(result, colorNumber+"1516239022"+colorReset) {
		t.Error("number not colorized with number color")
	}
}

func TestColorize_NegativeNumber(t *testing.T) {
	input := `{"val": -42}`
	result := colorize(input)

	if !strings.Contains(result, colorNumber+"-42"+colorReset) {
		t.Error("negative number not colorized with number color")
	}
}

func TestColorize_FloatNumber(t *testing.T) {
	input := `{"val": 3.14}`
	result := colorize(input)

	if !strings.Contains(result, colorNumber+"3.14"+colorReset) {
		t.Error("float number not colorized with number color")
	}
}

func TestColorize_ScientificNotation(t *testing.T) {
	input := `{"val": 1e10}`
	result := colorize(input)

	if !strings.Contains(result, colorNumber+"1e10"+colorReset) {
		t.Error("scientific notation number not colorized with number color")
	}
}

func TestColorize_BoolTrue(t *testing.T) {
	input := `{"admin": true}`
	result := colorize(input)

	if !strings.Contains(result, colorBool+"true"+colorReset) {
		t.Error("true not colorized with bool color")
	}
}

func TestColorize_BoolFalse(t *testing.T) {
	input := `{"admin": false}`
	result := colorize(input)

	if !strings.Contains(result, colorBool+"false"+colorReset) {
		t.Error("false not colorized with bool color")
	}
}

func TestColorize_Null(t *testing.T) {
	input := `{"val": null}`
	result := colorize(input)

	if !strings.Contains(result, colorNull+"null"+colorReset) {
		t.Error("null not colorized with null color")
	}
}

func TestColorize_Braces(t *testing.T) {
	input := `{"a": [1]}`
	result := colorize(input)

	if !strings.Contains(result, colorBrace+"{"+colorReset) {
		t.Error("opening brace not colorized")
	}
	if !strings.Contains(result, colorBrace+"}"+colorReset) {
		t.Error("closing brace not colorized")
	}
	if !strings.Contains(result, colorBrace+"["+colorReset) {
		t.Error("opening bracket not colorized")
	}
	if !strings.Contains(result, colorBrace+"]"+colorReset) {
		t.Error("closing bracket not colorized")
	}
}

func TestColorize_EscapedQuoteInString(t *testing.T) {
	input := `{"key": "val\"ue"}`
	result := colorize(input)

	// The escaped quote should NOT break colorization - the string value
	// should still be wrapped in string color.
	if !strings.Contains(result, colorString+`"val\"ue"`+colorReset) {
		t.Errorf("escaped quote in string value broke colorization, got: %q", result)
	}
}

func TestColorize_EmptyObject(t *testing.T) {
	input := `{}`
	result := colorize(input)

	expected := colorBrace + "{" + colorReset + colorBrace + "}" + colorReset
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestColorize_MultipleKeys(t *testing.T) {
	input := `{"a": "1", "b": "2"}`
	result := colorize(input)

	if !strings.Contains(result, colorKey+`"a"`+colorReset) {
		t.Error("key 'a' not colorized")
	}
	if !strings.Contains(result, colorKey+`"b"`+colorReset) {
		t.Error("key 'b' not colorized")
	}
	if !strings.Contains(result, colorString+`"1"`+colorReset) {
		t.Error("value '1' not colorized")
	}
	if !strings.Contains(result, colorString+`"2"`+colorReset) {
		t.Error("value '2' not colorized")
	}
}

func TestColorize_PreservesWhitespace(t *testing.T) {
	input := "{\n  \"key\": \"val\"\n}"
	result := colorize(input)

	// Newlines and spaces should be preserved
	if !strings.Contains(result, "\n  ") {
		t.Error("whitespace not preserved in colorized output")
	}
}

// --- printSection ------------------------------------------------------------

func TestPrintSection_NoColor(t *testing.T) {
	data := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	output := captureStdout(t, func() {
		printSection("Header", data, false)
	})

	if !strings.HasPrefix(output, "Header\n") {
		t.Errorf("expected output to start with 'Header\\n', got: %q", output)
	}
	if !strings.Contains(output, `"alg": "HS256"`) {
		t.Error("output missing alg field")
	}
	if !strings.Contains(output, `"typ": "JWT"`) {
		t.Error("output missing typ field")
	}
	// Should NOT contain ANSI codes
	if strings.Contains(output, "\033[") {
		t.Error("no-color output contains ANSI escape codes")
	}
}

func TestPrintSection_WithColor(t *testing.T) {
	data := map[string]interface{}{
		"alg": "HS256",
	}

	output := captureStdout(t, func() {
		printSection("Header", data, true)
	})

	// Should start with colored label
	if !strings.HasPrefix(output, colorLabel+"Header"+colorReset+"\n") {
		t.Errorf("expected colored Header label, got prefix: %q", output[:min(len(output), 40)])
	}
	// Should contain ANSI codes in the JSON body
	if !strings.Contains(output, colorKey) {
		t.Error("colored output missing key color codes")
	}
}

// --- printSignature ----------------------------------------------------------

func TestPrintSignature_NoColor(t *testing.T) {
	output := captureStdout(t, func() {
		printSignature("abc123sig", false)
	})

	expected := "Signature\nabc123sig\n"
	if output != expected {
		t.Errorf("expected %q, got %q", expected, output)
	}
}

func TestPrintSignature_WithColor(t *testing.T) {
	output := captureStdout(t, func() {
		printSignature("abc123sig", true)
	})

	if !strings.Contains(output, colorLabel+"Signature"+colorReset) {
		t.Error("missing colored Signature label")
	}
	if !strings.Contains(output, colorDim+"abc123sig"+colorReset) {
		t.Error("missing dimmed signature value")
	}
}

// --- end-to-end via decodeAndPrint -------------------------------------------

func TestDecodeAndPrint_EndToEnd(t *testing.T) {
	// jwt.io example token (HS256)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	output := captureStdout(t, func() {
		err := decodeAndPrint(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Verify decoded content
	checks := []string{
		`"alg": "HS256"`,
		`"typ": "JWT"`,
		`"sub": "1234567890"`,
		`"name": "John Doe"`,
		"2018-01-18T01:30:22Z",
		"Header",
		"Payload",
		"Signature",
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestDecodeAndPrint_EmptyToken(t *testing.T) {
	err := decodeAndPrint("")
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

	output := captureStdout(t, func() {
		err := decodeAndPrint(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(output, "nested") {
		t.Error("output missing nested key")
	}
	if !strings.Contains(output, "value") {
		t.Error("output missing nested value")
	}
}

// --- formatTimestamps --------------------------------------------------------

func TestFormatTimestamps_AllTimestampFields(t *testing.T) {
	data := map[string]interface{}{
		"iat": float64(1516239022),
		"exp": float64(1716239022),
		"nbf": float64(1516239022),
	}

	formatTimestamps(data)

	expected := time.Unix(1516239022, 0).UTC().Format(time.RFC3339)
	if data["iat"] != expected {
		t.Errorf("iat: expected %q, got %v", expected, data["iat"])
	}
	if data["nbf"] != expected {
		t.Errorf("nbf: expected %q, got %v", expected, data["nbf"])
	}

	expectedExp := time.Unix(1716239022, 0).UTC().Format(time.RFC3339)
	if data["exp"] != expectedExp {
		t.Errorf("exp: expected %q, got %v", expectedExp, data["exp"])
	}
}

func TestFormatTimestamps_NonTimestampFieldsUnchanged(t *testing.T) {
	data := map[string]interface{}{
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
	data := map[string]interface{}{
		"sub": "user123",
		"iat": float64(0),
		"exp": float64(1700000000),
	}

	formatTimestamps(data)

	if data["sub"] != "user123" {
		t.Errorf("sub changed: %v", data["sub"])
	}

	expectedIat := time.Unix(0, 0).UTC().Format(time.RFC3339)
	if data["iat"] != expectedIat {
		t.Errorf("iat: expected %q, got %v", expectedIat, data["iat"])
	}

	expectedExp := time.Unix(1700000000, 0).UTC().Format(time.RFC3339)
	if data["exp"] != expectedExp {
		t.Errorf("exp: expected %q, got %v", expectedExp, data["exp"])
	}
}

func TestFormatTimestamps_NonNumericTimestampField(t *testing.T) {
	data := map[string]interface{}{
		"iat": "not-a-number",
	}

	formatTimestamps(data)

	// Should be left as-is when the value is not a number
	if data["iat"] != "not-a-number" {
		t.Errorf("non-numeric iat was modified: %v", data["iat"])
	}
}

func TestFormatTimestamps_EmptyMap(t *testing.T) {
	data := map[string]interface{}{}
	formatTimestamps(data) // should not panic
	if len(data) != 0 {
		t.Errorf("empty map modified: %v", data)
	}
}

func TestFormatTimestamps_OutputFormat(t *testing.T) {
	data := map[string]interface{}{
		"iat": float64(1516239022),
	}

	formatTimestamps(data)

	val, ok := data["iat"].(string)
	if !ok {
		t.Fatalf("iat should be a string after formatting, got %T", data["iat"])
	}

	// Verify it's a valid RFC3339 timestamp
	_, err := time.Parse(time.RFC3339, val)
	if err != nil {
		t.Errorf("iat is not valid RFC3339: %v", err)
	}

	// Verify the specific value
	if val != "2018-01-18T01:30:22Z" {
		t.Errorf("expected 2018-01-18T01:30:22Z, got %s", val)
	}
}

func TestDecodeAndPrint_TimestampsFormatted(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256"}`,
		`{"sub":"user1","iat":1516239022,"exp":1716239022,"nbf":1516239022}`,
		"sig",
	)

	output := captureStdout(t, func() {
		err := decodeAndPrint(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// Should contain formatted dates, not raw numbers
	if strings.Contains(output, "1516239022") {
		t.Error("output still contains raw iat/nbf timestamp")
	}
	if strings.Contains(output, "1716239022") {
		t.Error("output still contains raw exp timestamp")
	}
	if !strings.Contains(output, "2018-01-18T01:30:22Z") {
		t.Error("output missing formatted iat/nbf date")
	}
	if !strings.Contains(output, "2024-05-20T") {
		t.Error("output missing formatted exp date")
	}
}
