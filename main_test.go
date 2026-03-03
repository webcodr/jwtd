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

// --- decodeAndPrint ----------------------------------------------------------

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

	plain := stripANSI(output)

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
			err := decodeAndPrint(tt.token)
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

	err := decodeAndPrint(token)
	if err == nil {
		t.Fatal("expected error for invalid header")
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

	plain := stripANSI(output)
	if !strings.Contains(plain, "nested") {
		t.Error("output missing nested key")
	}
	if !strings.Contains(plain, "value") {
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

	_, err := time.Parse(time.RFC3339, val)
	if err != nil {
		t.Errorf("iat is not valid RFC3339: %v", err)
	}

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

	plain := stripANSI(output)

	if strings.Contains(plain, "1516239022") {
		t.Error("output still contains raw iat/nbf timestamp")
	}
	if strings.Contains(plain, "1716239022") {
		t.Error("output still contains raw exp timestamp")
	}
	if !strings.Contains(plain, "2018-01-18T01:30:22Z") {
		t.Error("output missing formatted iat/nbf date")
	}
	if !strings.Contains(plain, "2024-05-20T") {
		t.Error("output missing formatted exp date")
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
	data := map[string]interface{}{
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
	data := map[string]interface{}{
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
	data := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	output := captureStdout(t, func() {
		printSection(f, "Header", data)
	})

	plain := stripANSI(output)

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
	data := map[string]interface{}{
		"a": float64(1),
		"b": "two",
	}

	output := captureStdout(t, func() {
		printSection(f, "Test", data)
	})

	plain := stripANSI(output)

	// Should be pretty-printed (multi-line with indentation)
	lines := strings.Split(strings.TrimSpace(plain), "\n")
	if len(lines) < 3 {
		t.Errorf("expected multi-line output, got %d lines", len(lines))
	}
}

// --- printSignature ----------------------------------------------------------

func TestPrintSignature_Output(t *testing.T) {
	output := captureStdout(t, func() {
		printSignature("abc123sig")
	})

	plain := stripANSI(output)

	if !strings.Contains(plain, "Signature") {
		t.Error("missing Signature label")
	}
	if !strings.Contains(plain, "abc123sig") {
		t.Error("missing signature value")
	}
}

func TestPrintSignature_LabelsOnSeparateLines(t *testing.T) {
	output := captureStdout(t, func() {
		printSignature("mysig")
	})

	plain := stripANSI(output)
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

	output := captureStdout(t, func() {
		err := decodeAndPrint(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	plain := stripANSI(output)

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

	output := captureStdout(t, func() {
		err := decodeAndPrint(token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	plain := stripANSI(output)

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
