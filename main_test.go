package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// helper to build a JWT from raw JSON header/payload and a signature string.
func makeJWT(headerJSON, payloadJSON, sig string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return h + "." + p + "." + sig
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

// captureStdout is retained only for tests that exercise stdin-reading code paths
// which still write to os.Stdout internally (e.g. readToken). For all other tests,
// use a bytes.Buffer passed as io.Writer directly.
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

// --- formatTimestamps --------------------------------------------------------

func TestFormatTimestamps_AllTimestampFields(t *testing.T) {
	data := map[string]any{
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

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())

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

	if strings.Contains(plain, "1516239022") {
		t.Error("output contains raw timestamp, should be formatted")
	}
	if !strings.Contains(plain, "2018-01-18T01:30:22Z") {
		t.Error("output missing formatted timestamp")
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

// --- decodedLen --------------------------------------------------------------

func TestDecodedLen_ValidBase64(t *testing.T) {
	data := base64.RawURLEncoding.EncodeToString([]byte("hello world"))
	n := decodedLen(data)
	if n != 11 {
		t.Errorf("expected 11, got %d", n)
	}
}

func TestDecodedLen_InvalidBase64(t *testing.T) {
	n := decodedLen("!!!invalid!!!")
	if n != 0 {
		t.Errorf("expected 0 for invalid base64, got %d", n)
	}
}

func TestDecodedLen_Empty(t *testing.T) {
	n := decodedLen("")
	if n != 0 {
		t.Errorf("expected 0 for empty string, got %d", n)
	}
}

// --- jweHeaderMap ------------------------------------------------------------

func TestJweHeaderMap_ExtractsAlgorithm(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"test"}`))

	jwe, err := jose.ParseEncrypted(token, allKeyAlgorithms(), allContentEncryptions())
	if err != nil {
		t.Fatalf("parsing JWE: %v", err)
	}

	m := jweHeaderMap(jwe)
	if m["alg"] != "RSA-OAEP-256" {
		t.Errorf("expected alg RSA-OAEP-256, got %v", m["alg"])
	}
	if m["enc"] != "A256GCM" {
		t.Errorf("expected enc A256GCM, got %v", m["enc"])
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

	// Timestamp should be formatted.
	if strings.Contains(plain, "1700000000") {
		t.Error("output contains raw timestamp")
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := stripANSI(buf.String())
	if !strings.Contains(output, "Signature: INVALID") {
		t.Errorf("expected invalid signature message, got:\n%s", output)
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
