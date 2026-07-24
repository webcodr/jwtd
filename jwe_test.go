package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

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
			keyArg := symmetricKeyArg(t, symKey)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyArg)
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
			keyArg := symmetricKeyArg(t, symKey)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyArg)
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
			keyArg := symmetricKeyArg(t, symKey)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyArg)
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
			// For PBES2 the "key" is a password, so it is passed as an
			// explicit literal secret.
			passwordArg := "raw:" + string(password)

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, passwordArg)
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
	keyArg := symmetricKeyArg(t, symKey)

	for _, tt := range contentEncs {
		t.Run("A256KW/"+tt.name, func(t *testing.T) {
			token := encryptJWEGeneric(t, jose.A256KW, tt.enc, symKey,
				[]byte(`{"sub":"a256kw-combo","result":"success"}`))

			var buf bytes.Buffer
			err := decodeAndPrintJWE(&buf, token, keyArg)
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
