package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

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

func TestDecodeAndPrint_PreservesLargeJSONNumberInHeader(t *testing.T) {
	token := makeJWT(
		`{"alg":"HS256","custom":9007199254740993}`,
		`{"sub":"header-precision"}`,
		"sig",
	)

	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	plain := stripANSI(buf.String())
	if !strings.Contains(plain, "9007199254740993") {
		t.Errorf("output did not preserve large JSON number in header:\n%s", plain)
	}
}

func TestDecodeAndPrint_RejectsTrailingJWTHeaderData(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "trailing junk", header: `{"alg":"HS256"} trailing-junk`},
		{name: "second JSON value", header: `{"alg":"HS256"} {"second":true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := makeJWT(tt.header, `{"sub":"trailing-header"}`, "sig")

			var buf bytes.Buffer
			err := decodeAndPrint(&buf, token, "")
			if err == nil {
				t.Fatal("expected malformed JWT header error")
			}
			// golang-jwt rejects trailing header data during parsing;
			// the strict re-decode in parseUnverifiedJWT is the backstop.
			if !strings.Contains(err.Error(), "header") {
				t.Errorf("expected JWT header parsing error, got: %v", err)
			}
			if output := stripANSI(buf.String()); strings.Contains(output, "Payload") {
				t.Errorf("malformed header rendered as a normal token:\n%s", output)
			}
		})
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

// An attacker who knows a published key file's bytes must not be able to sign
// an HS256 token with them and have jwtd report it as authentic. This is the
// classic public-key-as-HMAC-secret forgery, reached through key-format
// fallback rather than through the "alg" header.
func TestVerifySignature_RejectsForgedHMACFromPublishedKeyFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	rsaKey := generateRSAKey(t)
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	tests := []struct {
		name     string
		filename string
		contents string
	}{
		{
			name:     "openssh public key",
			filename: "id_ed25519.pub",
			contents: sshEd25519PublicKeyLine(pub, "victim@host") + "\n",
		},
		{
			name:     "authorized_keys entry",
			filename: "authorized_keys",
			contents: sshEd25519PublicKeyLine(pub, "victim@host") + "\n",
		},
		{
			name:     "base64 public key in a file",
			filename: "key.b64",
			contents: base64.StdEncoding.EncodeToString(der) + "\n",
		},
		{
			name:     "empty key file",
			filename: "converted.pem",
			contents: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := writeTextKeyFile(t, tt.filename, tt.contents)
			// The attacker signs with exactly what the victim's key file
			// holds, trailing newline trimmed as jwtd trims it.
			secret := []byte(strings.TrimRight(tt.contents, "\n"))
			forged := signHS256(t, secret, jwt.MapClaims{"sub": "attacker", "role": "admin"})

			var buf bytes.Buffer
			err := verifySignature(&buf, forged, keyPath)
			if err == nil {
				t.Fatal("forged HMAC token accepted")
			}
			if output := stripANSI(buf.String()); strings.Contains(output, "Signature: VALID") {
				t.Errorf("forged HMAC token reported as valid:\n%s", output)
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
