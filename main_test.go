package main

import (
	"bytes"
	"crypto/ecdh"
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
	// exp is in the past, so it carries the expired annotation alongside the
	// original epoch value. The elapsed duration depends on the wall clock
	// (timeNow is not pinned here), so only the stable prefix is asserted.
	if !strings.Contains(plain, "(1716239022, expired ") {
		t.Error("output missing original exp epoch value with expired annotation")
	}
}

// A JSON "null" decodes without error and leaves the target map nil, which
// would otherwise be rendered as an empty object with a VALID claim verdict.
// Both segments must be rejected as not naming a JSON object, the way the JWE
// protected header already is.
func TestParseUnverifiedJWT_RejectsNullHeaderAndPayload(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "null payload",
			token: makeJWT(`{"alg":"none"}`, `null`, ""),
			want:  "parsing JWT claims: expected JSON object",
		},
		{
			name:  "null header",
			token: makeJWT(`null`, `{"sub":"x"}`, ""),
			want:  "parsing JWT header: expected JSON object",
		},
		{
			name:  "non-object payload",
			token: makeJWT(`{"alg":"none"}`, `[1,2]`, ""),
			want:  "parsing JWT claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseUnverifiedJWT(tt.token); err == nil {
				t.Fatalf("expected an error for %q", tt.token)
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q missing %q", err, tt.want)
			}
		})
	}
}

// A null header or payload must not reach the output at all: a nil map renders
// as "{}", which would silently misreport the token's contents.
func TestDecodeAndPrint_NullPayloadWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, makeJWT(`{"alg":"none"}`, `null`, ""), ""); err == nil {
		t.Fatal("expected an error for a null payload")
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should be written for a null payload, got %q", buf.String())
	}
}

// The key is resolved before any section is written, so an unusable key
// argument produces an error alone instead of a decoded token followed by one.
// The JWE and --json paths behave the same way.
func TestPrintParsedJWT_KeyErrorWritesNothing(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"x"}`, "sig")
	p, err := parseUnverifiedJWT(token)
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}

	var buf bytes.Buffer
	err = printParsedJWT(&buf, p, filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil {
		t.Fatal("expected an error for an unusable key")
	}
	if !strings.Contains(err.Error(), "error loading key") {
		t.Errorf("error should name the key load failure, got: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no section may be written before the key is resolved, got %q", buf.String())
	}
}

// --- readToken ---------------------------------------------------------------

// An empty or whitespace-only token argument carries no token, so it is
// reported the same way an empty pipe is instead of as a malformed token.
func TestReadToken_EmptyArgIsNoToken(t *testing.T) {
	for _, arg := range []string{"", "   ", "\n\t "} {
		if _, err := readToken([]string{arg}); !errors.Is(err, errNoToken) {
			t.Errorf("readToken(%q): expected errNoToken, got %v", arg, err)
		}
	}
}

// stdin is bounded, so an unbounded pipe fails with a clear message rather than
// being buffered whole or silently truncated into a wrong token.
func TestReadToken_StdinOverLimitErrors(t *testing.T) {
	origStdin := os.Stdin

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	go func() {
		// Exactly one byte past the limit: enough to be detected, and fully
		// consumed by the reader so this goroutine finishes.
		_, _ = w.Write(bytes.Repeat([]byte("a"), maxStdinTokenBytes+1))
		w.Close()
	}()

	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	_, err = readToken([]string{})
	if err == nil {
		t.Fatal("expected an error for stdin past the limit")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should report the limit, got: %v", err)
	}
}

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

// TestReadToken_EmptyStdinPipe pins that a pipe carrying only whitespace is
// reported as "no token provided", matching the interactive prompt, instead of
// surfacing as a malformed-token parse error.
func TestReadToken_EmptyStdinPipe(t *testing.T) {
	origStdin := os.Stdin

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	go func() {
		fmt.Fprint(w, " \n")
		w.Close()
	}()

	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	_, err = readToken([]string{})
	if !errors.Is(err, errNoToken) {
		t.Fatalf("expected errNoToken, got: %v", err)
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

// A JWK Set commonly carries several rotated keys. jwtd must verify against the
// entry named by the token's kid header, not blindly against the first key.
func TestVerifySignature_JWKSetSelectsKeyByKID(t *testing.T) {
	path, _, priv2 := writeJWKSet(t) // entries key-1, key-2

	// Sign with key-2's private key and name it in the header, so verifying
	// against the set only succeeds if kid selection picks the second entry.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "kid-test"})
	token.Header["kid"] = "key-2"
	signed, err := token.SignedString(priv2)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}

	var buf bytes.Buffer
	if err := verifySignature(&buf, signed, path); err != nil {
		t.Fatalf("expected valid signature via kid selection, got: %v", err)
	}
	if output := stripANSI(buf.String()); !strings.Contains(output, "Signature: VALID") {
		t.Errorf("kid-selected verification did not report VALID:\n%s", output)
	}
}

// A kid that names no entry in the set must fail closed with a clear error
// rather than silently verifying against some other key.
func TestVerifySignature_JWKSetUnknownKIDFails(t *testing.T) {
	path, _, priv2 := writeJWKSet(t)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "kid-test"})
	token.Header["kid"] = "key-99"
	signed, err := token.SignedString(priv2)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}

	var buf bytes.Buffer
	err = verifySignature(&buf, signed, path)
	if err == nil {
		t.Fatal("expected an error when the token's kid matches no JWK Set entry")
	}
	if !strings.Contains(err.Error(), "key-99") {
		t.Errorf("error should name the unmatched kid, got: %v", err)
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
			forged := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "attacker", "role": "admin"})

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

// An "oct" JWK with empty key material is the same forgery as `raw:`: the
// empty secret is a published value, so a token HMAC'd with it must never
// verify, in the human path or under --json.
func TestVerifySignature_RejectsForgedHMACFromEmptyOctJWK(t *testing.T) {
	keyPath := writeTextKeyFile(t, "empty.jwk", `{"kty":"oct","k":""}`)
	forged := signJWTWithHMAC(t, []byte{}, jwt.MapClaims{"sub": "attacker", "role": "admin"})

	var buf bytes.Buffer
	if err := verifySignature(&buf, forged, keyPath); err == nil {
		t.Fatal("token forged with the empty JWK secret accepted")
	}
	if output := stripANSI(buf.String()); strings.Contains(output, "Signature: VALID") {
		t.Errorf("forged HMAC token reported as valid:\n%s", output)
	}

	var jsonBuf bytes.Buffer
	if err := decodeJWTJSON(&jsonBuf, forged, keyPath, claimChecks{}); err == nil {
		t.Errorf("--json accepted the token forged with the empty JWK secret:\n%s", jsonBuf.String())
	}
}

// RFC 7515 requires "kid" to be a string. A present non-string kid must be an
// error: treating it as "no kid named" would silently select the first JWK Set
// entry and report a signature made with a key the token never pointed at.
func TestVerifySignature_RejectsNonStringKID(t *testing.T) {
	first := []byte("first-key-32-bytes-of-secret-abc")
	second := []byte("second-key-32-bytes-of-secret-xy")
	setPath := writeTextKeyFile(t, "jwks.json", `{"keys":[`+
		`{"kty":"oct","kid":"a","k":"`+base64.RawURLEncoding.EncodeToString(first)+`"},`+
		`{"kty":"oct","kid":"b","k":"`+base64.RawURLEncoding.EncodeToString(second)+`"}]}`)

	tests := []struct {
		name string
		kid  any
	}{
		{name: "number", kid: 123},
		{name: "null", kid: nil},
		{name: "bool", kid: true},
		{name: "array", kid: []any{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signJWTWithHMACHeader(t, first, map[string]any{"kid": tt.kid},
				jwt.MapClaims{"sub": "attacker"})

			var buf bytes.Buffer
			err := verifySignature(&buf, token, setPath)
			if err == nil {
				t.Fatal("token with a non-string kid accepted")
			}
			if !strings.Contains(err.Error(), "kid") {
				t.Errorf("error should name the kid header, got %v", err)
			}
			if output := stripANSI(buf.String()); strings.Contains(output, "Signature: VALID") {
				t.Errorf("token with a non-string kid reported as valid:\n%s", output)
			}

			var jsonBuf bytes.Buffer
			if err := decodeJWTJSON(&jsonBuf, token, setPath, claimChecks{}); err == nil {
				t.Errorf("--json accepted a token with a non-string kid:\n%s", jsonBuf.String())
			}
		})
	}

	// A well-formed kid still selects its entry, so the check does not break
	// ordinary JWK Set verification.
	t.Run("string kid still verifies", func(t *testing.T) {
		token := signJWTWithHMACHeader(t, second, map[string]any{"kid": "b"},
			jwt.MapClaims{"sub": "test"})

		var buf bytes.Buffer
		if err := verifySignature(&buf, token, setPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if output := stripANSI(buf.String()); !strings.Contains(output, "Signature: VALID") {
			t.Errorf("expected a valid signature, got:\n%s", output)
		}
	})
}

func TestHeaderKID(t *testing.T) {
	tests := []struct {
		name    string
		header  map[string]any
		want    string
		wantErr bool
	}{
		{name: "absent", header: map[string]any{"alg": "HS256"}},
		{name: "string", header: map[string]any{"kid": "key-1"}, want: "key-1"},
		{name: "empty string", header: map[string]any{"kid": ""}},
		{name: "number", header: map[string]any{"kid": json.Number("123")}, wantErr: true},
		{name: "null", header: map[string]any{"kid": nil}, wantErr: true},
		{name: "bool", header: map[string]any{"kid": true}, wantErr: true},
		{name: "object", header: map[string]any{"kid": map[string]any{}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := headerKID(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				if !errors.Is(err, errNonStringKID) {
					t.Errorf("expected errNonStringKID, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("headerKID = %q, want %q", got, tt.want)
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
	wrongKey := generateDistinctRSAKey(t)
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
	wrongKeyPath := writeKeyFile(t, generateDistinctRSAKey(t))
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

// TestDecodeAndPrint_UnparseableKeyNeverBecomesHMACSecret pins the post-5.0.0
// property that key material jwtd cannot parse is rejected outright rather than
// falling back to an HMAC secret. Each row signs a token with the key bytes
// themselves, which is exactly what an attacker who knows a published key can
// do, and asserts the signature is never reported valid. The rows are the
// inputs that reached the old fallback through its various heuristics; the
// heuristics are gone, so they share one body.
func TestDecodeAndPrint_UnparseableKeyNeverBecomesHMACSecret(t *testing.T) {
	rsaKey := generateRSAKey(t)
	publicJWK, err := json.Marshal(jose.JSONWebKey{Key: &rsaKey.PublicKey})
	if err != nil {
		t.Fatalf("marshaling public JWK: %v", err)
	}
	bomPublicJWK := append([]byte{0xef, 0xbb, 0xbf}, publicJWK...)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "BOM-prefixed public JWK", data: bomPublicJWK},
		{name: "escaped JWK member", data: []byte(`{"\u006bty":"oct","k":`)},
		{name: "literal kty after malformed value", data: []byte(`{"bad":truX,"kty":"RSA","n":"public"}`)},
		{name: "escaped kty after malformed value", data: []byte(`{"bad":truX,"\u006bty":"RSA","n":"public"}`)},
		{name: "later keys", data: []byte(`{"bad":truX,"keys":[`)},
		{name: "kty truncated before colon", data: []byte(`{"bad":truX,"kty"`)},
		{name: "missing comma before literal kty", data: []byte(`{"note":"x" "kty":"RSA","n":"public"}`)},
		{name: "missing comma before escaped kty", data: []byte(`{"note":"x" "\u006bty":"RSA","n":"public"}`)},
		{name: "missing comma before literal kty at EOF", data: []byte(`{"note":"x" "kty"`)},
		{name: "escaped keys at EOF after malformed value", data: []byte(`{"bad":truX "\u006b\u0065\u0079\u0073"`)},
		{name: "literal kty with missing colon", data: []byte(`{"kty" "RSA","n":"public"}`)},
		{name: "escaped kty with replaced colon", data: []byte(`{"\u006bty";"RSA","n":"public"}`)},
		{name: "literal keys with replaced colon", data: []byte(`{"keys"=[{"kty":"RSA"}]}`)},
		{name: "escaped keys with missing colon", data: []byte(`{"\u006b\u0065\u0079\u0073" [{"kty":"RSA"}]}`)},
		{name: "truncated kty member", data: []byte(`{"kty`)},
		{name: "malformed JWK fields without kty", data: []byte(`{"n":"public","e":"AQAB",`)},
	}

	// Both readings of a key argument reach the same rejection, so every row
	// runs as a file and as inline base64.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []string{"file", "base64"} {
				t.Run(mode, func(t *testing.T) {
					keyInput := base64.StdEncoding.EncodeToString(tt.data)
					if mode == "file" {
						keyInput = writeTempFile(t, "malformed.jwk", tt.data)
					}
					token := signJWTWithHMAC(t, tt.data, jwt.MapClaims{"sub": "test"})

					var buf bytes.Buffer
					if err := decodeAndPrint(&buf, token, keyInput); err == nil {
						t.Fatalf("expected unparseable key material to be rejected, got output:\n%s", stripANSI(buf.String()))
					}
					if strings.Contains(stripANSI(buf.String()), "Signature: VALID") {
						t.Fatalf("unparseable key material was accepted as an HMAC secret:\n%s", stripANSI(buf.String()))
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
	keyArg := symmetricKeyArg(t, symKey)
	claims := jwt.MapClaims{"sub": "test"}
	token := signJWTWithHMAC(t, symKey, claims)

	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, keyArg)
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
	pubKeyPath := writeTempFile(t, "test-ed25519-pub.pem", pem.EncodeToMemory(block))

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
	wrongKey := generateDistinctRSAKey(t)
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

// Key detection is precedence-based, so a value meant one way can be read
// another. The CLI says which reading applied whenever it is not a file, and
// flags the process-list exposure that inline key material carries.
func TestRun_KeyInterpretationHint(t *testing.T) {
	secret := []byte("a-32-byte-symmetric-test-secret!")
	token := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "hint"})

	tests := []struct {
		name       string
		args       []string
		env        string
		wantStderr []string
		notStderr  []string
		// Some readings are reported and then rejected; the note still has
		// to reach the user, which is when it is most useful.
		wantErr bool
	}{
		{
			name:       "literal secret",
			args:       []string{token, "--key", "raw:" + string(secret)},
			wantStderr: []string{"--key used as a literal symmetric secret", "process list"},
		},
		{
			// Opaque inline base64 is reported, then rejected: symmetric
			// secrets have to be explicit.
			name:       "inline base64",
			args:       []string{token, "--key", base64.StdEncoding.EncodeToString(secret)},
			wantStderr: []string{"is not an existing file", "decoded as base64", "process list"},
			wantErr:    true,
		},
		{
			name:      "explicit secret file stays silent",
			args:      []string{token, "--key", symmetricKeyArg(t, secret)},
			notStderr: []string{"Note:", "process list"},
		},
		{
			// The env var is readable only by the owning user, unlike argv,
			// so it carries the interpretation note without the exposure line.
			name:       "env var omits the process-list warning",
			args:       []string{token},
			env:        "raw:" + string(secret),
			wantStderr: []string{"JWTD_KEY used as a literal symmetric secret"},
			notStderr:  []string{"process list"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("JWTD_KEY", tt.env)
			}

			rootCmd := newRootCommand()
			var out, errBuf bytes.Buffer
			rootCmd.SetOut(&out)
			rootCmd.SetErr(&errBuf)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()
			if tt.wantErr && err == nil {
				t.Fatal("expected the key to be rejected")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			stderr := stripANSI(errBuf.String())
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr, want) {
					t.Errorf("expected stderr to mention %q, got:\n%s", want, stderr)
				}
			}
			for _, unwanted := range tt.notStderr {
				if strings.Contains(stderr, unwanted) {
					t.Errorf("stderr must not mention %q, got:\n%s", unwanted, stderr)
				}
			}
			// The hint is diagnostic output and must never reach stdout,
			// which is parsed by tooling.
			if stdout := stripANSI(out.String()); strings.Contains(stdout, "Note:") {
				t.Errorf("key hint leaked into stdout:\n%s", stdout)
			}
		})
	}
}

func TestRun_InvalidSignatureReturnsErrorWithoutUsage(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKeyPath := writeKeyFile(t, generateDistinctRSAKey(t))
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

// TestVerifyJWTSignature_RejectsAlgOutsideKeyTypeAllowlist pins the algorithm
// restriction across every supported key type. Verification runs from the
// already-parsed token rather than through jwt.Parse, so the allowlist that
// jwt.WithValidMethods used to apply is now jwtd's own check: without it, an
// HS256 token signed with the bytes of a published public key would verify
// against that key.
func TestVerifyJWTSignature_RejectsAlgOutsideKeyTypeAllowlist(t *testing.T) {
	rsaKey := generateRSAKey(t)
	ecKey := generateECKey(t)
	edKey := generateEd25519Key(t)
	secret := []byte("a-shared-secret-of-sufficient-len")

	hmacToken := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "test"})
	rsaToken := signJWT(t, rsaKey, jwt.MapClaims{"sub": "test"})

	tests := []struct {
		name    string
		token   string
		keyArg  string
		wantAlg string
	}{
		{
			name:    "HS256 token against RSA public key",
			token:   hmacToken,
			keyArg:  writeRSAPublicKeyFile(t, &rsaKey.PublicKey),
			wantAlg: "HS256",
		},
		{
			name:    "HS256 token against EC public key",
			token:   hmacToken,
			keyArg:  writeECPublicKeyFile(t, &ecKey.PublicKey),
			wantAlg: "HS256",
		},
		{
			name:    "HS256 token against Ed25519 key",
			token:   hmacToken,
			keyArg:  writeEd25519KeyFile(t, edKey),
			wantAlg: "HS256",
		},
		{
			name:    "RS256 token against symmetric secret",
			token:   rsaToken,
			keyArg:  "raw:" + string(secret),
			wantAlg: "RS256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseUnverifiedJWT(tt.token)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			valid, reason, err := verifyJWTSignature(p, tt.keyArg)
			if err != nil {
				t.Fatalf("unexpected hard error: %v", err)
			}
			if valid {
				t.Fatal("signature accepted for an algorithm the key type cannot carry")
			}
			want := "signing method " + tt.wantAlg + " is invalid"
			if reason == nil || !strings.Contains(reason.Error(), want) {
				t.Errorf("expected %q in reason, got: %v", want, reason)
			}
		})
	}
}

// TestVerifyJWTSignature_RejectsKeyTypeWithoutJWSAlgorithms pins that the
// allowlist fails closed for a key type it does not know. An X25519 key parses
// (it is a valid JWE key) but can verify no JWS algorithm, so the allowlist
// itself must refuse it — before any Verify implementation is asked to.
func TestVerifyJWTSignature_RejectsKeyTypeWithoutJWSAlgorithms(t *testing.T) {
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating X25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(x25519Key)
	if err != nil {
		t.Fatalf("marshalling X25519 key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "x25519.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	if methods := validMethodsForKey(x25519Key); len(methods) != 0 {
		t.Fatalf("validMethodsForKey(X25519) = %v, want none", methods)
	}

	for _, token := range []string{
		signJWTWithHMAC(t, []byte("a-shared-secret-of-sufficient-len"), jwt.MapClaims{"sub": "test"}),
		signJWT(t, generateRSAKey(t), jwt.MapClaims{"sub": "test"}),
	} {
		p, err := parseUnverifiedJWT(token)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		valid, reason, err := verifyJWTSignature(p, keyPath)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if valid {
			t.Fatal("signature accepted against a key type that can verify no JWS")
		}
		if reason == nil || !strings.Contains(reason.Error(), "cannot verify a JWS") {
			t.Errorf("expected key-type rejection in reason, got: %v", reason)
		}
	}
}

// TestParseUnverifiedJWT_RejectsMalformedTokens pins the token shapes the
// decoder refuses. parseUnverifiedJWT splits and decodes the segments itself
// instead of calling jwt.ParseUnverified, so these rejections are jwtd's own
// and must not quietly widen.
func TestParseUnverifiedJWT_RejectsMalformedTokens(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{name: "no delimiters", token: "notatoken", want: "invalid number of segments"},
		{name: "two segments", token: header + "." + payload, want: "invalid number of segments"},
		{name: "four segments", token: header + "." + payload + ".sig.extra", want: "invalid number of segments"},
		{name: "unknown alg", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"NOPE"}`)) + "." + payload + ".sig", want: "signing method (alg) is unavailable"},
		{name: "missing alg", token: base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`)) + "." + payload + ".sig", want: "signing method (alg) is unspecified"},
		{name: "signature not base64url", token: header + "." + payload + "._!!_", want: "could not base64 decode signature"},
		{name: "header not base64url", token: "_!!_." + payload + ".sig", want: "decoding header"},
		{name: "payload not base64url", token: header + "._!!_.sig", want: "decoding payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseUnverifiedJWT(tt.token)
			if err == nil {
				t.Fatalf("expected error, got a parsed token: %+v", p)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected %q in error, got: %v", tt.want, err)
			}
		})
	}
}

// TestParseUnverifiedJWT_DecodesSegmentsOnce checks that the parsed token
// carries everything the later steps need, so neither the signature check nor
// claim validation has to decode the token a second time.
func TestParseUnverifiedJWT_DecodesSegmentsOnce(t *testing.T) {
	secret := []byte("a-shared-secret-of-sufficient-len")
	token := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "test"})

	p, err := parseUnverifiedJWT(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := p.header["alg"]; got != "HS256" {
		t.Errorf("expected HS256 header alg, got %v", got)
	}
	if p.method == nil || p.method.Alg() != "HS256" {
		t.Errorf("expected HS256 signing method, got %v", p.method)
	}
	if len(p.signature) == 0 {
		t.Error("expected decoded signature bytes")
	}
	if got, _ := p.claims["sub"].(string); got != "test" {
		t.Errorf("expected sub claim, got %v", p.claims["sub"])
	}
	if len(p.parts) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(p.parts))
	}
	if p.parts[0]+"."+p.parts[1]+"."+p.parts[2] != token {
		t.Error("segments do not reassemble into the original token")
	}
}

func TestReadToken_StripsBearerPrefixAndQuotes(t *testing.T) {
	tok := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"

	validCases := []struct {
		name  string
		input string
	}{
		{"Bearer space", "Bearer " + tok},
		{"lowercase bearer", "bearer " + tok},
		{"uppercase BEARER tab", "BEARER\t" + tok},
		{"Bearer newline", "Bearer\n" + tok},
		{"Authorization Bearer", "Authorization: Bearer " + tok},
		{"lowercase authorization no space after colon", "authorization:bearer " + tok},
		{"Authorization spaces around colon", "Authorization : Bearer " + tok},
		{"double quoted token", `"` + tok + `"`},
		{"single quoted token", `'` + tok + `'`},
		{"double quoted Bearer token", `"Bearer ` + tok + `"`},
		{"Authorization with quoted Bearer", `Authorization: "Bearer ` + tok + `"`},
		{"Bearer with quoted token", `Bearer "` + tok + `"`},
		{"wrapped multiline Authorization Bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.\neyJzdWIiOiIxMjMifQ.\nsig\n"},
	}

	for _, tt := range validCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readToken([]string{tt.input})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tok {
				t.Errorf("got %q, want %q", got, tok)
			}
		})
	}

	t.Run("empty or prefix-only returns errNoToken", func(t *testing.T) {
		for _, input := range []string{`""`, `''`, `Authorization:`, `Authorization:   `, `Authorization: Bearer`, `Authorization: "Bearer"`} {
			if got, err := readToken([]string{input}); !errors.Is(err, errNoToken) {
				t.Errorf("readToken(%q) = (%q, %v), want errNoToken", input, got, err)
			}
		}
	})

	t.Run("unmatched quotes preserved", func(t *testing.T) {
		got, err := readToken([]string{`"` + tok})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != `"`+tok {
			t.Errorf("got %q, want unmatched quote preserved", got)
		}
	})

	t.Run("word starting with Bearer not stripped", func(t *testing.T) {
		got, err := readToken([]string{"BearerToken.payload.sig"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "BearerToken.payload.sig" {
			t.Errorf("got %q, want BearerToken.payload.sig", got)
		}
	})
}

func TestVerifySignature_JWKSetDisambiguatesByUseAndAlg(t *testing.T) {
	encKey := generateDistinctRSAKey(t)
	sigKey := generateRSAKey(t)
	jwksPath := writeJWKSetFile(t, "jwks.json",
		jose.JSONWebKey{Key: &encKey.PublicKey, KeyID: "shared-kid", Use: "enc", Algorithm: "RSA-OAEP-256"},
		jose.JSONWebKey{Key: &sigKey.PublicKey, KeyID: "shared-kid", Use: "sig", Algorithm: "RS256"},
	)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "jws-disambiguated"})
	token.Header["kid"] = "shared-kid"
	signed, err := token.SignedString(sigKey)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}

	var buf bytes.Buffer
	if err := verifySignature(&buf, signed, jwksPath); err != nil {
		t.Fatalf("expected valid signature via use/alg disambiguation, got %v", err)
	}
	assertOutputContains(t, buf.String(), "Signature: VALID")
}

func execCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newRootCommand()
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return stripANSI(outBuf.String()), stripANSI(errBuf.String()), err
}

func TestRun_AlgPinning(t *testing.T) {
	rsaKey := generateRSAKey(t)
	rsaKeyPath := writeKeyFile(t, rsaKey)
	jwtToken := signJWT(t, rsaKey, jwt.MapClaims{"sub": "alg-test"})
	jweToken := encryptJWE(t, rsaKey, []byte(`{"sub":"jwe-alg"}`))

	t.Run("JWT matching alg succeeds", func(t *testing.T) {
		out, _, err := execCLI(t, "--alg", "RS256", "--key", rsaKeyPath, jwtToken)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertOutputContains(t, out, "Signature: VALID")
	})

	t.Run("JWT mismatched alg fails before output", func(t *testing.T) {
		for _, extra := range [][]string{{}, {"--key", rsaKeyPath}, {"--json"}, {"--json", "--key", rsaKeyPath}} {
			args := append([]string{"--alg", "EdDSA"}, extra...)
			args = append(args, jwtToken)
			out, _, err := execCLI(t, args...)
			if err == nil || !strings.Contains(err.Error(), `does not match expected --alg "EdDSA"`) {
				t.Fatalf("args %v: expected alg mismatch error, got %v", args, err)
			}
			if out != "" {
				t.Errorf("args %v: expected empty stdout on alg mismatch, got %q", args, out)
			}
		}
	})

	t.Run("JWE matching alg succeeds", func(t *testing.T) {
		out, _, err := execCLI(t, "--alg", "RSA-OAEP-256", "--key", rsaKeyPath, jweToken)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertOutputContains(t, out, "jwe-alg")
	})

	t.Run("JWE mismatched alg fails before decrypting or printing", func(t *testing.T) {
		for _, extra := range [][]string{{}, {"--key", rsaKeyPath}, {"--json"}, {"--json", "--key", rsaKeyPath}} {
			args := append([]string{"--alg", "RSA-OAEP"}, extra...)
			args = append(args, jweToken)
			out, _, err := execCLI(t, args...)
			if err == nil || !strings.Contains(err.Error(), `does not match expected --alg "RSA-OAEP"`) {
				t.Fatalf("args %v: expected alg mismatch error, got %v", args, err)
			}
			if out != "" {
				t.Errorf("args %v: expected empty stdout on alg mismatch, got %q", args, out)
			}
		}
	})

	t.Run("outer JWE alg match allows differently-alg nested JWT", func(t *testing.T) {
		secret := []byte("nested-hmac-secret-32-bytes-long")
		inner := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "inner"})
		outer := encryptJWE(t, rsaKey, []byte(inner))

		out, _, err := execCLI(t, "--alg", "RSA-OAEP-256", "--key", rsaKeyPath, outer)
		if !errors.Is(err, errInvalidSignature) {
			t.Fatalf("expected nested errInvalidSignature, got %v", err)
		}
		assertOutputContains(t, out, "nested JWT", "inner")
	})
}

func TestRun_QuietMode(t *testing.T) {
	secret := []byte("quiet-mode-secret-32-bytes-long!")
	pinTime(t, 1000)
	liveToken := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "u1", "exp": float64(2000)})
	expiredToken := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "u1", "exp": float64(500)})

	t.Run("valid JWT produces no stdout", func(t *testing.T) {
		out, _, err := execCLI(t, "-q", "--key", "raw:"+string(secret), "--verify-claims", liveToken)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "" {
			t.Errorf("expected empty stdout in quiet mode, got %q", out)
		}
	})

	t.Run("valid JWE produces no stdout", func(t *testing.T) {
		key := generateRSAKey(t)
		jweToken := encryptJWE(t, key, []byte(`{"sub":"u1"}`))
		out, _, err := execCLI(t, "--quiet", "--key", writeKeyFile(t, key), jweToken)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "" {
			t.Errorf("expected empty stdout in quiet mode, got %q", out)
		}
	})

	t.Run("invalid signature returns sentinel with empty stdout", func(t *testing.T) {
		for _, extra := range [][]string{{}, {"--json"}} {
			args := append([]string{"-q", "--key", "raw:wrong"}, extra...)
			args = append(args, liveToken)
			out, _, err := execCLI(t, args...)
			if !errors.Is(err, errInvalidSignature) {
				t.Fatalf("args %v: expected errInvalidSignature, got %v", args, err)
			}
			if out != "" {
				t.Errorf("args %v: expected empty stdout in quiet mode, got %q", args, out)
			}
		}
	})

	t.Run("invalid claims returns sentinel with empty stdout", func(t *testing.T) {
		for _, extra := range [][]string{{}, {"--json"}} {
			args := append([]string{"-q", "--verify-claims"}, extra...)
			args = append(args, expiredToken)
			out, _, err := execCLI(t, args...)
			if !errors.Is(err, errInvalidClaims) {
				t.Fatalf("args %v: expected errInvalidClaims, got %v", args, err)
			}
			if out != "" {
				t.Errorf("args %v: expected empty stdout in quiet mode, got %q", args, out)
			}
		}
	})
}

func TestRun_AtFlag(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1","exp":2000}`, "sig")

	t.Run("RFC3339 adjusts annotations and claim verdict", func(t *testing.T) {
		out, _, err := execCLI(t, "--at", "1970-01-01T00:16:40Z", "--verify-claims", token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertOutputContains(t, out, "expires in 16m", "Claims: VALID")
	})

	t.Run("Unix seconds in past-expiry evaluates invalid", func(t *testing.T) {
		out, _, err := execCLI(t, "--at", "2600", "--verify-claims", token)
		if !errors.Is(err, errInvalidClaims) {
			t.Fatalf("expected errInvalidClaims, got %v", err)
		}
		assertOutputContains(t, out, "expired 10m ago", "Claims: INVALID")
	})

	t.Run("--at alone does not imply claim enforcement", func(t *testing.T) {
		out, _, err := execCLI(t, "--at", "2600", token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertOutputContains(t, out, "expired 10m ago")
		if strings.Contains(out, "Claims:") {
			t.Errorf("Claims section should not appear without claim flags:\n%s", out)
		}
	})

	t.Run("invalid and out-of-range --at values error", func(t *testing.T) {
		for _, bad := range []string{"not-a-time", "253402300800", "-62167219201"} {
			if _, _, err := execCLI(t, "--at", bad, token); err == nil {
				t.Errorf("expected error for --at %q", bad)
			}
		}
	})
}

func TestRun_TimezoneAndClaimFlags(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"alice","iat":1516239022,"auth_time":1516239000,"exp":1516239622}`, "sig")

	t.Run("--tz formats timestamps in requested zone", func(t *testing.T) {
		out, _, err := execCLI(t, "--tz", "America/New_York", "--at", "1516239022", token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertOutputContains(t, out,
			"2018-01-17T20:30:22-05:00 (1516239022)",
			"2018-01-17T20:30:00-05:00 (1516239000)",
			"2018-01-17T20:40:22-05:00 (1516239622, expires in 10m)",
		)
	})

	t.Run("--json ignores --tz and keeps raw timestamps", func(t *testing.T) {
		out, _, err := execCLI(t, "--json", "--tz", "America/New_York", token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "-05:00") || !strings.Contains(out, `"iat": 1516239022`) {
			t.Errorf("expected raw numeric timestamps in --json output, got:\n%s", out)
		}
	})

	t.Run("--local uses time.Local", func(t *testing.T) {
		out, _, err := execCLI(t, "--local", token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Unix(1516239022, 0).In(time.Local).Format(time.RFC3339Nano) + " (1516239022)"
		assertOutputContains(t, out, want)
	})

	t.Run("--local and --tz together error", func(t *testing.T) {
		if _, _, err := execCLI(t, "--local", "--tz", "UTC", token); err == nil {
			t.Fatal("expected error when both --local and --tz are set")
		}
	})

	t.Run("invalid --tz errors", func(t *testing.T) {
		if _, _, err := execCLI(t, "--tz", "Mars/Olympus_Mons", token); err == nil {
			t.Fatal("expected error for invalid --tz")
		}
	})

	t.Run("negative --leeway errors", func(t *testing.T) {
		if _, _, err := execCLI(t, "--leeway", "-5s", token); err == nil {
			t.Fatal("expected error for negative --leeway")
		}
	})

	t.Run("--sub, --leeway, and --require-exp wire through CLI", func(t *testing.T) {
		out, _, err := execCLI(t, "--at", "1516239640", "--leeway", "30s", "--sub", "alice", "--require-exp", token)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertOutputContains(t, out, "Claims: VALID")

		noExp := makeJWT(`{"alg":"HS256"}`, `{"sub":"alice"}`, "sig")
		out, _, err = execCLI(t, "--require-exp", noExp)
		if !errors.Is(err, errInvalidClaims) {
			t.Fatalf("expected errInvalidClaims for missing exp, got %v", err)
		}
		assertOutputContains(t, out, "Claims: INVALID")
	})
}

// runRootCommand executes the CLI with args and returns what it wrote to
// stdout and stderr, so extraction tests can assert on each stream.
func runRootCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	rootCmd := newRootCommand()
	var out, errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetArgs(args)
	err = rootCmd.Execute()
	return out.String(), errOut.String(), err
}

func TestRun_ClaimExtraction(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1"}`, "sig")
	stdout, _, err := runRootCommand(t, "--claim", "sub", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout != "u1\n" {
		t.Errorf("stdout = %q, want %q", stdout, "u1\n")
	}
}

func TestRun_SelectorsMutuallyExclusive(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1"}`, "sig")
	_, _, err := runRootCommand(t, "--header", "--payload", token)
	if err == nil || !strings.Contains(err.Error(), "none of the others can be") {
		t.Fatalf("err = %v, want a mutually-exclusive flags error", err)
	}
}

func TestRun_EmptyClaimRejectedBeforeToken(t *testing.T) {
	_, _, err := runRootCommand(t, "--claim", "")
	if err == nil || !strings.Contains(err.Error(), "--claim requires a claim name") {
		t.Fatalf("err = %v, want the empty --claim to be rejected", err)
	}
	if errors.Is(err, errNoToken) {
		t.Errorf("empty --claim must be rejected before the token is read")
	}
}

func TestRun_ClaimExtractionWithholdsOnBadSignature(t *testing.T) {
	token := signJWTWithHMAC(t, []byte("signing-secret-a"), jwt.MapClaims{"sub": "u1"})
	stdout, stderr, err := runRootCommand(t, "--key", "raw:different-secret-b", "--claim", "sub", token)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("err = %v, want errInvalidSignature", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stripANSI(stderr), "Signature: INVALID") {
		t.Errorf("stderr = %q, want the failing signature verdict", stderr)
	}
}

func TestRun_JWEPayloadUsesEnvKey(t *testing.T) {
	key := generateRSAKey(t)
	t.Setenv("JWTD_KEY", writeKeyFile(t, key))
	token := encryptJWE(t, key, []byte(`{"sub":"env-extract"}`))

	stdout, _, err := runRootCommand(t, "--json", "--payload", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout != "{\"sub\":\"env-extract\"}\n" {
		t.Errorf("stdout = %q, want the decrypted payload", stdout)
	}
}

func TestRun_QuietWithSelector(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1"}`, "sig")
	stdout, _, err := runRootCommand(t, "-q", "--claim", "sub", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty under -q", stdout)
	}
}

func TestRun_AlgPinAppliesToExtraction(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1"}`, "sig")
	stdout, _, err := runRootCommand(t, "--alg", "EdDSA", "--claim", "sub", token)
	if err == nil || !strings.Contains(err.Error(), "does not match expected --alg") {
		t.Fatalf("err = %v, want an --alg mismatch", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestRun_JWEExtractionValidatesClaims(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	token := encryptJWE(t, key, []byte(`{"sub":"x","aud":"other"}`))

	stdout, stderr, err := runRootCommand(t, "--key", keyPath, "--aud", "mine", "--claim", "sub", token)
	if !errors.Is(err, errInvalidClaims) {
		t.Fatalf("err = %v, want errInvalidClaims", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty: a value whose claims failed must be withheld", stdout)
	}
	if !strings.Contains(stripANSI(stderr), "Claims: INVALID") {
		t.Errorf("stderr = %q, want the failing claims verdict", stderr)
	}
}

// signedThenEncrypted returns an RS256 JWS signed by an issuer key and
// encrypted to a recipient key, plus the recipient private key file and the
// issuer public key file: the shape of an encrypted OIDC ID token.
func signedThenEncrypted(t *testing.T, claims jwt.MapClaims) (token, recipientPath, issuerPubPath string) {
	t.Helper()
	recipient := generateRSAKey(t)
	issuer := generateDistinctRSAKey(t)
	token = encryptJWE(t, recipient, []byte(signJWT(t, issuer, claims)))
	return token, writeKeyFile(t, recipient), writeRSAPublicKeyFile(t, &issuer.PublicKey)
}

func TestRun_VerifyKeyNestedJWS(t *testing.T) {
	token, recipientPath, issuerPub := signedThenEncrypted(t, jwt.MapClaims{"sub": "alice"})
	stdout, _, err := runRootCommand(t, "--key", recipientPath, "--verify-key", issuerPub, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stripANSI(stdout), "Signature: VALID") {
		t.Errorf("stdout missing the inner verdict:\n%s", stdout)
	}
}

func TestRun_VerifyKeyFromEnv(t *testing.T) {
	secret := []byte("env-verify-secret")
	token := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "u1"})
	t.Setenv("JWTD_VERIFY_KEY", symmetricKeyArg(t, secret))
	// A global decryption key must not get in the way of a plain JWT.
	t.Setenv("JWTD_KEY", symmetricKeyArg(t, []byte("unrelated-secret")))

	stdout, _, err := runRootCommand(t, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stripANSI(stdout), "Signature: VALID") {
		t.Errorf("stdout missing a valid verdict:\n%s", stdout)
	}
}

func TestRun_VerifyKeyUnused(t *testing.T) {
	token, _, issuerPub := signedThenEncrypted(t, jwt.MapClaims{"sub": "alice"})
	stdout, _, err := runRootCommand(t, "--verify-key", issuerPub, token)
	want := "--verify-key was given but no JWS signature was reached (pass --key to decrypt the JWE first)"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestRun_VerifyKeyUnusedOnEncryptedClaimsSet(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	token := encryptJWE(t, key, []byte(`{"sub":"x"}`))
	_, _, err := runRootCommand(t, "--key", keyPath, "--verify-key", keyPath, token)
	if err == nil || err.Error() != "--verify-key was given but no JWS signature was reached" {
		t.Fatalf("err = %v, want the unused verify key error without the --key hint", err)
	}
}

func TestRun_ClaimsOnNestedJWS(t *testing.T) {
	pinTime(t, 2000000000)
	token, recipientPath, issuerPub := signedThenEncrypted(t, jwt.MapClaims{"sub": "alice", "exp": 1700000000})
	stdout, _, err := runRootCommand(t, "--key", recipientPath, "--verify-key", issuerPub, "--verify-claims", token)
	if !errors.Is(err, errInvalidClaims) {
		t.Fatalf("err = %v, want errInvalidClaims", err)
	}
	if !strings.Contains(stripANSI(stdout), "Claims: INVALID") {
		t.Errorf("stdout missing the claims verdict:\n%s", stdout)
	}
}

func TestRun_ClaimsOnJWEWithoutKey(t *testing.T) {
	token := encryptJWE(t, generateRSAKey(t), []byte(`{"sub":"x"}`))
	stdout, stderr, err := runRootCommand(t, "--verify-claims", token)
	if !errors.Is(err, errInvalidClaims) {
		t.Fatalf("err = %v, want errInvalidClaims: a claim check that cannot run must not pass", err)
	}
	plain := stripANSI(stdout)
	if !strings.Contains(plain, "Claims: INVALID") || !strings.Contains(plain, "pass --key to decrypt it") {
		t.Errorf("stdout missing the unreachable-claims verdict:\n%s", stdout)
	}
	if strings.Contains(stderr, "skipped for JWE") {
		t.Errorf("the skipped-for-JWE note must be gone, stderr:\n%s", stderr)
	}
}

func TestRun_ClaimsOnEncryptedClaimsSet(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"sub":"x","aud":"a"}`))
	stdout, _, err := runRootCommand(t, "--key", writeKeyFile(t, key), "--aud", "a", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stripANSI(stdout), "Claims: VALID") {
		t.Errorf("stdout missing a valid claims verdict:\n%s", stdout)
	}
}

func TestRun_VerifyKeyInterpretationNote(t *testing.T) {
	token := signJWTWithHMAC(t, []byte("note-secret"), jwt.MapClaims{"sub": "u1"})
	_, stderr, err := runRootCommand(t, "--verify-key", "raw:note-secret", token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stderr, "--verify-key used as a literal symmetric secret") {
		t.Errorf("stderr missing the --verify-key interpretation note:\n%s", stderr)
	}
}
