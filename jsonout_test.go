package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// decodeJWTJSONMap runs decodeJWTJSON and returns the parsed object plus the
// error, so tests can assert on both the shape and the exit-driving error.
func decodeJWTJSONMap(t *testing.T, token, key string) (map[string]any, error) {
	t.Helper()
	var buf bytes.Buffer
	err := decodeJWTJSON(&buf, token, key)

	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	dec.UseNumber()
	if derr := dec.Decode(&out); derr != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", derr, buf.String())
	}
	return out, err
}

func TestDecodeJWTJSON_NoKeyOmitsSignatureValid(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"abc","exp":1516239022}`, "sig")

	out, err := decodeJWTJSONMap(t, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := out["signatureValid"]; present {
		t.Error("signatureValid must be absent when no key is supplied")
	}
	if out["signature"] != "sig" {
		t.Errorf("signature: expected raw segment %q, got %v", "sig", out["signature"])
	}
	payload, _ := out["payload"].(map[string]any)
	// exp must stay a raw numeric value, not the human RFC3339 rendering.
	if got, ok := payload["exp"].(json.Number); !ok || got.String() != "1516239022" {
		t.Errorf("exp must be the exact numeric claim, got %v (%T)", payload["exp"], payload["exp"])
	}
}

func TestDecodeJWTJSON_PreservesLargeIntegerExactly(t *testing.T) {
	// A value beyond float64's integer range must survive verbatim.
	token := makeJWT(`{"alg":"HS256"}`, `{"id":9007199254740993}`, "sig")

	out, err := decodeJWTJSONMap(t, token, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload, _ := out["payload"].(map[string]any)
	if got, _ := payload["id"].(json.Number); got.String() != "9007199254740993" {
		t.Errorf("large integer not preserved, got %v", payload["id"])
	}
}

func TestDecodeJWTJSON_ValidSignature(t *testing.T) {
	secret := []byte("a-random-looking-test-key-with-32b")
	token := signHS256(t, secret, jwt.MapClaims{"sub": "abc"})

	out, err := decodeJWTJSONMap(t, token, "raw:"+string(secret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["signatureValid"] != true {
		t.Errorf("signatureValid: expected true, got %v", out["signatureValid"])
	}
}

func TestDecodeJWTJSON_InvalidSignatureStillEmitsJSONAndErrors(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"abc"}`, "not-the-real-signature")

	out, err := decodeJWTJSONMap(t, token, "raw:wrong-secret")
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature, got %v", err)
	}
	// The JSON must still be emitted so consumers see the decoded token.
	if out["signatureValid"] != false {
		t.Errorf("signatureValid: expected false, got %v", out["signatureValid"])
	}
}

func TestDecodeJWEJSON_NoKeyReportsEncryptedSizes(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte(`{"secret":"value"}`))

	var buf bytes.Buffer
	if err := decodeJWEJSON(&buf, token, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := out["protectedHeader"].(map[string]any); !ok {
		t.Error("protectedHeader missing from JWE JSON")
	}
	enc, ok := out["encrypted"].(map[string]any)
	if !ok {
		t.Fatal("encrypted metadata missing when no key is supplied")
	}
	if _, ok := enc["ciphertextBytes"]; !ok {
		t.Error("encrypted metadata missing ciphertextBytes")
	}
	if _, present := out["decryptedPayload"]; present {
		t.Error("decryptedPayload must be absent without a key")
	}
}

func TestDecodeJWEJSON_WithKeyDecryptsPayload(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	token := encryptJWE(t, key, []byte(`{"secret":"value"}`))

	var buf bytes.Buffer
	if err := decodeJWEJSON(&buf, token, keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	payload, ok := out["decryptedPayload"].(map[string]any)
	if !ok {
		t.Fatalf("decryptedPayload missing or not an object: %v", out["decryptedPayload"])
	}
	if payload["secret"] != "value" {
		t.Errorf("decrypted payload mismatch: %v", payload)
	}
	if _, present := out["encrypted"]; present {
		t.Error("encrypted metadata must be omitted once the payload is decrypted")
	}
}

// A JSON payload output must escape ESC so it cannot smuggle a terminal control
// sequence through when printed.
func TestDecodeJWTJSON_EscapesTerminalControls(t *testing.T) {
	// Build a claim whose value contains a real ESC byte, encoded as valid
	// JSON. Decoding yields the ESC byte in memory; the JSON output must
	// re-escape it rather than emit it raw where a terminal could act on it.
	payload, err := json.Marshal(map[string]string{"sub": string(rune(0x1b)) + "[31mred"})
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	token := makeJWT(`{"alg":"HS256"}`, string(payload), "sig")

	var buf bytes.Buffer
	if err := decodeJWTJSON(&buf, token, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.ContainsRune(buf.Bytes(), 0x1b) {
		t.Error("raw ESC byte leaked into JSON output")
	}
	if !strings.Contains(buf.String(), "\\u001b") {
		t.Error("ESC should be encoded as the \\u001b escape")
	}
}

func TestApplyColorMode(t *testing.T) {
	// applyColorMode flips the fatih/color global; restore it so later tests
	// see the TTY-derived default rather than this test's last mutation.
	orig := color.NoColor
	t.Cleanup(func() { color.NoColor = orig })

	tests := []struct {
		name        string
		mode        string
		jsonOut     bool
		wantErr     bool
		wantNoColor bool
	}{
		{name: "always forces color on", mode: "always", wantNoColor: false},
		{name: "never disables color", mode: "never", wantNoColor: true},
		{name: "json forces color off regardless", mode: "always", jsonOut: true, wantNoColor: true},
		{name: "invalid value errors", mode: "bogus", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := applyColorMode(tt.mode, tt.jsonOut)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error for invalid --color value")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if color.NoColor != tt.wantNoColor {
				t.Errorf("color.NoColor = %v, want %v", color.NoColor, tt.wantNoColor)
			}
		})
	}
}
