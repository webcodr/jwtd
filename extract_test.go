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

// disableColor pins color off for one test so exact-output assertions do not
// depend on TTY detection or on state another test left behind.
func disableColor(t *testing.T) {
	t.Helper()
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })
}

func runExtractJWT(t *testing.T, token, keyStr string, checks claimChecks, sel selection, jsonOut bool) (stdout, stderr string, err error) {
	t.Helper()
	p, perr := parseUnverifiedJWT(token)
	if perr != nil {
		t.Fatalf("parsing token: %v", perr)
	}
	var out, errOut bytes.Buffer
	err = extractJWT(&out, &errOut, p, keyStr, checks, sel, jsonOut)
	return out.String(), errOut.String(), err
}

func TestExtractJWT_Selections(t *testing.T) {
	disableColor(t)
	token := makeJWT(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"u1","n":12345678901234567890,"roles":["a","b"],"x":null,"exp":1700000000}`, "sig")

	tests := []struct {
		name    string
		sel     selection
		jsonOut bool
		want    string
	}{
		{"bare string claim", selection{kind: selectClaim, claim: "sub"}, false, "u1\n"},
		{"json string claim", selection{kind: selectClaim, claim: "sub"}, true, "\"u1\"\n"},
		{"exact number claim", selection{kind: selectClaim, claim: "n"}, false, "12345678901234567890\n"},
		{"array claim", selection{kind: selectClaim, claim: "roles"}, false, "[\"a\",\"b\"]\n"},
		{"null claim is present", selection{kind: selectClaim, claim: "x"}, false, "null\n"},
		{"timestamp claim stays raw", selection{kind: selectClaim, claim: "exp"}, false, "1700000000\n"},
		{"json header", selection{kind: selectHeader}, true, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runExtractJWT(t, token, "", claimChecks{}, tt.sel, tt.jsonOut)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stdout != tt.want {
				t.Errorf("stdout = %q, want %q", stdout, tt.want)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}

	t.Run("formatted payload is raw valid JSON", func(t *testing.T) {
		stdout, _, err := runExtractJWT(t, token, "", claimChecks{}, selection{kind: selectPayload}, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("payload output is not valid JSON:\n%s", stdout)
		}
		if !strings.Contains(stdout, "1700000000") || strings.Contains(stdout, "UTC") {
			t.Errorf("payload timestamps must stay raw, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "12345678901234567890") {
			t.Errorf("payload must keep exact numbers, got:\n%s", stdout)
		}
	})
}

func TestExtractJWT_MissingClaim(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1"}`, "sig")
	stdout, _, err := runExtractJWT(t, token, "", claimChecks{}, selection{kind: selectClaim, claim: "nope"}, false)
	if err == nil || err.Error() != `claim "nope" not present` {
		t.Fatalf("err = %v, want claim \"nope\" not present", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestExtractJWT_EscapesBareClaimString(t *testing.T) {
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"\u001b[31mx"}`, "sig")
	stdout, _, err := runExtractJWT(t, token, "", claimChecks{}, selection{kind: selectClaim, claim: "sub"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ContainsRune(stdout, 0x1b) {
		t.Errorf("bare claim output carries a raw ESC byte: %q", stdout)
	}
	if !strings.Contains(stdout, "[31mx") {
		t.Errorf("bare claim output lost the rest of the value: %q", stdout)
	}
}

func TestExtractJWT_InvalidSignatureWithholdsValue(t *testing.T) {
	disableColor(t)
	token := signJWTWithHMAC(t, []byte("signing-secret-a"), jwt.MapClaims{"sub": "u1"})
	keyStr := symmetricKeyArg(t, []byte("different-secret-b"))

	stdout, stderr, err := runExtractJWT(t, token, keyStr, claimChecks{}, selection{kind: selectClaim, claim: "sub"}, false)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("err = %v, want errInvalidSignature", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty: a value that failed its check must be withheld", stdout)
	}
	if !strings.Contains(stripANSI(stderr), "Signature: INVALID") {
		t.Errorf("stderr = %q, want the failing signature verdict", stderr)
	}
}

func TestExtractJWT_InvalidClaimsWithholdsValue(t *testing.T) {
	disableColor(t)
	pinTime(t, 2000000000)
	token := makeJWT(`{"alg":"HS256"}`, `{"sub":"u1","exp":1700000000}`, "sig")

	stdout, stderr, err := runExtractJWT(t, token, "", claimChecks{verify: true}, selection{kind: selectClaim, claim: "sub"}, false)
	if !errors.Is(err, errInvalidClaims) {
		t.Fatalf("err = %v, want errInvalidClaims", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stripANSI(stderr), "Claims: INVALID") {
		t.Errorf("stderr = %q, want the failing claims verdict", stderr)
	}
}

func TestExtractJWT_SignatureVerdictTakesPrecedence(t *testing.T) {
	disableColor(t)
	pinTime(t, 2000000000)
	token := signJWTWithHMAC(t, []byte("signing-secret-a"), jwt.MapClaims{"sub": "u1", "exp": 1700000000})
	keyStr := symmetricKeyArg(t, []byte("different-secret-b"))

	stdout, stderr, err := runExtractJWT(t, token, keyStr, claimChecks{verify: true}, selection{kind: selectHeader}, false)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("err = %v, want errInvalidSignature to take precedence", err)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	plain := stripANSI(stderr)
	if !strings.Contains(plain, "Signature: INVALID") || !strings.Contains(plain, "Claims: INVALID") {
		t.Errorf("stderr = %q, want both failing verdicts", stderr)
	}
}

func TestExtractJWT_ValidChecksPrintNothingToStderr(t *testing.T) {
	disableColor(t)
	pinTime(t, 1700000000)
	secret := []byte("signing-secret-a")
	token := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "u1", "exp": 1800000000})

	stdout, stderr, err := runExtractJWT(t, token, symmetricKeyArg(t, secret), claimChecks{verify: true}, selection{kind: selectClaim, claim: "sub"}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout != "u1\n" {
		t.Errorf("stdout = %q, want %q", stdout, "u1\n")
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty when every check passes", stderr)
	}
}

func TestExtractJWE(t *testing.T) {
	disableColor(t)
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	nestedJWT := signJWTWithHMAC(t, []byte("nested-secret"), jwt.MapClaims{"sub": "inner"})

	tests := []struct {
		name      string
		plaintext string
		keyStr    string
		sel       selection
		jsonOut   bool
		want      string // exact stdout, when wantErr is empty
		wantErr   string // substring of the error
		check     func(t *testing.T, stdout string)
	}{
		{name: "header needs no key", plaintext: `{"sub":"j1"}`, sel: selection{kind: selectHeader}, jsonOut: true, check: func(t *testing.T, stdout string) {
			var header map[string]any
			if err := json.Unmarshal([]byte(stdout), &header); err != nil || header["alg"] == nil {
				t.Errorf("header output = %q, want a JSON object with alg", stdout)
			}
		}},
		{name: "payload without key", plaintext: `{"sub":"j1"}`, sel: selection{kind: selectPayload}, wantErr: "requires --key to decrypt"},
		{name: "claim without key", plaintext: `{"sub":"j1"}`, sel: selection{kind: selectClaim, claim: "sub"}, wantErr: "requires --key to decrypt"},
		{name: "json payload", plaintext: `{"sub":"j1"}`, keyStr: keyPath, sel: selection{kind: selectPayload}, jsonOut: true, want: "{\"sub\":\"j1\"}\n"},
		{name: "text payload is escaped", plaintext: "hello\x1b", keyStr: keyPath, sel: selection{kind: selectPayload}, check: func(t *testing.T, stdout string) {
			if strings.ContainsRune(stdout, 0x1b) || !strings.Contains(stdout, "hello") {
				t.Errorf("text payload output = %q, want escaped text containing hello", stdout)
			}
		}},
		{name: "claim", plaintext: `{"sub":"j1"}`, keyStr: keyPath, sel: selection{kind: selectClaim, claim: "sub"}, want: "j1\n"},
		{name: "claim on non-object payload", plaintext: `[1,2]`, keyStr: keyPath, sel: selection{kind: selectClaim, claim: "sub"}, wantErr: "decrypted payload is not a JSON object"},
		{name: "claim on nested token", plaintext: nestedJWT, keyStr: keyPath, sel: selection{kind: selectClaim, claim: "sub"}, wantErr: "nested token is not supported"},
		{name: "missing claim", plaintext: `{"sub":"j1"}`, keyStr: keyPath, sel: selection{kind: selectClaim, claim: "nope"}, wantErr: `claim "nope" not present`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := encryptJWE(t, key, []byte(tt.plaintext))
			jwe, header, err := parseJWE(token)
			if err != nil {
				t.Fatalf("parsing JWE: %v", err)
			}
			var out bytes.Buffer
			err = extractJWE(&out, jwe, header, tt.keyStr, tt.sel, tt.jsonOut)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				if out.Len() != 0 {
					t.Errorf("stdout = %q, want empty on error", out.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, out.String())
				return
			}
			if out.String() != tt.want {
				t.Errorf("stdout = %q, want %q", out.String(), tt.want)
			}
		})
	}
}
