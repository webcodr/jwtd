package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestClaimChecks_Requested(t *testing.T) {
	tests := []struct {
		name string
		c    claimChecks
		want bool
	}{
		{"zero value", claimChecks{}, false},
		{"verify", claimChecks{verify: true}, true},
		{"audience", claimChecks{audience: "api"}, true},
		{"issuer", claimChecks{issuer: "iss"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.requested(); got != tt.want {
				t.Errorf("requested() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateClaimsSet(t *testing.T) {
	// now = 1000: exp>1000 is live, nbf<=1000 is active.
	pinTime(t, 1000)
	tests := []struct {
		name       string
		claims     jwt.MapClaims
		checks     claimChecks
		wantValid  bool
		wantReason []string // substrings the reason must contain when invalid
	}{
		{
			name:      "live temporal window",
			claims:    jwt.MapClaims{"exp": float64(2000), "nbf": float64(500)},
			checks:    claimChecks{verify: true},
			wantValid: true,
		},
		{
			name:       "expired",
			claims:     jwt.MapClaims{"exp": float64(500)},
			checks:     claimChecks{verify: true},
			wantValid:  false,
			wantReason: []string{"expired"},
		},
		{
			name:       "not yet valid",
			claims:     jwt.MapClaims{"nbf": float64(1500)},
			checks:     claimChecks{verify: true},
			wantValid:  false,
			wantReason: []string{"not valid yet"},
		},
		{
			name:      "no temporal claims present",
			claims:    jwt.MapClaims{"sub": "a"},
			checks:    claimChecks{verify: true},
			wantValid: true,
		},
		{
			name:      "audience match",
			claims:    jwt.MapClaims{"aud": "my-api"},
			checks:    claimChecks{audience: "my-api"},
			wantValid: true,
		},
		{
			name:       "audience mismatch",
			claims:     jwt.MapClaims{"aud": "other"},
			checks:     claimChecks{audience: "my-api"},
			wantValid:  false,
			wantReason: []string{"aud"},
		},
		{
			name:       "audience required but missing",
			claims:     jwt.MapClaims{"sub": "a"},
			checks:     claimChecks{audience: "my-api"},
			wantValid:  false,
			wantReason: []string{"aud"},
		},
		{
			name:      "issuer match",
			claims:    jwt.MapClaims{"iss": "https://issuer.example"},
			checks:    claimChecks{issuer: "https://issuer.example"},
			wantValid: true,
		},
		{
			name:       "issuer mismatch",
			claims:     jwt.MapClaims{"iss": "https://evil.example"},
			checks:     claimChecks{issuer: "https://issuer.example"},
			wantValid:  false,
			wantReason: []string{"issuer"},
		},
		{
			name:       "multiple failures joined",
			claims:     jwt.MapClaims{"exp": float64(500), "aud": "other"},
			checks:     claimChecks{verify: true, audience: "my-api"},
			wantValid:  false,
			wantReason: []string{"expired", "aud"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, reason := validateClaimsSet(tt.claims, tt.checks)
			if valid != tt.wantValid {
				t.Fatalf("valid = %v (reason %v), want %v", valid, reason, tt.wantValid)
			}
			if tt.wantValid {
				if reason != nil {
					t.Errorf("expected nil reason on valid, got %v", reason)
				}
				return
			}
			for _, want := range tt.wantReason {
				if !strings.Contains(reason.Error(), want) {
					t.Errorf("reason %q missing %q", reason.Error(), want)
				}
			}
		})
	}
}

func TestVerifyClaims_ValidPrintsAndReturnsNil(t *testing.T) {
	pinTime(t, 1000)
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})

	var buf bytes.Buffer
	if err := verifyClaims(&buf, token, claimChecks{verify: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stripANSI(buf.String()), "Claims: VALID") {
		t.Errorf("expected Claims: VALID, got %q", buf.String())
	}
}

func TestVerifyClaims_InvalidReturnsSentinelAndReason(t *testing.T) {
	pinTime(t, 1000)
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

	var buf bytes.Buffer
	err := verifyClaims(&buf, token, claimChecks{verify: true})
	if !errors.Is(err, errInvalidClaims) {
		t.Fatalf("expected errInvalidClaims, got %v", err)
	}
	out := stripANSI(buf.String())
	if !strings.Contains(out, "Claims: INVALID") || !strings.Contains(out, "expired") {
		t.Errorf("expected INVALID with reason, got %q", out)
	}
}

func TestVerifyClaims_UnparseableTokenIsHardError(t *testing.T) {
	var buf bytes.Buffer
	err := verifyClaims(&buf, "not.a.jwt", claimChecks{verify: true})
	if err == nil {
		t.Fatal("expected an error for an unparseable token")
	}
	if errors.Is(err, errInvalidClaims) {
		t.Errorf("a parse failure must be a hard error, not errInvalidClaims: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should be printed for an unparseable token, got %q", buf.String())
	}
}

func TestClaimReason_FlattensJoinedErrors(t *testing.T) {
	joined := errors.Join(errors.New("token is expired"), errors.New("token has invalid audience"))
	got := claimReason(joined)
	if strings.Contains(got, "\n") {
		t.Errorf("reason should be a single line, got %q", got)
	}
	if got != "token is expired; token has invalid audience" {
		t.Errorf("unexpected flattened reason %q", got)
	}
}

// --- decodeJWTHuman integration ---------------------------------------------

func TestDecodeJWTHuman_NoClaimSectionWhenNotRequested(t *testing.T) {
	pinTime(t, 1000)
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

	var buf bytes.Buffer
	if err := decodeJWTHuman(&buf, token, "", claimChecks{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "Claims:") {
		t.Errorf("no Claims section expected without claim flags, got %q", buf.String())
	}
}

func TestDecodeJWTHuman_ClaimsSectionAfterSignature(t *testing.T) {
	pinTime(t, 1000)
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})

	var buf bytes.Buffer
	if err := decodeJWTHuman(&buf, token, "raw:secret", claimChecks{verify: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stripANSI(buf.String())
	sigIdx := strings.Index(out, "Signature: VALID")
	claimIdx := strings.Index(out, "Claims: VALID")
	if sigIdx == -1 || claimIdx == -1 {
		t.Fatalf("expected both Signature: VALID and Claims: VALID, got %q", out)
	}
	if claimIdx < sigIdx {
		t.Errorf("Claims section should follow the signature verdict, got %q", out)
	}
}

func TestDecodeJWTHuman_ValidSignatureInvalidClaims(t *testing.T) {
	pinTime(t, 1000)
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

	var buf bytes.Buffer
	err := decodeJWTHuman(&buf, token, "raw:secret", claimChecks{verify: true})
	if !errors.Is(err, errInvalidClaims) {
		t.Fatalf("expected errInvalidClaims, got %v", err)
	}
	out := stripANSI(buf.String())
	if !strings.Contains(out, "Signature: VALID") || !strings.Contains(out, "Claims: INVALID") {
		t.Errorf("expected valid signature and invalid claims, got %q", out)
	}
}

func TestDecodeJWTHuman_InvalidSignatureStillShowsClaims(t *testing.T) {
	pinTime(t, 1000)
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})

	var buf bytes.Buffer
	// Wrong key: the signature is invalid, but the claims are still live.
	err := decodeJWTHuman(&buf, token, "raw:wrong-secret", claimChecks{verify: true})
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature to take precedence, got %v", err)
	}
	out := stripANSI(buf.String())
	if !strings.Contains(out, "Signature: INVALID") || !strings.Contains(out, "Claims: VALID") {
		t.Errorf("expected both sections shown, got %q", out)
	}
}

// --- decodeJWTJSON claim reporting ------------------------------------------

func TestDecodeJWTJSON_ClaimsValidField(t *testing.T) {
	pinTime(t, 1000)

	t.Run("valid", func(t *testing.T) {
		token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})
		var buf bytes.Buffer
		if err := decodeJWTJSON(&buf, token, "", claimChecks{verify: true}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), `"claimsValid": true`) {
			t.Errorf("expected claimsValid true, got %q", buf.String())
		}
	})

	t.Run("expired emits json then sentinel", func(t *testing.T) {
		token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})
		var buf bytes.Buffer
		err := decodeJWTJSON(&buf, token, "", claimChecks{verify: true})
		if !errors.Is(err, errInvalidClaims) {
			t.Fatalf("expected errInvalidClaims, got %v", err)
		}
		if !strings.Contains(buf.String(), `"claimsValid": false`) {
			t.Errorf("JSON should still be emitted with claimsValid false, got %q", buf.String())
		}
	})

	t.Run("not requested omits field", func(t *testing.T) {
		token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})
		var buf bytes.Buffer
		if err := decodeJWTJSON(&buf, token, "", claimChecks{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(buf.String(), "claimsValid") {
			t.Errorf("claimsValid must be omitted when not requested, got %q", buf.String())
		}
	})
}

func TestDecodeJWTJSON_SignatureTakesPrecedenceOverClaims(t *testing.T) {
	pinTime(t, 1000)
	// Expired claims and a wrong key: both checks fail.
	token := signHS256(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

	var buf bytes.Buffer
	err := decodeJWTJSON(&buf, token, "raw:wrong-secret", claimChecks{verify: true})
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature to take precedence, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"signatureValid": false`) || !strings.Contains(out, `"claimsValid": false`) {
		t.Errorf("expected both verdicts false in JSON, got %q", out)
	}
}
