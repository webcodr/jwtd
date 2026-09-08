package main

import (
	"bytes"
	"encoding/json"
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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})

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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})

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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})

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
		token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})
		var buf bytes.Buffer
		if err := decodeJWTJSON(&buf, token, "", claimChecks{verify: true}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(buf.String(), `"claimsValid": true`) {
			t.Errorf("expected claimsValid true, got %q", buf.String())
		}
	})

	t.Run("expired emits json then sentinel", func(t *testing.T) {
		token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})
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
		token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(2000)})
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
	token := signJWTWithHMAC(t, []byte("secret"), jwt.MapClaims{"exp": float64(500)})

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

// golang-jwt converts the temporal claims with a Float64 whose error it
// discards and then casts to int64, so a value outside int64 range wraps and
// the validator returns the opposite verdict: an absurd "exp" reads as expired
// and an absurd "nbf" as long since valid. Such a value must be reported as
// what it is instead, and the verdict must not depend on which way it wrapped.
func TestValidateClaimsSet_RejectsUnrepresentableTemporalClaims(t *testing.T) {
	pinTime(t, 1000)

	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   string
	}{
		{
			name:   "exp past int64 range",
			claims: jwt.MapClaims{"exp": json.Number("10000000000000000000")},
			want:   "exp claim 10000000000000000000 is not a representable timestamp",
		},
		{
			name:   "exp with an absurd exponent",
			claims: jwt.MapClaims{"exp": json.Number("1e400")},
			want:   "exp claim 1e400 is not a representable timestamp",
		},
		{
			name:   "nbf with an absurd exponent",
			claims: jwt.MapClaims{"nbf": json.Number("1e400")},
			want:   "nbf claim 1e400 is not a representable timestamp",
		},
		{
			name:   "nbf below int64 range",
			claims: jwt.MapClaims{"nbf": json.Number("-10000000000000000000")},
			want:   "nbf claim -10000000000000000000 is not a representable timestamp",
		},
		{
			name:   "iat unrepresentable alongside a live exp",
			claims: jwt.MapClaims{"iat": json.Number("1e400"), "exp": json.Number("2000")},
			want:   "iat claim 1e400 is not a representable timestamp",
		},
		{
			name:   "float64 claim past the representable range",
			claims: jwt.MapClaims{"exp": 1e300},
			want:   "exp claim",
		},
		{
			name: "exp reported before nbf",
			claims: jwt.MapClaims{
				"exp": json.Number("1e400"),
				"nbf": json.Number("1e400"),
			},
			want: "exp claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, reason := validateClaimsSet(tt.claims, claimChecks{verify: true})
			if valid {
				t.Fatalf("expected an invalid verdict for %v", tt.claims)
			}
			if !strings.Contains(reason.Error(), tt.want) {
				t.Errorf("reason %q missing %q", reason.Error(), tt.want)
			}
		})
	}
}

// The pre-check must not change the verdict for values it can represent, and
// must leave a non-numeric temporal claim to the validator's own message.
func TestValidateClaimsSet_RepresentableAndNonNumericClaimsUnaffected(t *testing.T) {
	pinTime(t, 1000)

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		wantValid bool
		wantAbout string
	}{
		{
			name:      "ordinary integer seconds",
			claims:    jwt.MapClaims{"exp": json.Number("2000"), "iat": json.Number("900")},
			wantValid: true,
		},
		{
			name:      "fractional seconds",
			claims:    jwt.MapClaims{"exp": json.Number("2000.5")},
			wantValid: true,
		},
		{
			name:      "exponent form within range",
			claims:    jwt.MapClaims{"exp": json.Number("2e3")},
			wantValid: true,
		},
		{
			name:      "string exp is the validator's to reject",
			claims:    jwt.MapClaims{"exp": "tomorrow"},
			wantValid: false,
			wantAbout: "exp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, reason := validateClaimsSet(tt.claims, claimChecks{verify: true})
			if valid != tt.wantValid {
				t.Fatalf("valid = %v, want %v (reason: %v)", valid, tt.wantValid, reason)
			}
			if tt.wantValid {
				return
			}
			if strings.Contains(reason.Error(), "representable") {
				t.Errorf("a non-numeric claim must not be reported as unrepresentable: %v", reason)
			}
			if !strings.Contains(reason.Error(), tt.wantAbout) {
				t.Errorf("reason %q missing %q", reason.Error(), tt.wantAbout)
			}
		})
	}
}

// An unrepresentable claim reaches both output paths through the shared core,
// so neither can report the wrapped verdict.
func TestUnrepresentableClaimFailsBothOutputPaths(t *testing.T) {
	pinTime(t, 1000)
	token := makeJWT(`{"alg":"HS256"}`, `{"nbf":1e400}`, "sig")

	t.Run("human", func(t *testing.T) {
		var buf bytes.Buffer
		err := decodeJWTHuman(&buf, token, "", claimChecks{verify: true})
		if !errors.Is(err, errInvalidClaims) {
			t.Fatalf("expected errInvalidClaims, got %v", err)
		}
		out := stripANSI(buf.String())
		if !strings.Contains(out, "Claims: INVALID") || !strings.Contains(out, "nbf claim") {
			t.Errorf("expected an INVALID verdict naming nbf, got %q", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		var buf bytes.Buffer
		err := decodeJWTJSON(&buf, token, "", claimChecks{verify: true})
		if !errors.Is(err, errInvalidClaims) {
			t.Fatalf("expected errInvalidClaims, got %v", err)
		}
		if !strings.Contains(buf.String(), `"claimsValid": false`) {
			t.Errorf("expected claimsValid false, got %q", buf.String())
		}
	})
}

// The reason is rendered on one line, so a very long claim literal is truncated
// rather than pasted into it whole.
func TestTruncateClaimValue(t *testing.T) {
	got := truncateClaimValue(strings.Repeat("9", 200))
	if len(got) != 35 || !strings.HasSuffix(got, "...") {
		t.Errorf("expected a 32-character prefix plus an ellipsis, got %q", got)
	}
	if short := truncateClaimValue("1758000000"); short != "1758000000" {
		t.Errorf("a short value must be kept verbatim, got %q", short)
	}
}
