package main

import (
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func mustOpen(t *testing.T, token string, keys tokenKeys) *tokenLayer {
	t.Helper()
	l, err := openToken(token, keys)
	if err != nil {
		t.Fatalf("openToken: %v", err)
	}
	return l
}

func TestOpenToken_TopLevel(t *testing.T) {
	secret := []byte("layer-secret-a")
	secretArg := symmetricKeyArg(t, secret)
	wrongArg := symmetricKeyArg(t, []byte("layer-secret-b"))
	hsToken := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "u1"})

	t.Run("plain jwt without a key has no verdict", func(t *testing.T) {
		l := mustOpen(t, makeJWT(`{"alg":"HS256"}`, `{"sub":"u1"}`, "sig"), tokenKeys{})
		if l.jws == nil || l.sig != nil {
			t.Fatalf("got jws=%v sig=%v, want a JWS layer with no verdict", l.jws != nil, l.sig)
		}
	})
	t.Run("decrypt key verifies as the fallback", func(t *testing.T) {
		l := mustOpen(t, hsToken, tokenKeys{decrypt: secretArg})
		if l.sig == nil || !l.sig.valid {
			t.Fatalf("sig = %+v, want valid", l.sig)
		}
	})
	t.Run("verify key wins over the decrypt key", func(t *testing.T) {
		l := mustOpen(t, hsToken, tokenKeys{decrypt: wrongArg, verify: secretArg})
		if l.sig == nil || !l.sig.valid {
			t.Fatalf("sig = %+v, want valid", l.sig)
		}
	})
	t.Run("unusable top-level key is a hard error", func(t *testing.T) {
		_, err := openToken(hsToken, tokenKeys{decrypt: "raw:"})
		if err == nil || !strings.Contains(err.Error(), "signature verification: error loading key") {
			t.Fatalf("err = %v, want a key-loading error", err)
		}
	})

	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	jweToken := encryptJWE(t, key, []byte(`{"sub":"x"}`))

	t.Run("jwe without a key stays encrypted", func(t *testing.T) {
		l := mustOpen(t, jweToken, tokenKeys{})
		if l.jwe == nil || l.decrypted {
			t.Fatalf("got jwe=%v decrypted=%v, want an undecrypted JWE layer", l.jwe != nil, l.decrypted)
		}
	})
	t.Run("jwe with a key decrypts", func(t *testing.T) {
		l := mustOpen(t, jweToken, tokenKeys{decrypt: keyPath})
		if !l.decrypted || string(l.plaintext) != `{"sub":"x"}` || l.nested != nil {
			t.Fatalf("got decrypted=%v plaintext=%q nested=%v", l.decrypted, l.plaintext, l.nested != nil)
		}
	})
	t.Run("jwe with the wrong key is a hard error", func(t *testing.T) {
		_, err := openToken(jweToken, tokenKeys{decrypt: writeKeyFile(t, generateDistinctRSAKey(t))})
		if err == nil || !strings.Contains(err.Error(), "decrypting JWE") {
			t.Fatalf("err = %v, want a decryption error", err)
		}
	})
}

func TestOpenToken_SignedThenEncrypted(t *testing.T) {
	recipient := generateRSAKey(t)
	issuer := generateDistinctRSAKey(t)
	recipientPath := writeKeyFile(t, recipient)
	issuerPub := writeRSAPublicKeyFile(t, &issuer.PublicKey)
	outer := encryptJWE(t, recipient, []byte(signJWT(t, issuer, jwt.MapClaims{"sub": "alice"})))

	t.Run("separate verify key verifies the inner jws", func(t *testing.T) {
		l := mustOpen(t, outer, tokenKeys{decrypt: recipientPath, verify: issuerPub})
		if l.nested == nil || l.nested.jws == nil || l.nested.sig == nil || !l.nested.sig.valid {
			t.Fatalf("nested = %+v, want a valid inner JWS", l.nested)
		}
	})
	t.Run("decrypt key alone is offered to the inner jws, as today", func(t *testing.T) {
		l := mustOpen(t, outer, tokenKeys{decrypt: recipientPath})
		if l.nested == nil || l.nested.sig == nil || l.nested.sig.valid {
			t.Fatalf("nested = %+v, want an invalid verdict from the recipient key", l.nested)
		}
	})

	kidOuter := encryptJWE(t, recipient, []byte(signJWTWithKID(t, issuer, "nope", jwt.MapClaims{"sub": "alice"})))
	t.Run("explicit verify key that misses the kid is a hard error", func(t *testing.T) {
		verifySet := writeJWKSetFile(t, "issuer.jwks", jose.JSONWebKey{Key: &issuer.PublicKey, KeyID: "iss1"})
		_, err := openToken(kidOuter, tokenKeys{decrypt: recipientPath, verify: verifySet})
		if err == nil || !strings.Contains(err.Error(), "nested JWT signature verification") {
			t.Fatalf("err = %v, want a nested verification error", err)
		}
	})
	t.Run("fallback key that misses the kid gives no verdict", func(t *testing.T) {
		decryptSet := writeJWKSetFile(t, "recipient.jwks", jose.JSONWebKey{Key: recipient, KeyID: "rec1"})
		l := mustOpen(t, kidOuter, tokenKeys{decrypt: decryptSet})
		if l.nested == nil || l.nested.jws == nil || l.nested.sig != nil {
			t.Fatalf("nested = %+v, want an inner JWS with no verdict", l.nested)
		}
	})
}

func TestOpenToken_NestedJWEUndecryptable(t *testing.T) {
	keyA := generateRSAKey(t)
	keyB := generateDistinctRSAKey(t)
	outer := encryptJWE(t, keyA, []byte(encryptJWE(t, keyB, []byte(`{"sub":"x"}`))))

	l := mustOpen(t, outer, tokenKeys{decrypt: writeKeyFile(t, keyA)})
	if l.nested == nil || l.nested.jwe == nil || l.nested.decrypted {
		t.Fatalf("nested = %+v, want an undecrypted inner JWE", l.nested)
	}
}

func TestTokenLayer_ClaimsTarget(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	issuer := generateDistinctRSAKey(t)
	other := generateDistinctRSAKey(t)

	tests := []struct {
		name       string
		token      string
		keys       tokenKeys
		wantSub    string
		wantReason string
	}{
		{"jwt", makeJWT(`{"alg":"HS256"}`, `{"sub":"j"}`, "sig"), tokenKeys{}, "j", ""},
		{"jwe without key", encryptJWE(t, key, []byte(`{"sub":"x"}`)), tokenKeys{}, "", "the JWE payload is encrypted; pass --key to decrypt it"},
		{"encrypted claims set", encryptJWE(t, key, []byte(`{"sub":"x"}`)), tokenKeys{decrypt: keyPath}, "x", ""},
		{"text plaintext", encryptJWE(t, key, []byte("text")), tokenKeys{decrypt: keyPath}, "", "the decrypted payload is not a JSON claims set"},
		{"undecryptable nested jwe", encryptJWE(t, key, []byte(encryptJWE(t, other, []byte(`{"sub":"x"}`)))), tokenKeys{decrypt: keyPath}, "", "a nested JWE could not be decrypted"},
		{"nested jws", encryptJWE(t, key, []byte(signJWT(t, issuer, jwt.MapClaims{"sub": "alice"}))), tokenKeys{decrypt: keyPath}, "alice", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, reason := mustOpen(t, tt.token, tt.keys).claimsTarget()
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
			if tt.wantReason != "" {
				if claims != nil {
					t.Errorf("claims = %v, want nil with a reason", claims)
				}
				return
			}
			if claims["sub"] != tt.wantSub {
				t.Errorf("claims[sub] = %v, want %q", claims["sub"], tt.wantSub)
			}
		})
	}
}

func TestTokenLayer_SignatureFailureAndHasJWS(t *testing.T) {
	recipient := generateRSAKey(t)
	issuer := generateDistinctRSAKey(t)
	outer := encryptJWE(t, recipient, []byte(signJWT(t, issuer, jwt.MapClaims{"sub": "alice"})))

	l := mustOpen(t, outer, tokenKeys{decrypt: writeKeyFile(t, recipient)})
	if !l.hasJWS() {
		t.Errorf("hasJWS() = false, want true for a JWE wrapping a JWS")
	}
	if f := l.signatureFailure(); f == nil || f.valid {
		t.Errorf("signatureFailure() = %+v, want the inner invalid verdict", f)
	}

	plain := mustOpen(t, encryptJWE(t, recipient, []byte(`{"sub":"x"}`)), tokenKeys{decrypt: writeKeyFile(t, recipient)})
	if plain.hasJWS() || plain.signatureFailure() != nil {
		t.Errorf("a JWE claims set has no JWS and no signature failure")
	}
}
