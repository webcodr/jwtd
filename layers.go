package main

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// tokenKeys holds the two key arguments. decrypt (--key / JWTD_KEY) decrypts
// every JWE layer. verify (--verify-key / JWTD_VERIFY_KEY) verifies every JWS
// layer; without it, decrypt is offered for verification as well, which is the
// single-key behaviour jwtd had before the two were separated.
type tokenKeys struct {
	decrypt string
	verify  string
}

// verification reports the key a JWS layer is verified with and whether the
// user named it explicitly. An explicit key is never skipped: a nested JWS it
// cannot be used on is an error, not a keyless retry.
func (k tokenKeys) verification() (keyStr string, explicit bool) {
	if k.verify != "" {
		return k.verify, true
	}
	return k.decrypt, false
}

// verdict is the outcome of a signature check that ran.
type verdict struct {
	valid  bool
	reason string
}

// tokenLayer is one layer of an opened token: a JWS, or a JWE with its
// plaintext and, when that plaintext is itself a token, the layer it opened
// into. Exactly one of jws and jwe is set.
//
// Every decryption and every verification happens while opening, before any
// output is written, so the human, --json, and extraction renderers share one
// implementation of the key rules and can make fail-closed decisions (a
// verification key that met no signature, claims that cannot be reached) up
// front.
type tokenLayer struct {
	jws *parsedJWT
	// sig is nil when no verification ran: no key was given, or, in fallback
	// mode on a nested JWS, the decryption key could not be used for it.
	sig *verdict
	// sigSkipped records why, in that second case, so every mode can say on
	// stderr that a nested signature went unverified although a key was given.
	sigSkipped string

	jweToken  string
	jwe       *jose.JSONWebEncryption
	header    map[string]any // the JWE protected header
	plaintext []byte
	decrypted bool

	nested *tokenLayer
}

// openToken parses a compact token and opens it as the outermost layer.
func openToken(token string, keys tokenKeys) (*tokenLayer, error) {
	if isJWE(token) {
		jwe, header, err := parseJWE(token)
		if err != nil {
			return nil, err
		}
		return openJWE(token, jwe, header, keys, false)
	}
	p, err := parseUnverifiedJWT(token)
	if err != nil {
		return nil, err
	}
	return openJWT(p, keys, false)
}

// openJWT verifies an already-parsed JWS when a key applies to it.
//
// The outermost JWS fails hard on a key it cannot use, as it always has. A
// nested one fails hard only when the key was named explicitly with
// --verify-key; in fallback mode the decryption key is merely offered, and a
// nested token that cannot use it is shown without a verdict, as before.
func openJWT(p *parsedJWT, keys tokenKeys, nested bool) (*tokenLayer, error) {
	l := &tokenLayer{jws: p}
	keyStr, explicit := keys.verification()
	if keyStr == "" {
		return l, nil
	}

	kid, err := headerKID(p.header)
	if err == nil {
		var key any
		key, err = loadKeyForToken(keyStr, keySelector{kid: kid, use: "sig", alg: p.method.Alg()})
		if err == nil {
			valid, reason := verifyLoadedKeySignature(p, key)
			l.sig = &verdict{valid: valid}
			if !valid {
				l.sig.reason = reason.Error()
			}
			return l, nil
		}
		err = fmt.Errorf("error loading key: %w", err)
	}

	switch {
	case !nested:
		return nil, fmt.Errorf("signature verification: %w", err)
	case explicit:
		return nil, fmt.Errorf("nested JWT signature verification: %w", err)
	default:
		l.sigSkipped = err.Error()
		return l, nil
	}
}

// openJWE decrypts an already-parsed JWE when a decryption key is given, and
// opens its plaintext when that is a token in turn.
//
// The outermost JWE fails hard on a key it cannot use or a failed decryption,
// as it always has. A nested JWE that cannot be decrypted is shown undecrypted
// instead, which is what the keyless retry used to produce.
func openJWE(token string, jwe *jose.JSONWebEncryption, header map[string]any, keys tokenKeys, nested bool) (*tokenLayer, error) {
	l := &tokenLayer{jweToken: token, jwe: jwe, header: header}
	if keys.decrypt == "" {
		return l, nil
	}

	plaintext, err := decryptJWE(jwe, header, keys.decrypt)
	if err != nil {
		if nested {
			return l, nil
		}
		return nil, err
	}
	l.plaintext = plaintext
	l.decrypted = true

	inner, err := openPlaintext(plaintext, keys)
	if err != nil {
		return nil, err
	}
	l.nested = inner
	return l, nil
}

// decryptJWE loads the decryption key the header selects and decrypts. It is
// the one place the JWE key-load-and-decrypt sequence lives.
func decryptJWE(jwe *jose.JSONWebEncryption, header map[string]any, keyStr string) ([]byte, error) {
	kid, err := headerKID(header)
	if err != nil {
		return nil, err
	}
	alg, _ := header["alg"].(string)
	key, err := loadKeyForToken(keyStr, keySelector{kid: kid, use: "enc", alg: alg})
	if err != nil {
		return nil, fmt.Errorf("loading decryption key: %w", err)
	}
	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypting JWE: %w", err)
	}
	return plaintext, nil
}

// openPlaintext opens a decrypted payload that is itself a token. A payload
// that is not token-shaped, or does not parse as the token it looks like,
// returns nil and is rendered as JSON or text. Only an explicit verification
// key's failure on a nested JWS is an error.
func openPlaintext(plaintext []byte, keys tokenKeys) (*tokenLayer, error) {
	if isJWEBytes(plaintext) {
		token := string(plaintext)
		if jwe, header, err := parseJWE(token); err == nil {
			return openJWE(token, jwe, header, keys, true)
		}
	}
	if isJWTBytes(plaintext) {
		if p, err := parseUnverifiedJWT(string(plaintext)); err == nil {
			return openJWT(p, keys, true)
		}
	}
	return nil, nil
}

// innermost returns the deepest layer that opened.
func (l *tokenLayer) innermost() *tokenLayer {
	for l.nested != nil {
		l = l.nested
	}
	return l
}

// Reasons claim validation cannot reach a claims set. Each makes the claims
// verdict invalid: a requested check that cannot run must not pass.
const (
	reasonClaimsEncrypted    = "the JWE payload is encrypted; pass --key to decrypt it"
	reasonNestedUndecrypted  = "a nested JWE could not be decrypted"
	reasonPayloadNotClaimSet = "the decrypted payload is not a JSON claims set"
)

// claimsTarget returns the innermost claims set: a JWS's claims, or a decrypted
// JWE plaintext that is a JSON object (an encrypted, unsigned JWT). When there
// is none it returns nil and the reason.
func (l *tokenLayer) claimsTarget() (jwt.MapClaims, string) {
	in := l.innermost()
	if in.jws != nil {
		return in.jws.claims, ""
	}
	if !in.decrypted {
		if in == l {
			return nil, reasonClaimsEncrypted
		}
		return nil, reasonNestedUndecrypted
	}
	var claims map[string]any
	if err := decodeJSON(in.plaintext, &claims); err != nil || claims == nil {
		return nil, reasonPayloadNotClaimSet
	}
	return jwt.MapClaims(claims), ""
}

// signatureFailure returns the outermost invalid signature verdict, or nil.
func (l *tokenLayer) signatureFailure() *verdict {
	for ; l != nil; l = l.nested {
		if l.sig != nil && !l.sig.valid {
			return l.sig
		}
	}
	return nil
}

// hasJWS reports whether any opened layer is a JWS.
func (l *tokenLayer) hasJWS() bool {
	for ; l != nil; l = l.nested {
		if l.jws != nil {
			return true
		}
	}
	return false
}

// errVerifyKeyUnused is returned when a verification key was given but the
// opened token holds no JWS for it to verify.
var errVerifyKeyUnused = errors.New("--verify-key was given but no JWS signature was reached")
