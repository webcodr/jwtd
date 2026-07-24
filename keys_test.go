package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

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

func TestLoadKey_RawPrefix(t *testing.T) {
	loaded, err := loadKey("raw:my-literal-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if string(symKey) != "my-literal-secret" {
		t.Errorf("expected literal secret, got %q", symKey)
	}
}

func TestLoadKey_TextKeyFileTrimsTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("my-text-secret\n"), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if string(symKey) != "my-text-secret" {
		t.Errorf("expected trailing newline trimmed, got %q", symKey)
	}
}

func TestLoadKey_BinaryKeyFileKeepsTrailingNewlineByte(t *testing.T) {
	binKey := []byte{0x00, 0x01, 0xfe, 0xff, '\n'}
	keyPath := writeSymmetricKeyFile(t, binKey)

	loaded, err := loadKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if !bytes.Equal(symKey, binKey) {
		t.Errorf("binary key modified: expected % x, got % x", binKey, symKey)
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

func TestLoadKey_X509Certificate(t *testing.T) {
	priv := generateRSAKey(t)
	pemPath, derPath, pemBytes := writeRSACertificateFiles(t, priv)
	tests := []struct {
		name  string
		input string
	}{
		{name: "PEM file", input: pemPath},
		{name: "DER file", input: derPath},
		{name: "base64 PEM", input: base64.StdEncoding.EncodeToString(pemBytes)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loaded, err := loadKey(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			publicKey, ok := loaded.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
			}
			if publicKey.N.Cmp(priv.PublicKey.N) != 0 || publicKey.E != priv.PublicKey.E {
				t.Error("loaded certificate public key does not match original")
			}
		})
	}
}

func TestLoadKey_RejectsMalformedStructuredData(t *testing.T) {
	unsupportedDER, err := asn1.Marshal(struct{ Value int }{Value: 1})
	if err != nil {
		t.Fatalf("marshaling unsupported DER: %v", err)
	}
	publicKey := generateRSAKey(t)
	publicJWK, err := json.Marshal(jose.JSONWebKey{Key: &publicKey.PublicKey})
	if err != nil {
		t.Fatalf("marshaling public JWK: %v", err)
	}
	publicJWKSet, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &publicKey.PublicKey}}})
	if err != nil {
		t.Fatalf("marshaling public JWK Set: %v", err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "malformed PEM", data: []byte("-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "malformed PEM after preamble", data: []byte("Bag Attributes\n    localKeyID: 01 00\n-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "indented malformed PEM after preamble", data: []byte("Bag Attributes\n    -----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "malformed PEM after BOM and preamble", data: []byte("\xef\xbb\xbfBag Attributes\n-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n")},
		{name: "malformed JWK JSON", data: []byte(`{"kty":"RSA","n":`)},
		{name: "malformed JWK with escaped kty", data: []byte(`{"\u006bty":"oct","k":`)},
		{name: "malformed JWK Set with escaped keys", data: []byte(`{"\u006b\u0065\u0079\u0073":[`)},
		{name: "escaped strings before escaped kty", data: []byte(`{"note":"escaped quote: \" and slash: \\","\u006bty":"oct","k":`)},
		{name: "literal kty after malformed value", data: []byte(`{"bad":truX,"kty":"RSA","n":"public"}`)},
		{name: "escaped kty after malformed value", data: []byte(`{"bad":truX,"\u006bty":"RSA","n":"public"}`)},
		{name: "literal kty after missing comma", data: []byte(`{"note":"x" "kty":"RSA","n":"public"}`)},
		{name: "escaped kty after missing comma", data: []byte(`{"note":"x" "\u006bty":"RSA","n":"public"}`)},
		{name: "literal keys after malformed value", data: []byte(`{"bad":truX,"keys":[`)},
		{name: "escaped keys after malformed value", data: []byte(`{"bad":truX,"\u006b\u0065\u0079\u0073":[`)},
		{name: "literal kty truncated before colon", data: []byte(`{"bad":truX,"kty"`)},
		{name: "escaped kty truncated before colon", data: []byte(`{"bad":truX,"\u006bty"`)},
		{name: "literal kty at EOF after missing comma", data: []byte(`{"note":"x" "kty"`)},
		{name: "escaped kty at EOF after malformed value", data: []byte(`{"bad":truX "\u006bty"`)},
		{name: "literal keys at EOF after missing comma", data: []byte(`{"note":"x" "keys"`)},
		{name: "escaped keys at EOF after malformed value", data: []byte(`{"bad":truX "\u006b\u0065\u0079\u0073"`)},
		{name: "literal kty with missing colon", data: []byte(`{"kty" "RSA","n":"public"}`)},
		{name: "escaped kty with missing colon", data: []byte(`{"\u006bty" "RSA","n":"public"}`)},
		{name: "literal keys with missing colon", data: []byte(`{"keys" [{"kty":"RSA"}]}`)},
		{name: "escaped keys with missing colon", data: []byte(`{"\u006b\u0065\u0079\u0073" [{"kty":"RSA"}]}`)},
		{name: "literal kty with replaced colon", data: []byte(`{"kty";"RSA","n":"public"}`)},
		{name: "escaped kty with replaced colon", data: []byte(`{"\u006bty";"RSA","n":"public"}`)},
		{name: "literal keys with replaced colon", data: []byte(`{"keys"=[{"kty":"RSA"}]}`)},
		{name: "escaped keys with replaced colon", data: []byte(`{"\u006b\u0065\u0079\u0073"=[{"kty":"RSA"}]}`)},
		{name: "truncated first member name", data: []byte(`{"kty`)},
		{name: "BOM-prefixed escaped truncated first member name", data: []byte("\xef\xbb\xbf \n{\t\"\\u006b")},
		{name: "malformed JWK fields without kty", data: []byte(`{"n":"public","e":"AQAB",`)},
		{name: "marker-like value followed by colon", data: []byte(`{"label":"kty":`)},
		{name: "escaped marker-like value followed by colon", data: []byte(`{"label":"\u006bty":`)},
		{name: "marker-like value followed by missing separator", data: []byte(`{"label":"keys" "opaque"`)},
		{name: "escaped marker-like value followed by replaced separator", data: []byte(`{"label":"\u006bty";opaque`)},
		{name: "escaped quote and backslash value", data: []byte(`{"label":"escaped quote: \" and slash: \\":`)},
		{name: "marker-like object value at EOF", data: []byte(`{"label":"kty"`)},
		{name: "marker-like nested array value", data: []byte(`{"values":["keys":`)},
		{name: "nested metadata kty member", data: []byte(`{"meta":{"kty":"custom"},"bad":truX}`)},
		{name: "marker in truncated value string", data: []byte(`{"label":"truncated kty`)},
		{name: "BOM-prefixed malformed JWK JSON", data: []byte("\xef\xbb\xbf{\"kty\":\"RSA\",\"n\":")},
		{name: "BOM-prefixed malformed JWK with escaped kty", data: []byte("\xef\xbb\xbf{\"\\u006bty\":\"oct\",\"k\":")},
		{name: "BOM-prefixed public JWK", data: append([]byte{0xef, 0xbb, 0xbf}, publicJWK...)},
		{name: "BOM-prefixed public JWK Set", data: append([]byte{0xef, 0xbb, 0xbf}, publicJWKSet...)},
		{name: "valid unsupported JSON object", data: []byte(`{"secret":"value"}`)},
		{name: "unsupported ASN.1 DER sequence", data: unsupportedDER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("file", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "structured-key")
				if err := os.WriteFile(path, tt.data, 0600); err != nil {
					t.Fatalf("writing structured key data: %v", err)
				}
				if loaded, err := loadKey(path); err == nil {
					t.Fatalf("expected parsing error, got %T", loaded)
				} else if !strings.Contains(err.Error(), path) {
					t.Fatalf("expected error to contain key path %q, got %v", path, err)
				}
			})

			t.Run("base64", func(t *testing.T) {
				encoded := base64.StdEncoding.EncodeToString(tt.data)
				if loaded, err := loadKey(encoded); err == nil {
					t.Fatalf("expected parsing error, got %T", loaded)
				}
			})
		})
	}
}

func TestLoadKey_OpaqueStructuredPrefixesRemainRaw(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "leading object brace", data: []byte("{opaque-symmetric-key")},
		{name: "lone object brace", data: []byte("{")},
		{name: "object brace followed by whitespace", data: []byte("{ \t")},
		{name: "BOM-prefixed object brace followed by opaque bytes", data: []byte("\xef\xbb\xbf \n{opaque-symmetric-key")},
		{name: "leading array bracket", data: []byte("[opaque-symmetric-key")},
		{name: "valid JSON array", data: []byte(`["opaque","symmetric","key"]`)},
		{name: "ASN.1 sequence with incomplete contents", data: []byte{0x30, 0x03, 0x02, 0x02, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []string{"file", "base64"} {
				t.Run(mode, func(t *testing.T) {
					input := base64.StdEncoding.EncodeToString(tt.data)
					if mode == "file" {
						input = filepath.Join(t.TempDir(), "opaque-key")
						if err := os.WriteFile(input, tt.data, 0600); err != nil {
							t.Fatalf("writing opaque key: %v", err)
						}
					}

					loaded, err := loadKey(input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					key, ok := loaded.([]byte)
					if !ok {
						t.Fatalf("expected []byte, got %T", loaded)
					}
					if !bytes.Equal(key, tt.data) {
						t.Fatalf("opaque key modified: expected % x, got % x", tt.data, key)
					}
				})
			}
		})
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

// --- public key material must never degrade into a symmetric secret --------
//
// Public keys are published values. If key material jwtd cannot parse fell
// back to raw symmetric bytes, anyone who knows the key file's contents could
// sign an HS256 token that verifies. These formats must fail closed instead.

func TestLoadKey_RejectsSSHPublicKeyFile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	tests := []struct {
		name     string
		contents string
	}{
		{
			name:     "openssh ed25519",
			contents: sshEd25519PublicKeyLine(pub, "victim@host") + "\n",
		},
		{
			name:     "openssh rsa",
			contents: sshPublicKeyLine("ssh-rsa", []byte("rsa-key-material"), "victim@host") + "\n",
		},
		{
			name:     "openssh ecdsa",
			contents: sshPublicKeyLine("ecdsa-sha2-nistp256", []byte("ec-key-material"), "") + "\n",
		},
		{
			name:     "security key",
			contents: sshPublicKeyLine("sk-ssh-ed25519@openssh.com", []byte("sk-key-material"), "") + "\n",
		},
		{
			name:     "certificate",
			contents: sshPublicKeyLine("ssh-ed25519-cert-v01@openssh.com", []byte("cert-material"), "") + "\n",
		},
		{
			name: "authorized_keys with options",
			contents: `command="/bin/true",no-pty ` +
				sshEd25519PublicKeyLine(pub, "victim@host") + "\n",
		},
		{
			name: "rfc4716 armor",
			contents: "---- BEGIN SSH2 PUBLIC KEY ----\n" +
				"Comment: \"256-bit ED25519\"\n" +
				base64.StdEncoding.EncodeToString(pub) + "\n" +
				"---- END SSH2 PUBLIC KEY ----\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTextKeyFile(t, "id_key.pub", tt.contents)

			loaded, err := loadKey(path)
			if err == nil {
				t.Fatalf("SSH public key accepted as a %T key", loaded)
			}
			if !strings.Contains(err.Error(), "SSH public key format is not supported") {
				t.Errorf("expected an SSH format error, got: %v", err)
			}
		})
	}
}

func TestLoadKey_RejectsBase64EncodedSSHPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(sshEd25519PublicKeyLine(pub, "victim@host")))

	loaded, err := loadKey(encoded)
	if err == nil {
		t.Fatalf("base64-encoded SSH public key accepted as a %T key", loaded)
	}
	if !strings.Contains(err.Error(), "SSH public key format is not supported") {
		t.Errorf("expected an SSH format error, got: %v", err)
	}
}

// Key material stored base64-encoded in a file must be decoded like an inline
// key argument, so the same bytes cannot mean an RSA key inline and a
// symmetric secret in a file.
func TestLoadKey_Base64KeyMaterialInFileParsesAsKey(t *testing.T) {
	priv := generateRSAKey(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)

	wrapped := strings.Builder{}
	for i := 0; i < len(encoded); i += 64 {
		wrapped.WriteString(encoded[i:min(i+64, len(encoded))])
		wrapped.WriteString("\n")
	}

	tests := []struct {
		name     string
		contents string
	}{
		{name: "single line", contents: encoded + "\n"},
		{name: "wrapped at 64 columns", contents: wrapped.String()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTextKeyFile(t, "key.b64", tt.contents)

			loaded, err := loadKey(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			rsaPub, ok := loaded.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
			}
			if rsaPub.N.Cmp(priv.PublicKey.N) != 0 {
				t.Error("loaded key does not match original")
			}
		})
	}
}

// An empty key is known to every attacker, so it must never become an HMAC
// secret. A failed key conversion writing a zero-byte file is the realistic
// way to end up here.
func TestLoadKey_RejectsEmptyKeyMaterial(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		path := writeTextKeyFile(t, "empty.pem", "")

		loaded, err := loadKey(path)
		if err == nil {
			t.Fatalf("empty key file accepted as a %T key", loaded)
		}
		if !strings.Contains(err.Error(), "is empty") {
			t.Errorf("expected an empty-key error, got: %v", err)
		}
	})

	t.Run("whitespace-only file", func(t *testing.T) {
		path := writeTextKeyFile(t, "blank.pem", "\n\n")

		loaded, err := loadKey(path)
		if err == nil {
			t.Fatalf("whitespace-only key file accepted as a %T key", loaded)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected an empty-key error, got: %v", err)
		}
	})

	t.Run("raw prefix with no secret", func(t *testing.T) {
		loaded, err := loadKey("raw:")
		if err == nil {
			t.Fatalf("empty raw secret accepted as a %T key", loaded)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected an empty-key error, got: %v", err)
		}
	})
}

// Opaque secrets must keep working: the base64 decoding added for encoded key
// material must not reinterpret a symmetric secret that happens to look like
// base64.
func TestLoadKey_Base64LookingSecretFileStaysLiteral(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString([]byte("a-32-byte-symmetric-test-secret!"))
	path := writeTextKeyFile(t, "secret.b64", secret+"\n")

	loaded, err := loadKey(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	symKey, ok := loaded.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", loaded)
	}
	if string(symKey) != secret {
		t.Errorf("expected the literal file contents, got %q", symKey)
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
