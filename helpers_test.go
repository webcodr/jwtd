package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// helper to build a JWT from raw JSON header/payload and a signature string.
func makeJWT(headerJSON, payloadJSON, sig string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return h + "." + p + "." + sig
}

func makeHMACJWTWithRawPayload(t *testing.T, payload string, key []byte) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingString := header + "." + encodedPayload
	signature, err := jwt.SigningMethodHS256.Sign(signingString, key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signingString + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// stripANSI removes ANSI escape sequences from a string for easier assertion.
func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++ // skip the 'm'
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func assertEscapedControlRunes(t *testing.T, output []byte, controls ...rune) {
	t.Helper()
	for _, control := range controls {
		visible := fmt.Sprintf(`\u%04x`, control)
		if !bytes.Contains(output, []byte(visible)) {
			t.Errorf("output missing visible escape %q:\n%q", visible, output)
		}
		if encoded := []byte(string(control)); bytes.Contains(output, encoded) {
			t.Errorf("output contains literal UTF-8 control U+%04X (% x):\n%q", control, encoded, output)
		}
	}
}

// --- JWE helpers -------------------------------------------------------------

// generateRSAKey creates a fresh RSA key pair for testing.
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

// encryptJWE creates a JWE compact serialization token encrypting the given plaintext.
func encryptJWE(t *testing.T, key *rsa.PrivateKey, plaintext []byte) string {
	t.Helper()
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &key.PublicKey},
		nil,
	)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	jwe, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWE: %v", err)
	}
	return compact
}

// writeKeyFile writes an RSA private key to a temp PEM file and returns the path.
func writeKeyFile(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-key.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// generateECKey creates a fresh ECDSA P-256 key pair for testing.
func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	return key
}

// writeECKeyFile writes an ECDSA private key to a temp PEM file and returns the path.
func writeECKeyFile(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling EC key: %v", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-ec-key.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// symmetricKeyArg writes symmetric key bytes to a temp file and returns the
// hmac:<path> argument that asks jwtd to use them as a secret. Symmetric keys
// must be requested explicitly, so this is how tests pass one.
func symmetricKeyArg(t *testing.T, key []byte) string {
	t.Helper()
	return "hmac:" + writeSymmetricKeyFile(t, key)
}

// writeSymmetricKeyFile writes raw symmetric key bytes to a temp file and returns the path.
func writeSymmetricKeyFile(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-sym-key.bin")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatalf("writing symmetric key file: %v", err)
	}
	return path
}

// encryptJWEGeneric creates a JWE compact serialization with the given algorithms and key.
func encryptJWEGeneric(t *testing.T, keyAlg jose.KeyAlgorithm, contentEnc jose.ContentEncryption, encryptionKey any, plaintext []byte) string {
	t.Helper()
	rcpt := jose.Recipient{Algorithm: keyAlg, Key: encryptionKey}
	enc, err := jose.NewEncrypter(contentEnc, rcpt, nil)
	if err != nil {
		t.Fatalf("creating encrypter (%s/%s): %v", keyAlg, contentEnc, err)
	}
	jwe, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting (%s/%s): %v", keyAlg, contentEnc, err)
	}
	compact, err := jwe.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWE (%s/%s): %v", keyAlg, contentEnc, err)
	}
	return compact
}

// symmetricKeyForEnc returns a random symmetric key of the correct size for the
// given content encryption algorithm when used with direct key agreement.
func symmetricKeyForEnc(t *testing.T, enc jose.ContentEncryption) []byte {
	t.Helper()
	var size int
	switch enc {
	case jose.A128CBC_HS256:
		size = 32
	case jose.A192CBC_HS384:
		size = 48
	case jose.A256CBC_HS512:
		size = 64
	case jose.A128GCM:
		size = 16
	case jose.A192GCM:
		size = 24
	case jose.A256GCM:
		size = 32
	default:
		t.Fatalf("unknown content encryption: %s", enc)
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating symmetric key: %v", err)
	}
	return key
}

// --- public key loading ------------------------------------------------------

// writeRSAPublicKeyFile writes an RSA public key to a temp PEM file and returns the path.
func writeRSAPublicKeyFile(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshaling RSA public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-rsa-pub.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// writeECPublicKeyFile writes an ECDSA public key to a temp PEM file and returns the path.
func writeECPublicKeyFile(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshaling EC public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-ec-pub.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

func writeRSACertificateFiles(t *testing.T, key *rsa.PrivateKey) (pemPath, derPath string, pemBytes []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwtd test certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	dir := t.TempDir()
	pemPath = filepath.Join(dir, "test-cert.pem")
	derPath = filepath.Join(dir, "test-cert.der")
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(pemPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing PEM certificate: %v", err)
	}
	if err := os.WriteFile(derPath, der, 0600); err != nil {
		t.Fatalf("writing DER certificate: %v", err)
	}
	return pemPath, derPath, pemBytes
}

// --- JWS signature verification -----------------------------------------------

// signJWT creates a signed JWT with the given claims and RSA private key.
func signJWT(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signed
}

// signJWTWithHMAC creates a signed JWT using HMAC-SHA256 with the given symmetric key.
func signJWTWithHMAC(t *testing.T, key []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signed
}

type failOnWriteWriter struct {
	failedWrite int
	writes      int
	err         error
}

func (w *failOnWriteWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failedWrite {
		return 0, w.err
	}
	return len(p), nil
}

// generateEd25519Key creates a fresh Ed25519 key pair for testing.
func generateEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	return priv
}

// writeEd25519KeyFile writes an Ed25519 private key to a temp PEM file and returns the path.
func writeEd25519KeyFile(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling Ed25519 key: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "test-ed25519-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// signJWTWithEd25519 creates a signed JWT using Ed25519 with the given private key.
// sshWireString encodes a value in the SSH wire format: a big-endian length
// followed by the bytes.
func sshWireString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// sshPublicKeyLine renders a public key in the one-line OpenSSH format, as
// found in id_*.pub and authorized_keys files. Only the wire-format key type
// prefix drives jwtd's detection, so body stands in for the remaining key
// material.
func sshPublicKeyLine(keyType string, body []byte, comment string) string {
	blob := append(sshWireString([]byte(keyType)), sshWireString(body)...)
	line := keyType + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return line
}

// sshEd25519PublicKeyLine renders a real ed25519 public key exactly as
// ssh-keygen writes it to id_ed25519.pub.
func sshEd25519PublicKeyLine(pub ed25519.PublicKey, comment string) string {
	return sshPublicKeyLine("ssh-ed25519", pub, comment)
}

func writeTextKeyFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

// signHS256 signs a token with an HMAC secret, standing in for an attacker who
// knows the bytes of a published key file.
func signHS256(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("signing HS256 token: %v", err)
	}
	return token
}

func signJWTWithEd25519(t *testing.T, key ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return signed
}
