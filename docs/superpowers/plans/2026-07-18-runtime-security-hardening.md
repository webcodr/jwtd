# Runtime Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden key interpretation, signature failure semantics, JSON number handling, decrypted text output, and JWE protected-header display.

**Architecture:** Keep production code in `main.go` and tests in `main_test.go`. Add small helpers only at parsing and output trust boundaries, preserve opaque symmetric-key files, and keep go-jose and golang-jwt authoritative for cryptographic operations.

**Tech Stack:** Go 1.26, Cobra, golang-jwt/jwt v5, go-jose v4, standard-library crypto/x509, encoding/json, encoding/asn1, math/big, and unicode/utf8.

---

## File Map

- Modify: `main.go` - structured key detection, certificate loading, verification errors, exact JSON numbers, safe raw output, and protected-header decoding.
- Modify: `main_test.go` - regression and integration coverage for every runtime finding.
- Modify: `README.md` - user-facing key and exit-status behavior.
- Modify: `AGENTS.md` - architecture and development guidance.
- Reference: `docs/superpowers/specs/2026-07-18-security-and-release-hardening-design.md` - approved behavior.

Do not commit unless the user explicitly requests it.

### Task 1: Parse Certificates And Reject Structured Key Failures

**Files:**
- Modify: `main_test.go:3-24,591-727,935-1035`
- Modify: `main.go:3-25,418-560`

- [ ] **Step 1: Add certificate and structured-data test helpers**

Add `encoding/asn1`, `crypto/x509/pkix`, and `math/big` to `main_test.go`, then add this helper beside the existing key-file helpers:

```go
func writeCertificateFiles(t *testing.T, key *rsa.PrivateKey) (pemPath, derPath string, pemBytes []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwtd-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemPath = filepath.Join(t.TempDir(), "certificate.pem")
	derPath = filepath.Join(t.TempDir(), "certificate.der")
	if err := os.WriteFile(pemPath, pemBytes, 0600); err != nil {
		t.Fatalf("writing PEM certificate: %v", err)
	}
	if err := os.WriteFile(derPath, der, 0600); err != nil {
		t.Fatalf("writing DER certificate: %v", err)
	}
	return pemPath, derPath, pemBytes
}
```

- [ ] **Step 2: Add failing key-loading regression tests**

Add these tests under the key-loading section:

```go
func TestLoadKey_X509CertificatesReturnPublicKey(t *testing.T) {
	privateKey := generateRSAKey(t)
	pemPath, derPath, _ := writeCertificateFiles(t, privateKey)
	for _, path := range []string{pemPath, derPath} {
		t.Run(filepath.Ext(path), func(t *testing.T) {
			loaded, err := loadKey(path)
			if err != nil {
				t.Fatalf("loading certificate: %v", err)
			}
			publicKey, ok := loaded.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected *rsa.PublicKey, got %T", loaded)
			}
			if publicKey.N.Cmp(privateKey.N) != 0 {
				t.Fatal("certificate public key does not match")
			}
		})
	}
}

func TestLoadKey_RejectsMalformedStructuredFiles(t *testing.T) {
	unsupportedDER, err := asn1.Marshal(struct{ Value string }{Value: "not a key"})
	if err != nil {
		t.Fatalf("marshaling unsupported DER: %v", err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"malformed PEM", []byte("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n")},
		{"malformed JWK", []byte(`{"kty":"RSA","n":"invalid"`)},
		{"unsupported DER", unsupportedDER},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key-data")
			if err := os.WriteFile(path, tt.data, 0600); err != nil {
				t.Fatalf("writing key data: %v", err)
			}
			if key, err := loadKey(path); err == nil {
				t.Fatalf("expected structured key error, got key %T", key)
			}
		})
	}
}
```

- [ ] **Step 3: Run the new tests and verify they fail**

Run: `go test ./... -run 'TestLoadKey_(X509CertificatesReturnPublicKey|RejectsMalformedStructuredFiles)' -count=1`

Expected: certificate cases return `[]byte`, and malformed structured cases unexpectedly succeed as `[]byte`.

- [ ] **Step 4: Add structured-envelope detection**

Add `encoding/asn1` to `main.go`, then add this helper above `parseKeyData`:

```go
func isStructuredKeyData(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return true
	}
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return true
	}
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(trimmed, &value)
	return err == nil && len(rest) == 0 && value.Tag == asn1.TagSequence && value.IsCompound
}
```

- [ ] **Step 5: Parse X.509 certificates**

In `parseKeyData`, try a raw DER certificate after the existing key parsers:

```go
	if certificate, err := x509.ParseCertificate(data); err == nil {
		return certificate.PublicKey, nil
	}
```

In `parseDERKey`, add a certificate case and certificate fallback:

```go
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return certificate.PublicKey, nil
```

Add this before the final error in the default branch:

```go
		if certificate, err := x509.ParseCertificate(der); err == nil {
			return certificate.PublicKey, nil
		}
```

- [ ] **Step 6: Prevent structured parsing failures from falling back to HMAC bytes**

Replace the file-path parsing block in `loadKey` with:

```go
	if data, err := os.ReadFile(keyStr); err == nil {
		key, parseErr := parseKeyData(data)
		if parseErr == nil {
			return key, nil
		}
		if isStructuredKeyData(data) {
			return nil, fmt.Errorf("parsing structured key file %q: %w", keyStr, parseErr)
		}
		if isTextKey(data) {
			return bytes.TrimRight(data, "\r\n"), nil
		}
		return data, nil
	}
```

After attempting to parse decoded base64 bytes, reject recognized structured data before raw fallback:

```go
	if key, err := parseKeyData(decoded); err == nil {
		return key, nil
	} else if isStructuredKeyData(decoded) {
		return nil, fmt.Errorf("parsing structured base64 key data: %w", err)
	}
	return decoded, nil
```

- [ ] **Step 7: Run focused and existing key tests**

Run: `go test ./... -run 'TestLoadKey' -count=1`

Expected: PASS, including opaque text and binary file tests.

### Task 2: Return Nonzero For Invalid Signatures

**Files:**
- Modify: `main.go:27-36,50-64,186-218`
- Modify: `main_test.go:3-24,2026-2300,2396-2428`

- [ ] **Step 1: Update invalid-signature tests to require a sentinel error**

Add `errors` to `main_test.go`. In the wrong RSA key, algorithm mismatch, and wrong Ed25519 key tests, replace the current nil-error assertion with:

```go
	err := decodeAndPrint(&buf, token, wrongKeyPath)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature, got %v", err)
	}
```

For the algorithm-mismatch test, use `pubKeyPath` in place of `wrongKeyPath`. Keep every existing output assertion.

- [ ] **Step 2: Add the certificate/HMAC confusion regression test**

```go
func TestDecodeAndPrint_CertificateCannotBecomeHMACSecret(t *testing.T) {
	privateKey := generateRSAKey(t)
	certificatePath, _, certificatePEM := writeCertificateFiles(t, privateKey)
	secret := bytes.TrimRight(certificatePEM, "\r\n")
	token := signJWTWithHMAC(t, secret, jwt.MapClaims{"sub": "forged"})
	var buf bytes.Buffer
	err := decodeAndPrint(&buf, token, certificatePath)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature, got %v", err)
	}
	if output := stripANSI(buf.String()); !strings.Contains(output, "Signature: INVALID") {
		t.Fatalf("expected invalid signature output, got:\n%s", output)
	}
}
```

- [ ] **Step 3: Run the signature regressions and verify they fail**

Run: `go test ./... -run 'TestDecodeAndPrint_(SignatureInvalid|CertificateCannotBecomeHMACSecret)' -count=1`

Expected: invalid-signature tests receive nil instead of `errInvalidSignature`.

- [ ] **Step 4: Add the sentinel error and return it after output succeeds**

Add `errors` to `main.go` and define:

```go
var errInvalidSignature = errors.New("invalid signature")
```

Replace the invalid branch in `verifySignature` with:

```go
	if err != nil {
		if _, writeErr := color.New(color.FgRed, color.Bold).Fprintln(w, "Signature: INVALID"); writeErr != nil {
			return writeErr
		}
		if _, writeErr := dimColor.Fprintf(w, "  %v\n", err); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("%w: %v", errInvalidSignature, err)
	}
```

- [ ] **Step 5: Suppress Cobra usage for runtime failures**

Set this field on the root command in `main`:

```go
		SilenceUsage: true,
```

Also set `SilenceUsage: true` on test Cobra commands that exercise `run`.

- [ ] **Step 6: Add a Cobra-level failure test**

```go
func TestRun_InvalidSignatureReturnsErrorWithoutUsage(t *testing.T) {
	signingKey := generateRSAKey(t)
	wrongKey := generateRSAKey(t)
	token := signJWT(t, signingKey, jwt.MapClaims{"sub": "test"})
	rootCmd := &cobra.Command{
		Use:          "jwtd [token]",
		Args:         cobra.MaximumNArgs(1),
		RunE:         run,
		SilenceUsage: true,
	}
	rootCmd.Flags().StringP("key", "k", "", "key")
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"--key", writeKeyFile(t, wrongKey), token})
	err := rootCmd.Execute()
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature, got %v", err)
	}
	if strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("runtime error printed usage:\n%s", stderr.String())
	}
}
```

- [ ] **Step 7: Run all signature and run tests**

Run: `go test ./... -run 'Test(DecodeAndPrint_Signature|DecodeAndPrint_Certificate|Run_)' -count=1`

Expected: PASS.

### Task 3: Preserve JSON Numbers And Fractional NumericDate Values

**Files:**
- Modify: `main.go:3-25,143-145,200-204,352-395,594-610`
- Modify: `main_test.go:168-309,813-832,907-933`

- [ ] **Step 1: Add failing exact-number tests**

```go
func TestDecodeAndPrint_PreservesLargeInteger(t *testing.T) {
	token := makeJWT(`{"alg":"none"}`, `{"id":9007199254740993}`, "")
	var buf bytes.Buffer
	if err := decodeAndPrint(&buf, token, ""); err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	output := stripANSI(buf.String())
	if !strings.Contains(output, "9007199254740993") {
		t.Fatalf("large integer lost precision:\n%s", output)
	}
}

func TestFormatTimestamps_PreservesFraction(t *testing.T) {
	data := map[string]any{"iat": json.Number("1516239022.75")}
	formatTimestamps(data)
	if got := data["iat"]; got != "2018-01-18T01:30:22.75Z (1516239022.75)" {
		t.Fatalf("unexpected fractional timestamp: %v", got)
	}
}

func TestFormatTimestamps_LeavesOutOfRangeValue(t *testing.T) {
	data := map[string]any{"exp": json.Number("999999999999999999999")}
	formatTimestamps(data)
	if got := data["exp"]; got != json.Number("999999999999999999999") {
		t.Fatalf("out-of-range timestamp changed: %v", got)
	}
}
```

Add this decrypted-JWE test for both JSON container types:

```go
func TestDecodeAndPrintJWE_PreservesLargeInteger(t *testing.T) {
	key := generateRSAKey(t)
	keyPath := writeKeyFile(t, key)
	tests := []struct {
		name    string
		payload string
	}{
		{"object", `{"id":9007199254740993}`},
		{"array", `[9007199254740993]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := encryptJWE(t, key, []byte(tt.payload))
			var buf bytes.Buffer
			if err := decodeAndPrintJWE(&buf, token, keyPath); err != nil {
				t.Fatalf("decrypting JWE: %v", err)
			}
			if output := stripANSI(buf.String()); !strings.Contains(output, "9007199254740993") {
				t.Fatalf("large integer lost precision:\n%s", output)
			}
		})
	}
}
```

- [ ] **Step 2: Run the number tests and verify they fail**

Run: `go test ./... -run 'Test(DecodeAndPrint_PreservesLargeInteger|FormatTimestamps_PreservesFraction|FormatTimestamps_LeavesOutOfRangeValue|DecodeAndPrintJWE_PreservesLargeInteger)' -count=1`

Expected: large integers round and fractional timestamps truncate.

- [ ] **Step 3: Enable `json.Number` in JWT parsers**

Construct the display parser as:

```go
	parser := jwt.NewParser(jwt.WithJSONNumber())
```

Add `jwt.WithJSONNumber()` to the verification parser options:

```go
	opts := []jwt.ParserOption{jwt.WithoutClaimsValidation(), jwt.WithJSONNumber()}
```

- [ ] **Step 4: Decode decrypted JSON with `UseNumber` and reject trailing data**

Add:

```go
func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
```

Replace both `json.Unmarshal(plaintext, ...)` calls in `printDecryptedPayload` with `decodeJSON(plaintext, ...)`.

- [ ] **Step 5: Format timestamps from exact rational values**

Add `math/big` and `strconv`, then replace `formatTimestamps` with:

```go
func formatTimestamps(data map[string]any) {
	for key, value := range data {
		if !slices.Contains(timestampKeyNames, key) {
			continue
		}
		raw := ""
		switch value := value.(type) {
		case json.Number:
			raw = value.String()
		case float64:
			raw = strconv.FormatFloat(value, 'f', -1, 64)
		default:
			continue
		}
		numericDate, ok := new(big.Rat).SetString(raw)
		if !ok {
			continue
		}
		seconds := new(big.Int).Quo(numericDate.Num(), numericDate.Denom())
		if !seconds.IsInt64() {
			continue
		}
		remainder := new(big.Int).Rem(numericDate.Num(), numericDate.Denom())
		nanoseconds := new(big.Int).Mul(remainder, big.NewInt(int64(time.Second)))
		nanoseconds.Quo(nanoseconds, numericDate.Denom())
		if !nanoseconds.IsInt64() {
			continue
		}
		timestamp := time.Unix(seconds.Int64(), nanoseconds.Int64()).UTC()
		if timestamp.Year() < 0 || timestamp.Year() > 9999 {
			continue
		}
		data[key] = fmt.Sprintf("%s (%s)", timestamp.Format(time.RFC3339Nano), raw)
	}
}
```

- [ ] **Step 6: Run formatting and JWE JSON tests**

Run: `go test ./... -run 'Test(DecodeAndPrint.*(LargeInteger|Timestamp)|FormatTimestamps|DecodeAndPrintJWE.*(LargeInteger|Timestamp|JSONArray))' -count=1`

Expected: PASS.

### Task 4: Escape Terminal Controls In Raw Decrypted Text

**Files:**
- Modify: `main.go:3-25,397-402`
- Modify: `main_test.go:861-905`

- [ ] **Step 1: Add failing unit and integration tests**

```go
func TestEscapeTerminalText(t *testing.T) {
	input := []byte{'o', 'k', '\n', '\t', '\r', 0x1b, 0x07, 0x7f, 0xc2, 0x85, 0xff}
	got := escapeTerminalText(input)
	want := "ok\n\t\\x0d\\x1b\\x07\\x7f\\u0085\\xff"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\x07') {
		t.Fatalf("active terminal control remains in %q", got)
	}
}
```

Add this JWE integration test:

```go
func TestDecodeAndPrintJWE_EscapesTerminalControls(t *testing.T) {
	key := generateRSAKey(t)
	token := encryptJWE(t, key, []byte("safe\x1b]52;c;payload\x07\rtext"))
	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, writeKeyFile(t, key)); err != nil {
		t.Fatalf("decrypting JWE: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, `\x1b`) || !strings.Contains(output, `\x07`) || !strings.Contains(output, `\x0d`) {
		t.Fatalf("escaped controls missing:\n%s", output)
	}
	if strings.ContainsRune(output, '\x1b') || strings.ContainsRune(output, '\x07') || strings.ContainsRune(output, '\r') {
		t.Fatalf("active terminal control remains:\n%q", output)
	}
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `go test ./... -run 'Test(EscapeTerminalText|DecodeAndPrintJWE_EscapesTerminalControls)' -count=1`

Expected: `escapeTerminalText` is undefined and raw output contains controls.

- [ ] **Step 3: Implement terminal-safe escaping**

Add `unicode/utf8` and this helper:

```go
func escapeTerminalText(data []byte) string {
	var output strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&output, "\\x%02x", data[0])
			data = data[1:]
			continue
		}
		switch {
		case r == '\n' || r == '\t':
			output.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&output, "\\x%02x", r)
		case r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&output, "\\u%04x", r)
		default:
			output.WriteRune(r)
		}
		data = data[size:]
	}
	return output.String()
}
```

Change the raw fallback to:

```go
	_, err := fmt.Fprintln(w, escapeTerminalText(plaintext))
```

- [ ] **Step 4: Run raw payload tests**

Run: `go test ./... -run 'Test(EscapeTerminalText|DecodeAndPrintJWE_(EscapesTerminalControls|NonJSONPayload|DottedTextPayload))' -count=1`

Expected: PASS.

### Task 5: Display The Complete JWE Protected Header

**Files:**
- Modify: `main.go:255-265,291-310`
- Modify: `main_test.go:1058-1076`

- [ ] **Step 1: Replace the existing header-map test with a failing compact-header test**

```go
func TestJWEProtectedHeaderMap_PreservesAllFields(t *testing.T) {
	headerJSON := []byte(`{"alg":"dir","enc":"A256GCM","x5c":["certificate"],"custom":9007199254740993}`)
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + ".a.b.c.d"
	header, err := jweProtectedHeaderMap(token)
	if err != nil {
		t.Fatalf("decoding protected header: %v", err)
	}
	if got := header["x5c"].([]any)[0]; got != "certificate" {
		t.Fatalf("x5c missing: %v", header)
	}
	if got := header["custom"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("custom field lost precision: %v", got)
	}
}
```

Add an output integration test using a valid certificate value:

```go
func TestDecodeAndPrintJWE_DisplaysX5CProtectedHeader(t *testing.T) {
	key := generateRSAKey(t)
	_, derPath, _ := writeCertificateFiles(t, key)
	certificateDER, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatalf("reading certificate: %v", err)
	}
	certificate := base64.StdEncoding.EncodeToString(certificateDER)
	options := new(jose.EncrypterOptions).WithHeader(jose.HeaderKey("x5c"), []string{certificate})
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &key.PublicKey},
		options,
	)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	encrypted, err := encrypter.Encrypt([]byte(`{"sub":"test"}`))
	if err != nil {
		t.Fatalf("encrypting payload: %v", err)
	}
	token, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWE: %v", err)
	}
	var buf bytes.Buffer
	if err := decodeAndPrintJWE(&buf, token, ""); err != nil {
		t.Fatalf("decoding JWE: %v", err)
	}
	output := stripANSI(buf.String())
	if !strings.Contains(output, `"x5c"`) || !strings.Contains(output, certificate) {
		t.Fatalf("x5c missing from output:\n%s", output)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `go test ./... -run 'Test(JWEProtectedHeaderMap_PreservesAllFields|DecodeAndPrintJWE_DisplaysX5CProtectedHeader)' -count=1`

Expected: `jweProtectedHeaderMap` is undefined and current JWE output omits `x5c`.

- [ ] **Step 3: Decode the compact protected header directly**

Replace `jweHeaderMap` with:

```go
func jweProtectedHeaderMap(token string) (map[string]any, error) {
	protected, _, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("JWE has no protected header segment")
	}
	data, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return nil, fmt.Errorf("decoding JWE protected header: %w", err)
	}
	var header map[string]any
	if err := decodeJSON(data, &header); err != nil {
		return nil, fmt.Errorf("parsing JWE protected header: %w", err)
	}
	return header, nil
}
```

In `decodeAndPrintJWE`, replace `jweHeaderMap(jwe)` with:

```go
	header, err := jweProtectedHeaderMap(tokenStr)
	if err != nil {
		return err
	}
```

- [ ] **Step 4: Run all JWE tests**

Run: `go test ./... -run 'Test(JWE|DecodeAndPrintJWE|IsJWE|PartSize|PrintEncryptedParts)' -count=1`

Expected: PASS.

### Task 6: Update Documentation And Verify Runtime Hardening

**Files:**
- Modify: `README.md:5-18,84-117`
- Modify: `AGENTS.md:5-22,49-59`

- [ ] **Step 1: Update user documentation**

Add these facts to `README.md`:

```markdown
- Key loading from PEM files, DER files, X.509 certificates, JWK/JWK Set, or base64-encoded input
- Invalid signatures produce a nonzero exit status when `--key`/`JWTD_KEY` is used
```

Replace the current raw-file explanation in the key-formats section with:

```markdown
X.509 certificates in PEM or DER form are accepted for signature verification; jwtd extracts their public key. Recognizable structured data such as PEM, JWK/JWK Set JSON, certificates, and ASN.1 DER must parse successfully or jwtd returns an error. Files with no structured envelope are treated as raw symmetric keys; text files have trailing newlines trimmed and binary files remain byte-exact.

When `--key` or `JWTD_KEY` is supplied for a JWS, an invalid signature prints `Signature: INVALID` and exits with a nonzero status. Claims such as expiry remain outside signature validation.
```

- [ ] **Step 2: Update maintainer documentation**

Use these architecture descriptions in `AGENTS.md`:

```markdown
- `verifySignature()` - Verifies a JWS signature with `jwt.WithoutClaimsValidation()` so the result reflects only the cryptographic signature, not expiry; prints `Signature: VALID`/`INVALID` and returns a sentinel error for invalid signatures so the CLI exits nonzero
- `loadKey()` / `parseKeyData()` / `parseDERKey()` / `parseJWK()` - Load a key from a file path, base64 string, or `raw:<secret>` literal; supports PEM, DER (PKCS#1/PKCS#8/PKIX), X.509 certificates, JWK/JWK Set, and opaque raw symmetric keys; recognizable structured data is rejected when parsing fails
```

- [ ] **Step 3: Format and run the full verification suite**

Run: `gofmt -w main.go main_test.go`

Run: `go test -race ./...`

Expected: PASS.

Run: `go vet ./...`

Expected: no output and exit 0.

Run: `gofmt -l .`

Expected: no output.

Run: `go build ./...`

Expected: exit 0.

- [ ] **Step 4: Confirm only intended files changed**

Run: `git diff --check && git status --short`

Expected: no whitespace errors; only `main.go`, `main_test.go`, `README.md`, `AGENTS.md`, and approved documentation/plan files are listed.
