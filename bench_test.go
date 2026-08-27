package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// These benchmarks exist so performance claims about jwtd can be checked
// rather than argued. For scale: a whole run of the binary costs roughly
// 650µs before main() is entered (process exec plus Go runtime and package
// init), so anything here in the microseconds is already far below the floor
// a user can observe. The large-payload cases are where the remaining time
// actually is.
//
//	go test -run XXX -bench . -benchmem

// benchSmallToken is a token of ordinary size: the claim set a real service
// issues, and the case every invocation of jwtd pays for.
func benchSmallToken() string {
	return makeJWT(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":2516239022}`,
		"AAAA",
	)
}

// benchLargeToken is a deliberately oversized token (~725 KB of payload). No
// ordinary token looks like this; it exists to expose the cost that scales
// with payload size, which the small case is too fast to show.
func benchLargeToken(b *testing.B) string {
	b.Helper()
	items := make([]string, 8000)
	for i := range items {
		items[i] = strings.Repeat("x", 64)
	}
	payload, err := json.Marshal(map[string]any{"data": items, "exp": 2516239022})
	if err != nil {
		b.Fatalf("building payload: %v", err)
	}
	return makeJWT(`{"alg":"HS256","typ":"JWT"}`, string(payload), "AAAA")
}

// benchParse parses a token or fails the benchmark, so setup errors are not
// silently measured as work.
func benchParse(b *testing.B, token string) *parsedJWT {
	b.Helper()
	p, err := parseUnverifiedJWT(token)
	if err != nil {
		b.Fatalf("parsing token: %v", err)
	}
	return p
}

// benchPinColor fixes fatih/color's global switch for the duration of a
// benchmark, so the measurement cannot depend on TTY detection or on state a
// previously run test left behind. Color is pinned *on*: it is the more
// expensive path and the one an interactive user gets.
func benchPinColor(b *testing.B) {
	b.Helper()
	previous := color.NoColor
	color.NoColor = false
	b.Cleanup(func() { color.NoColor = previous })
}

// BenchmarkDecodeAndPrint measures the whole decode-and-render path, the work
// one invocation of jwtd does for a token of each size.
func BenchmarkDecodeAndPrint(b *testing.B) {
	benchPinColor(b)
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"small", benchSmallToken()},
		{"large", benchLargeToken(b)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for b.Loop() {
				if err := decodeAndPrint(io.Discard, tc.token, ""); err != nil {
					b.Fatalf("decoding: %v", err)
				}
			}
		})
	}
}

// BenchmarkParseUnverifiedJWT isolates the strict parse — base64 decoding both
// segments and JSON-decoding them with exact json.Number values.
func BenchmarkParseUnverifiedJWT(b *testing.B) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"small", benchSmallToken()},
		{"large", benchLargeToken(b)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := parseUnverifiedJWT(tc.token); err != nil {
					b.Fatalf("parsing token: %v", err)
				}
			}
		})
	}
}

// BenchmarkPrintParsedJWT measures rendering alone, with the parse hoisted out
// of the loop. Comparing it against BenchmarkFormatterMarshal shows how much of
// rendering is the JSON colorizer and how much is everything around it.
func BenchmarkPrintParsedJWT(b *testing.B) {
	benchPinColor(b)
	p := benchParse(b, benchLargeToken(b))
	b.ResetTimer()
	for b.Loop() {
		if err := printParsedJWT(io.Discard, p, ""); err != nil {
			b.Fatalf("printing token: %v", err)
		}
	}
}

// BenchmarkFormatterMarshal isolates the colorizer, which dominated rendering
// for large payloads until it replaced go-prettyjson.
func BenchmarkFormatterMarshal(b *testing.B) {
	benchPinColor(b)
	p := benchParse(b, benchLargeToken(b))
	f := newFormatter()
	b.ResetTimer()
	for b.Loop() {
		if _, err := f.Marshal(map[string]any(p.claims)); err != nil {
			b.Fatalf("formatting claims: %v", err)
		}
	}
}

// BenchmarkEscapeFormattedJSONControls measures the sanitizing pass over
// already-formatted JSON, the one scan that touches every byte of the output.
// SetBytes reports it as throughput, since that is what the fast path is for.
func BenchmarkEscapeFormattedJSONControls(b *testing.B) {
	benchPinColor(b)
	p := benchParse(b, benchLargeToken(b))
	pretty, err := newFormatter().Marshal(map[string]any(p.claims))
	if err != nil {
		b.Fatalf("formatting claims: %v", err)
	}
	b.SetBytes(int64(len(pretty)))
	b.ResetTimer()
	for b.Loop() {
		_ = escapeFormattedJSONControls(pretty)
	}
}

// BenchmarkVerifyJWTSignature measures the signature check on an already
// parsed token, key loading included, for the symmetric case.
func BenchmarkVerifyJWTSignature(b *testing.B) {
	key := []byte("benchmark-secret")
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","exp":2516239022}`))
	signature, err := jwt.SigningMethodHS256.Sign(signingInput, key)
	if err != nil {
		b.Fatalf("signing token: %v", err)
	}
	p := benchParse(b, signingInput+"."+base64.RawURLEncoding.EncodeToString(signature))
	keyArg := "raw:" + string(key)
	b.ResetTimer()
	for b.Loop() {
		valid, reason, err := verifyJWTSignature(p, keyArg)
		if err != nil {
			b.Fatalf("verifying signature: %v", err)
		}
		if !valid {
			b.Fatalf("signature reported invalid: %v", reason)
		}
	}
}
