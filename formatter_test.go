package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hokaccha/go-prettyjson"
)

// referenceFormatter builds a go-prettyjson formatter configured exactly as
// newFormatter is. go-prettyjson is kept as a test-only dependency so the
// formatter that replaced it can be held to its output byte for byte.
func referenceFormatter() *prettyjson.Formatter {
	f := prettyjson.NewFormatter()
	f.KeyColor = color.New(color.FgBlue, color.Bold)
	f.StringColor = color.New(color.FgGreen)
	f.NumberColor = color.New(color.FgYellow)
	f.BoolColor = color.New(color.FgMagenta)
	f.NullColor = color.New(color.FgRed)
	f.Indent = 2
	return f
}

// assertFormatterMatchesReference formats a value both ways and fails unless
// the bytes are identical, with color both on and off.
func assertFormatterMatchesReference(t *testing.T, value any) {
	t.Helper()
	for _, colored := range []bool{true, false} {
		t.Run(fmt.Sprintf("colored=%v", colored), func(t *testing.T) {
			previous := color.NoColor
			color.NoColor = !colored
			t.Cleanup(func() { color.NoColor = previous })

			want, err := referenceFormatter().Marshal(value)
			if err != nil {
				t.Fatalf("reference formatter: %v", err)
			}
			got, err := newFormatter().Marshal(value)
			if err != nil {
				t.Fatalf("formatter: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("output differs from go-prettyjson\n got: %q\nwant: %q", got, want)
			}
		})
	}
}

// number is shorthand for a claim value as jwtd's strict decode produces it.
func number(s string) json.Number { return json.Number(s) }

// TestFormatterMatchesPrettyJSON pins the formatter's output against the
// library it replaced, across the value shapes a decoded JWT can carry.
func TestFormatterMatchesPrettyJSON(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"empty object", map[string]any{}},
		{"empty array", []any{}},
		{"typical claims", map[string]any{
			"sub":  "1234567890",
			"name": "John Doe",
			"iat":  number("1516239022"),
			"adm":  true,
		}},
		{"every scalar", map[string]any{
			"string": "value",
			"number": number("42"),
			"float":  number("3.14159"),
			"exp":    number("1.5e10"),
			"neg":    number("-17"),
			"true":   true,
			"false":  false,
			"null":   nil,
		}},
		{"nested containers", map[string]any{
			"a": map[string]any{"b": map[string]any{"c": []any{number("1"), "two", nil}}},
			"d": []any{map[string]any{"e": true}, []any{}, map[string]any{}},
		}},
		{"array at top level", []any{"a", number("1"), false, nil, map[string]any{"k": "v"}}},
		{"key ordering", map[string]any{"b": number("2"), "a": number("1"), "C": number("3"), "": number("0")}},
		{"keys needing escapes", map[string]any{"quote\"key": "v", "back\\slash": "v", "new\nline": "v"}},
		{"string escapes", map[string]any{
			"quote":     `he said "hi"`,
			"backslash": `C:\path`,
			"control":   "a\x00\x1f\x7fb",
			"newline":   "line\nline\ttab",
			"html":      "<a href='x'>&amp;</a>",
			"unicode":   "caf\u00e9 \u4e16\u754c \U0001f600",
			"bidi":      "a\u202eb",
			"line sep":  "a\u2028b\u2029c",
			"invalid":   string([]byte{'a', 0xff, 0x80, 'b'}),
		}},
		{"deep nesting past the indent buffer", deeplyNested(24)},
		{"large exact number", map[string]any{"big": number("123456789012345678901234567890.123456789")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFormatterMatchesReference(t, tt.value)
		})
	}
}

// TestFormatterMatchesPrettyJSON_FallbackValues covers values the direct walk
// does not accept, which must still match because they are normalized through
// the same marshal-and-redecode the library did unconditionally.
func TestFormatterMatchesPrettyJSON_FallbackValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{"named map type", jwt.MapClaims{"sub": "abc", "exp": number("1516239022")}},
		{"float64 values", map[string]any{"a": float64(3.5), "b": float64(1e21), "c": float64(0)}},
		{"integer values", map[string]any{"a": 1, "b": int64(-2), "c": uint8(3)}},
		{"struct", struct {
			Name string `json:"name"`
			Age  int    `json:"age"`
		}{"Ada", 36}},
		{"typed slice", []string{"a", "b"}},
		{"nested named map", map[string]any{"claims": jwt.MapClaims{"a": number("1")}}},
		{"top-level string", "just a string"},
		{"top-level null", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertFormatterMatchesReference(t, tt.value)
		})
	}
}

// TestFormatterMatchesPrettyJSON_Random compares the two formatters over
// pseudo-random JSON values, so agreement does not rest only on the shapes
// someone thought to enumerate. The seed is fixed, so a failure reproduces.
func TestFormatterMatchesPrettyJSON_Random(t *testing.T) {
	random := rand.New(rand.NewSource(20260827))
	for i := range 200 {
		t.Run(fmt.Sprintf("value%d", i), func(t *testing.T) {
			assertFormatterMatchesReference(t, randomJSONValue(random, 4))
		})
	}
}

// TestFormatterRejectsUnmarshalableValue pins that a value neither path can
// render is reported as an error rather than silently rendered as empty, which
// is what go-prettyjson's own fallthrough did.
func TestFormatterRejectsUnmarshalableValue(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value any
	}{
		{"channel", make(chan int)},
		{"function", func() {}},
		{"NaN", math.NaN()},
		{"infinity", math.Inf(1)},
		{"nested channel", map[string]any{"ch": make(chan int)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newFormatter().Marshal(tt.value); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

// TestFormatterReusesBufferAcrossCalls pins that a formatter used for more than
// one section does not carry output over from the previous one.
func TestFormatterReusesBufferAcrossCalls(t *testing.T) {
	f := newFormatter()
	first, err := f.Marshal(map[string]any{"a": "first"})
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	firstCopy := string(first)

	second, err := f.Marshal(map[string]any{"b": "second"})
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if strings.Contains(string(second), "first") {
		t.Errorf("second output carried over the first: %q", second)
	}

	want, err := referenceFormatter().Marshal(map[string]any{"a": "first"})
	if err != nil {
		t.Fatalf("reference formatter: %v", err)
	}
	if firstCopy != string(want) {
		t.Errorf("first output = %q, want %q", firstCopy, want)
	}
}

// deeplyNested builds an object nested depth levels down, so indentation past
// the length of the shared space buffer is exercised.
func deeplyNested(depth int) map[string]any {
	value := map[string]any{"leaf": "bottom"}
	for range depth {
		value = map[string]any{"n": value}
	}
	return value
}

// randomJSONValue builds a pseudo-random value of the kinds a JSON decode
// produces, nesting at most depth levels deep.
func randomJSONValue(random *rand.Rand, depth int) any {
	kinds := 6
	if depth <= 0 {
		kinds = 4
	}
	switch random.Intn(kinds) {
	case 0:
		return randomJSONString(random)
	case 1:
		return number(randomJSONNumber(random))
	case 2:
		return random.Intn(2) == 0
	case 3:
		return nil
	case 4:
		value := map[string]any{}
		for range random.Intn(5) {
			value[randomJSONString(random)] = randomJSONValue(random, depth-1)
		}
		return value
	default:
		value := []any{}
		for range random.Intn(5) {
			value = append(value, randomJSONValue(random, depth-1))
		}
		return value
	}
}

// randomJSONString draws from an alphabet weighted toward the characters that
// interact with quoting: escapes, controls, HTML, multibyte runes, and bidi.
func randomJSONString(random *rand.Rand) string {
	alphabet := []string{
		"a", "b", "Z", "0", " ", "_", "-",
		`"`, `\`, "/", "<", ">", "&", "'",
		"\n", "\t", "\r", "\x00", "\x1b", "\x7f",
		"\u0080", "\u009f", "caf\u00e9", "\u4e16", "\U0001f600",
		"\u202e", "\u200e", "\u2028", "\u2029",
	}
	var b strings.Builder
	for range random.Intn(8) {
		b.WriteString(alphabet[random.Intn(len(alphabet))])
	}
	return b.String()
}

// randomJSONNumber produces numeric literals in the forms JSON permits,
// including the exponent and high-precision ones that must survive verbatim.
func randomJSONNumber(random *rand.Rand) string {
	switch random.Intn(5) {
	case 0:
		return fmt.Sprintf("%d", random.Int63n(2_000_000_000))
	case 1:
		return fmt.Sprintf("-%d", random.Int63n(2_000_000_000))
	case 2:
		return fmt.Sprintf("%d.%d", random.Intn(1000), random.Intn(1_000_000))
	case 3:
		return fmt.Sprintf("%de%d", random.Intn(100), random.Intn(20)-10)
	default:
		return "123456789012345678901234567890.12345678901234567890"
	}
}

// TestStyleMatchesColorPackage pins that the cached escape pair renders exactly
// what fatih/color's own Fprintln and Fprintf write, in both color states. The
// styles are jwtd's only colored output, so a drift here would be a drift in
// every section header, verdict, and dimmed line.
func TestStyleMatchesColorPackage(t *testing.T) {
	cases := []struct {
		name       string
		style      *style
		attributes []color.Attribute
	}{
		{"label", labelStyle, []color.Attribute{color.FgCyan, color.Bold}},
		{"dim", dimStyle, []color.Attribute{color.Faint}},
		{"valid", validStyle, []color.Attribute{color.FgGreen, color.Bold}},
		{"invalid", invalidStyle, []color.Attribute{color.FgRed, color.Bold}},
		{"key", keyStyle, []color.Attribute{color.FgBlue, color.Bold}},
		{"string", stringStyle, []color.Attribute{color.FgGreen}},
		{"number", numberStyle, []color.Attribute{color.FgYellow}},
		{"bool", boolStyle, []color.Attribute{color.FgMagenta}},
		{"null", nullStyle, []color.Attribute{color.FgRed}},
	}

	for _, tc := range cases {
		for _, colored := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/colored=%v", tc.name, colored), func(t *testing.T) {
				previous := color.NoColor
				color.NoColor = !colored
				t.Cleanup(func() { color.NoColor = previous })

				reference := color.New(tc.attributes...)

				var want, got bytes.Buffer
				if _, err := reference.Fprintln(&want, "Header"); err != nil {
					t.Fatalf("reference Fprintln: %v", err)
				}
				if err := tc.style.fprintln(&got, "Header"); err != nil {
					t.Fatalf("style fprintln: %v", err)
				}
				if got.String() != want.String() {
					t.Errorf("fprintln = %q, want %q", got.String(), want.String())
				}

				want.Reset()
				got.Reset()
				if _, err := reference.Fprintf(&want, "  %s\n", "a reason"); err != nil {
					t.Fatalf("reference Fprintf: %v", err)
				}
				if err := tc.style.fprintf(&got, "  %s\n", "a reason"); err != nil {
					t.Fatalf("style fprintf: %v", err)
				}
				if got.String() != want.String() {
					t.Errorf("fprintf = %q, want %q", got.String(), want.String())
				}
			})
		}
	}
}
