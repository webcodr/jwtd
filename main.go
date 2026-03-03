package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	prettyjson "github.com/hokaccha/go-prettyjson"
	"github.com/spf13/cobra"
)

// timestampKeys are JWT claims that contain Unix timestamps.
var timestampKeys = map[string]bool{
	"iat": true,
	"exp": true,
	"nbf": true,
}

// Color definitions used for labels and signature output.
var (
	labelColor = color.New(color.FgCyan, color.Bold)
	dimColor   = color.New(color.Faint)
)

// newFormatter creates a prettyjson formatter matching the project color scheme.
func newFormatter() *prettyjson.Formatter {
	f := prettyjson.NewFormatter()
	f.KeyColor = color.New(color.FgBlue, color.Bold)
	f.StringColor = color.New(color.FgGreen)
	f.NumberColor = color.New(color.FgYellow)
	f.BoolColor = color.New(color.FgMagenta)
	f.NullColor = color.New(color.FgRed)
	f.Indent = 2
	return f
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "jwtd [token]",
		Short: "Decode and pretty-print JSON Web Tokens",
		Long:  "jwtd decodes JWTs and displays the header, payload, and signature with syntax-highlighted JSON output.",
		Args:  cobra.MaximumNArgs(1),
		RunE:  run,
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	token, err := readToken(args)
	if err != nil {
		return err
	}
	return decodeAndPrint(token)
}

// readToken resolves the JWT string from arguments, stdin pipe, or interactive prompt.
func readToken(args []string) (string, error) {
	if len(args) > 0 {
		return strings.TrimSpace(args[0]), nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	return readInteractive()
}

// readInteractive prompts the user for a token using readline.
func readInteractive() (string, error) {
	rl, err := readline.New("Enter JWT: ")
	if err != nil {
		return "", fmt.Errorf("initializing readline: %w", err)
	}
	defer rl.Close()

	line, err := rl.Readline()
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}

	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("no token provided")
	}
	return token, nil
}

// decodeAndPrint parses the JWT and prints header, payload, and signature.
func decodeAndPrint(tokenStr string) error {
	parser := jwt.NewParser()
	token, parts, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("unexpected claims type")
	}

	f := newFormatter()

	printSection(f, "Header", token.Header)
	fmt.Fprintln(os.Stdout)
	formatTimestamps(claims)
	printSection(f, "Payload", map[string]interface{}(claims))
	fmt.Fprintln(os.Stdout)
	printSignature(parts[2])

	return nil
}

// formatTimestamps converts numeric Unix timestamp values for known JWT claims
// into human-readable date strings. The map is modified in place.
func formatTimestamps(data map[string]interface{}) {
	for key, val := range data {
		if !timestampKeys[key] {
			continue
		}
		num, ok := val.(float64)
		if !ok {
			continue
		}
		t := time.Unix(int64(num), 0).UTC()
		data[key] = t.Format(time.RFC3339)
	}
}

// printSection outputs a labeled, pretty-printed JSON section.
func printSection(f *prettyjson.Formatter, label string, data map[string]interface{}) {
	labelColor.Fprintln(os.Stdout, label)

	pretty, err := f.Marshal(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting %s: %v\n", label, err)
		return
	}
	fmt.Fprintln(os.Stdout, string(pretty))
}

// printSignature outputs the raw signature string in dimmed text.
func printSignature(sig string) {
	labelColor.Fprintln(os.Stdout, "Signature")
	dimColor.Fprintln(os.Stdout, sig)
}
