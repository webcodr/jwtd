package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorKey    = "\033[1;34m" // bold blue
	colorString = "\033[0;32m" // green
	colorNumber = "\033[0;33m" // yellow
	colorBool   = "\033[0;35m" // magenta
	colorNull   = "\033[0;31m" // red
	colorBrace  = "\033[0;37m" // white
	colorLabel  = "\033[1;36m" // bold cyan
	colorDim    = "\033[2m"    // dim
)

func main() {
	token, err := readToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := decodeAndPrint(token); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func readToken() (string, error) {
	if len(os.Args) > 1 {
		return strings.TrimSpace(os.Args[1]), nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	return "", fmt.Errorf("usage: jwtd <token> or echo <token> | jwtd")
}

func decodeAndPrint(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT: expected 3 parts separated by '.', got %d", len(parts))
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return fmt.Errorf("decoding header: %w", err)
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return fmt.Errorf("decoding payload: %w", err)
	}

	useColor := isTerminal()

	printSection("Header", header, useColor)
	fmt.Println()
	printSection("Payload", payload, useColor)
	fmt.Println()
	printSignature(parts[2], useColor)

	return nil
}

func decodeSegment(seg string) (map[string]interface{}, error) {
	// JWT uses base64url encoding without padding
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	return result, nil
}

func printSection(label string, data map[string]interface{}, useColor bool) {
	if useColor {
		fmt.Printf("%s%s%s\n", colorLabel, label, colorReset)
	} else {
		fmt.Println(label)
	}

	pretty, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting %s: %v\n", label, err)
		return
	}

	if useColor {
		fmt.Println(colorize(string(pretty)))
	} else {
		fmt.Println(string(pretty))
	}
}

func printSignature(sig string, useColor bool) {
	if useColor {
		fmt.Printf("%s%s%s\n", colorLabel, "Signature", colorReset)
		fmt.Printf("%s%s%s\n", colorDim, sig, colorReset)
	} else {
		fmt.Println("Signature")
		fmt.Println(sig)
	}
}

func colorize(jsonStr string) string {
	var b strings.Builder
	inString := false
	isKey := false
	escaped := false
	i := 0

	for i < len(jsonStr) {
		ch := jsonStr[i]

		if escaped {
			b.WriteByte(ch)
			escaped = false
			i++
			continue
		}

		if ch == '\\' && inString {
			escaped = true
			b.WriteByte(ch)
			i++
			continue
		}

		if ch == '"' {
			if !inString {
				inString = true
				// Determine if this is a key by looking ahead for ':'
				isKey = isJSONKey(jsonStr, i)
				if isKey {
					b.WriteString(colorKey)
				} else {
					b.WriteString(colorString)
				}
				b.WriteByte(ch)
			} else {
				b.WriteByte(ch)
				b.WriteString(colorReset)
				inString = false
			}
			i++
			continue
		}

		if inString {
			b.WriteByte(ch)
			i++
			continue
		}

		// Outside of strings
		switch {
		case ch == '{' || ch == '}' || ch == '[' || ch == ']':
			b.WriteString(colorBrace)
			b.WriteByte(ch)
			b.WriteString(colorReset)
		case ch == 't' && i+4 <= len(jsonStr) && jsonStr[i:i+4] == "true":
			b.WriteString(colorBool)
			b.WriteString("true")
			b.WriteString(colorReset)
			i += 3
		case ch == 'f' && i+5 <= len(jsonStr) && jsonStr[i:i+5] == "false":
			b.WriteString(colorBool)
			b.WriteString("false")
			b.WriteString(colorReset)
			i += 4
		case ch == 'n' && i+4 <= len(jsonStr) && jsonStr[i:i+4] == "null":
			b.WriteString(colorNull)
			b.WriteString("null")
			b.WriteString(colorReset)
			i += 3
		case ch >= '0' && ch <= '9' || ch == '-':
			start := i
			for i < len(jsonStr) && (jsonStr[i] >= '0' && jsonStr[i] <= '9' || jsonStr[i] == '.' || jsonStr[i] == 'e' || jsonStr[i] == 'E' || jsonStr[i] == '+' || jsonStr[i] == '-') {
				i++
			}
			b.WriteString(colorNumber)
			b.WriteString(jsonStr[start:i])
			b.WriteString(colorReset)
			continue
		default:
			b.WriteByte(ch)
		}
		i++
	}

	return b.String()
}

// isJSONKey checks if the quote at position i starts a JSON key
// by scanning ahead past the string to find a ':'.
func isJSONKey(s string, i int) bool {
	// Skip opening quote
	j := i + 1
	for j < len(s) {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == '"' {
			// Found closing quote, now look for ':'
			j++
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			return j < len(s) && s[j] == ':'
		}
		j++
	}
	return false
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
