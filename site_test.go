package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readWebsiteFile(t *testing.T, elements ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(elements...))
	if err != nil {
		t.Fatalf("reading website file %s: %v", filepath.Join(elements...), err)
	}
	return string(data)
}

func TestWebsiteContentContract(t *testing.T) {
	if got, want := readWebsiteFile(t, "site", "CNAME"), "jwtd.webcodr.io\n"; got != want {
		t.Fatalf("site/CNAME must be exactly %q, got %q", want, got)
	}

	index := readWebsiteFile(t, "site", "index.html")
	for label, required := range map[string]string{
		"canonical URL":      `<link rel="canonical" href="https://jwtd.webcodr.io/">`,
		"content security":   `default-src 'none'`,
		"skip link":          `href="#main-content"`,
		"header landmark":    `<header class="site-header">`,
		"main landmark":      `<main id="main-content">`,
		"capabilities":       `id="capabilities"`,
		"installation":       `id="install"`,
		"usage":              `id="usage"`,
		"key formats":        `id="key-formats"`,
		"release security":   `id="release-security"`,
		"footer landmark":    `<footer class="site-footer">`,
		"local stylesheet":   `href="/styles.css"`,
		"local script":       `src="/script.js"`,
		"local favicon":      `href="/favicon.svg"`,
		"tab semantics":      `role="tablist"`,
		"tabpanel semantics": `role="tabpanel"`,
	} {
		if !strings.Contains(index, required) {
			t.Errorf("site/index.html is missing %s marker %q", label, required)
		}
	}
	for _, forbidden := range []string{"<style", "style=", "<script>"} {
		if strings.Contains(index, forbidden) {
			t.Errorf("site/index.html must not contain inline script/style marker %q", forbidden)
		}
	}

	styles := readWebsiteFile(t, "site", "styles.css")
	for name, color := range map[string]string{
		"background": "#1a1b26",
		"surface":    "#24283b",
		"text":       "#c0caf5",
		"muted text": "#a9b1d6",
		"comment":    "#565f89",
		"blue":       "#7aa2f7",
		"cyan":       "#7dcfff",
		"green":      "#9ece6a",
		"yellow":     "#e0af68",
		"magenta":    "#bb9af7",
		"red":        "#f7768e",
	} {
		if !strings.Contains(styles, color) {
			t.Errorf("site/styles.css is missing Tokyo Night %s token %s", name, color)
		}
	}
	for class, token := range map[string]string{
		".token-key":     "var(--blue)",
		".token-string":  "var(--green)",
		".token-number":  "var(--yellow)",
		".token-boolean": "var(--magenta)",
		".token-null":    "var(--red)",
		".token-label":   "var(--cyan)",
	} {
		if !strings.Contains(styles, class) || !strings.Contains(styles, token) {
			t.Errorf("site/styles.css must preserve CLI syntax mapping %s -> %s", class, token)
		}
	}

	for _, asset := range []string{"styles.css", "script.js", "favicon.svg"} {
		if _, err := os.Stat(filepath.Join("site", asset)); err != nil {
			t.Errorf("local asset site/%s must exist: %v", asset, err)
		}
	}
}
