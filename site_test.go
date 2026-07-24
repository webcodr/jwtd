package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readWebsiteFile(t *testing.T, elements ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(elements...))
	if err != nil {
		t.Fatalf("reading website file %s: %v", filepath.Join(elements...), err)
	}
	return string(data)
}

var (
	selfClosingVoid = regexp.MustCompile(`\s*/>`)
	whitespaceRun   = regexp.MustCompile(`\s+`)
	whitespaceGT    = regexp.MustCompile(`\s*>\s*`)
	whitespaceLT    = regexp.MustCompile(`\s+<`)
)

// normalizeMarkup canonicalizes HTML whitespace and self-closing void
// elements so the copy/content contracts match regardless of formatter
// reflows: line wrapping, attribute splitting, whitespace around tag
// delimiters, and "<tag />" versus "<tag>". Both the document and the
// expected marker are passed through it before comparison.
func normalizeMarkup(s string) string {
	s = selfClosingVoid.ReplaceAllString(s, ">")
	s = whitespaceRun.ReplaceAllString(s, " ")
	s = whitespaceGT.ReplaceAllString(s, ">")
	s = whitespaceLT.ReplaceAllString(s, "<")
	return strings.TrimSpace(s)
}

func TestWebsiteContentContract(t *testing.T) {
	if got, want := readWebsiteFile(t, "site", "CNAME"), "jwtd.webcodr.io\n"; got != want {
		t.Fatalf("site/CNAME must be exactly %q, got %q", want, got)
	}

	index := readWebsiteFile(t, "site", "index.html")
	normalizedIndex := normalizeMarkup(index)
	for label, required := range map[string]string{
		"canonical URL":    `<link rel="canonical" href="https://jwtd.webcodr.io/">`,
		"content security": `default-src 'none'`,
		"skip link":        `href="#main-content"`,
		"header landmark":  `<header class="site-header">`,
		"main landmark":    `<main id="main-content">`,
		"capabilities":     `id="capabilities"`,
		"installation":     `id="install"`,
		"usage":            `id="usage"`,
		"key formats":      `id="key-formats"`,
		"release security": `id="release-security"`,
		"footer landmark":  `<footer class="site-footer">`,
		"local stylesheet": `href="/styles.css"`,
		"local script":     `src="/script.js"`,
		"local favicon":    `href="/favicon.svg"`,
		"structured data":  `<script type="application/ld+json">`,
		"release version":  `<p class="panel-kicker">Latest release: <a href="https://github.com/webcodr/jwtd/releases/latest">VERSION</a></p>`,
		"install controls": `data-install-tabs`,
		"install methods":  `data-install-method="macos"`,
		"install panels":   `data-install-panel="macos"`,
	} {
		if !strings.Contains(normalizedIndex, normalizeMarkup(required)) {
			t.Errorf("site/index.html is missing %s marker %q", label, required)
		}
	}
	for _, forbidden := range []string{"<style", "style=", "<script>", `role="tablist"`, `role="tab"`, `role="tabpanel"`, `aria-selected=`} {
		if strings.Contains(index, forbidden) {
			t.Errorf("site/index.html must not contain static enhancement marker %q", forbidden)
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

	for _, asset := range []string{"styles.css", "script.js", "favicon.svg", "robots.txt", "sitemap.xml"} {
		if _, err := os.Stat(filepath.Join("site", asset)); err != nil {
			t.Errorf("local asset site/%s must exist: %v", asset, err)
		}
	}
}

func TestWebsiteCopyContract(t *testing.T) {
	index := readWebsiteFile(t, "site", "index.html")
	normalizedIndex := normalizeMarkup(index)
	for label, required := range map[string]string{
		"page title":          `<title>jwtd - JWT, JWS, and JWE inspection</title>`,
		"meta description":    `<meta name="description" content="Decode JWTs, verify JWS signatures, and decrypt JWEs from the terminal.">`,
		"Open Graph title":    `<meta property="og:title" content="jwtd - JWT, JWS, and JWE inspection">`,
		"Open Graph summary":  `<meta property="og:description" content="Decode JWTs, verify JWS signatures, and decrypt JWEs from the terminal.">`,
		"hero eyebrow":        `<p class="eyebrow">A command-line tool for JWT, JWS, and JWE</p>`,
		"hero heading":        `<h1 id="hero-title">Inspect tokens<br><span>from the terminal.</span></h1>`,
		"primary action":      `<a class="button" href="#install">Install jwtd</a>`,
		"secondary action":    `<a class="text-link" href="#usage">View usage</a>`,
		"overview heading":    `<h2 id="capabilities-title">Focused tools for token inspection.</h2>`,
		"install heading":     `<h2 id="install-title">Install jwtd.</h2>`,
		"usage heading":       `<h2 id="usage-title">Common workflows.</h2>`,
		"signature guidance":  `Verify the cryptographic signature without evaluating claims such as expiry. Invalid signatures exit nonzero.`,
		"decryption guidance": `Compact JWEs are detected automatically. Provide a private key to decrypt the payload.`,
		"keys heading":        `<h2 id="key-formats-title">Use the key format you have.</h2>`,
		"security heading":    `<h2 id="release-security-title">Verifiable releases.</h2>`,
		"security guidance":   `Release archives and Linux packages are listed in <code>checksums.txt</code>, which is signed with a keyless Cosign bundle. Each archive also includes a Syft SPDX SBOM.`,
		"ssh key guidance":    `OpenSSH keys, <code>authorized_keys</code> entries, and RFC 4716 armor are recognized and rejected with an error, rather than being used as a symmetric secret.`,
		"footer copy":         `<p>A focused CLI for JWT, JWS, and JWE inspection.</p>`,
	} {
		if !strings.Contains(normalizedIndex, normalizeMarkup(required)) {
			t.Errorf("site/index.html is missing refined %s %q", label, required)
		}
	}

	for _, retired := range []string{
		"Trust the evidence.",
		"the full token path",
		"Read the field guide",
		"Bring real keys",
		"Verify before execution",
		"people who live in terminals",
	} {
		if strings.Contains(index, retired) {
			t.Errorf("site/index.html must not retain dramatic phrase %q", retired)
		}
	}
}

func TestLinuxPackageHeaderLayout(t *testing.T) {
	styles := readWebsiteFile(t, "site", "styles.css")
	for selector, declarations := range map[string][]string{
		".linux-commands .command-block > p": {
			"display: flex",
			"align-items: flex-start",
			"justify-content: space-between",
			"gap: 1rem",
		},
		".package-link": {
			"float: none",
			"flex: 0 0 auto",
			"white-space: nowrap",
		},
	} {
		rule := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`).FindStringSubmatch(styles)
		if rule == nil {
			t.Errorf("site/styles.css is missing %s rule", selector)
			continue
		}
		for _, declaration := range declarations {
			if !strings.Contains(rule[1], declaration) {
				t.Errorf("site/styles.css %s rule is missing %q", selector, declaration)
			}
		}
	}
}

type pagesWorkflowContract struct {
	Permissions map[string]string `yaml:"permissions"`
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress bool   `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]struct {
		Needs       string            `yaml:"needs"`
		Permissions map[string]string `yaml:"permissions"`
		Environment struct {
			Name string `yaml:"name"`
			URL  string `yaml:"url"`
		} `yaml:"environment"`
		Steps []struct {
			ID   string         `yaml:"id"`
			Uses string         `yaml:"uses"`
			Run  string         `yaml:"run"`
			With map[string]any `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func TestWebsitePagesWorkflowContract(t *testing.T) {
	data := readWebsiteFile(t, ".github", "workflows", "pages.yml")
	var workflow pagesWorkflowContract
	if err := yaml.Unmarshal([]byte(data), &workflow); err != nil {
		t.Fatalf("parsing Pages workflow: %v", err)
	}

	if want := map[string]string{"contents": "read", "pages": "read"}; !maps.Equal(workflow.Permissions, want) {
		t.Errorf("root Pages permissions must be exactly %v, got %v", want, workflow.Permissions)
	}
	if workflow.Concurrency.Group != "pages" || !workflow.Concurrency.CancelInProgress {
		t.Errorf("Pages concurrency must cancel superseded deployments, got %+v", workflow.Concurrency)
	}

	build, ok := workflow.Jobs["build"]
	if !ok {
		t.Fatal("Pages workflow must define a build job")
	}
	deploy, ok := workflow.Jobs["deploy"]
	if !ok {
		t.Fatal("Pages workflow must define a deploy job")
	}
	if deploy.Needs != "build" {
		t.Errorf("deploy job must need build, got %q", deploy.Needs)
	}
	if want := map[string]string{"pages": "write", "id-token": "write"}; !maps.Equal(deploy.Permissions, want) {
		t.Errorf("deploy permissions must be exactly %v, got %v", want, deploy.Permissions)
	}
	if deploy.Environment.Name != "github-pages" || deploy.Environment.URL != "${{ steps.deployment.outputs.page_url }}" {
		t.Errorf("deploy environment must expose the official Pages URL, got %+v", deploy.Environment)
	}

	wantActions := map[string]string{
		"actions/checkout":              "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
		"actions/configure-pages":       "actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b",
		"actions/upload-pages-artifact": "actions/upload-pages-artifact@7b1f4a764d45c48632c6b24a0339c27f5614fb0b",
		"actions/deploy-pages":          "actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
	}
	seen := make(map[string]string)
	shaPinned := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			if !shaPinned.MatchString(step.Uses) {
				t.Errorf("Pages action must use a full SHA: %q", step.Uses)
			}
			name := strings.SplitN(step.Uses, "@", 2)[0]
			seen[name] = step.Uses
		}
	}
	if !maps.Equal(seen, wantActions) {
		t.Errorf("Pages actions must be exactly pinned official actions %v, got %v", wantActions, seen)
	}

	var artifactPath string
	for _, step := range build.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-pages-artifact@") {
			artifactPath = fmt.Sprint(step.With["path"])
		}
	}
	if artifactPath != "site" {
		t.Errorf("Pages artifact path must be site, got %q", artifactPath)
	}

	var bakeScript string
	for _, step := range build.Steps {
		bakeScript += step.Run
	}
	if !strings.Contains(bakeScript, "gh release view") || !strings.Contains(bakeScript, "VERSION") {
		t.Errorf("Pages build job must bake the latest release version into the site, got %q", bakeScript)
	}

	var deploymentID string
	for _, step := range deploy.Steps {
		if strings.HasPrefix(step.Uses, "actions/deploy-pages@") {
			deploymentID = step.ID
		}
	}
	if deploymentID != "deployment" {
		t.Errorf("deploy-pages step id must be deployment, got %q", deploymentID)
	}
}

func TestWebsiteToolingContract(t *testing.T) {
	testWorkflow := readWebsiteFile(t, ".github", "workflows", "test.yml")
	for label, required := range map[string]string{
		"pinned Node setup":       "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
		"Node version":            "node-version: 26.4.0",
		"JavaScript syntax check": "node --check site/script.js",
		"JavaScript unit tests":   "node --test site/script.test.js",
	} {
		if !strings.Contains(testWorkflow, required) {
			t.Errorf("test workflow is missing %s marker %q", label, required)
		}
	}

	shaPinned := regexp.MustCompile(`uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s|$)`)
	usesLine := regexp.MustCompile(`(?m)^\s*- uses:\s+\S+`)
	for _, line := range usesLine.FindAllString(testWorkflow, -1) {
		if !shaPinned.MatchString(line) {
			t.Errorf("test workflow action must preserve full-SHA pinning: %q", strings.TrimSpace(line))
		}
	}
}
