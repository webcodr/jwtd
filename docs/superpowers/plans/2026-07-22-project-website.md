# jwtd Project Website Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy a fast, accessible, progressively enhanced single-page website for jwtd at `https://jwtd.webcodr.io/`.

**Architecture:** Serve a hand-built static document from `site/` with all essential content and anchor navigation in HTML, Tokyo Night presentation in one local stylesheet, and optional browser enhancements in one local script. A focused Go contract test locks down repository-owned website and GitHub Pages invariants, while Node's built-in test runner exercises the script's pure OS detection logic without adding npm or a frontend build step.

**Tech Stack:** Semantic HTML5, CSS, browser JavaScript, Node.js 26.4.0 built-in test runner, Go 1.26 repository tests, GitHub Pages official actions.

---

## File Map

- Create: `site/index.html` - complete single-page content, metadata, semantic landmarks, no-JavaScript navigation, installation methods, usage documentation, and local asset references.
- Create: `site/styles.css` - responsive terminal-editorial layout, approved Tokyo Night tokens, CLI syntax colors, focus states, tab/mobile-menu enhancement states, and reduced-motion behavior.
- Create: `site/script.js` - pure OS detection plus accessible installation tabs, copy feedback, and mobile navigation enhancements.
- Create: `site/script.test.js` - dependency-free Node tests for OS detection, install-method mapping, fallback, and source-priority behavior.
- Create: `site/favicon.svg` - local, Tokyo Night-colored favicon with no external resource.
- Create: `site/CNAME` - exact custom domain declaration, `jwtd.webcodr.io`.
- Create: `site_test.go` - focused repository contract for the custom domain, canonical URL, core sections, local assets, CSP, Tokyo Night/CLI colors, Pages workflow, and pinned Node CI support.
- Create: `.github/workflows/pages.yml` - build-free Pages artifact upload and deployment with full-SHA official actions, least privilege, deployment environment, and concurrency.
- Modify: `.github/workflows/test.yml` - install a full-SHA-pinned Node 26.4.0 only in the test job, then run syntax and built-in tests; leave mise, release jobs, and all existing Go and release-package checks unchanged.

Do not modify application source, release configuration, `.github/workflows/release.yml`, release packaging, README content, or any existing release behavior. DNS remains an external prerequisite: `jwtd.webcodr.io` must be a CNAME for `webcodr.github.io`.

### Task 1: Add Tested Progressive Enhancements

**Files:**
- Create: `site/script.test.js`
- Create: `site/script.js`

- [ ] **Step 1: Write the failing OS detection tests**

Create the site directory after verifying its parent: `ls . && mkdir site`.

Expected: the repository root listing succeeds and the empty `site/` directory is created.

Create `site/script.test.js`:

```javascript
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectOperatingSystem,
  installMethodForOperatingSystem,
} = require("./script.js");

test("detectOperatingSystem classifies supported operating systems", () => {
  const cases = [
    ["macOS", "", "", "macos"],
    ["", "MacIntel", "", "macos"],
    ["", "", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"],
    ["Windows", "", "", "windows"],
    ["", "Win32", "", "windows"],
    ["", "", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"],
    ["Linux", "", "", "linux"],
    ["", "Linux x86_64", "", "linux"],
    ["", "", "Mozilla/5.0 (X11; Linux x86_64)", "linux"],
  ];

  for (const [userAgentDataPlatform, platform, userAgent, expected] of cases) {
    assert.equal(
      detectOperatingSystem(userAgentDataPlatform, platform, userAgent),
      expected,
    );
  }
});

test("detectOperatingSystem returns unknown when no platform matches", () => {
  assert.equal(detectOperatingSystem("", "", ""), "unknown");
  assert.equal(detectOperatingSystem("Plan 9", "Unknown", "custom-client"), "unknown");
});

test("installMethodForOperatingSystem selects the approved default", () => {
  assert.equal(installMethodForOperatingSystem("macos"), "homebrew");
  assert.equal(installMethodForOperatingSystem("windows"), "scoop");
  assert.equal(installMethodForOperatingSystem("linux"), "linux");
  assert.equal(installMethodForOperatingSystem("unknown"), "homebrew");
});

test("detectOperatingSystem honors platform source priority", () => {
  assert.equal(
    detectOperatingSystem("Windows", "MacIntel", "Mozilla/5.0 (X11; Linux x86_64)"),
    "windows",
  );
  assert.equal(
    detectOperatingSystem("", "MacIntel", "Mozilla/5.0 (Windows NT 10.0)"),
    "macos",
  );
});
```

- [ ] **Step 2: Run the tests and verify the module is missing**

Run: `node --test site/script.test.js`

Expected: FAIL with `Cannot find module './script.js'`.

- [ ] **Step 3: Implement the pure detector and browser enhancements**

Create `site/script.js`:

```javascript
"use strict";

function classifyPlatform(value) {
  const normalized = String(value || "").toLowerCase();

  if (/mac|iphone|ipad|ipod/.test(normalized)) {
    return "macos";
  }
  if (/win/.test(normalized)) {
    return "windows";
  }
  if (/linux|x11/.test(normalized)) {
    return "linux";
  }
  return "unknown";
}

function detectOperatingSystem(userAgentDataPlatform, platform, userAgent) {
  for (const candidate of [userAgentDataPlatform, platform, userAgent]) {
    const detected = classifyPlatform(candidate);
    if (detected !== "unknown") {
      return detected;
    }
  }
  return "unknown";
}

function installMethodForOperatingSystem(operatingSystem) {
  if (operatingSystem === "windows") {
    return "scoop";
  }
  if (operatingSystem === "linux") {
    return "linux";
  }
  return "homebrew";
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { detectOperatingSystem, installMethodForOperatingSystem };
}

if (typeof document !== "undefined") {
  document.documentElement.classList.add("js");

  const initialize = () => {
    const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
    const panels = Array.from(document.querySelectorAll('[role="tabpanel"]'));

    const selectTab = (method, moveFocus = false) => {
      for (const tab of tabs) {
        const selected = tab.dataset.installMethod === method;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected && moveFocus) {
          tab.focus();
        }
      }

      for (const panel of panels) {
        panel.hidden = panel.dataset.installPanel !== method;
      }
    };

    if (tabs.length > 0 && panels.length > 0) {
      let operatingSystem = "unknown";
      try {
        operatingSystem = detectOperatingSystem(
          navigator.userAgentData?.platform || "",
          navigator.platform || "",
          navigator.userAgent || "",
        );
      } catch {
        operatingSystem = "unknown";
      }

      selectTab(installMethodForOperatingSystem(operatingSystem));

      tabs.forEach((tab, index) => {
        tab.addEventListener("click", (event) => {
          event.preventDefault();
          selectTab(tab.dataset.installMethod);
        });

        tab.addEventListener("keydown", (event) => {
          let nextIndex;
          if (event.key === "ArrowRight" || event.key === "ArrowDown") {
            nextIndex = (index + 1) % tabs.length;
          } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
            nextIndex = (index - 1 + tabs.length) % tabs.length;
          } else if (event.key === "Home") {
            nextIndex = 0;
          } else if (event.key === "End") {
            nextIndex = tabs.length - 1;
          } else {
            return;
          }

          event.preventDefault();
          selectTab(tabs[nextIndex].dataset.installMethod, true);
        });
      });
    }

    const feedbackTimers = new WeakMap();
    for (const button of document.querySelectorAll("[data-copy-target]")) {
      button.addEventListener("click", async () => {
        const command = document.getElementById(button.dataset.copyTarget);
        const feedback = button.parentElement.querySelector("[data-copy-feedback]");
        if (!command || !feedback) {
          return;
        }

        const previousTimer = feedbackTimers.get(button);
        if (previousTimer) {
          window.clearTimeout(previousTimer);
        }

        try {
          if (!navigator.clipboard?.writeText) {
            throw new Error("Clipboard API unavailable");
          }
          await navigator.clipboard.writeText(command.textContent.trim());
          feedback.textContent = "Copied.";
        } catch {
          feedback.textContent = "Select the command and copy it manually.";
        }

        feedbackTimers.set(
          button,
          window.setTimeout(() => {
            feedback.textContent = "";
          }, 3000),
        );
      });
    }

    const navToggle = document.querySelector("[data-nav-toggle]");
    const navigation = document.getElementById("primary-navigation");
    if (navToggle && navigation) {
      const closeNavigation = (restoreFocus = false) => {
        navToggle.setAttribute("aria-expanded", "false");
        navigation.dataset.open = "false";
        if (restoreFocus) {
          navToggle.focus();
        }
      };

      navToggle.addEventListener("click", () => {
        const open = navToggle.getAttribute("aria-expanded") !== "true";
        navToggle.setAttribute("aria-expanded", String(open));
        navigation.dataset.open = String(open);
      });

      navigation.addEventListener("click", (event) => {
        if (event.target.closest("a")) {
          closeNavigation();
        }
      });

      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && navToggle.getAttribute("aria-expanded") === "true") {
          closeNavigation(true);
        }
      });
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
}
```

- [ ] **Step 4: Run JavaScript tests and syntax checking**

Run: `node --test site/script.test.js && node --check site/script.js`

Expected: four passing tests followed by a zero-exit syntax check with no output.

- [ ] **Step 5: Commit the independently tested enhancement module**

```bash
git add site/script.js site/script.test.js
git commit -m "feat: add website progressive enhancements"
```

### Task 2: Build the Static Page and Tokyo Night Presentation

**Files:**
- Create: `site_test.go`
- Create: `site/index.html`
- Create: `site/styles.css`
- Create: `site/favicon.svg`
- Create: `site/CNAME`

- [ ] **Step 1: Write the failing static-site contract test**

Create `site_test.go`:

```go
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
		"canonical URL":     `<link rel="canonical" href="https://jwtd.webcodr.io/">`,
		"content security":  `default-src 'none'`,
		"skip link":         `href="#main-content"`,
		"header landmark":   `<header class="site-header">`,
		"main landmark":     `<main id="main-content">`,
		"capabilities":      `id="capabilities"`,
		"installation":      `id="install"`,
		"usage":             `id="usage"`,
		"key formats":       `id="key-formats"`,
		"release security":  `id="release-security"`,
		"footer landmark":   `<footer class="site-footer">`,
		"local stylesheet":  `href="/styles.css"`,
		"local script":      `src="/script.js"`,
		"local favicon":     `href="/favicon.svg"`,
		"tab semantics":     `role="tablist"`,
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
```

- [ ] **Step 2: Run the contract and verify the static site is absent**

Run: `go test -run '^TestWebsiteContentContract$'`

Expected: FAIL with `reading website file site/CNAME`.

- [ ] **Step 3: Add the exact custom domain and local favicon**

Create `site/CNAME`:

```text
jwtd.webcodr.io
```

Create `site/favicon.svg`:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="jwtd">
  <rect width="64" height="64" rx="12" fill="#1a1b26"/>
  <path d="M16 17h8v23c0 7-4 11-11 11h-2v-7h2c2 0 3-1 3-4V17Zm13 0h8l4 20 5-20h7l-9 34h-7l-8-34Z" fill="#7dcfff"/>
</svg>
```

- [ ] **Step 4: Add the complete semantic page**

Create `site/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Decode JWTs, verify JWS signatures, and decrypt JWEs from your terminal with jwtd.">
    <meta name="theme-color" content="#1a1b26">
    <meta property="og:type" content="website">
    <meta property="og:title" content="jwtd - inspect JSON web tokens from the terminal">
    <meta property="og:description" content="A focused CLI for decoding JWTs, verifying JWS signatures, and decrypting JWEs.">
    <meta property="og:url" content="https://jwtd.webcodr.io/">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests">
    <link rel="canonical" href="https://jwtd.webcodr.io/">
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="/styles.css">
    <script defer src="/script.js"></script>
    <title>jwtd - JWT, JWS, and JWE tools for the terminal</title>
  </head>
  <body>
    <a class="skip-link" href="#main-content">Skip to main content</a>

    <header class="site-header">
      <div class="header-inner">
        <a class="wordmark" href="#top" aria-label="jwtd home">jwtd<span aria-hidden="true">_</span></a>
        <button class="nav-toggle" type="button" aria-controls="primary-navigation" aria-expanded="false" data-nav-toggle>Menu</button>
        <nav class="site-nav" id="primary-navigation" aria-label="Primary" data-open="false">
          <a href="#capabilities">Capabilities</a>
          <a href="#usage">Usage</a>
          <a href="#key-formats">Keys</a>
          <a href="#release-security">Security</a>
        </nav>
        <div class="header-actions">
          <a class="text-link" href="https://github.com/webcodr/jwtd">GitHub</a>
          <a class="button button-small" href="#install">Install</a>
        </div>
      </div>
    </header>

    <main id="main-content">
      <section class="hero" id="top" aria-labelledby="hero-title">
        <div class="hero-copy">
          <p class="eyebrow">JWT / JWS / JWE inspection</p>
          <h1 id="hero-title">Read the token.<br><span>Trust the evidence.</span></h1>
          <p class="hero-lede">jwtd decodes JSON web tokens, verifies signatures, and decrypts encrypted payloads without leaving your terminal.</p>
          <div class="hero-actions">
            <a class="button" href="#install">Choose an install method</a>
            <a class="text-link" href="#usage">Read the field guide</a>
          </div>
          <div class="command-block compact-command">
            <pre><code id="hero-install-command">brew install webcodr/tap/jwtd</code></pre>
            <div class="command-actions">
              <button type="button" data-copy-target="hero-install-command">Copy</button>
              <span class="copy-feedback" data-copy-feedback aria-live="polite"></span>
            </div>
          </div>
        </div>

        <div class="terminal" aria-label="Example jwtd terminal output">
          <div class="terminal-bar">
            <span></span><span></span><span></span>
            <p>jwtd - token inspection</p>
          </div>
          <pre><code><span class="prompt">$</span> jwtd eyJhbGciOiJSUzI1NiIs...

<span class="token-label">Header:</span>
{
  <span class="token-key">"alg"</span>: <span class="token-string">"RS256"</span>,
  <span class="token-key">"typ"</span>: <span class="token-string">"JWT"</span>
}

<span class="token-label">Payload:</span>
{
  <span class="token-key">"sub"</span>: <span class="token-string">"user_2048"</span>,
  <span class="token-key">"admin"</span>: <span class="token-boolean">true</span>,
  <span class="token-key">"iat"</span>: <span class="token-number">1784689200</span>,
  <span class="token-key">"note"</span>: <span class="token-null">null</span>
}

<span class="signature">Signature: eyJfX2p3dGRfXyI...</span></code></pre>
        </div>
      </section>

      <section class="section capabilities" id="capabilities" aria-labelledby="capabilities-title">
        <div class="section-heading">
          <p class="eyebrow">01 / capabilities</p>
          <h2 id="capabilities-title">One command, the full token path.</h2>
          <p>Inspect first. Add a key only when cryptographic proof or plaintext is needed.</p>
        </div>
        <div class="capability-list">
          <article><span>01</span><div><h3>Decode JWTs</h3><p>Pretty-print exact JSON values and human-readable token timestamps.</p></div></article>
          <article><span>02</span><div><h3>Verify JWS</h3><p>Check the cryptographic signature independently from claim expiry.</p></div></article>
          <article><span>03</span><div><h3>Decrypt JWE</h3><p>Detect compact JWEs and reveal protected content with the supplied key.</p></div></article>
          <article><span>04</span><div><h3>Follow nesting</h3><p>Recursively inspect JWT-inside-JWE and JWE-inside-JWE payloads.</p></div></article>
          <article><span>05</span><div><h3>Bring real keys</h3><p>Use PEM, DER, certificates, JWK Sets, encoded material, or raw secrets.</p></div></article>
        </div>
      </section>

      <section class="section installation" id="install" aria-labelledby="install-title">
        <div class="section-heading narrow-heading">
          <p class="eyebrow">02 / installation</p>
          <h2 id="install-title">Put jwtd on your path.</h2>
          <p>The suggested method follows your operating system when JavaScript is available. Every method remains below when it is not.</p>
        </div>

        <div class="install-tabs" role="tablist" aria-label="Installation methods">
          <a id="install-tab-homebrew" href="#install-homebrew" role="tab" aria-controls="install-homebrew" aria-selected="true" data-install-method="homebrew">Homebrew</a>
          <a id="install-tab-scoop" href="#install-scoop" role="tab" aria-controls="install-scoop" aria-selected="false" data-install-method="scoop">Scoop</a>
          <a id="install-tab-linux" href="#install-linux" role="tab" aria-controls="install-linux" aria-selected="false" data-install-method="linux">Linux packages</a>
          <a id="install-tab-go" href="#install-go" role="tab" aria-controls="install-go" aria-selected="false" data-install-method="go">Go</a>
          <a id="install-tab-archives" href="#install-archives" role="tab" aria-controls="install-archives" aria-selected="false" data-install-method="archives">Archives</a>
        </div>

        <div class="install-panel" id="install-homebrew" role="tabpanel" aria-labelledby="install-tab-homebrew" data-install-panel="homebrew">
          <div><p class="panel-kicker">macOS / Linux</p><h3>Homebrew formula</h3><p>Installs the current release from the webcodr tap.</p></div>
          <div class="command-block">
            <pre><code id="brew-command">brew install webcodr/tap/jwtd</code></pre>
            <div class="command-actions"><button type="button" data-copy-target="brew-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div>
          </div>
        </div>

        <div class="install-panel" id="install-scoop" role="tabpanel" aria-labelledby="install-tab-scoop" data-install-panel="scoop">
          <div><p class="panel-kicker">Windows</p><h3>Scoop bucket</h3><p>Add the bucket once, then install jwtd.</p></div>
          <div class="command-block">
            <pre><code id="scoop-command">scoop bucket add webcodr https://github.com/webcodr/scoop-bucket
scoop install jwtd</code></pre>
            <div class="command-actions"><button type="button" data-copy-target="scoop-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div>
          </div>
        </div>

        <div class="install-panel" id="install-linux" role="tabpanel" aria-labelledby="install-tab-linux" data-install-panel="linux">
          <div><p class="panel-kicker">Linux / choose package and architecture</p><h3>Native packages</h3><p>Download the matching release asset. Distro and CPU architecture are intentionally not guessed.</p></div>
          <div class="linux-commands">
            <div class="command-block"><p>Debian / Ubuntu - amd64 <a class="package-link" href="https://github.com/webcodr/jwtd/releases/latest/download/jwtd-linux-amd64.deb">Download .deb</a></p><pre><code id="deb-amd64-command">sudo dpkg -i jwtd-linux-amd64.deb</code></pre><div class="command-actions"><button type="button" data-copy-target="deb-amd64-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div>
            <div class="command-block"><p>Debian / Ubuntu - arm64 <a class="package-link" href="https://github.com/webcodr/jwtd/releases/latest/download/jwtd-linux-arm64.deb">Download .deb</a></p><pre><code id="deb-arm64-command">sudo dpkg -i jwtd-linux-arm64.deb</code></pre><div class="command-actions"><button type="button" data-copy-target="deb-arm64-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div>
            <div class="command-block"><p>Fedora / RHEL / openSUSE - amd64 <a class="package-link" href="https://github.com/webcodr/jwtd/releases/latest/download/jwtd-linux-amd64.rpm">Download .rpm</a></p><pre><code id="rpm-amd64-command">sudo rpm -i jwtd-linux-amd64.rpm</code></pre><div class="command-actions"><button type="button" data-copy-target="rpm-amd64-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div>
            <div class="command-block"><p>Fedora / RHEL / openSUSE - arm64 <a class="package-link" href="https://github.com/webcodr/jwtd/releases/latest/download/jwtd-linux-arm64.rpm">Download .rpm</a></p><pre><code id="rpm-arm64-command">sudo rpm -i jwtd-linux-arm64.rpm</code></pre><div class="command-actions"><button type="button" data-copy-target="rpm-arm64-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div>
          </div>
          <a class="text-link" href="https://github.com/webcodr/jwtd/releases">Download Linux package assets</a>
        </div>

        <div class="install-panel" id="install-go" role="tabpanel" aria-labelledby="install-tab-go" data-install-panel="go">
          <div><p class="panel-kicker">Go 1.26+</p><h3>Install from source</h3><p>Build the latest tagged version with your Go toolchain.</p></div>
          <div class="command-block"><pre><code id="go-command">go install github.com/webcodr/jwtd@latest</code></pre><div class="command-actions"><button type="button" data-copy-target="go-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div>
        </div>

        <div class="install-panel" id="install-archives" role="tabpanel" aria-labelledby="install-tab-archives" data-install-panel="archives">
          <div><p class="panel-kicker">Linux / macOS / Windows</p><h3>Release archives</h3><p>Choose amd64 or arm64 for your platform, verify it, and place the binary on your path.</p></div>
          <div class="archive-grid"><span>linux-amd64</span><span>linux-arm64</span><span>darwin-amd64</span><span>darwin-arm64</span><span>windows-amd64</span><span>windows-arm64</span></div>
          <a class="button button-small" href="https://github.com/webcodr/jwtd/releases">Browse release archives</a>
        </div>
      </section>

      <section class="section usage" id="usage" aria-labelledby="usage-title">
        <div class="section-heading">
          <p class="eyebrow">03 / usage</p>
          <h2 id="usage-title">From readable to verified.</h2>
          <p>Tokens can arrive as an argument, through stdin, or at the interactive prompt.</p>
        </div>
        <div class="usage-list">
          <article><div class="usage-number">01</div><div class="usage-copy"><h3>Decode a JWT</h3><p>Inspect the header, claims, and signature without requiring a key.</p></div><div class="command-block"><pre><code id="decode-command">jwtd eyJhbGciOiJIUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="decode-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
          <article><div class="usage-number">02</div><div class="usage-copy"><h3>Verify a JWS signature</h3><p>A failed signature prints INVALID and exits nonzero. Claim expiry is not part of this cryptographic check.</p></div><div class="command-block"><pre><code id="verify-command">jwtd --key /path/to/public-key.pem eyJhbGciOiJSUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="verify-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
          <article><div class="usage-number">03</div><div class="usage-copy"><h3>Decrypt a JWE</h3><p>Five-part compact tokens are detected automatically; provide the private key to reveal the payload.</p></div><div class="command-block"><pre><code id="decrypt-command">jwtd --key /path/to/private-key.pem eyJhbGciOiJSU0EtT0FF...</code></pre><div class="command-actions"><button type="button" data-copy-target="decrypt-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
        </div>
      </section>

      <section class="section key-formats" id="key-formats" aria-labelledby="key-formats-title">
        <div class="section-heading narrow-heading">
          <p class="eyebrow">04 / key formats</p>
          <h2 id="key-formats-title">Use the key material you already have.</h2>
          <p>The <code>--key</code> flag and <code>JWTD_KEY</code> environment variable share the same format detection path.</p>
        </div>
        <div class="key-layout">
          <ul class="key-list">
            <li><strong>PEM</strong><span>RSA, EC, Ed25519, private or public</span></li>
            <li><strong>DER</strong><span>PKCS#1, PKCS#8, SEC 1, PKIX</span></li>
            <li><strong>X.509</strong><span>Certificate public keys</span></li>
            <li><strong>JWK / JWK Set</strong><span>Single keys or the first set entry</span></li>
            <li><strong>Base64</strong><span>Standard or URL-safe encoded material</span></li>
            <li><strong>raw:</strong><span>Explicit literal symmetric secrets</span></li>
          </ul>
          <div class="command-block key-command"><p>Explicit HMAC secret</p><pre><code id="raw-key-command">jwtd --key raw:my-hmac-secret eyJhbGciOiJIUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="raw-key-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div>
        </div>
      </section>

      <section class="section release-security" id="release-security" aria-labelledby="release-security-title">
        <div class="security-copy">
          <p class="eyebrow">05 / release security</p>
          <h2 id="release-security-title">Verify before execution.</h2>
          <p>Every archive and Linux package is covered by <code>checksums.txt</code>. The checksum file carries a keyless Cosign bundle tied to this repository's release workflow, and every archive ships with a Syft SPDX SBOM.</p>
          <a class="text-link" href="https://github.com/webcodr/jwtd#installation">Read the exhaustive verification instructions</a>
        </div>
        <div class="command-block security-command">
          <p>Verify the signed checksum file</p>
          <pre><code id="cosign-command">cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/webcodr/jwtd/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt</code></pre>
          <div class="command-actions"><button type="button" data-copy-target="cosign-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div><a class="wordmark" href="#top">jwtd<span aria-hidden="true">_</span></a><p>Token inspection for people who live in terminals.</p></div>
      <nav aria-label="Project links">
        <a href="https://github.com/webcodr/jwtd">Repository</a>
        <a href="https://github.com/webcodr/jwtd/releases">Releases</a>
        <a href="https://github.com/webcodr/jwtd/blob/main/LICENSE">MIT License</a>
        <a href="https://go.dev/">Go project</a>
      </nav>
    </footer>
  </body>
</html>
```

- [ ] **Step 5: Add the complete responsive Tokyo Night stylesheet**

Use the approved `#565f89` muted shade for nonessential terminal decoration only. Tokyo Night's `#a9b1d6` secondary foreground is used for readable muted body copy because `#565f89` does not provide sufficient contrast against `#1a1b26` at normal text sizes.

Create `site/styles.css`:

```css
:root {
  color-scheme: dark;
  --background: #1a1b26;
  --surface: #24283b;
  --text: #c0caf5;
  --muted: #a9b1d6;
  --comment: #565f89;
  --blue: #7aa2f7;
  --cyan: #7dcfff;
  --green: #9ece6a;
  --yellow: #e0af68;
  --magenta: #bb9af7;
  --red: #f7768e;
  --border: #3b4261;
  --background-deep: #16161e;
  --sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  --content: 1180px;
}

* {
  box-sizing: border-box;
}

html {
  scroll-behavior: smooth;
}

body {
  margin: 0;
  background:
    linear-gradient(rgba(122, 162, 247, 0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(122, 162, 247, 0.035) 1px, transparent 1px),
    var(--background);
  background-size: 40px 40px;
  color: var(--text);
  font-family: var(--sans);
  line-height: 1.6;
}

a {
  color: inherit;
}

button,
a {
  -webkit-tap-highlight-color: transparent;
}

button {
  font: inherit;
}

:focus-visible {
  outline: 3px solid var(--yellow);
  outline-offset: 3px;
}

.skip-link {
  position: fixed;
  z-index: 100;
  top: 0.75rem;
  left: 0.75rem;
  padding: 0.7rem 1rem;
  background: var(--yellow);
  color: var(--background-deep);
  font-weight: 800;
  transform: translateY(-180%);
}

.skip-link:focus {
  transform: translateY(0);
}

.site-header {
  position: sticky;
  z-index: 20;
  top: 0;
  border-bottom: 1px solid rgba(59, 66, 97, 0.8);
  background: rgba(26, 27, 38, 0.94);
  backdrop-filter: blur(14px);
}

.header-inner,
.hero,
.section,
.site-footer {
  width: min(calc(100% - 2.5rem), var(--content));
  margin-inline: auto;
}

.header-inner {
  min-height: 70px;
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 2rem;
}

.wordmark {
  color: var(--cyan);
  font-family: var(--mono);
  font-size: 1.25rem;
  font-weight: 800;
  letter-spacing: -0.04em;
  text-decoration: none;
}

.wordmark span {
  color: var(--magenta);
}

.site-nav {
  display: flex;
  justify-content: center;
  gap: 1.6rem;
}

.site-nav a,
.site-footer nav a {
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.8rem;
  text-decoration: none;
}

.site-nav a:hover,
.site-footer nav a:hover,
.text-link:hover {
  color: var(--cyan);
}

.header-actions,
.hero-actions {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.text-link {
  color: var(--blue);
  font-weight: 750;
  text-underline-offset: 0.25em;
}

.button {
  display: inline-flex;
  min-height: 46px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--blue);
  background: var(--blue);
  color: var(--background-deep);
  font-family: var(--mono);
  font-weight: 800;
  padding: 0.75rem 1rem;
  text-decoration: none;
  box-shadow: 4px 4px 0 rgba(187, 154, 247, 0.35);
}

.button:hover {
  background: var(--cyan);
  border-color: var(--cyan);
}

.button-small {
  min-height: 40px;
  padding: 0.55rem 0.85rem;
  font-size: 0.8rem;
}

.nav-toggle {
  display: none;
  min-height: 42px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  font-family: var(--mono);
}

.hero {
  min-height: calc(100vh - 70px);
  display: grid;
  grid-template-columns: minmax(0, 0.88fr) minmax(500px, 1.12fr);
  align-items: center;
  gap: clamp(2.5rem, 6vw, 6rem);
  padding-block: 5rem;
}

.eyebrow,
.panel-kicker {
  margin: 0 0 1rem;
  color: var(--cyan);
  font-family: var(--mono);
  font-size: 0.75rem;
  font-weight: 800;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

h1,
h2,
h3,
p {
  margin-top: 0;
}

h1 {
  margin-bottom: 1.5rem;
  font-size: clamp(3.4rem, 7vw, 6.7rem);
  line-height: 0.92;
  letter-spacing: -0.075em;
}

h1 span {
  color: var(--blue);
}

h2 {
  margin-bottom: 1rem;
  font-size: clamp(2.1rem, 4vw, 4.2rem);
  line-height: 1.02;
  letter-spacing: -0.055em;
}

h3 {
  margin-bottom: 0.35rem;
  font-size: 1.05rem;
}

.hero-lede,
.section-heading > p,
.security-copy > p {
  color: var(--muted);
  font-size: clamp(1rem, 1.5vw, 1.2rem);
}

.hero-lede {
  max-width: 34rem;
  margin-bottom: 2rem;
}

.hero-actions {
  margin-bottom: 2rem;
}

.terminal {
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--border);
  background: var(--background-deep);
  box-shadow: 18px 18px 0 rgba(122, 162, 247, 0.08), -8px -8px 0 rgba(187, 154, 247, 0.05);
}

.terminal-bar {
  min-height: 45px;
  display: flex;
  align-items: center;
  gap: 0.45rem;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  padding: 0 1rem;
}

.terminal-bar span {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--red);
}

.terminal-bar span:nth-child(2) {
  background: var(--yellow);
}

.terminal-bar span:nth-child(3) {
  background: var(--green);
}

.terminal-bar p {
  margin: 0 auto;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.72rem;
}

.terminal pre,
.command-block pre {
  margin: 0;
  overflow-x: auto;
}

.terminal pre {
  padding: clamp(1.25rem, 3vw, 2rem);
}

code {
  font-family: var(--mono);
}

.terminal code {
  color: var(--text);
  font-size: clamp(0.76rem, 1.2vw, 0.92rem);
  line-height: 1.75;
}

.prompt {
  color: var(--magenta);
}

.token-key {
  color: var(--blue);
  font-weight: 700;
}

.token-string {
  color: var(--green);
}

.token-number {
  color: var(--yellow);
}

.token-boolean {
  color: var(--magenta);
}

.token-null {
  color: var(--red);
}

.token-label {
  color: var(--cyan);
  font-weight: 800;
}

.signature {
  color: var(--muted);
}

.section {
  padding-block: clamp(5rem, 10vw, 9rem);
  border-top: 1px solid var(--border);
  scroll-margin-top: 70px;
}

.section-heading {
  max-width: 52rem;
  margin-bottom: 3rem;
}

.narrow-heading {
  max-width: 42rem;
}

.capabilities {
  display: grid;
  grid-template-columns: minmax(280px, 0.8fr) minmax(420px, 1.2fr);
  gap: clamp(3rem, 8vw, 8rem);
}

.capability-list article {
  display: grid;
  grid-template-columns: 2.5rem 1fr;
  gap: 1rem;
  border-top: 1px solid var(--border);
  padding: 1.25rem 0;
}

.capability-list article > span,
.usage-number {
  color: var(--magenta);
  font-family: var(--mono);
  font-size: 0.75rem;
}

.capability-list p,
.usage-copy p,
.install-panel p,
.key-list span,
.site-footer p {
  margin-bottom: 0;
  color: var(--muted);
}

.install-tabs {
  display: flex;
  gap: 0.4rem;
  overflow-x: auto;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0;
}

.install-tabs a {
  flex: 0 0 auto;
  min-height: 46px;
  display: inline-flex;
  align-items: center;
  border: 1px solid transparent;
  border-bottom: 0;
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.82rem;
  padding: 0.7rem 1rem;
  text-decoration: none;
}

.install-tabs a[aria-selected="true"] {
  border-color: var(--border);
  background: var(--surface);
  color: var(--cyan);
}

.install-panel {
  display: grid;
  grid-template-columns: minmax(220px, 0.65fr) minmax(0, 1.35fr);
  gap: 3rem;
  border: 1px solid var(--border);
  border-top: 0;
  background: rgba(36, 40, 59, 0.72);
  padding: clamp(1.5rem, 4vw, 3rem);
}

.install-panel + .install-panel {
  margin-top: 1.5rem;
  border-top: 1px solid var(--border);
}

.js .install-panel + .install-panel {
  margin-top: 0;
  border-top: 0;
}

.js [role="tabpanel"][hidden] {
  display: none;
}

.command-block {
  min-width: 0;
  border: 1px solid var(--border);
  background: var(--background-deep);
}

.command-block > p {
  margin: 0;
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  font-family: var(--mono);
  font-size: 0.72rem;
  padding: 0.65rem 1rem;
}

.package-link {
  float: right;
  color: var(--blue);
  font-weight: 700;
  text-underline-offset: 0.2em;
}

.command-block pre {
  padding: 1rem;
}

.command-block code {
  color: var(--green);
  font-size: 0.82rem;
  white-space: pre;
}

.command-actions {
  min-height: 40px;
  display: none;
  align-items: center;
  gap: 0.75rem;
  border-top: 1px solid var(--border);
  padding: 0.35rem 0.5rem;
}

.js .command-actions {
  display: flex;
}

.command-actions button {
  min-width: 64px;
  min-height: 32px;
  border: 1px solid var(--blue);
  background: transparent;
  color: var(--blue);
  cursor: pointer;
  font-family: var(--mono);
  font-size: 0.75rem;
}

.command-actions button:hover {
  background: var(--blue);
  color: var(--background-deep);
}

.copy-feedback {
  color: var(--yellow);
  font-family: var(--mono);
  font-size: 0.72rem;
}

.compact-command {
  max-width: 32rem;
}

.linux-commands {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.archive-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.7rem;
}

.archive-grid span {
  border-left: 2px solid var(--magenta);
  background: var(--background-deep);
  color: var(--text);
  font-family: var(--mono);
  font-size: 0.78rem;
  padding: 0.75rem;
}

.usage-list {
  display: grid;
  gap: 1px;
  background: var(--border);
  border: 1px solid var(--border);
}

.usage-list article {
  display: grid;
  grid-template-columns: 2.5rem minmax(220px, 0.7fr) minmax(0, 1.3fr);
  align-items: center;
  gap: 2rem;
  background: var(--background);
  padding: 2rem;
}

.key-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: clamp(2rem, 7vw, 7rem);
  align-items: start;
}

.key-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.key-list li {
  display: flex;
  justify-content: space-between;
  gap: 2rem;
  border-bottom: 1px solid var(--border);
  padding: 1rem 0;
}

.key-list strong {
  color: var(--blue);
  font-family: var(--mono);
  font-size: 0.85rem;
}

.key-list span {
  text-align: right;
}

.key-command {
  margin-top: 2rem;
}

.release-security {
  display: grid;
  grid-template-columns: 0.8fr 1.2fr;
  gap: clamp(3rem, 8vw, 8rem);
  align-items: center;
}

.security-command code {
  color: var(--text);
}

.site-footer {
  display: flex;
  justify-content: space-between;
  gap: 2rem;
  border-top: 1px solid var(--border);
  padding-block: 3rem;
}

.site-footer nav {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
}

@media (max-width: 900px) {
  .hero {
    min-height: auto;
    grid-template-columns: 1fr;
    padding-block: 4rem;
  }

  .capabilities,
  .release-security {
    grid-template-columns: 1fr;
    gap: 2rem;
  }

  .capabilities .section-heading {
    margin-bottom: 0;
  }

  .usage-list article {
    grid-template-columns: 2rem 1fr;
  }

  .usage-list .command-block {
    grid-column: 2;
  }
}

@media (max-width: 720px) {
  .header-inner,
  .hero,
  .section,
  .site-footer {
    width: min(calc(100% - 1.5rem), var(--content));
  }

  .header-inner {
    grid-template-columns: auto 1fr auto;
    gap: 0.65rem;
  }

  .js .nav-toggle {
    display: inline-block;
    grid-column: 3;
    grid-row: 1;
    justify-self: end;
    padding: 0.45rem 0.65rem;
  }

  .site-nav {
    grid-column: 1 / -1;
    justify-content: flex-start;
    flex-wrap: wrap;
    padding-bottom: 0.85rem;
  }

  .js .site-nav[data-open="false"] {
    display: none;
  }

  .js .site-nav[data-open="true"] {
    display: flex;
  }

  .header-actions {
    grid-column: 2;
    grid-row: 1;
    justify-self: end;
  }

  .header-actions .text-link {
    font-size: 0.78rem;
  }

  .js .header-actions {
    justify-self: start;
  }

  h1 {
    font-size: clamp(3rem, 16vw, 5rem);
  }

  .hero-actions {
    align-items: flex-start;
    flex-direction: column;
  }

  .terminal {
    box-shadow: 8px 8px 0 rgba(122, 162, 247, 0.08);
  }

  .terminal pre {
    overflow-x: auto;
  }

  .install-panel,
  .key-layout {
    grid-template-columns: 1fr;
    gap: 1.5rem;
  }

  .linux-commands,
  .archive-grid {
    grid-template-columns: 1fr;
  }

  .usage-list article {
    grid-template-columns: 1fr;
    gap: 0.75rem;
    padding: 1.25rem;
  }

  .usage-list .command-block {
    grid-column: 1;
  }

  .key-list li {
    align-items: flex-start;
    flex-direction: column;
    gap: 0.3rem;
  }

  .key-list span {
    text-align: left;
  }

  .site-footer {
    flex-direction: column;
  }
}

@media (max-width: 430px) {
  .install-tabs a {
    padding-inline: 0.8rem;
  }
}

@media (prefers-reduced-motion: reduce) {
  html {
    scroll-behavior: auto;
  }

  *,
  *::before,
  *::after {
    scroll-behavior: auto !important;
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
  }
}
```

- [ ] **Step 6: Run the static contract and JavaScript regression tests**

Run: `gofmt -w site_test.go && go test -run '^TestWebsiteContentContract$' && node --test site/script.test.js && node --check site/script.js`

Expected: the Go contract and all four Node tests PASS; syntax checking exits zero without output.

- [ ] **Step 7: Preview from an HTTP origin and inspect response headers/content**

Run:

```bash
python3 -m http.server 4173 --directory site >/tmp/jwtd-site-http.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
curl --fail --silent --show-error http://127.0.0.1:4173/ >/tmp/jwtd-site-index.html
curl --fail --silent --show-error http://127.0.0.1:4173/styles.css >/dev/null
curl --fail --silent --show-error http://127.0.0.1:4173/script.js >/dev/null
kill "$server_pid"
trap - EXIT
```

Expected: all three requests return HTTP 200 and the command exits zero.

- [ ] **Step 8: Commit the static website foundation**

```bash
git add site/CNAME site/favicon.svg site/index.html site/styles.css site_test.go
git commit -m "feat: add project website"
```

### Task 3: Add Least-Privilege GitHub Pages Deployment

**Files:**
- Modify: `site_test.go`
- Create: `.github/workflows/pages.yml`

- [ ] **Step 1: Extend the focused contract with Pages workflow invariants**

Replace `site_test.go` with:

```go
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

	if want := map[string]string{"contents": "read"}; !maps.Equal(workflow.Permissions, want) {
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
```

- [ ] **Step 2: Run the Pages contract and verify the workflow is missing**

Run: `gofmt -w site_test.go && go test -run '^TestWebsitePagesWorkflowContract$'`

Expected: FAIL with `reading website file .github/workflows/pages.yml`.

- [ ] **Step 3: Add the full-SHA-pinned Pages workflow**

Create `.github/workflows/pages.yml`:

```yaml
name: pages

on:
  push:
    branches: [main]
    paths:
      - "site/**"
      - ".github/workflows/pages.yml"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      - uses: actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b # v5.0.0
      - uses: actions/upload-pages-artifact@7b1f4a764d45c48632c6b24a0339c27f5614fb0b # v4.0.0
        with:
          path: site

  deploy:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e # v4.0.5
```

- [ ] **Step 4: Run the focused and complete Go test suites**

Run: `go test -run '^TestWebsite(Content|PagesWorkflow)Contract$' && go test ./...`

Expected: both focused contracts PASS and the full repository test suite exits zero.

- [ ] **Step 5: Commit Pages deployment separately**

```bash
git add .github/workflows/pages.yml site_test.go
git commit -m "ci: deploy website to github pages"
```

### Task 4: Run Website JavaScript Checks in CI

**Files:**
- Modify: `site_test.go`
- Modify: `.github/workflows/test.yml`

- [ ] **Step 1: Add the failing tooling contract to the end of `site_test.go`**

Append this complete test function after `TestWebsitePagesWorkflowContract`:

```go
func TestWebsiteToolingContract(t *testing.T) {
	testWorkflow := readWebsiteFile(t, ".github", "workflows", "test.yml")
	for label, required := range map[string]string{
		"pinned Node setup":        "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
		"Node version":             "node-version: 26.4.0",
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
```

- [ ] **Step 2: Run the tooling contract and verify CI support is absent**

Run: `gofmt -w site_test.go && go test -run '^TestWebsiteToolingContract$'`

Expected: FAIL with missing pinned Node setup, Node version, syntax check, and unit test markers.

- [ ] **Step 3: Add pinned Node and JavaScript checks without changing existing CI steps**

In `.github/workflows/test.yml`, insert these steps immediately after the existing `jdx/mise-action` step and before `Check formatting`; leave every existing line before and after the insertion unchanged:

```yaml
      - uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0
        with:
          node-version: 26.4.0

      - name: Check website JavaScript syntax
        run: node --check site/script.js

      - name: Run website JavaScript tests
        run: node --test site/script.test.js
```

- [ ] **Step 4: Run the tooling contract and JavaScript checks**

Run: `go test -run '^TestWebsiteToolingContract$' && node --test site/script.test.js && node --check site/script.js`

Expected: the Go contract and four Node tests PASS; syntax checking exits zero without output.

- [ ] **Step 5: Commit isolated website CI support**

```bash
git add .github/workflows/test.yml site_test.go
git commit -m "ci: test website javascript"
```

### Task 5: Final Automated and Manual Verification

**Files:**
- Verify only; no new files.

- [ ] **Step 1: Verify formatting and JavaScript in the pinned environment**

Run:

```bash
gofmt -w site_test.go
test -z "$(gofmt -l .)"
node --test site/script.test.js
node --check site/script.js
```

Expected: four Node tests PASS; both formatting and syntax commands exit zero with no output.

- [ ] **Step 2: Verify the complete Go repository**

Run:

```bash
go test ./...
go vet ./...
```

Expected: all Go tests PASS and `go vet` exits zero without diagnostics.

- [ ] **Step 3: Verify patch hygiene**

Run: `git diff --check`

Expected: zero exit with no whitespace errors.

- [ ] **Step 4: Repeat the local HTTP smoke check**

Run:

```bash
python3 -m http.server 4173 --directory site >/tmp/jwtd-site-http.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
for path in / /styles.css /script.js /favicon.svg /CNAME; do
  curl --fail --silent --show-error "http://127.0.0.1:4173$path" >/dev/null
done
kill "$server_pid"
trap - EXIT
```

Expected: every request returns HTTP 200 and the loop exits zero.

- [ ] **Step 5: Complete responsive and visual browser checks against `http://127.0.0.1:4173/`**

Use browser responsive mode at 320x568, 390x844, 768x1024, and 1440x900. Confirm the hero is split only when space allows, the mobile page is a single reading column, no horizontal page overflow occurs, terminal/command samples scroll internally, touch targets remain usable, the sticky header retains the wordmark plus GitHub/install access, and all approved Tokyo Night colors and CLI token mappings are visually present.

Expected: content is readable and controls remain operable at every viewport.

- [ ] **Step 6: Complete progressive-enhancement and OS-selection checks**

In browser developer tools, test macOS, Windows, Linux, and an unknown user agent. Confirm defaults are Homebrew, Scoop, Linux packages, and Homebrew respectively; manually select all five installation tabs after each default; confirm Linux simultaneously exposes `.deb` and `.rpm` plus amd64 and arm64 without guessed distro/architecture.

Disable JavaScript and reload. Confirm every installation panel and command is visible, Homebrew appears first, every header/section anchor works, and no essential content depends on the menu, tabs, or copy controls.

Expected: detection only changes the initial selected panel when JavaScript runs; all alternatives remain reachable and the no-JavaScript document remains complete.

- [ ] **Step 7: Complete keyboard and assistive-state checks**

Navigate from the skip link through the entire page using only Tab, Shift+Tab, Enter, Space where button semantics apply, arrow keys, Home, End, and Escape. Confirm focus is always visible; installation tabs wrap with arrow keys, Home selects the first, End selects the last, and `aria-selected`/`tabindex` track selection; the mobile menu reports `aria-expanded`, closes after choosing a destination, and Escape closes it while returning focus; code scrollers do not trap focus; heading levels and header/nav/main/section/footer landmarks are logical.

Expected: every interactive element is reachable and operable without a pointer, with accurate exposed state.

- [ ] **Step 8: Complete clipboard, motion, CSP, and privacy checks**

Confirm a permitted copy announces `Copied.` inline and clears it after about three seconds. Deny clipboard permission or remove Clipboard API access and confirm the inline message says `Select the command and copy it manually.` without an alert; manually select the command text. Enable reduced motion and confirm anchor navigation has no smooth movement. Inspect the network and console: only `/`, `/styles.css`, `/script.js`, and `/favicon.svg` load, there are no runtime API/font/analytics requests, no CSP violations, no cookies/local storage writes, and no token input UI.

Expected: enhancement failures are non-blocking and the page makes no visitor-data or external runtime requests.

- [ ] **Step 9: Verify the deployment after repository settings and DNS are ready**

Confirm the repository's Pages source is GitHub Actions, set the Pages custom domain to `jwtd.webcodr.io`, enable HTTPS enforcement after the certificate is issued, and confirm the external DNS record maps `jwtd.webcodr.io` to `webcodr.github.io`. Push through normal review, wait for the `pages` workflow, then run:

```bash
curl --fail --silent --show-error https://jwtd.webcodr.io/ >/dev/null
curl --fail --silent --show-error https://jwtd.webcodr.io/styles.css >/dev/null
curl --fail --silent --show-error https://jwtd.webcodr.io/script.js >/dev/null
```

Expected: all requests succeed over HTTPS, the browser reports a valid certificate, the canonical URL is `https://jwtd.webcodr.io/`, and direct anchor URLs load the deployed page.

- [ ] **Step 10: Review the final diff scope**

Run: `git status --short && git log --oneline -4`

Expected: the worktree is clean and the four newest commits are the website enhancement, static page, Pages deployment, and website JavaScript CI commits; no application, release, or packaging files were committed.
