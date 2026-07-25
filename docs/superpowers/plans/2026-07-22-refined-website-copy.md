# Refined Website Copy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the jwtd website's dramatic language with the approved quiet, precise copy without changing layout, behavior, commands, or deployment.

**Architecture:** Add a focused Go content contract that requires the new editorial anchors and rejects retired phrases, then update only text and metadata in `site/index.html`. Existing Go, Node, HTTP, and Chromium checks verify that the copy-only change leaves application behavior and responsive composition intact.

**Tech Stack:** Semantic HTML5, Go repository tests, Node.js built-in test runner, headless Chromium.

---

## File Map

- Modify: `site_test.go` - add the exact copy contract without changing existing website, workflow, or tooling invariants.
- Modify: `site/index.html` - replace metadata, headings, descriptions, actions, and footer copy only.

Do not modify `site/styles.css`, `site/script.js`, commands, links, section IDs, navigation labels, deployment workflows, application source, or release configuration.

### Task 1: Refine the Website Voice

**Files:**
- Modify: `site_test.go:24-95`
- Modify: `site/index.html:6-205`

- [ ] **Step 1: Add the failing copy contract**

Insert this test immediately after `TestWebsiteContentContract` in `site_test.go`:

```go
func TestWebsiteCopyContract(t *testing.T) {
	index := readWebsiteFile(t, "site", "index.html")
	for label, required := range map[string]string{
		"page title":        "jwtd - JWT, JWS, and JWE inspection",
		"metadata summary":  "Decode JWTs, verify JWS signatures, and decrypt JWEs from the terminal.",
		"hero eyebrow":      "A command-line tool for JWT, JWS, and JWE",
		"hero heading":      "Inspect tokens",
		"hero continuation": "from the terminal.",
		"overview heading":  "Focused tools for token inspection.",
		"install heading":   "Install jwtd.",
		"usage heading":     "Common workflows.",
		"keys heading":      "Use the key format you have.",
		"security heading":  "Verifiable releases.",
		"footer copy":       "A focused CLI for JWT, JWS, and JWE inspection.",
	} {
		if !strings.Contains(index, required) {
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
```

- [ ] **Step 2: Run the focused test and verify the old copy fails**

Run: `gofmt -w site_test.go && go test -run '^TestWebsiteCopyContract$'`

Expected: FAIL with missing refined-copy errors and errors for the retired phrases still present in `site/index.html`.

- [ ] **Step 3: Replace metadata and hero copy**

Apply these exact replacements in `site/index.html`:

```diff
-    <meta name="description" content="Decode JWTs, verify JWS signatures, and decrypt JWEs from your terminal with jwtd.">
+    <meta name="description" content="Decode JWTs, verify JWS signatures, and decrypt JWEs from the terminal.">
@@
-    <meta property="og:title" content="jwtd - inspect JSON web tokens from the terminal">
-    <meta property="og:description" content="A focused CLI for decoding JWTs, verifying JWS signatures, and decrypting JWEs.">
+    <meta property="og:title" content="jwtd - JWT, JWS, and JWE inspection">
+    <meta property="og:description" content="Decode JWTs, verify JWS signatures, and decrypt JWEs from the terminal.">
@@
-    <title>jwtd - JWT, JWS, and JWE tools for the terminal</title>
+    <title>jwtd - JWT, JWS, and JWE inspection</title>
@@
-          <p class="eyebrow">JWT / JWS / JWE inspection</p>
-          <h1 id="hero-title">Read the token.<br><span>Trust the evidence.</span></h1>
-          <p class="hero-lede">jwtd decodes JSON web tokens, verifies signatures, and decrypts encrypted payloads without leaving your terminal.</p>
+          <p class="eyebrow">A command-line tool for JWT, JWS, and JWE</p>
+          <h1 id="hero-title">Inspect tokens<br><span>from the terminal.</span></h1>
+          <p class="hero-lede">Decode JWTs, verify signatures, and decrypt JWEs with clear, syntax-highlighted output.</p>
@@
-            <a class="button" href="#install">Choose an install method</a>
-            <a class="text-link" href="#usage">Read the field guide</a>
+            <a class="button" href="#install">Install jwtd</a>
+            <a class="text-link" href="#usage">View usage</a>
```

- [ ] **Step 4: Replace overview and installation copy**

Apply these exact replacements in `site/index.html`:

```diff
-          <p class="eyebrow">01 / capabilities</p>
-          <h2 id="capabilities-title">One command, the full token path.</h2>
-          <p>Inspect first. Add a key only when cryptographic proof or plaintext is needed.</p>
+          <p class="eyebrow">01 / overview</p>
+          <h2 id="capabilities-title">Focused tools for token inspection.</h2>
+          <p>Decode without a key. Add one when you need signature verification or decrypted content.</p>
@@
-          <article><span>01</span><div><h3>Decode JWTs</h3><p>Pretty-print exact JSON values and human-readable token timestamps.</p></div></article>
-          <article><span>02</span><div><h3>Verify JWS</h3><p>Check the cryptographic signature independently from claim expiry.</p></div></article>
-          <article><span>03</span><div><h3>Decrypt JWE</h3><p>Detect compact JWEs and reveal protected content with the supplied key.</p></div></article>
-          <article><span>04</span><div><h3>Follow nesting</h3><p>Recursively inspect JWT-inside-JWE and JWE-inside-JWE payloads.</p></div></article>
-          <article><span>05</span><div><h3>Bring real keys</h3><p>Use PEM, DER, certificates, JWK Sets, encoded material, or raw secrets.</p></div></article>
+          <article><span>01</span><div><h3>Decode JWTs</h3><p>View headers, claims, signatures, and readable timestamps.</p></div></article>
+          <article><span>02</span><div><h3>Verify signatures</h3><p>Check JWS signatures independently from claim validation.</p></div></article>
+          <article><span>03</span><div><h3>Decrypt JWEs</h3><p>Inspect protected headers and decrypt compact JWEs with the appropriate key.</p></div></article>
+          <article><span>04</span><div><h3>Inspect nested tokens</h3><p>Follow JWT and JWE payloads through nested token structures.</p></div></article>
+          <article><span>05</span><div><h3>Use established key formats</h3><p>Load PEM, DER, certificates, JWKs, encoded keys, or raw secrets.</p></div></article>
@@
-          <h2 id="install-title">Put jwtd on your path.</h2>
-          <p>The suggested method follows your operating system when JavaScript is available. Every method remains below when it is not.</p>
+          <h2 id="install-title">Install jwtd.</h2>
+          <p>A suitable method is selected for your operating system. All options remain available.</p>
@@
-          <div><p class="panel-kicker">macOS / Linux</p><h3>Homebrew formula</h3><p>Installs the current release from the webcodr tap.</p></div>
+          <div><p class="panel-kicker">macOS / Linux</p><h3>Homebrew formula</h3><p>Install the current release from the webcodr tap.</p></div>
@@
-          <div><p class="panel-kicker">Windows</p><h3>Scoop bucket</h3><p>Add the bucket once, then install jwtd.</p></div>
+          <div><p class="panel-kicker">Windows</p><h3>Scoop bucket</h3><p>Add the webcodr bucket once, then install jwtd.</p></div>
@@
-          <div><p class="panel-kicker">Linux / choose package and architecture</p><h3>Native packages</h3><p>Download the matching release asset. Distro and CPU architecture are intentionally not guessed.</p></div>
+          <div><p class="panel-kicker">Linux / package and architecture required</p><h3>Native packages</h3><p>Choose the package format and architecture for your system.</p></div>
@@
-          <a class="text-link" href="https://github.com/webcodr/jwtd/releases">Browse all Linux package assets</a>
+          <a class="text-link" href="https://github.com/webcodr/jwtd/releases">View all Linux packages</a>
@@
-          <div><p class="panel-kicker">Go 1.26+</p><h3>Install from source</h3><p>Build the latest tagged version with your Go toolchain.</p></div>
+          <div><p class="panel-kicker">Go 1.26+</p><h3>Install from source</h3><p>Build the latest tagged release with your Go toolchain.</p></div>
@@
-          <div><p class="panel-kicker">Linux / macOS / Windows</p><h3>Release archives</h3><p>Choose amd64 or arm64 for your platform, verify it, and place the binary on your path.</p></div>
+          <div><p class="panel-kicker">Linux / macOS / Windows</p><h3>Release archives</h3><p>Choose the platform and architecture, verify the archive, and place the binary on your path.</p></div>
@@
-          <a class="button button-small" href="https://github.com/webcodr/jwtd/releases">Browse release archives</a>
+          <a class="button button-small" href="https://github.com/webcodr/jwtd/releases">View release archives</a>
```

- [ ] **Step 5: Replace usage, key, security, and footer copy**

Apply these exact replacements in `site/index.html`:

```diff
-          <h2 id="usage-title">From readable to verified.</h2>
-          <p>Tokens can arrive as an argument, through stdin, or at the interactive prompt.</p>
+          <h2 id="usage-title">Common workflows.</h2>
+          <p>Pass a token as an argument, pipe it through stdin, or use the interactive prompt.</p>
@@
-          <article><div class="usage-number">01</div><div class="usage-copy"><h3>Decode a JWT</h3><p>Inspect the header, claims, and signature without requiring a key.</p></div><div class="command-block"><pre><code id="decode-command">jwtd eyJhbGciOiJIUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="decode-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
+          <article><div class="usage-number">01</div><div class="usage-copy"><h3>Decode a JWT</h3><p>View the header, claims, and signature without a key.</p></div><div class="command-block"><pre><code id="decode-command">jwtd eyJhbGciOiJIUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="decode-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
@@
-          <article><div class="usage-number">02</div><div class="usage-copy"><h3>Verify a JWS signature</h3><p>A failed signature prints INVALID and exits nonzero. Claim expiry is not part of this cryptographic check.</p></div><div class="command-block"><pre><code id="verify-command">jwtd --key /path/to/public-key.pem eyJhbGciOiJSUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="verify-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
+          <article><div class="usage-number">02</div><div class="usage-copy"><h3>Verify a JWS signature</h3><p>Verify the cryptographic signature without evaluating claims such as expiry. Invalid signatures exit nonzero.</p></div><div class="command-block"><pre><code id="verify-command">jwtd --key /path/to/public-key.pem eyJhbGciOiJSUzI1NiIs...</code></pre><div class="command-actions"><button type="button" data-copy-target="verify-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
@@
-          <article><div class="usage-number">03</div><div class="usage-copy"><h3>Decrypt a JWE</h3><p>Five-part compact tokens are detected automatically; provide the private key to reveal the payload.</p></div><div class="command-block"><pre><code id="decrypt-command">jwtd --key /path/to/private-key.pem eyJhbGciOiJSU0EtT0FF...</code></pre><div class="command-actions"><button type="button" data-copy-target="decrypt-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
+          <article><div class="usage-number">03</div><div class="usage-copy"><h3>Decrypt a JWE</h3><p>Compact JWEs are detected automatically. Provide a private key to decrypt the payload.</p></div><div class="command-block"><pre><code id="decrypt-command">jwtd --key /path/to/private-key.pem eyJhbGciOiJSU0EtT0FF...</code></pre><div class="command-actions"><button type="button" data-copy-target="decrypt-command">Copy</button><span class="copy-feedback" data-copy-feedback aria-live="polite"></span></div></div></article>
@@
-          <h2 id="key-formats-title">Use the key material you already have.</h2>
-          <p>The <code>--key</code> flag and <code>JWTD_KEY</code> environment variable share the same format detection path.</p>
+          <h2 id="key-formats-title">Use the key format you have.</h2>
+          <p>The <code>--key</code> flag and <code>JWTD_KEY</code> environment variable use the same format detection.</p>
@@
-          <h2 id="release-security-title">Verify before execution.</h2>
-          <p>Every archive and Linux package is covered by <code>checksums.txt</code>. The checksum file carries a keyless Cosign bundle tied to this repository's release workflow, and every archive ships with a Syft SPDX SBOM.</p>
-          <a class="text-link" href="https://github.com/webcodr/jwtd#installation">Read the exhaustive verification instructions</a>
+          <h2 id="release-security-title">Verifiable releases.</h2>
+          <p>Release archives and Linux packages are listed in <code>checksums.txt</code>, which is signed with a keyless Cosign bundle. Each archive also includes a Syft SPDX SBOM.</p>
+          <a class="text-link" href="https://github.com/webcodr/jwtd#installation">View verification instructions</a>
@@
-          <p>Verify the signed checksum file</p>
+          <p>Verify checksums.txt</p>
@@
-      <div><a class="wordmark" href="#top">jwtd<span aria-hidden="true">_</span></a><p>Token inspection for people who live in terminals.</p></div>
+      <div><a class="wordmark" href="#top">jwtd<span aria-hidden="true">_</span></a><p>A focused CLI for JWT, JWS, and JWE inspection.</p></div>
```

- [ ] **Step 6: Run focused and complete automated verification**

Run:

```bash
gofmt -w site_test.go
go test -run '^TestWebsite(Content|Copy)Contract$'
go test ./...
go vet ./...
node --test site/script.test.js
node --check site/script.js
git diff --check
```

Expected: both focused website contracts and the complete Go suite PASS; four Node tests PASS; vet, JavaScript syntax, and whitespace checks exit zero without diagnostics.

- [ ] **Step 7: Verify the copy through a local HTTP origin**

Run:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory site >/tmp/jwtd-copy-http.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
sleep 1
curl --fail --silent --show-error http://127.0.0.1:4173/ | rg -F "Inspect tokens" >/dev/null
curl --fail --silent --show-error http://127.0.0.1:4173/ | rg -F "Verifiable releases." >/dev/null
kill "$server_pid"
trap - EXIT
```

Expected: both copy checks receive HTTP 200 content and the command exits zero.

- [ ] **Step 8: Verify desktop and mobile composition in Chromium**

Run:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory site >/tmp/jwtd-copy-http.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
sleep 1
chromium --headless --no-sandbox --disable-gpu --hide-scrollbars --window-size=1440,900 --screenshot=/tmp/opencode/jwtd-copy-desktop.png http://127.0.0.1:4173/
chromium --headless --no-sandbox --disable-gpu --hide-scrollbars --window-size=390,844 --screenshot=/tmp/opencode/jwtd-copy-mobile.png http://127.0.0.1:4173/
chromium --headless --no-sandbox --disable-gpu --hide-scrollbars --window-size=320,568 --screenshot=/tmp/opencode/jwtd-copy-320.png http://127.0.0.1:4173/
kill "$server_pid"
trap - EXIT
```

Inspect all three screenshots. Confirm the revised hero retains its intended line break, no heading or action overflows, command panels remain unchanged, and the page has no horizontal overflow.

Expected: the copy is calm and readable at all three widths with no visual regression.

- [ ] **Step 9: Commit the copy refinement**

```bash
git add site/index.html site_test.go
git commit -m "refactor: refine website copy"
```
