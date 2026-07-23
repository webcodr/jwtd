# Website improvement suggestions

Review of `site/` (single-page static site deployed via GitHub Pages). The site is
in good shape overall: strict CSP, skip link, reduced-motion support,
keyboard-navigable tabs, OS-aware install tab selection, and test coverage of the
content contract in `site_test.go`. Suggestions below are ordered by impact.

## Functional issues worth fixing

> Status: items 1–5 are implemented (script.js hash handling + OS-aware hero
> command, combined curl/install snippets in the Linux panel, tabpanel
> `tabindex`, outside-click close for the mobile nav).

### 1. Install tabs ignore the URL hash

`site/script.js`

The tabs are real anchors (`#install-scoop`, etc.), but on load `selectTab()`
always uses OS detection — opening `/#install-scoop` gets overridden. The click
handler also calls `preventDefault()` without updating `location.hash`, so users
cannot copy or share a link to a specific install method.

**Fix:** honor `location.hash` on load (validate against known methods), and use
`history.replaceState` (or let the default anchor behavior run) on tab click.
*Implemented, including a `hashchange` listener.*

### 2. Hero install command is hardcoded to Homebrew

`site/index.html`

The tab selection adapts to the visitor's OS, but the hero's copyable command
always shows `brew install webcodr/tap/jwtd`. A Windows user sees a command that
does not work for them as the very first call to action.

**Fix:** sync the hero command with the existing `detectOperatingSystem()` result
(scoop for Windows, a Linux package command for Linux, Homebrew otherwise).
*Implemented via `heroCommandForOperatingSystem()`: Windows gets the scoop
bucket+install pair, Linux the amd64 .deb curl+dpkg one-liner, macOS/unknown
Homebrew.*

### 3. Linux package install snippets have a gap

`site/index.html`, `install-linux` panel

The commands are `sudo dpkg -i jwtd-linux-amd64.deb`, but nothing downloads the
file first — the download link is a separate element. A combined snippet such as
`curl -fLO <url> && sudo dpkg -i jwtd-linux-amd64.deb` is copy-paste-runnable in
one shot. (Note: `dpkg -i` cannot read from stdin, so a two-command form is
required.) *Implemented for all four .deb/.rpm blocks; the direct download links
remain.*

## Accessibility

### 4. Tab panels lack `tabindex="0"`

`site/script.js`

The WAI-ARIA tabs pattern recommends `tabindex="0"` on tabpanels so keyboard
users can tab into panel content. The script already sets the other ARIA wiring
(`role`, `aria-controls`, `aria-labelledby`); this is one more line in the same
loop. *Implemented via `panel.tabIndex = 0`.*

### 5. Mobile nav does not close on outside click

`site/script.js`

Only Escape, a link click, or the toggle itself closes the mobile navigation. A
click-outside listener would match user expectations. *Implemented.*

## SEO / social

### 6. No `og:image` / Twitter card meta

`site/index.html`

Shares on Slack/Discord/X render with no preview. Add a static `og.png`
(1200×630, terminal mockup plus wordmark) and `twitter:card` meta. The CSP is
unaffected — social crawlers fetch the image server-side, and `img-src 'self'`
already permits same-origin images.

### 7. No JSON-LD `SoftwareApplication` structured data

A small `<script type="application/ld+json">` block (name, description,
repository URL, license, operating systems) improves search rich results. Note:
the CSP `script-src 'self'` blocks inline scripts, so the JSON-LD must either be
served from an external file or the CSP extended with a `'sha256-…'` hash (hashes
do work for inline blocks in a meta-delivered CSP).

### 8. Add `robots.txt` and `sitemap.xml`

Trivial for a one-pager, but completes the picture. Both are plain files that fit
the existing `site/` → Pages artifact workflow.

## Content / polish

### 9. Show the current release version

There is no version anywhere on the page. Options that respect
`connect-src 'none'`: bake it in at deploy time in `.github/workflows/pages.yml`
(a small step querying the GitHub API and substituting into the HTML), or link
"Latest release" without a number.

### 10. FAQ as `<details>` / `<summary>`

Progressive enhancement with zero JavaScript: the three FAQ entries would
collapse into a native accordion.

### 11. Favicon fallback

Only an SVG favicon is provided; older browsers and some tools expect
`/favicon.ico`. Adding a PNG or ICO fallback costs one file.

### 12. Optional light theme

`:root { color-scheme: dark }` is hardcoded. The Tokyo Night palette is
deliberate branding, so this may be intentional, but a
`prefers-color-scheme: light` variant would help users with light-mode OS
settings.

## Bigger swings (optional)

### 13. In-browser demo playground

A paste-a-token decoder in pure JavaScript would be fully local — consistent with
the "your tokens never leave your machine" message — and is the single most
engaging addition possible. It conflicts with the "install first" funnel and
grows the JS surface and test burden, so only pursue it if the site should be a
tool rather than just a landing page.

### 14. Animated terminal in the hero

The static mockup is accurate; a subtle looping typing animation would add life.
Must respect the existing `prefers-reduced-motion` handling.

## Security note

The CSP meta tag cannot express `frame-ancestors 'none'` — it is ignored inside
`<meta>` and GitHub Pages does not allow custom response headers. Worth a comment
in the HTML so nobody assumes clickjacking protection is in place.

## Suggested quick wins

Items 1–5 are done. Item 6 remains a small, high-value change that fits the
existing architecture and test setup (`site_test.go` contract tests,
`node --test site/script.test.js` for the script).
