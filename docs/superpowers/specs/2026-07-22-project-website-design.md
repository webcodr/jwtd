# jwtd Project Website Design

## Summary

Create a small, single-page project website for jwtd at
`https://jwtd.webcodr.io/`. The site will help visitors install jwtd quickly and
provide concise documentation for its core JWT, JWS, and JWE workflows.

The site will be a hand-built static page with a terminal-editorial visual style
based on the Tokyo Night color palette. It will be deployed from this repository
to GitHub Pages and use `jwtd.webcodr.io` as its custom domain.

## Goals

- Explain what jwtd does and why a developer would use it.
- Select a suitable installation method based on the visitor's operating system.
- Document the main decode, signature verification, and decryption workflows.
- Summarize supported key formats and release security features.
- Load quickly and work on desktop and mobile without a build-time toolchain.
- Remain useful when JavaScript, clipboard access, or OS detection is unavailable.

## Non-Goals

- Do not decode, verify, decrypt, or accept tokens in the browser.
- Do not replace the README as the exhaustive project reference.
- Do not add analytics, cookies, forms, accounts, or other data collection.
- Do not add a package manager, frontend framework, or static-site generator.
- Do not query the GitHub API at runtime or depend on external runtime assets.

## Architecture

The website will live in a dedicated `site/` directory:

- `site/index.html` contains the complete page content and semantic structure.
- `site/styles.css` contains the responsive Tokyo Night presentation.
- `site/script.js` contains progressive enhancements for installation selection,
  command copying, and mobile navigation.
- `site/CNAME` contains exactly `jwtd.webcodr.io`.

The page will use root-relative asset paths because it is served from the root of
the custom subdomain. Local preview will use a static HTTP server rather than
opening `index.html` directly.

A GitHub Actions workflow will upload `site/` as a GitHub Pages artifact and
deploy it through the official Pages actions. The workflow will use the minimum
required permissions and a deployment concurrency group. DNS configuration is
external to this repository: `jwtd.webcodr.io` must be a CNAME for
`webcodr.github.io`.

## Page Structure

The page is a single document with anchor navigation and these sections:

1. **Header:** jwtd wordmark, section links, GitHub link, and install action.
2. **Hero:** concise value proposition, primary install command, and a realistic
   terminal session showing colorized decoded JWT output.
3. **Capabilities:** a compact summary of JWT decoding, JWS verification, JWE
   decryption, nested token support, and key format support.
4. **Installation:** operating-system-aware tabs for Homebrew, Scoop, Linux
   packages, Go installation, and release archives.
5. **Usage:** examples that progress from decoding a token to verifying a JWS
   signature and decrypting a JWE.
6. **Key formats:** PEM, DER, X.509, JWK/JWK Sets, base64 input, and explicit raw
   symmetric secrets.
7. **Release security:** checksums, keyless Cosign verification, and per-archive
   SBOM availability, with a link to the exhaustive README instructions.
8. **Footer:** repository, releases, MIT license, and Go project links.

Website copy is curated independently from the README. It should stay concise
and link to the repository when exhaustive detail would interrupt the page.

## Visual Design

The visual language is a polished terminal manual rather than a generic product
landing page. The foundation is the Tokyo Night palette:

| Role | Color |
| --- | --- |
| Main background | `#1a1b26` |
| Raised terminal surface | `#24283b` |
| Primary text | `#c0caf5` |
| Muted text | `#565f89` |
| Blue / JSON keys | `#7aa2f7` |
| Cyan / section labels | `#7dcfff` |
| Green / strings and success | `#9ece6a` |
| Yellow / numbers | `#e0af68` |
| Magenta / booleans | `#bb9af7` |
| Red / null and errors | `#f7768e` |

The page will use system sans-serif and monospace stacks, avoiding external font
requests. Subtle grids, borders, and blue-to-purple accents may add depth, but
decoration must not overpower documentation. Terminal examples will mirror
jwtd's CLI syntax-color roles.

The desktop hero uses a split composition with editorial copy on the left and a
terminal example on the right. Content sections vary between reading columns,
command panels, and compact capability rows to avoid a repetitive card grid.

On mobile, the layout becomes a single reading column. Terminal examples scroll
horizontally, controls retain touch-friendly targets, and the sticky header is
reduced to the project name plus install and GitHub access.

## Interaction Design

All content is present in the HTML. JavaScript enhances, but does not create,
essential content.

### Installation Selection

On initial load, the script chooses an installation tab using
`navigator.userAgentData.platform` when available, followed by
`navigator.platform` and `navigator.userAgent` as compatibility fallbacks:

- macOS selects Homebrew.
- Windows selects Scoop.
- Linux selects Linux packages.
- Unknown platforms retain Homebrew as the HTML default.

The result is neither stored nor transmitted. Visitors can always select another
tab. The Linux panel presents `.deb` and `.rpm` instructions equally because a
browser cannot reliably identify the distribution. It also presents amd64 and
arm64 choices rather than guessing CPU architecture.

Tabs will follow accessible tab semantics and support keyboard operation. With
JavaScript disabled, Homebrew remains visible and all other commands remain
available in the document as ordinary content.

### Command Copying

Copy buttons use the Clipboard API. Success is announced inline for a short
period. Failure produces a concise instruction to select and copy the command
manually; it never uses a blocking alert. Commands remain selectable at all
times.

### Navigation

Anchor navigation works without JavaScript. JavaScript only controls the compact
mobile menu and closes it after a destination is selected. Motion is restrained
and disabled under `prefers-reduced-motion`.

## Reliability And Security

- The page performs no runtime network requests and processes no visitor data.
- OS detection failure is ignored and leaves the Homebrew fallback selected.
- Clipboard failure does not block access to installation commands.
- Local static assets avoid third-party availability and privacy risks.
- A restrictive Content Security Policy will permit only the local resources
  required by the page.
- GitHub and release links will be ordinary links rather than API-derived data.

## Accessibility And Metadata

- Use semantic header, navigation, main, section, and footer landmarks.
- Maintain a logical heading hierarchy and a useful skip link.
- Provide visible keyboard focus and sufficient Tokyo Night color contrast.
- Label all controls and expose tab state to assistive technologies.
- Keep horizontally scrolling code samples from trapping keyboard focus.
- Respect reduced-motion preferences.
- Set the canonical URL to `https://jwtd.webcodr.io/`.
- Include a concise search description, Open Graph metadata, favicon treatment,
  and matching browser theme color.

## Verification

Automated verification will include:

- `go test ./...` to ensure the existing application remains unaffected.
- A lightweight repository test covering the exact CNAME, canonical URL, core
  sections, and local asset references.
- JavaScript syntax checking with Node where Node is available.

Manual browser verification will cover:

- Desktop and mobile layouts.
- macOS, Windows, Linux, and unknown-platform installation defaults.
- Manual switching among every installation method.
- Copy success and clipboard-denied behavior.
- Anchor and mobile navigation.
- Keyboard-only operation and visible focus.
- Reduced-motion and no-JavaScript behavior.
- Direct loading from `https://jwtd.webcodr.io/` after deployment.

## Success Criteria

- A visitor can identify jwtd's purpose and reach an appropriate installation
  command from the initial viewport.
- The site defaults to Homebrew on macOS, Scoop on Windows, and Linux packages on
  Linux without hiding alternative methods.
- The page clearly documents decode, verify, and decrypt commands.
- The page remains readable and navigable on common mobile and desktop widths.
- The custom domain resolves to the deployed GitHub Pages site with HTTPS.
- The website requires no frontend dependency installation or build step.
