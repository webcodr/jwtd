# Refined Website Copy Design

## Summary

Refine the jwtd website's voice from dramatic, promotional language to quiet,
precise technical language. Preserve the existing Tokyo Night design, oversized
hero typography, page structure, commands, interactions, and deployment.

## Goals

- Make the first impression more understated and polished.
- Describe capabilities directly without slogans or heightened language.
- Keep terminology technically accurate and consistent with the README.
- Preserve concise installation and usage guidance.

## Non-Goals

- Do not change typography, spacing, colors, layout, or responsive behavior.
- Do not change commands, links, OS detection, tabs, copying, or navigation.
- Do not add or remove sections.
- Do not rewrite detailed security claims beyond making them more concise.

## Voice

The revised voice is calm, factual, and concise. Headings name the subject of a
section instead of making a claim. Supporting paragraphs explain behavior in
plain technical language. Calls to action state the destination or action.

Avoid dramatic or branded phrases such as:

- "Trust the evidence."
- "the full token path"
- "Read the field guide"
- "Bring real keys"
- "Verify before execution"
- "people who live in terminals"

## Exact Copy

### Metadata

- Page title: `jwtd - JWT, JWS, and JWE inspection`
- Open Graph title: `jwtd - JWT, JWS, and JWE inspection`
- Search description and Open Graph description:
  `Decode JWTs, verify JWS signatures, and decrypt JWEs from the terminal.`

### Hero

- Eyebrow: `A command-line tool for JWT, JWS, and JWE`
- Heading: `Inspect tokens from the terminal.`
  - Keep the current line break before `from the terminal.` and retain the
    existing accent span around that phrase.
- Description:
  `Decode JWTs, verify signatures, and decrypt JWEs with clear, syntax-highlighted output.`
- Primary action: `Install jwtd`
- Secondary action: `View usage`
- Terminal title: `jwtd - token inspection`

### Overview

- Eyebrow: `01 / overview`
- Heading: `Focused tools for token inspection.`
- Introduction:
  `Decode without a key. Add one when you need signature verification or decrypted content.`
- Capability 1: `Decode JWTs`
  - `View headers, claims, signatures, and readable timestamps.`
- Capability 2: `Verify signatures`
  - `Check JWS signatures independently from claim validation.`
- Capability 3: `Decrypt JWEs`
  - `Inspect protected headers and decrypt compact JWEs with the appropriate key.`
- Capability 4: `Inspect nested tokens`
  - `Follow JWT and JWE payloads through nested token structures.`
- Capability 5: `Use established key formats`
  - `Load PEM, DER, certificates, JWKs, encoded keys, or raw secrets.`

The existing `capabilities` section ID and navigation label remain unchanged to
avoid unrelated navigation changes.

### Installation

- Heading: `Install jwtd.`
- Introduction:
  `A suitable method is selected for your operating system. All options remain available.`
- Homebrew description: `Install the current release from the webcodr tap.`
- Scoop description: `Add the webcodr bucket once, then install jwtd.`
- Linux kicker: `Linux / package and architecture required`
- Linux description: `Choose the package format and architecture for your system.`
- Linux releases link: `View all Linux packages`
- Go description: `Build the latest tagged release with your Go toolchain.`
- Archives description:
  `Choose the platform and architecture, verify the archive, and place the binary on your path.`
- Archives link: `View release archives`

### Usage

- Heading: `Common workflows.`
- Introduction:
  `Pass a token as an argument, pipe it through stdin, or use the interactive prompt.`
- Decode description: `View the header, claims, and signature without a key.`
- Verify description:
  `Verify the cryptographic signature without evaluating claims such as expiry. Invalid signatures exit nonzero.`
- Decrypt description:
  `Compact JWEs are detected automatically. Provide a private key to decrypt the payload.`

### Key Formats

- Heading: `Use the key format you have.`
- Introduction:
  `The --key flag and JWTD_KEY environment variable use the same format detection.`
- Preserve the existing key format labels and concise format details.
- Preserve the `Explicit HMAC secret` example label and command.

### Release Security

- Heading: `Verifiable releases.`
- Introduction:
  `Release archives and Linux packages are listed in checksums.txt, which is signed with a keyless Cosign bundle. Each archive also includes a Syft SPDX SBOM.`
- Documentation link: `View verification instructions`
- Command label: `Verify checksums.txt`
- Preserve the complete Cosign command unchanged.

### Footer

- Description: `A focused CLI for JWT, JWS, and JWE inspection.`
- Preserve all project links.

## Verification

- Extend the website content contract to require the revised hero and section
  headings.
- Assert that the retired dramatic phrases are absent.
- Run `gofmt`, `go test ./...`, `go vet ./...`, the Node test suite, and the
  JavaScript syntax check.
- Run the existing local HTTP and Chromium responsive checks to confirm that
  copy length changes do not cause overflow or broken composition.

## Success Criteria

- The entire page uses a quiet, precise technical voice.
- No dramatic phrases listed in this design remain on the page.
- All technical claims, commands, links, interactions, and security guidance
  retain their meaning.
- The existing desktop and mobile layouts remain unchanged and free of overflow.
