# Incremental GoReleaser Migration Plan

**Goal:** Introduce GoReleaser as jwtd's build, cross-compilation, archive, and
checksum engine without handing it GitHub release publication or Homebrew tap
publication.

**Approach:** Migrate in two independently reviewable phases. First, add and
continuously validate a pinned GoReleaser configuration while the current
release workflow remains unchanged. Second, replace only the release workflow's
build matrix and hand-written archive commands with a non-publishing GoReleaser
run. Keep the existing version validation, tested-SHA tag proof, draft release
reconciliation, byte-for-byte asset verification, semantic latest-release
handling, and `Formula/jwtd.rb` publication flow.

**Tooling:** Go 1.26.1, GoReleaser 2.17.0 managed by mise, GitHub Actions, Bash,
`jq`, and the existing Go/YAML workflow tests.

**Do not commit unless the user explicitly requests it.**

---

## Scope and invariants

The migration must preserve these externally visible properties:

- Release invocation remains a manual `workflow_dispatch` with a SemVer version
  lacking a leading `v`.
- Releases can only be dispatched from `main`.
- Every release artifact comes from the tested `GITHUB_SHA`.
- Existing archive names remain unchanged:
  - `jwtd-linux-amd64.tar.gz`
  - `jwtd-linux-arm64.tar.gz`
  - `jwtd-darwin-amd64.tar.gz`
  - `jwtd-darwin-arm64.tar.gz`
  - `jwtd-windows-amd64.tar.gz`
  - `jwtd-windows-arm64.tar.gz`
- Each archive remains binary-only, with `jwtd` or `jwtd.exe` at its root.
- `main.version` continues to receive the validated version without the leading
  `v`.
- Releases continue to be created as drafts, verified after upload, and then
  published.
- Published releases built after this migration remain immutable and must
  byte-match rerun artifacts. Pre-migration releases (v1.0.0 through v3.0.0)
  were archived with GNU tar/gzip; GoReleaser's Go-native archiver will not
  reproduce those bytes, so re-dispatching the workflow for a pre-migration
  version will fail the existing `cmp` verification. This is intentional
  fail-closed behavior — the rerun fails without modifying the published
  release — not a preserved byte-match.
- Prereleases do not update Homebrew, and older stable releases do not become
  GitHub's latest release.
- `Formula/jwtd.rb` and the `webcodr/homebrew-tap` push logic remain the
  Homebrew implementation.

The only intentional release-asset change is a new `checksums.txt` file
containing SHA-256 hashes for all six archives.

GoReleaser must not publish anything during this migration. Enforce that twice:

1. `.goreleaser.yaml` sets `release.disable: true`.
2. CI invokes `goreleaser release` with `--skip=publish` for real release
   builds.

Do not add `homebrew_casks`, deprecated `brews`, signing, SBOM, package-manager,
or announcement configuration in this migration.

---

## File map

- Create: `.goreleaser.yaml` — pinned v2 configuration for the six builds,
  deterministic binary-only archives, and checksums.
- Modify: `.mise.toml` — install the exact GoReleaser version used locally and
  in CI.
- Modify: `.gitignore` — ignore GoReleaser's `dist/` output.
- Modify: `workflow_test.go` — executable configuration and workflow security
  invariants.
- Modify: `.github/workflows/test.yml` — validate the config and produce/inspect
  a non-publishing snapshot on pull requests and `main`.
- Modify: `.github/workflows/release.yml` — replace only the build matrix with
  GoReleaser packaging; retain release reconciliation and Homebrew jobs.
- Modify: `README.md` — document local snapshot validation.
- Modify: `AGENTS.md` — document GoReleaser's limited role and release
  verification commands.
- Leave unchanged: `Formula/jwtd.rb` — current Homebrew template remains
  authoritative.

---

## Phase 1: Add GoReleaser without changing releases

### Task 1: Add failing GoReleaser configuration invariants

**Files:**

- Modify: `workflow_test.go`
- Future target: `.goreleaser.yaml`

- [ ] Add a `goReleaserConfig` test model for the subset of `.goreleaser.yaml`
      that jwtd relies on: schema version, project name, build matrix, flags,
      ldflags, modification timestamp, archives, archive metadata, checksums,
      changelog disabling, and release disabling.
- [ ] Add `TestGoReleaserConfigurationInvariants` that reads and parses
      `.goreleaser.yaml` with `gopkg.in/yaml.v3`.
- [ ] Require exactly one build with:
  - ID and binary `jwtd`
  - main package `.`
  - `CGO_ENABLED=0`
  - only `linux`, `darwin`, and `windows`
  - only `amd64` and `arm64`
  - `-trimpath`
  - `-s -w -X main.version={{ .Version }}`
  - `mod_timestamp: "{{ .CommitTimestamp }}"`
- [ ] Require exactly one `tar.gz` archive definition with the name template
      `jwtd-{{ .Os }}-{{ .Arch }}` and a non-matching file glob so
      README/LICENSE files are not added implicitly.
- [ ] Require deterministic archive metadata: root ownership and a fixed RFC3339
      epoch mtime.
- [ ] Require one SHA-256 checksum file named `checksums.txt`.
- [ ] Require `changelog.disable: true` and `release.disable: true`; these are
      defense-in-depth assertions that GoReleaser is not the publisher.
- [ ] Run `go test ./... -run TestGoReleaserConfigurationInvariants -count=1`.

Expected: FAIL because `.goreleaser.yaml` does not exist yet.

### Task 2: Add the pinned configuration and local tooling

**Files:**

- Create: `.goreleaser.yaml`
- Modify: `.mise.toml`
- Modify: `.gitignore`

- [ ] Add GoReleaser `2.17.0` to `.mise.toml` alongside Go `1.26.1`; do not use
      `latest` or a version range.
- [ ] Add `dist/` to `.gitignore`.
- [ ] Create `.goreleaser.yaml` with this intended shape:

```yaml
version: 2
project_name: jwtd

builds:
  - id: jwtd
    main: .
    binary: jwtd
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    flags:
      - -trimpath
    ldflags:
      - -s -w -X main.version={{ .Version }}
    mod_timestamp: "{{ .CommitTimestamp }}"

archives:
  - id: jwtd
    ids:
      - jwtd
    formats:
      - tar.gz
    name_template: "jwtd-{{ .Os }}-{{ .Arch }}"
    files:
      - none*
    builds_info:
      owner: root
      group: root
      mtime: "1970-01-01T00:00:00Z"

checksum:
  name_template: checksums.txt
  algorithm: sha256

changelog:
  disable: true

release:
  disable: true
```

- [ ] Run `mise install`.
- [ ] Run `goreleaser check`.
- [ ] Run the previously failing Go configuration test.
- [ ] Run `goreleaser release --snapshot --clean`.
- [ ] Inspect `dist/artifacts.json` rather than relying on GoReleaser's internal
      per-target binary directories.
- [ ] Assert that `dist/artifacts.json` reports exactly six `Archive` artifacts
      with the established names and one `Checksum` artifact named
      `checksums.txt`.
- [ ] For each archive, run `tar -tzf` and assert its only entry is `jwtd`
      (`jwtd.exe` for Windows).
- [ ] Run `cd dist && sha256sum --check checksums.txt`; require all six archives
      to pass.

Expected: all checks pass. If GoReleaser emits any extra archive suffix such as
`_v1`, correct the archive name template/configuration rather than renaming
files after generation.

### Task 3: Validate GoReleaser snapshots in normal CI

**Files:**

- Modify: `.github/workflows/test.yml`

- [ ] Pin `actions/checkout` and `jdx/mise-action` to full commit SHAs, reusing
      the exact SHAs already pinned in `.github/workflows/release.yml`
      (checkout v7.0.0, mise-action v4.2.1) rather than introducing a second
      pinned version to maintain.
- [ ] Check out with `fetch-depth: 0`. GoReleaser's version discovery needs
      repository history and tags; the default shallow, tag-less checkout
      either fails outright or computes a wrong snapshot version.
- [ ] Keep the existing formatting, vet, and Go test steps.
- [ ] Add `goreleaser check` after mise setup.
- [ ] Add `goreleaser release --snapshot --clean` after the Go tests. Snapshot
      mode must not receive any publication token.
- [ ] Add an artifact-contract verification step that parses
      `dist/artifacts.json` with `jq`, compares the sorted `Archive` names to
      the exact six-name allowlist, requires exactly one `Checksum` named
      `checksums.txt`, verifies archive contents, and runs `sha256sum --check`.
- [ ] Do not upload snapshot artifacts; their purpose is configuration and
      cross-build validation.
- [ ] Run `actionlint .github/workflows/test.yml` when available.
- [ ] Push Phase 1 as its own reviewable change before modifying release
      production behavior.

**Phase 1 acceptance criterion:** pull requests prove that GoReleaser can
reproduce the current platform/archive contract, while
`.github/workflows/release.yml` and Homebrew publishing are still untouched.

---

## Phase 2: Use GoReleaser for release packaging only

### Task 4: Add failing release-workflow migration invariants

**Files:**

- Modify: `workflow_test.go`
- Future target: `.github/workflows/release.yml`

- [ ] Extend the parsed workflow test model as needed to inspect job
      permissions, environment, steps, and artifact paths.
- [ ] Add assertions that the release workflow has one non-matrix build job
      which:
  - depends on `validate`
  - checks out full history
  - installs the mise-pinned tools
  - establishes a local `v$VERSION` tag at `GITHUB_SHA` only for GoReleaser's
    version discovery
  - sets `GORELEASER_CURRENT_TAG` to `v$VERSION` on the GoReleaser step
  - runs exactly `goreleaser release --clean --skip=publish`
  - does not expose a write-capable token to GoReleaser
  - uploads the six archives plus `checksums.txt`
- [ ] Remove the `matrix.` exemption from the run-script interpolation
      assertion in `TestReleaseWorkflowSecurityInvariants`; with the matrix
      gone it is dead code that loosens the invariant, and no `${{ }}`
      expression should remain in any run script.
- [ ] Require `.goreleaser.yaml` to keep `release.disable: true`.
- [ ] Require the release job's fixed `expected_assets` list to contain exactly
      the six existing archives plus `checksums.txt`.
- [ ] Preserve the existing assertions for full-SHA action pins, root
      `contents: read`, safe workflow-input handling, and every downstream job
      depending on validation.
- [ ] Add a negative assertion that the release workflow no longer contains the
      hand-written cross-build `go build`, `tar`, or matrix packaging commands.
- [ ] Keep positive assertions for remote tag creation at `GITHUB_SHA`, forced
      tag fetch/peel verification, draft upload, byte comparison, immutable
      published-release handling, and Homebrew ordering.
- [ ] Run the focused workflow tests.

Expected: FAIL because the release build still uses the current matrix and
hand-written archive commands.

### Task 5: Replace the build matrix with a non-publishing GoReleaser job

**Files:**

- Modify: `.github/workflows/release.yml`

- [ ] Keep the `validate` job unchanged, including ref validation, SemVer
      validation, formatting, vet, and tests.
- [ ] Replace the six-entry build matrix with one `ubuntu-latest` build job that
      still needs `validate`.
- [ ] Checkout with `fetch-depth: 0` so GoReleaser can inspect repository
      history and tags.
- [ ] Run the pinned `jdx/mise-action`; use the GoReleaser version from
      `.mise.toml` rather than adding a second installation mechanism.
- [ ] Before invoking GoReleaser, create or force only a local lightweight tag
      at the checked-out `GITHUB_SHA`:

```bash
tag="v$VERSION"
git tag --force "$tag" "$GITHUB_SHA"
```

This local tag supplies GoReleaser's `.Version`; it must not push or alter the
remote tag. The existing release job remains responsible for creating, freshly
fetching, peeling, and proving the remote tag.

- [ ] Run, with `GORELEASER_CURRENT_TAG="v$VERSION"` set in the step's
      environment:

```bash
goreleaser release --clean --skip=publish
```

`GORELEASER_CURRENT_TAG` removes tag-detection ambiguity: with
`fetch-depth: 0` the checkout also fetches all remote tags, and when
`GITHUB_SHA` already carries another tag (a stable release cut from the same
commit as its prerelease, or a rerun), GoReleaser could otherwise pick the
wrong tag and bake the wrong `main.version` into the binaries.

Do not provide `GITHUB_TOKEN` to this step. Workflow default permissions remain
`contents: read`, and `.goreleaser.yaml` independently disables release
publication. Passing the read-only token to the mise setup step alone is
acceptable — `jdx/mise-action` downloads GoReleaser from GitHub releases and
can hit anonymous rate limits on shared runners — but it must not reach the
GoReleaser invocation.

- [ ] Parse `dist/artifacts.json` and fail unless it contains the exact six
      expected archives and `checksums.txt`.
- [ ] Copy only those seven allowlisted files into a clean staging directory. Do
      not upload `dist/` wholesale, internal binaries, metadata, or unexpected
      future GoReleaser artifacts.
- [ ] Verify archive member names and `checksums.txt` before upload.
- [ ] Upload the staging directory as one GitHub Actions artifact for the
      existing release job. Preserve the downstream extraction layout so files
      land directly under `artifacts/`.
- [ ] Add `checksums.txt` to `expected_assets` in the release job. The existing
      `gh release upload`, download, exact-count, and `cmp` verification then
      applies to all seven assets.
- [ ] Leave the release job's tag-provenance, draft reconciliation, prerelease
      classification, semantic latest handling, and immutable rerun logic
      unchanged.
- [ ] Leave `update-homebrew` structurally unchanged. It continues hashing the
      four GoReleaser-produced macOS/Linux archives, rendering
      `Formula/jwtd.rb`, and pushing to `webcodr/homebrew-tap` only for stable
      releases.

### Task 6: Verify the migrated release path

**Files:**

- Verify all modified files.

- [ ] Run `goreleaser check`.
- [ ] Run `goreleaser release --snapshot --clean` and repeat the exact
      artifact-contract checks used in CI.
- [ ] Run `go test -race ./...`.
- [ ] Run `go vet ./...`.
- [ ] Run `gofmt -l .` and require no output.
- [ ] Run `actionlint .github/workflows/test.yml .github/workflows/release.yml`
      when available.
- [ ] Run `git diff --check`.
- [ ] Review the release workflow manually and confirm:
  - GoReleaser has no write token and publishing is disabled in both config and
    command.
  - The local build tag never reaches the remote.
  - The release job still proves the remote tag resolves to `GITHUB_SHA` before
    release creation.
  - Only seven allowlisted files cross the build/release job boundary.
  - Existing draft/published asset verification includes `checksums.txt`.
  - Homebrew remains downstream of a successfully published stable release.

**Phase 2 acceptance criterion:** a manually dispatched release has the same six
archives and Homebrew update behavior as before, plus `checksums.txt`;
GoReleaser owns only compilation and packaging, while the existing workflow
remains the publisher and integrity authority.

---

## Documentation and rollout

### Task 7: Document the supported developer and release commands

**Files:**

- Modify: `README.md`
- Modify: `AGENTS.md`

- [ ] Add development commands:

```sh
mise install
goreleaser check
goreleaser release --snapshot --clean
```

- [ ] Explain that snapshot artifacts are written to ignored `dist/` and are
      never published.
- [ ] Document that production releases remain manually dispatched and that
      GoReleaser does not publish GitHub releases or Homebrew metadata.
- [ ] Update the architecture description so `.goreleaser.yaml` owns target
      selection, version ldflags, archive naming, and checksums, while
      `.github/workflows/release.yml` owns validation, tag provenance, release
      publication, verification, and Homebrew.
- [ ] Mention `checksums.txt` in the release installation/download
      documentation.

### Rollout and rollback

- Land Phase 1 first and require at least one successful pull-request snapshot
  build before Phase 2.
- Land Phase 2 separately so the release build change can be reverted without
  removing the already validated GoReleaser configuration.
- For the first GoReleaser-backed release, download all seven assets and
  independently run `sha256sum --check checksums.txt` before considering the
  migration proven.
- If Phase 2 fails, restore only the previous matrix build job. No runtime code,
  release publication protocol, or Homebrew template needs to change.
- Re-dispatching the workflow for a pre-migration version (v1.0.0–v3.0.0) will
  fail asset verification by design; do not "fix" this by relaxing the `cmp`
  check.
- Any future GoReleaser or Go bump in `.mise.toml` can change archive bytes and
  will therefore break byte-match verification on reruns of releases built with
  the older pin. Treat tool bumps as a new byte-reproducibility baseline, not a
  regression.

---

## Deferred follow-ups

These are explicitly outside this migration and should receive separate designs:

- Moving Homebrew from the existing Formula to GoReleaser `homebrew_casks`.
- Letting GoReleaser publish GitHub releases.
- Signing checksums or binaries with Cosign.
- Generating SBOMs or GitHub artifact attestations.
- Adding Linux packages, Scoop, Winget, or other distribution channels.
- Replacing manual dispatch with tag-push releases.
- Cross-checking the hashes rendered into `Formula/jwtd.rb` against
  `checksums.txt` in `update-homebrew` (a cheap extra invariant, but it would
  modify a job this migration declares structurally unchanged).
