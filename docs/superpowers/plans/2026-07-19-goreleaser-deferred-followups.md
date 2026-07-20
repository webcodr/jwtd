# GoReleaser Deferred Follow-ups Plan

**Goal:** Implement the selected subset of the GoReleaser migration's deferred
follow-ups — supply-chain signing and provenance, Linux packages, a Scoop
channel, and a Homebrew-cask migration — **without** surrendering the hardened,
non-publishing release posture established in the incremental migration.

**Selected scope (from
[2026-07-19-goreleaser-incremental-migration.md](2026-07-19-goreleaser-incremental-migration.md),
"Deferred follow-ups"):**

1. Sign `checksums.txt` with keyless Cosign, and generate per-archive SBOMs.
2. Build Linux `.deb` and `.rpm` packages via GoReleaser's nfpm.
3. Render a Scoop manifest and publish it to a bucket repo.
4. Migrate Homebrew from the hand-rolled `Formula/jwtd.rb` to GoReleaser
   `homebrew_casks`, folding in the deferred `checksums.txt` cross-check.

**Explicitly out of scope** (still deferred, see end of document): Winget,
GitHub artifact attestations as a replacement for Cosign, letting GoReleaser
publish GitHub releases, and tag-push releases. The manual `workflow_dispatch`
release flow, the read-only GoReleaser step, and the byte-match verification
authority all remain.

**Approach:** Land four independently reviewable phases. Each phase is
test-first: extend `workflow_test.go` invariants so they fail, then satisfy them,
then verify a local `goreleaser` run reproduces the new artifact contract. Every
phase preserves the two independent non-publishing guarantees and the existing
release job's role as sole publisher and integrity authority.

**Tooling:** Go 1.26.1, GoReleaser 2.17.0, plus newly mise-pinned Cosign and
Syft, GitHub Actions, Bash, `jq`, and the existing Go/YAML workflow tests.

**Do not commit unless the user explicitly requests it.**

---

## Preserved invariants (unchanged from the migration)

- Release remains a manual `workflow_dispatch` with a leading-`v`-free SemVer,
  dispatchable only from `main`; every artifact comes from the tested
  `GITHUB_SHA`.
- The six existing archive names and their binary-only, deterministic contents
  are unchanged.
- GoReleaser never publishes. This is still enforced by **at least two**
  independent guarantees at every invocation site:
  1. `.goreleaser.yaml` keeps `release.disable: true`.
  2. The GoReleaser step never receives a write-capable token, and every new
     publisher pipe (`homebrew_casks`, `scoops`) sets `skip_upload: true`.
  3. CI keeps `--skip=publish` on real release builds (see the cross-cutting
     decision on manifest rendering below).
- `main.version` continues to receive the validated version without the leading
  `v`; the local build tag never reaches the remote.
- Releases are created as drafts, verified after upload, then published; the
  release job remains the sole creator/verifier of the remote tag and release.
- Prereleases update no downstream channel; older stable releases never become
  GitHub's latest.

New intentional, externally visible changes introduced by this plan:

- New release assets: `checksums.txt.sigstore.json`, six per-archive SBOMs, and
  the `.deb`/`.rpm` Linux packages.
- `checksums.txt` continues to list exactly the six archives (see D4;
  `checksum.ids` pins this). Phase 2 may extend it to the Linux packages only if
  nfpm output proves byte-reproducible.
- Homebrew moves from a **formula** at `Formula/jwtd.rb` (rendered by hand) to a
  **cask** at `Casks/jwtd.rb` in `webcodr/homebrew-tap` (rendered by GoReleaser).
  This is a user-facing install/upgrade change (see Risks).
- A new Scoop bucket repository begins receiving `jwtd.json`.

---

## Cross-cutting design decisions

These resolve interactions that recur across phases; each phase references them
rather than re-deriving.

### D1 — Manifests render in the Run phase, so `--skip=publish` stays

GoReleaser's Homebrew/Scoop pipes split work into a **Run** phase (writes the
manifest into `dist/` and registers the artifact) and a **Publish** phase (git
push). `--skip=publish` skips only the latter, so `goreleaser release --clean
--skip=publish` still renders the cask and scoop manifests locally. The current
invocation therefore does **not** change, keeping the belt-and-suspenders posture
intact.

**Must be empirically confirmed during Phase 3/4 implementation** (the docs are
explicit for Scoop, less so for casks): the first snapshot/`--skip=publish` run
must show `Casks/jwtd.rb` and the scoop `jwtd.json` present in `dist/`. If a cask
is found to render only in the Publish phase, the fallback is to drop
`--skip=publish` and rely on `release.disable: true` + `skip_upload: true` +
no-write-token as the (still ≥2) independent guarantees — documented explicitly,
never silently.

### D2 — Split "release assets" from "downstream manifests" in staging

Today `staging/` == the seven release assets, uploaded wholesale, and
`update-homebrew` reads archives from the same artifact. New artifacts break that
one-to-one mapping, so the build job stages two disjoint sets:

- `staging/release/` — assets uploaded to the GitHub release, byte/exact-count
  verified: the six archives, `checksums.txt`, `checksums.txt.sigstore.json`,
  six SBOMs, and the nfpm `.deb`/`.rpm` packages.
- `staging/manifests/` — consumed by publish jobs, **never** a release asset:
  `Casks/jwtd.rb` and `scoop/jwtd.json`.

The release job uploads and verifies only `staging/release/*`.
`update-homebrew` reads `staging/manifests/Casks/jwtd.rb`; `update-scoop` reads
`staging/manifests/scoop/jwtd.json`. Both are still gated on a successfully
published stable release.

### D3 — Derive allowlists empirically from `dist/artifacts.json`

The exact `type` strings and artifact counts (e.g. `Signature`, `SBOM`, `Linux
Package`, brew/scoop manifest types) and the exact membership of `checksums.txt`
must be read from a real snapshot, not assumed. Each phase's verification task
enumerates types/counts from `dist/artifacts.json` and encodes the observed,
exact per-type allowlist into both the workflow and `workflow_test.go`. This
mirrors the migration's "inspect `dist/artifacts.json`" discipline.

### D4 — Non-deterministic artifacts vs. the byte-match immutability rule

**Revised after empirical verification in Phase 1. The original form of this
decision was wrong in a way that would have broken the release contract.**

The original assumption was that only the Cosign bundle is non-reproducible.
Two back-to-back snapshot runs disproved it:

- The six archive hashes were **identical** across runs — archives remain
  byte-reproducible.
- All six SBOM hashes **differed** across runs. Syft SPDX output embeds a random
  `documentNamespace` UUID and a `created` timestamp, and Syft exposes no
  deterministic-UUID option (only `--source-name`/`--source-version`).
- GoReleaser includes SBOMs in `checksums.txt` by default, so **`checksums.txt`
  itself became non-reproducible** — the file the release job byte-compares and
  the file Cosign signs.

Resolution, in two parts:

1. **Keep `checksums.txt` reproducible** with `checksum.ids: [jwtd]`, which
   restricts the checksum file to the archive build id. Verified: `checksums.txt`
   is now byte-identical across runs, and its contents are unchanged from the
   already-released contract. This is load-bearing — without it every rerun
   produces a different signed checksum file. `workflow_test.go` asserts it with
   the rationale inline so it cannot be silently reverted.
2. **Partition `expected_assets` into two verification tiers:**
   - **Byte-reproducible tier** (strict `cmp`): the six archives and
     `checksums.txt`. Published releases remain provably immutable.
   - **Non-reproducible tier** (`nonreproducible_assets`; presence + exact total
     count only): the Cosign bundle and the six SBOMs. The bundle is
     additionally verified cryptographically with `cosign verify-blob` against
     the byte-verified `checksums.txt`, pinning the certificate identity to this
     repository's release workflow and the GitHub OIDC issuer.

Accepted residual gap: a tampered **SBOM** on a published release would pass
presence-and-count without being detected, since it cannot be byte-compared.
Archives, `checksums.txt`, and the signature remain fully verified, and SBOMs are
informational metadata. A cheap semantic check (published SBOM parses as JSON and
its `name` matches the corresponding archive) would narrow this gap and is
recommended if the tier ever covers anything load-bearing.

The "reruns of pre-migration or tool-bumped releases fail by design" stance is
unchanged.

**Consequence for Phase 2:** because `checksum.ids` is now an explicit
allowlist, nfpm packages will be **excluded** from `checksums.txt` unless their
build id is added to it. Phase 2 must confirm nfpm output is byte-reproducible
and, if so, extend `checksum.ids` — otherwise the packages join the
non-reproducible tier instead.

### D5 — New tooling is mise-pinned, exact versions only

Cosign and Syft are added to `.mise.toml` at exact pinned versions (never
`latest`), alongside Go and GoReleaser, so local and CI runs are identical and a
tool bump is a deliberate byte-reproducibility baseline change.

---

## File map

- Modify: `.goreleaser.yaml` — add `signs`, `sboms`, `nfpms`, `homebrew_casks`,
  and `scoops`; keep `release.disable: true`.
- Modify: `.mise.toml` — pin Cosign and Syft.
- Modify: `.github/workflows/release.yml` — add `id-token: write` to the build
  job; split staging (D2); extend asset verification (D3, D4); rework
  `update-homebrew` for the cask; add an `update-scoop` job.
- Modify: `.github/workflows/test.yml` — extend the snapshot artifact-contract
  check for the new artifacts.
- Modify: `workflow_test.go` — model and assert the new config blocks and
  workflow invariants.
- Delete: `Formula/jwtd.rb` — superseded by the GoReleaser-rendered cask.
- Modify: `README.md`, `AGENTS.md` — document new assets, the cask install
  change, Scoop, and the new local commands.

External prerequisites (outside the repo, must exist before the relevant phase
ships): a `webcodr/scoop-bucket` repository and a `SCOOP_BUCKET_TOKEN` secret;
confirmation of the desired `webcodr/homebrew-tap` cask layout.

---

## Phase 1: Cosign checksum signing + SBOMs — **implemented**

Landed on branch `goreleaser-signing-sbom` (uncommitted). `gofmt`, `go vet`,
`go test -race`, `goreleaser check`, `actionlint`, and `git diff --check` all
pass. D4 was corrected as a result of this phase.

**Verification status:** the SBOM pipeline and the artifact contract were
verified against real snapshot builds. The signing *plumbing* was verified with
a throwaway key-based run — artifact name `checksums.txt.sigstore.json`, path
`dist/checksums.txt.sigstore.json`, and `cosign verify-blob` returning
`Verified OK`. The **keyless OIDC exchange itself (Fulcio/Rekor and the
`--certificate-identity-regexp` flags) is not exercisable locally** and is first
proven on a real release dispatch. Local and CI snapshot runs therefore use
`--skip=sign`.

### Task 1.1 — Failing invariants

**Files:** `workflow_test.go`

- [ ] Extend `goReleaserConfig` with `Signs` and `Sboms` blocks.
- [ ] Assert exactly one `signs` entry using `cosign` `sign-blob` with
      `--bundle`, `artifacts: checksum`, and signature template
      `checksums.txt.sigstore.json`.
- [ ] Assert exactly one `sboms` entry with `artifacts: archive`.
- [ ] Add release-workflow assertions: the build job has `id-token: write`
      (and no other new write permission), the GoReleaser step still has no
      write token, and `expected_assets` gains `checksums.txt.sigstore.json`
      plus the six SBOM names.
- [ ] Assert the new signature asset is verified by validity, not `cmp` (D4).
- [ ] Run the focused tests; expect FAIL.

### Task 1.2 — Configuration and tooling

**Files:** `.goreleaser.yaml`, `.mise.toml`, `.github/workflows/release.yml`

- [ ] Pin Cosign and Syft in `.mise.toml`.
- [ ] Add to `.goreleaser.yaml`:

```yaml
sboms:
  - id: archive
    artifacts: archive

signs:
  - cmd: cosign
    artifacts: checksum
    signature: "${artifact}.sigstore.json"
    args:
      - sign-blob
      - "--bundle=${signature}"
      - "${artifact}"
      - "--yes"
```

- [ ] Grant the build job `permissions: { contents: read, id-token: write }`;
      keep the GoReleaser invocation token-free.
- [ ] Extend the build job's staging/allowlist to include the signature and
      SBOMs in `staging/release/` (D2, D3).
- [ ] In the release job, keep `cmp` for archives/checksums, add a
      `cosign verify-blob --bundle checksums.txt.sigstore.json checksums.txt`
      step, and raise the exact asset count (D4).

### Task 1.3 — Verify

- [x] `mise install`; `goreleaser check`.
- [x] `goreleaser release --snapshot --clean --skip=sign`; from
      `dist/artifacts.json` confirm the exact `Signature`/`SBOM` types and
      counts; encode them (D3). Observed types: `Archive` ×6, `Binary` ×6,
      `Checksum` ×1, `SBOM` ×6, `Metadata` ×1, plus `Signature` ×1 when signing
      runs. SBOM names follow `<archive>.sbom.json`.
- [x] Confirm SBOM determinism by diffing two snapshot runs; classify SBOMs per
      D4 accordingly. **Result: SBOMs are non-deterministic, which also made
      `checksums.txt` non-reproducible. D4 revised; `checksum.ids` added.**
- [x] `go test ./...`; the Phase 1 invariants pass.

---

## Phase 2: Linux packages (nfpm deb/rpm) — **implemented**

Landed on branch `goreleaser-signing-sbom` (committed). Full verification suite
passes.

**Outcome of the D4 question this phase had to answer:** nfpm output **is**
byte-reproducible once `mtime` is pinned to the epoch, verified by diffing two
snapshot runs. The packages therefore stay in the strict `cmp` tier. Because the
nfpm block shares the `jwtd` build id with the archives, the existing
`checksum.ids: [jwtd]` covers them automatically — `checksums.txt` now lists ten
entries (six archives + four packages) and remains byte-identical across runs,
so the Cosign signature covers the packages too. No tier change was needed.

Packages use the archives' version-free naming (`jwtd-linux-amd64.deb`) rather
than nfpm's conventional versioned file name, so all release assets share one
convention and the workflow allowlists stay static. Verified package internals:
payload installs to `/usr/bin/jwtd`, with correct maintainer, homepage,
description, section, priority, and architecture.

### Task 2.1 — Failing invariants

**Files:** `workflow_test.go`

- [ ] Add an `Nfpms` block to the model; assert one entry producing `deb` and
      `rpm` from the `jwtd` build with maintainer/description/license and
      `bindir: /usr/bin`.
- [ ] Extend `expected_assets` and the per-type allowlist for the two `.deb` and
      two `.rpm` packages (amd64/arm64).
- [ ] Assert the `checksum.ids` allowlist matches whichever tier the packages
      land in (D4): add the nfpm id only if the packages are byte-reproducible.
- [ ] Run focused tests; expect FAIL.

### Task 2.2 — Configuration

**Files:** `.goreleaser.yaml`, `.github/workflows/release.yml`

- [ ] Add `nfpms:` for `deb`/`rpm` over the `jwtd` build id.
- [ ] Add the four packages to `staging/release/` and the release
      `expected_assets` (D3).
- [ ] Diff two snapshot runs to classify nfpm determinism, then either extend
      `checksum.ids` with the nfpm id or add the packages to
      `nonreproducible_assets` (D4).

### Task 2.3 — Verify

- [ ] Snapshot build; confirm exactly four `Linux Package` artifacts and their
      checksum entries; the byte-`cmp` tier covers them (nfpm is deterministic
      under a fixed mtime/version).
- [ ] `go test ./...` passes.

---

## Phase 3: Homebrew cask migration (+ deferred cross-check) — **implemented**

Landed on branch `goreleaser-signing-sbom`. Full verification suite passes.

**D1 resolved.** The cask pipe runs in the Run phase, so it renders under both
`--skip=publish` and `--snapshot` — `--skip=publish` stays and the
belt-and-suspenders posture is intact. One prerequisite the plan did not
anticipate: because `release.disable: true`, GoReleaser cannot derive the
download URL and fails with `release is disabled, cannot use default
url_template`. An explicit `url.template` is required. (The field is
`url.template`, not `url_template`; `binary` is deprecated in favour of
`binaries`.) Cask output: `dist/homebrew/Casks/jwtd.rb`, artifact type
`Homebrew Cask`, name `jwtd.rb`.

**Accepted regression: Homebrew casks are macOS-only.** Installing a cask on
Linux fails with "Installing casks is supported only on macOS", so the previous
formula's working Linux support is dropped. This was confirmed before
implementing and accepted deliberately: Linux users now have the Phase 2
`.deb`/`.rpm` packages and the archives. GoReleaser still emits `on_linux`
blocks in the cask; they are inert on Linux and harmless. Using GoReleaser's
`brews` (formula) generator instead is not viable — it is deprecated and
`goreleaser check` fails on it, which would break CI.

**D2 implemented as two named artifacts** rather than staging subdirectories:
`jwtd-release-assets` and `jwtd-manifests`. The release job downloads only the
former, so the cask cannot become a release asset even by accident.

**Deferred item #7 folded in:** `update-homebrew` extracts every
sha256/archive pair from the generated cask and requires each to appear
verbatim in `checksums.txt`, failing closed on any mismatch or on a pair count
other than four. Verified against real generated files, including a negative
test with a tampered cask.

### Task 3.1 — Failing invariants

**Files:** `workflow_test.go`

- [ ] Add a `HomebrewCasks` block; assert one entry with `skip_upload: true`,
      repository `webcodr/homebrew-tap`, and directory `Casks`.
- [ ] Assert the cask is a **manifest** artifact (D2) — present in
      `staging/manifests/`, never in the release `expected_assets`.
- [ ] Rewrite the `update-homebrew` assertions: it consumes the rendered cask
      from the build artifact (no hand-rolled `sed`/`sha256sum`), pushes to
      `Casks/jwtd.rb`, keeps the stable-only gate and version-downgrade guard,
      and **cross-checks the cask's embedded sha256s against `checksums.txt`**
      (folds in deferred item #7).
- [ ] Assert `Formula/jwtd.rb` no longer exists and is unreferenced.
- [ ] Confirm `.goreleaser.yaml` keeps `release.disable: true`.
- [ ] Run focused tests; expect FAIL.

### Task 3.2 — Implementation

**Files:** `.goreleaser.yaml`, `.github/workflows/release.yml`, delete
`Formula/jwtd.rb`

- [ ] Add `homebrew_casks:` with `skip_upload: true`, repository
      `owner: webcodr`/`name: homebrew-tap`, `directory: Casks`, the macOS/Linux
      binary stanza, and a `test`/`caveats` equivalent to today's formula.
- [ ] Confirm D1: the cask renders into `dist/` under `--skip=publish`; if not,
      apply the documented fallback.
- [ ] Rework `update-homebrew`: read `staging/manifests/Casks/jwtd.rb`;
      cross-check its embedded sha256s against `checksums.txt`; push to
      `Casks/jwtd.rb` in the tap; preserve the stable-only gate, version guard,
      and idempotent "already current" handling.
- [ ] Handle the tap's old `Formula/jwtd.rb` (remove or leave per the confirmed
      tap layout) so formula and cask do not collide.
- [ ] Delete `Formula/jwtd.rb` from this repo.

### Task 3.3 — Verify

- [ ] Snapshot build; confirm `Casks/jwtd.rb` renders with correct URLs/hashes
      and lands only in `staging/manifests/`, not the release assets.
- [ ] Dry-run the cross-check against a snapshot `checksums.txt`.
- [ ] `go test ./...` passes; `AGENTS.md`/`README.md` updated for the cask.

---

## Phase 4: Scoop channel — **implemented (blocked on infrastructure)**

Landed on branch `goreleaser-signing-sbom`. Full verification suite passes.

Same shape as the cask: `scoops` with `skip_upload: true`, rendered to
`dist/scoop/jwtd.json` (artifact type `Scoop Manifest`), staged into the
`jwtd-manifests` artifact, and published by a new `update-scoop` job gated on a
successful stable release. It needs `url_template` for the same `release.disable`
reason as the cask — note scoop spells it `url_template` while `homebrew_casks`
uses a nested `url.template`.

The manifest is JSON, so its cross-check uses `jq` rather than the cask's awk
parsing: every hash must appear verbatim in `checksums.txt`, with exactly two
pairs expected. Verified against real generated files including a negative
tamper test.

**BLOCKED — prerequisites do not exist yet:**

- `webcodr/scoop-bucket` does **not** exist (confirmed via `gh repo view`;
  `webcodr/homebrew-tap` does). It must be created before the next stable
  release.
- The `SCOOP_BUCKET_TOKEN` secret must be configured.

Until both exist, `update-scoop` will fail on the next stable release. This is
fail-loud and does not affect the release itself, which completes before any
downstream channel job runs — but the workflow run will report failure.

**Known quirk:** the Windows archives are `.tar.gz` rather than `.zip`, which is
unusual for Scoop. Scoop handles it via 7-Zip, so this works, but switching the
Windows archive format was deliberately left alone: it would change the
established, already-released archive naming/format contract.

### Task 4.1 — Failing invariants

**Files:** `workflow_test.go`

- [ ] Add a `Scoops` block; assert one entry with `skip_upload: true` and a
      bucket repository.
- [ ] Assert a new `update-scoop` job: depends on `[validate, release]`,
      stable-only (`prerelease == 'false'`), consumes
      `staging/manifests/scoop/jwtd.json`, pushes to the bucket with
      `SCOOP_BUCKET_TOKEN`, and mirrors the version-downgrade guard.
- [ ] Assert the scoop manifest is a manifest artifact (D2), never a release
      asset.
- [ ] Run focused tests; expect FAIL.

### Task 4.2 — Implementation

**Files:** `.goreleaser.yaml`, `.github/workflows/release.yml`

- [ ] Add `scoops:` with `skip_upload: true` and repository
      `webcodr/scoop-bucket`, referencing the Windows archives.
- [ ] Add `update-scoop` modeled on `update-homebrew`.

### Task 4.3 — Verify

- [ ] Snapshot build; confirm `scoop/jwtd.json` renders with correct
      URLs/hashes and stays out of the release assets.
- [ ] `go test ./...` passes; README documents the Scoop install path.

---

## Global verification (before each phase merges)

- [ ] `goreleaser check`.
- [ ] `goreleaser release --snapshot --clean` and the full artifact-contract
      check for the current cumulative asset set.
- [ ] `go test -race ./...`, `go vet ./...`, `gofmt -l .` (no output),
      `git diff --check`.
- [ ] `actionlint` on both workflows when available.
- [ ] Manual review: GoReleaser still has no write token and two independent
      non-publish guarantees hold; the local build tag never reaches the remote;
      the release job still proves the remote tag resolves to `GITHUB_SHA`; only
      `staging/release/*` becomes release assets; the byte-match `cmp` set
      excludes only inherently non-deterministic assets (D4); downstream channels
      remain gated on a published stable release.

---

## Prerequisites and infrastructure

- **Cosign keyless** needs `id-token: write` on the build job (only). Each build
  writes the workflow identity to the public Rekor log — an accepted
  supply-chain trade-off; document it.
- **Scoop** needs a `webcodr/scoop-bucket` repo and a `SCOOP_BUCKET_TOKEN` repo
  secret before Phase 4 ships.
- **Homebrew cask** needs the tap's `Casks/` layout confirmed and the old
  `Formula/jwtd.rb` in the tap resolved.

## Rollout and rollback

- Land phases in order (1 → 4); each is independently revertible. Phases 1–2 are
  purely additive assets; Phase 3 changes user-facing install; Phase 4 adds a new
  channel and external dependency.
- Prove Phase 1 on a real release by downloading `checksums.txt` and its bundle
  and running `cosign verify-blob` independently before relying on it.
- Rolling back Phase 3 means restoring `Formula/jwtd.rb` and the hand-rolled
  `update-homebrew`; no other phase depends on it.
- Any Cosign/Syft/GoReleaser/Go bump in `.mise.toml` is a new
  byte-reproducibility baseline, not a regression.

## Risks

- **Formula → cask is user-facing.** Existing `brew install webcodr/tap/jwtd`
  users may need to re-tap or use cask semantics; call this out in README and
  release notes, and keep the tap change backward-friendly where possible.
- **Reruns of signed releases** cannot byte-match the Cosign bundle; D4 keeps
  the release fail-closed on tampering while allowing signature validity to be
  re-verified rather than byte-compared.
- **`checksums.txt` membership changes** once nfpm packages exist — an
  intentional asset-set change, like the original `checksums.txt` addition.

## Still deferred (not in this plan)

- Winget (a PR to `microsoft/winget-pkgs`; highest publishing complexity).
- GitHub artifact attestations as an alternative/supplement to Cosign.
- Letting GoReleaser publish GitHub releases.
- Replacing manual dispatch with tag-push releases.
