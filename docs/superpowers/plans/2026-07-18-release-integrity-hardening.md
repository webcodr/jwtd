# Release Integrity Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure every release is validated, safe from version-input shell injection, and bound to the exact tested `main` commit used to build its artifacts.

**Architecture:** Add a validation gate to the existing manual release workflow, pass version input through workflow environment data instead of direct shell interpolation, and bind releases to the dispatch SHA by atomically establishing and independently proving the version tag before verified-tag release creation. Preserve the build matrix and Homebrew publication behavior.

**Tech Stack:** GitHub Actions, Bash, Go 1.26, mise-action, GitHub CLI, Homebrew formula generation, and actionlint.

---

## File Map

- Modify: `.github/workflows/release.yml` - validation gate, safe version handling, tested-SHA tag proof, deterministic release reconciliation, and job dependencies.
- Modify: `main_test.go` - repository-level workflow security invariants.
- Reference: `docs/superpowers/specs/2026-07-18-security-and-release-hardening-design.md` - approved release behavior.

Do not commit unless the user explicitly requests it.

This plan records the original implementation sequence, updated where the final workflow adopted stronger tag-provenance, concurrency, and immutable-asset invariants.

### Task 1: Add Executable Release-Workflow Invariants

**Files:**
- Modify: `main_test.go`
- Test: `.github/workflows/release.yml`

- [ ] **Step 1: Add a failing workflow invariant test**

Add this test near the end of `main_test.go`:

```go
func TestReleaseWorkflowSecurityInvariants(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}
	workflow := string(data)
	required := []string{
		"VERSION: '${{ inputs.version }}'",
		"Validate release ref",
		"Validate semantic version",
		"Check formatting",
		"go vet ./...",
		"go test ./...",
		"needs: validate",
		"group: release-${{ github.repository }}-${{ github.ref }}-${{ inputs.version }}",
		"cancel-in-progress: false",
		`gh api --include --method POST "repos/$GH_REPO/git/refs"`,
		`-f sha="$GITHUB_SHA"`,
		`git fetch --force origin "refs/tags/$tag:refs/tags/$tag"`,
		`git rev-parse --verify "refs/tags/$tag^{commit}"`,
		"--verify-tag",
		"--draft",
		"for attempt in 1 2 3 4 5; do",
		`release_state=$(gh release view "$tag" --json isDraft,isPrerelease`,
		"expected_assets=(",
		`gh release upload "$tag" artifacts/* --clobber`,
		`gh release download "$tag" --dir "$verified_assets"`,
		`cmp -- "$verified_assets/$asset" "artifacts/$asset"`,
		`downloaded_count=$(find "$verified_assets" -maxdepth 1 -type f | wc -l)`,
	}
	for _, value := range required {
		if !strings.Contains(workflow, value) {
			t.Errorf("release workflow missing %q", value)
		}
	}
	if count := strings.Count(workflow, "${{ inputs.version }}"); count != 2 {
		t.Errorf("version input should appear only in root env.VERSION and the concurrency group, got %d occurrences", count)
	}
	forbidden := []string{
		"main.version=${{ inputs.version }}",
		`gh release create "v${{ inputs.version }}"`,
		`s/VERSION/${{ inputs.version }}/g`,
		`git commit -m "jwtd ${{ inputs.version }}"`,
	}
	for _, value := range forbidden {
		if strings.Contains(workflow, value) {
			t.Errorf("release workflow contains unsafe interpolation %q", value)
		}
	}
}
```

The final test suite strengthens this initial smoke test by parsing the workflow and shell commands and enforcing ordering, cardinality, per-version concurrency, conflict re-query, and complete asset-set invariants.

- [ ] **Step 2: Run the test and verify it fails**

Run: `go test ./... -run TestReleaseWorkflowSecurityInvariants -count=1`

Expected: FAIL because validation, `needs: validate`, tag-provenance proof, verified draft creation, and asset verification are absent and the input appears multiple times.

### Task 2: Gate Releases On A Tested Main Commit

**Files:**
- Modify: `.github/workflows/release.yml:1-117`

- [ ] **Step 1: Put the version input in workflow environment data**

Add this top-level block after `on`:

```yaml
env:
  VERSION: '${{ inputs.version }}'
```

This is one of two approved `${{ inputs.version }}` occurrences; the other is the per-version concurrency group. The expression must not appear directly in any `run` script.

- [ ] **Step 2: Add the validation job**

Add this job before `build`:

```yaml
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Validate release ref
        if: github.ref != 'refs/heads/main'
        run: |
          echo "Releases must be dispatched from main" >&2
          exit 1

      - name: Validate semantic version
        shell: bash
        run: |
          semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
          if [[ ! "$VERSION" =~ $semver_re ]]; then
            echo "Invalid semantic version: $VERSION" >&2
            exit 1
          fi

      - uses: actions/checkout@v4

      - uses: jdx/mise-action@v2

      - name: Check formatting
        run: |
          unformatted=$(gofmt -l .)
          if [ -n "$unformatted" ]; then
            echo "gofmt needed on:" >&2
            echo "$unformatted" >&2
            exit 1
          fi

      - name: Vet
        run: go vet ./...

      - name: Run tests
        run: go test ./...
```

- [ ] **Step 3: Make builds depend on validation**

Add this field to the `build` job before `strategy`:

```yaml
    needs: validate
```

The existing `release` and `update-homebrew` dependency chain then remains intact.

- [ ] **Step 4: Replace every shell interpolation and enforce verified release reconciliation**

Use these exact command fragments:

```yaml
          go build -ldflags="-s -w -X main.version=$VERSION" -o "jwtd${{ matrix.suffix }}" .
```

```yaml
          gh release create "v$VERSION" \
            --verify-tag \
            --title "$tag" \
            --generate-notes \
            --draft
```

The final release protocol uses a per-version concurrency group with cancellation disabled. The release job establishes a missing `refs/tags/v$VERSION` at `GITHUB_SHA` through the Git refs API, tolerating only the conflict caused by a concurrent creator. It then force-fetches the remote tag, peels it to a commit, and requires equality with `GITHUB_SHA` before creating or reconciling a release. Creation conflicts use bounded release re-query before state is reloaded.

Release creation produces an assetless draft with `--verify-tag`. The fixed artifact set is uploaded deterministically only to a draft, downloaded, and compared byte-for-byte before publication. A published release is never mutated; reruns download its complete asset set and require exact names and bytes.

```yaml
          sed \
            -e "s/VERSION/$VERSION/g" \
            -e "s/SHA256_DARWIN_ARM64/$SHA256_DARWIN_ARM64/g" \
            -e "s/SHA256_DARWIN_AMD64/$SHA256_DARWIN_AMD64/g" \
            -e "s/SHA256_LINUX_ARM64/$SHA256_LINUX_ARM64/g" \
            -e "s/SHA256_LINUX_AMD64/$SHA256_LINUX_AMD64/g" \
            Formula/jwtd.rb > jwtd.rb
```

```yaml
          git commit -m "jwtd $VERSION"
```

The SemVer gate excludes shell metacharacters and sed replacement metacharacters; quoted variable expansion prevents shell reparsing.

- [ ] **Step 5: Run the invariant test**

Run: `go test ./... -run TestReleaseWorkflowSecurityInvariants -count=1`

Expected: PASS.

### Task 3: Validate Workflow Syntax And Release Builds

**Files:**
- Verify: `.github/workflows/release.yml`
- Verify: `main_test.go`

- [ ] **Step 1: Run actionlint when installed**

Run: `actionlint .github/workflows/release.yml`

Expected: no output and exit 0. If `actionlint` is unavailable, report that explicitly and continue with the remaining checks.

- [ ] **Step 2: Run Go validation**

Run: `gofmt -w main_test.go`

Run: `go test -race ./...`

Expected: PASS.

Run: `go vet ./...`

Expected: no output and exit 0.

Run: `gofmt -l .`

Expected: no output.

- [ ] **Step 3: Cross-build every release target outside the repository**

Run each command:

```bash
GOOS=linux GOARCH=amd64 go build -o /tmp/jwtd-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o /tmp/jwtd-linux-arm64 .
GOOS=darwin GOARCH=amd64 go build -o /tmp/jwtd-darwin-amd64 .
GOOS=darwin GOARCH=arm64 go build -o /tmp/jwtd-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o /tmp/jwtd-windows-amd64.exe .
GOOS=windows GOARCH=arm64 go build -o /tmp/jwtd-windows-arm64.exe .
```

Expected: every command exits 0.

- [ ] **Step 4: Confirm the release invariants manually**

Read `.github/workflows/release.yml` and confirm:

- The version input expression appears only in root `env.VERSION` and the per-version concurrency group, never directly in a `run` script.
- Non-main dispatches fail in `validate`.
- SemVer validation precedes checkout, tests, and builds.
- `build` needs `validate`.
- Per-version concurrency disables cancellation and serializes release reconciliation.
- A missing tag is created through the Git refs API at `GITHUB_SHA`; every tag is freshly fetched, peeled, and required to resolve to that commit.
- Release creation uses verified-tag, assetless-draft semantics, and creation conflicts perform a bounded state re-query.
- The fixed draft asset set is uploaded deterministically and byte-verified before publication; published assets remain immutable and must exactly match on reruns.
- `update-homebrew` remains downstream of `release`.

- [ ] **Step 5: Confirm only intended files changed**

Run: `git diff --check && git status --short`

Expected: no whitespace errors; only `.github/workflows/release.yml`, `main_test.go`, and approved documentation/plan files are listed in addition to runtime-plan changes.
