package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// goReleaserConfig models the subset of .goreleaser.yaml that jwtd relies on:
// the build matrix, deterministic archive metadata, checksums, and the
// defense-in-depth assertions that GoReleaser does not publish anything.
type goReleaserConfig struct {
	Version     int    `yaml:"version"`
	ProjectName string `yaml:"project_name"`
	Before      struct {
		Hooks []string `yaml:"hooks"`
	} `yaml:"before"`
	Builds []struct {
		ID           string   `yaml:"id"`
		Main         string   `yaml:"main"`
		Binary       string   `yaml:"binary"`
		Env          []string `yaml:"env"`
		Goos         []string `yaml:"goos"`
		Goarch       []string `yaml:"goarch"`
		Flags        []string `yaml:"flags"`
		Ldflags      []string `yaml:"ldflags"`
		ModTimestamp string   `yaml:"mod_timestamp"`
	} `yaml:"builds"`
	Archives []struct {
		ID           string   `yaml:"id"`
		IDs          []string `yaml:"ids"`
		Formats      []string `yaml:"formats"`
		NameTemplate string   `yaml:"name_template"`
		Files        []string `yaml:"files"`
		BuildsInfo   struct {
			Owner string `yaml:"owner"`
			Group string `yaml:"group"`
			Mtime string `yaml:"mtime"`
		} `yaml:"builds_info"`
	} `yaml:"archives"`
	Checksum struct {
		NameTemplate string   `yaml:"name_template"`
		Algorithm    string   `yaml:"algorithm"`
		IDs          []string `yaml:"ids"`
	} `yaml:"checksum"`
	Nfpms []struct {
		ID               string   `yaml:"id"`
		PackageName      string   `yaml:"package_name"`
		IDs              []string `yaml:"ids"`
		Formats          []string `yaml:"formats"`
		Maintainer       string   `yaml:"maintainer"`
		Description      string   `yaml:"description"`
		License          string   `yaml:"license"`
		Homepage         string   `yaml:"homepage"`
		Bindir           string   `yaml:"bindir"`
		FileNameTemplate string   `yaml:"file_name_template"`
		Mtime            string   `yaml:"mtime"`
		Contents         []struct {
			Src      string `yaml:"src"`
			Dst      string `yaml:"dst"`
			FileInfo struct {
				Mode  int    `yaml:"mode"`
				Mtime string `yaml:"mtime"`
			} `yaml:"file_info"`
		} `yaml:"contents"`
	} `yaml:"nfpms"`
	Sboms []struct {
		ID        string   `yaml:"id"`
		Artifacts string   `yaml:"artifacts"`
		IDs       []string `yaml:"ids"`
		Cmd       string   `yaml:"cmd"`
		Args      []string `yaml:"args"`
		Documents []string `yaml:"documents"`
	} `yaml:"sboms"`
	Signs []struct {
		ID        string   `yaml:"id"`
		Cmd       string   `yaml:"cmd"`
		Artifacts string   `yaml:"artifacts"`
		Signature string   `yaml:"signature"`
		Args      []string `yaml:"args"`
	} `yaml:"signs"`
	Scoops []struct {
		Name        string   `yaml:"name"`
		IDs         []string `yaml:"ids"`
		Directory   string   `yaml:"directory"`
		SkipUpload  string   `yaml:"skip_upload"`
		Homepage    string   `yaml:"homepage"`
		Description string   `yaml:"description"`
		License     string   `yaml:"license"`
		URLTemplate string   `yaml:"url_template"`
		Repository  struct {
			Owner string `yaml:"owner"`
			Name  string `yaml:"name"`
		} `yaml:"repository"`
	} `yaml:"scoops"`
	Changelog struct {
		Disable bool `yaml:"disable"`
	} `yaml:"changelog"`
	Release struct {
		Disable bool `yaml:"disable"`
	} `yaml:"release"`
}

// releaseArchiveNames are the six tar.gz archives jwtd has always shipped.
// Each carries a Syft SBOM; the windows zips (below) deliberately do not, since
// they wrap the same binary as the windows tar.gz.
var releaseArchiveNames = []string{
	"jwtd-linux-amd64.tar.gz",
	"jwtd-linux-arm64.tar.gz",
	"jwtd-darwin-amd64.tar.gz",
	"jwtd-darwin-arm64.tar.gz",
	"jwtd-windows-amd64.tar.gz",
	"jwtd-windows-arm64.tar.gz",
}

// windowsZipNames are the additional zip archives shipped for WinGet, whose
// portable installer cannot consume tar.gz. They are byte-reproducible and so
// stay in the strict comparison tier alongside the tar.gz archives.
var windowsZipNames = []string{
	"jwtd-windows-amd64.zip",
	"jwtd-windows-arm64.zip",
}

// cosignBundleName is the keyless Cosign bundle covering checksums.txt.
const cosignBundleName = "checksums.txt.sigstore.json"

// Artifact names crossing the build/release job boundary. Release assets and
// downstream manifests travel separately so the release job can only ever
// upload the former.
const (
	releaseAssetsArtifact = "jwtd-release-assets"
	manifestsArtifact     = "jwtd-manifests"
)

// sbomNames returns the per-archive SBOM document names GoReleaser emits for
// the default "{{ .ArtifactName }}.sbom.json" document template.
func sbomNames() []string {
	names := make([]string, 0, len(releaseArchiveNames))
	for _, archive := range releaseArchiveNames {
		names = append(names, archive+".sbom.json")
	}
	return names
}

// sbomSignatureNames returns the keyless Cosign bundle names covering each
// SBOM. SBOMs cannot be listed in checksums.txt without making it
// non-reproducible, so an individual signature is what keeps them verifiable
// rather than merely present.
func sbomSignatureNames() []string {
	names := make([]string, 0, len(releaseArchiveNames))
	for _, sbom := range sbomNames() {
		names = append(names, sbom+".sigstore.json")
	}
	return names
}

// linuxPackageNames returns the nfpm package names. They deliberately reuse
// the version-free "jwtd-{os}-{arch}" scheme of the archives rather than
// nfpm's conventional versioned file name, so every release asset follows one
// naming convention and the workflow allowlists stay static.
func linuxPackageNames() []string {
	return []string{
		"jwtd-linux-amd64.deb",
		"jwtd-linux-arm64.deb",
		"jwtd-linux-amd64.rpm",
		"jwtd-linux-arm64.rpm",
	}
}

// TestGoReleaserConfigurationInvariants checks that .goreleaser.yaml builds
// exactly the six platform/arch archives jwtd already ships, with
// deterministic, binary-only archive contents, a SHA-256 checksums file, and
// GoReleaser's own changelog/release publication disabled.
func TestGoReleaserConfigurationInvariants(t *testing.T) {
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}

	var cfg goReleaserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing .goreleaser.yaml: %v", err)
	}

	if cfg.Version != 2 {
		t.Errorf("version must be 2, got %d", cfg.Version)
	}
	if cfg.ProjectName != "jwtd" {
		t.Errorf("project_name must be %q, got %q", "jwtd", cfg.ProjectName)
	}

	// Two builds: the original jwtd build (all six targets) and a windows-only
	// build feeding the WinGet zip. Both must carry identical, deterministic
	// settings so the windows binary is byte-for-byte the same in the tar.gz and
	// the zip.
	if len(cfg.Builds) != 2 {
		t.Fatalf("expected exactly two builds, got %d", len(cfg.Builds))
	}
	buildsByID := make(map[string]int, len(cfg.Builds))
	for i, b := range cfg.Builds {
		buildsByID[b.ID] = i
	}
	jwtdIdx, ok := buildsByID["jwtd"]
	if !ok {
		t.Fatalf("expected a build with id %q, got builds %v", "jwtd", slices.Collect(maps.Keys(buildsByID)))
	}
	winIdx, ok := buildsByID["jwtd-windows"]
	if !ok {
		t.Fatalf("expected a windows-only build with id %q, got builds %v", "jwtd-windows", slices.Collect(maps.Keys(buildsByID)))
	}
	build := cfg.Builds[jwtdIdx]
	winBuild := cfg.Builds[winIdx]

	// Shared, deterministic build settings both builds must honor.
	for _, name := range []string{"jwtd", "jwtd-windows"} {
		bd := cfg.Builds[buildsByID[name]]
		if bd.Binary != "jwtd" {
			t.Errorf("build %q binary must be %q, got %q", name, "jwtd", bd.Binary)
		}
		if bd.Main != "." {
			t.Errorf("build %q main must be %q, got %q", name, ".", bd.Main)
		}
		if !slices.Contains(bd.Env, "CGO_ENABLED=0") {
			t.Errorf("build %q env must contain %q, got %v", name, "CGO_ENABLED=0", bd.Env)
		}
		if !slices.Contains(bd.Flags, "-trimpath") {
			t.Errorf("build %q flags must contain %q, got %v", name, "-trimpath", bd.Flags)
		}
		if wantLdflags := "-s -w -X main.version={{ .Version }}"; !slices.Contains(bd.Ldflags, wantLdflags) {
			t.Errorf("build %q ldflags must contain %q, got %v", name, wantLdflags, bd.Ldflags)
		}
		if want := "{{ .CommitTimestamp }}"; bd.ModTimestamp != want {
			t.Errorf("build %q mod_timestamp must be %q, got %q", name, want, bd.ModTimestamp)
		}
		if wantGoarch := []string{"amd64", "arm64"}; !slices.Equal(slices.Sorted(slices.Values(bd.Goarch)), slices.Sorted(slices.Values(wantGoarch))) {
			t.Errorf("build %q goarch must be exactly %v, got %v", name, wantGoarch, bd.Goarch)
		}
	}
	if wantGoos := []string{"linux", "darwin", "windows"}; !slices.Equal(slices.Sorted(slices.Values(build.Goos)), slices.Sorted(slices.Values(wantGoos))) {
		t.Errorf("build jwtd goos must be exactly %v, got %v", wantGoos, build.Goos)
	}
	if wantGoos := []string{"windows"}; !slices.Equal(winBuild.Goos, wantGoos) {
		t.Errorf("build jwtd-windows goos must be exactly %v so the zip is windows-only, got %v", wantGoos, winBuild.Goos)
	}

	// Two archives: the tar.gz set (id jwtd) and the windows zip (id jwtd-zip)
	// fed by the windows-only build. Both must be deterministic and binary-only.
	if len(cfg.Archives) != 2 {
		t.Fatalf("expected exactly two archive definitions, got %d", len(cfg.Archives))
	}
	archivesByID := make(map[string]int, len(cfg.Archives))
	for i, a := range cfg.Archives {
		archivesByID[a.ID] = i
	}
	tarIdx, ok := archivesByID["jwtd"]
	if !ok {
		t.Fatalf("expected a tar.gz archive with id %q", "jwtd")
	}
	zipIdx, ok := archivesByID["jwtd-zip"]
	if !ok {
		t.Fatalf("expected a zip archive with id %q for WinGet", "jwtd-zip")
	}
	archive := cfg.Archives[tarIdx]
	zipArchive := cfg.Archives[zipIdx]
	if !slices.Equal(archive.Formats, []string{"tar.gz"}) {
		t.Errorf("archive jwtd formats must be exactly [tar.gz], got %v", archive.Formats)
	}
	if !slices.Equal(zipArchive.Formats, []string{"zip"}) {
		t.Errorf("archive jwtd-zip formats must be exactly [zip], got %v", zipArchive.Formats)
	}
	if !slices.Equal(zipArchive.IDs, []string{"jwtd-windows"}) {
		t.Errorf("archive jwtd-zip must be built from the windows-only build [jwtd-windows], got %v", zipArchive.IDs)
	}
	for _, a := range []struct {
		name string
		arc  int
	}{{"jwtd", tarIdx}, {"jwtd-zip", zipIdx}} {
		arc := cfg.Archives[a.arc]
		if want := "jwtd-{{ .Os }}-{{ .Arch }}"; arc.NameTemplate != want {
			t.Errorf("archive %q name_template must be %q, got %q", a.name, want, arc.NameTemplate)
		}
		if len(arc.Files) == 0 {
			t.Fatalf("archive %q files glob must be set so README/LICENSE are not implicitly added", a.name)
		}
		for _, glob := range arc.Files {
			for _, extra := range []string{"README.md", "LICENSE"} {
				if matched, err := filepath.Match(glob, extra); err != nil {
					t.Fatalf("invalid archive %q files glob %q: %v", a.name, glob, err)
				} else if matched {
					t.Errorf("archive %q files glob %q must not match %q; archives must stay binary-only", a.name, glob, extra)
				}
			}
		}
		if arc.BuildsInfo.Owner != "root" || arc.BuildsInfo.Group != "root" {
			t.Errorf("archive %q builds_info owner/group must be root/root, got %q/%q", a.name, arc.BuildsInfo.Owner, arc.BuildsInfo.Group)
		}
		if want := "1970-01-01T00:00:00Z"; arc.BuildsInfo.Mtime != want {
			t.Errorf("archive %q builds_info mtime must be the fixed epoch %q, got %q", a.name, want, arc.BuildsInfo.Mtime)
		}
	}

	if cfg.Checksum.Algorithm != "sha256" {
		t.Errorf("checksum algorithm must be sha256, got %q", cfg.Checksum.Algorithm)
	}
	if cfg.Checksum.NameTemplate != "checksums.txt" {
		t.Errorf("checksum name_template must be %q, got %q", "checksums.txt", cfg.Checksum.NameTemplate)
	}

	if !cfg.Changelog.Disable {
		t.Error("changelog.disable must be true; GoReleaser must not generate release notes")
	}
	if !cfg.Release.Disable {
		t.Error("release.disable must be true; GoReleaser must not publish releases")
	}
}

// TestGoReleaserSupplyChainInvariants checks that .goreleaser.yaml produces a
// per-archive SBOM set and a keyless Cosign bundle over checksums.txt.
// Signing the checksum file transitively covers every artifact the checksum
// file lists, so individual archives are deliberately not signed separately.
func TestGoReleaserSupplyChainInvariants(t *testing.T) {
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	var cfg goReleaserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing .goreleaser.yaml: %v", err)
	}

	if len(cfg.Sboms) != 1 {
		t.Fatalf("expected exactly one sboms entry, got %d", len(cfg.Sboms))
	}
	if want := "archive"; cfg.Sboms[0].Artifacts != want {
		t.Errorf("sboms artifacts must be %q so every shipped archive gets an SBOM, got %q", want, cfg.Sboms[0].Artifacts)
	}
	// SBOMs are scoped to the tar.gz archives (id "jwtd"). The windows zip
	// (id "jwtd-zip") wraps the same binary already cataloged by the windows
	// tar.gz SBOM, so a second SBOM would be redundant and non-reproducible
	// churn for no benefit.
	if want := []string{"jwtd"}; !slices.Equal(cfg.Sboms[0].IDs, want) {
		t.Errorf("sboms.ids must be exactly %v so only the tar.gz archives are cataloged, got %v", want, cfg.Sboms[0].IDs)
	}

	// Syft SBOMs embed a random documentNamespace UUID and a creation
	// timestamp, so they are not byte-reproducible. Restricting the checksum
	// file to the archive ids keeps checksums.txt itself reproducible. Without
	// this, every rerun would produce a different checksums.txt and the
	// release job's byte-for-byte verification of the signed file would fail.
	//
	// Both archive ids (tar.gz "jwtd" and zip "jwtd-zip") plus the nfpm packages
	// (id "jwtd") are covered by checksums.txt, while the SBOMs (sboms id
	// "archive") are excluded.
	if want := []string{"jwtd", "jwtd-zip"}; !slices.Equal(cfg.Checksum.IDs, want) {
		t.Errorf("checksum.ids must be exactly %v so archives and packages are covered but non-reproducible SBOMs stay out, got %v", want, cfg.Checksum.IDs)
	}
	if cfg.Sboms[0].ID == "jwtd" || cfg.Sboms[0].ID == "jwtd-zip" {
		t.Error(`sboms id must not be an archive id; that would pull non-reproducible SBOMs into checksums.txt`)
	}

	if len(cfg.Nfpms) != 1 {
		t.Fatalf("expected exactly one nfpms entry, got %d", len(cfg.Nfpms))
	}
	nfpm := cfg.Nfpms[0]
	if want := []string{"deb", "rpm"}; !slices.Equal(slices.Sorted(slices.Values(nfpm.Formats)), slices.Sorted(slices.Values(want))) {
		t.Errorf("nfpms formats must be exactly %v, got %v", want, nfpm.Formats)
	}
	if want := []string{"jwtd"}; !slices.Equal(nfpm.IDs, want) {
		t.Errorf("nfpms ids must be exactly %v so packages come from the audited build, got %v", want, nfpm.IDs)
	}
	// Sharing the "jwtd" id is what puts the packages inside checksums.txt,
	// and therefore under the Cosign signature, alongside the archives.
	if want := "jwtd"; nfpm.ID != want {
		t.Errorf("nfpms id must be %q so packages are covered by checksum.ids, got %q", want, nfpm.ID)
	}
	// Packages must stay byte-reproducible to remain in the strict cmp tier,
	// which requires a pinned mtime.
	if want := "1970-01-01T00:00:00Z"; nfpm.Mtime != want {
		t.Errorf("nfpms mtime must be the fixed epoch %q to keep packages reproducible, got %q", want, nfpm.Mtime)
	}
	if want := "/usr/bin"; nfpm.Bindir != want {
		t.Errorf("nfpms bindir must be %q, got %q", want, nfpm.Bindir)
	}
	// Packages reuse the archives' version-free naming so every release asset
	// follows one convention and the workflow allowlists stay static.
	if want := "jwtd-{{ .Os }}-{{ .Arch }}"; nfpm.FileNameTemplate != want {
		t.Errorf("nfpms file_name_template must be %q, got %q", want, nfpm.FileNameTemplate)
	}
	for field, value := range map[string]string{
		"maintainer":  nfpm.Maintainer,
		"description": nfpm.Description,
		"license":     nfpm.License,
		"homepage":    nfpm.Homepage,
	} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("nfpms %s must be set; package metadata is user-visible", field)
		}
	}

	// Two signing entries: checksums.txt covers every artifact it lists, and
	// the SBOMs are signed individually because they cannot go into
	// checksums.txt without making it non-reproducible. Together they leave no
	// published asset resting on a presence check alone.
	if len(cfg.Signs) != 2 {
		t.Fatalf("expected exactly two signs entries (checksum and sbom), got %d", len(cfg.Signs))
	}
	signedArtifacts := make(map[string]bool, len(cfg.Signs))
	for _, sign := range cfg.Signs {
		signedArtifacts[sign.Artifacts] = true
		if sign.Cmd != "cosign" {
			t.Errorf("signs cmd must be %q, got %q", "cosign", sign.Cmd)
		}
		if want := "${artifact}.sigstore.json"; sign.Signature != want {
			t.Errorf("signs signature template must be %q, got %q", want, sign.Signature)
		}
		if !slices.Contains(sign.Args, "sign-blob") {
			t.Errorf("signs args must invoke sign-blob, got %v", sign.Args)
		}
		if !slices.Contains(sign.Args, "--bundle=${signature}") {
			t.Errorf("signs args must write a sigstore bundle via --bundle=${signature}, got %v", sign.Args)
		}
		if !slices.Contains(sign.Args, "--yes") {
			t.Errorf("signs args must pass --yes so keyless signing is non-interactive in CI, got %v", sign.Args)
		}
		for _, arg := range sign.Args {
			if strings.Contains(arg, "--key") {
				t.Errorf("signing must stay keyless (OIDC); found long-lived key argument %q", arg)
			}
		}
	}
	for _, want := range []string{"checksum", "sbom"} {
		if !signedArtifacts[want] {
			t.Errorf("signs must cover %q artifacts; without it those assets ship unsigned", want)
		}
	}
}

// releaseWorkflowStep models one step of a job in
// .github/workflows/release.yml.
type releaseWorkflowStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
}

// releaseWorkflowJob models one job in .github/workflows/release.yml.
type releaseWorkflowJob struct {
	Needs       yaml.Node         `yaml:"needs"`
	If          string            `yaml:"if"`
	Permissions map[string]string `yaml:"permissions"`
	Strategy    *struct {
		Matrix map[string]any `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []releaseWorkflowStep `yaml:"steps"`
}

// releaseWorkflow models the subset of .github/workflows/release.yml needed
// to check the release security and GoReleaser migration invariants.
type releaseWorkflow struct {
	Permissions map[string]string             `yaml:"permissions"`
	Env         map[string]string             `yaml:"env"`
	Jobs        map[string]releaseWorkflowJob `yaml:"jobs"`
}

// workflowNeeds returns a job's needs as a list, accepting both the scalar
// and sequence YAML forms.
func workflowNeeds(t *testing.T, node yaml.Node) []string {
	t.Helper()
	switch node.Kind {
	case 0:
		return nil
	case yaml.ScalarNode:
		return []string{node.Value}
	case yaml.SequenceNode:
		var needs []string
		if err := node.Decode(&needs); err != nil {
			t.Fatalf("decoding needs list: %v", err)
		}
		return needs
	default:
		t.Fatalf("unexpected needs node kind %d", node.Kind)
		return nil
	}
}

// TestHomebrewFormulaInvariants checks that Homebrew is published as a formula
// rather than a cask. Casks quarantine their downloaded binaries, which macOS
// Gatekeeper blocks for jwtd's unsigned binaries, and Homebrew is deprecating
// casks that fail Gatekeeper; formulae do not quarantine and work on Linux too.
func TestHomebrewFormulaInvariants(t *testing.T) {
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	if strings.Contains(string(data), "homebrew_casks") {
		t.Error(".goreleaser.yaml must not configure homebrew_casks; Homebrew is published as a formula to avoid Gatekeeper quarantine")
	}

	template, err := os.ReadFile(filepath.Join("Formula", "jwtd.rb"))
	if err != nil {
		t.Fatalf("Formula/jwtd.rb template must exist: %v", err)
	}
	body := string(template)
	if !strings.Contains(body, "class Jwtd < Formula") {
		t.Error("Formula/jwtd.rb must be a Homebrew formula")
	}
	// The template must cover both platforms with per-arch placeholders that
	// the release workflow fills from checksums.txt.
	for _, placeholder := range []string{
		"VERSION",
		"SHA256_DARWIN_AMD64", "SHA256_DARWIN_ARM64",
		"SHA256_LINUX_AMD64", "SHA256_LINUX_ARM64",
	} {
		if !strings.Contains(body, placeholder) {
			t.Errorf("Formula/jwtd.rb must contain the %q placeholder for the release workflow to fill", placeholder)
		}
	}
	for _, stanza := range []string{"on_macos", "on_linux"} {
		if !strings.Contains(body, stanza) {
			t.Errorf("Formula/jwtd.rb must keep the %q stanza so both platforms are covered", stanza)
		}
	}
	// Completions are generated from the installed binary at brew-install time,
	// which keeps them out of the binary-only release archive.
	if !strings.Contains(body, `generate_completions_from_executable(bin/"jwtd", "completion")`) {
		t.Error("Formula/jwtd.rb must generate shell completions from the installed binary")
	}
}

// TestShellCompletionsPackaged checks that the deb/rpm packages ship shell
// completions generated from the CLI, and that they are pinned to the epoch so
// the packages stay byte-reproducible. The tar.gz archives deliberately do not
// carry them (that contract is asserted in TestGoReleaserConfigurationInvariants).
func TestShellCompletionsPackaged(t *testing.T) {
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	var cfg goReleaserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing .goreleaser.yaml: %v", err)
	}

	// A before-hook must generate each completion script the packages install,
	// so the src paths in nfpm contents actually exist at package time.
	for _, shell := range []string{"bash", "zsh", "fish"} {
		want := "go run . completion " + shell + " > completions/jwtd." + shell
		found := false
		for _, hook := range cfg.Before.Hooks {
			if strings.Contains(hook, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("before.hooks must generate the %s completion (%q)", shell, want)
		}
	}

	if len(cfg.Nfpms) != 1 {
		t.Fatalf("expected exactly one nfpms entry, got %d", len(cfg.Nfpms))
	}
	// Each completion lands at its shell's conventional path, mode 0644, with
	// mtime pinned to the epoch to preserve byte-for-byte reproducibility.
	wantContents := map[string]string{
		"./completions/jwtd.bash": "/usr/share/bash-completion/completions/jwtd",
		"./completions/jwtd.zsh":  "/usr/share/zsh/site-functions/_jwtd",
		"./completions/jwtd.fish": "/usr/share/fish/vendor_completions.d/jwtd.fish",
	}
	got := map[string]string{}
	for _, c := range cfg.Nfpms[0].Contents {
		got[c.Src] = c.Dst
		if c.FileInfo.Mode != 0o644 {
			t.Errorf("completion %q must be mode 0644, got %o", c.Src, c.FileInfo.Mode)
		}
		if want := "1970-01-01T00:00:00Z"; c.FileInfo.Mtime != want {
			t.Errorf("completion %q mtime must be the epoch %q for reproducibility, got %q", c.Src, want, c.FileInfo.Mtime)
		}
	}
	for src, dst := range wantContents {
		if got[src] != dst {
			t.Errorf("nfpm contents must install %q to %q, got %q", src, dst, got[src])
		}
	}
}

// TestScoopInvariants checks that the Scoop manifest is generated by
// GoReleaser but published by the release workflow, on the same terms as the
// Homebrew cask.
func TestScoopInvariants(t *testing.T) {
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	var cfg goReleaserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parsing .goreleaser.yaml: %v", err)
	}

	if len(cfg.Scoops) != 1 {
		t.Fatalf("expected exactly one scoops entry, got %d", len(cfg.Scoops))
	}
	scoop := cfg.Scoops[0]

	if scoop.SkipUpload != "true" {
		t.Errorf("scoops skip_upload must be %q so GoReleaser never pushes to the bucket, got %q", "true", scoop.SkipUpload)
	}
	// Windows now produces two archives (tar.gz and the WinGet zip); Scoop must
	// be pinned to the tar.gz id or GoReleaser cannot pick a single archive.
	if want := []string{"jwtd"}; !slices.Equal(scoop.IDs, want) {
		t.Errorf("scoops ids must be exactly %v so Scoop uses the tar.gz archive, not the WinGet zip, got %v", want, scoop.IDs)
	}
	if scoop.Repository.Owner != "webcodr" || scoop.Repository.Name != "scoop-bucket" {
		t.Errorf("scoops repository must be webcodr/scoop-bucket, got %s/%s", scoop.Repository.Owner, scoop.Repository.Name)
	}
	// release.disable prevents GoReleaser from deriving the download URL, so an
	// explicit url_template is required.
	if !strings.Contains(scoop.URLTemplate, "releases/download") {
		t.Errorf("scoops url_template must point at the release download URL; release.disable prevents deriving it, got %q", scoop.URLTemplate)
	}
	for field, value := range map[string]string{
		"homepage":    scoop.Homepage,
		"description": scoop.Description,
		"license":     scoop.License,
	} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("scoops %s must be set; manifest metadata is user-visible", field)
		}
	}
}

// TestAURInvariants checks that jwtd ships a prebuilt-binary AUR package
// (jwtd-bin) rendered from the signed checksums.txt and pushed by the release
// workflow, on the same terms as the Homebrew and Scoop channels: hashes
// derived from the signed checksum file, a version-downgrade guard, a pinned
// SSH host key, and publication gated to stable releases.
func TestAURInvariants(t *testing.T) {
	pkgbuild, err := os.ReadFile(filepath.Join("aur", "PKGBUILD"))
	if err != nil {
		t.Fatalf("aur/PKGBUILD template must exist: %v", err)
	}
	srcinfo, err := os.ReadFile(filepath.Join("aur", ".SRCINFO"))
	if err != nil {
		t.Fatalf("aur/.SRCINFO template must exist: %v", err)
	}
	pb := string(pkgbuild)
	si := string(srcinfo)

	// jwtd-bin installs the released Linux binary rather than compiling from
	// source, so it must carry no build toolchain and hit /usr/bin/jwtd like
	// the deb/rpm packages.
	if !strings.Contains(pb, "pkgname=jwtd-bin") {
		t.Error("aur/PKGBUILD must define pkgname=jwtd-bin")
	}
	if strings.Contains(pb, "go build") || strings.Contains(pb, "makedepends") {
		t.Error("aur/PKGBUILD (jwtd-bin) must install the prebuilt binary, not compile from source")
	}
	if !strings.Contains(pb, "/usr/bin/jwtd") {
		t.Error("aur/PKGBUILD must install the binary to /usr/bin/jwtd")
	}
	// provides/conflicts jwtd so the -bin package interoperates with a
	// hypothetical from-source package of the same binary.
	for _, want := range []string{"provides=('jwtd')", "conflicts=('jwtd')"} {
		if !strings.Contains(pb, want) {
			t.Errorf("aur/PKGBUILD must contain %q", want)
		}
	}
	// .SRCINFO must agree with PKGBUILD on the package identity so the AUR
	// server hook accepts the commit.
	if !strings.Contains(si, "pkgbase = jwtd-bin") || !strings.Contains(si, "pkgname = jwtd-bin") {
		t.Error("aur/.SRCINFO must declare pkgbase and pkgname jwtd-bin")
	}

	// Both templates must carry the placeholders the release workflow fills
	// from checksums.txt, cover both architectures, and point at the exact
	// release archives.
	for _, placeholder := range []string{"VERSION", "SHA256_LINUX_AMD64", "SHA256_LINUX_ARM64"} {
		if !strings.Contains(pb, placeholder) {
			t.Errorf("aur/PKGBUILD must contain the %q placeholder", placeholder)
		}
		if !strings.Contains(si, placeholder) {
			t.Errorf("aur/.SRCINFO must contain the %q placeholder", placeholder)
		}
	}
	for _, arch := range []string{"x86_64", "aarch64"} {
		if !strings.Contains(pb, arch) {
			t.Errorf("aur/PKGBUILD must cover the %q architecture", arch)
		}
		if !strings.Contains(si, "arch = "+arch) {
			t.Errorf("aur/.SRCINFO must cover the %q architecture", arch)
		}
	}
	for _, archive := range []string{"jwtd-linux-amd64.tar.gz", "jwtd-linux-arm64.tar.gz"} {
		if !strings.Contains(pb, archive) {
			t.Errorf("aur/PKGBUILD must download %q", archive)
		}
		if !strings.Contains(si, archive) {
			t.Errorf("aur/.SRCINFO must download %q", archive)
		}
	}

	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}
	var wf releaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing release workflow: %v", err)
	}

	aurJob, ok := wf.Jobs["update-aur"]
	if !ok {
		t.Fatal("release workflow must define an update-aur job")
	}
	if !slices.Contains(workflowNeeds(t, aurJob.Needs), "release") {
		t.Error("update-aur must run only after a successfully published release")
	}
	// The AUR channel publishes only for stable releases, like Homebrew/Scoop.
	if want := "needs.validate.outputs.prerelease == 'false'"; !strings.Contains(aurJob.If, want) {
		t.Errorf("update-aur must be gated on %q so prereleases never update the AUR, got %q", want, aurJob.If)
	}
	// The package hashes are taken from the signed checksums.txt, so the AUR
	// can only point at the exact archives this release published and verified.
	if findStepContainingRun(aurJob.Steps, "checksums.txt") == nil {
		t.Error("update-aur must derive the package hashes from checksums.txt")
	}
	pushStep := findStepContainingRun(aurJob.Steps, "git push")
	if pushStep == nil {
		t.Fatal("update-aur must push to the AUR")
	}
	if !strings.Contains(pushStep.Run, "ssh://aur@aur.archlinux.org/jwtd-bin.git") {
		t.Error("update-aur must push to the jwtd-bin AUR repository")
	}
	// The AUR host key is pinned so pushes cannot be redirected via
	// trust-on-first-use.
	if !strings.Contains(pushStep.Run, "known_hosts") || !strings.Contains(pushStep.Run, "aur.archlinux.org ssh-ed25519") {
		t.Error("update-aur must pin the AUR SSH host key in known_hosts")
	}
	if !strings.Contains(pushStep.Run, "Gem::Version") {
		t.Error("update-aur must keep the version-downgrade guard")
	}
	if got := pushStep.Env["AUR_SSH_KEY"]; !strings.Contains(got, "AUR_SSH_KEY") {
		t.Errorf("update-aur must authenticate with the AUR_SSH_KEY secret, got %q", got)
	}
}

// TestMiseLockInvariants checks that the release toolchain is pinned by
// checksum rather than by version alone. Every tool that builds and signs a
// release comes from mise, so a retagged or replaced upstream artifact would
// otherwise be installed silently. The lockfile is only consulted when the
// setting is on, and it is only meaningful while it matches the pinned
// versions, so both are enforced here. Source-built (`go:`) tools carry no
// checksum and are exempted; see the comment on that branch.
func TestMiseLockInvariants(t *testing.T) {
	config, err := os.ReadFile(".mise.toml")
	if err != nil {
		t.Fatalf("reading .mise.toml: %v", err)
	}
	if !regexp.MustCompile(`(?m)^\s*lockfile\s*=\s*true`).MatchString(string(config)) {
		t.Error(".mise.toml must set lockfile = true; without it mise.lock is not consulted")
	}

	lock, err := os.ReadFile("mise.lock")
	if err != nil {
		t.Fatalf("reading mise.lock: %v (regenerate with `mise lock --platform linux-x64,macos-arm64`)", err)
	}
	body := string(lock)

	tools := map[string]string{}
	inTools := false
	for _, line := range strings.Split(string(config), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inTools = trimmed == "[tools]"
			continue
		}
		if !inTools || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if name, version, ok := strings.Cut(trimmed, "="); ok {
			tools[strings.TrimSpace(name)] = strings.Trim(strings.TrimSpace(version), `"`)
		}
	}
	if len(tools) == 0 {
		t.Fatal(".mise.toml declares no tools")
	}

	for tool, version := range tools {
		// The map keys keep the TOML quoting from .mise.toml, which is how
		// mise.lock spells them too; the bare name only reads better in messages.
		name := strings.Trim(tool, `"`)
		// Every check runs against this tool's own block, so a neighbouring
		// entry can never satisfy one of them.
		header, ok := tomlSection(body, "[[tools."+tool+"]]", "[[tools.")
		if !ok {
			t.Errorf("mise.lock has no entry for %q; regenerate it after changing the tool set", name)
			continue
		}
		// The tool's own keys, before its per-platform subtables.
		keys, _ := tomlSection(header, "[[tools."+tool+"]]", "[")

		// A lockfile pinning a version other than the configured one is worse
		// than none: it looks authoritative while the pins disagree.
		versionRe := regexp.MustCompile(`(?m)^version = "([^"]+)"`)
		if m := versionRe.FindStringSubmatch(keys); m == nil {
			t.Errorf("mise.lock records no version for %q", name)
		} else if m[1] != version {
			t.Errorf("mise.lock pins %s %s but .mise.toml pins %s; regenerate the lockfile", name, m[1], version)
		}

		// `go:` tools are not downloaded, they are built by `go install`, so
		// there is no artifact for mise to checksum — their integrity comes from
		// the Go module checksum database instead. They are development-only
		// (gopls) and never touch the release path, which is what the checksum
		// requirement below protects. Both files must agree that the tool is
		// source-built before it is exempted: an edit to either one alone
		// cannot drop a prebuilt download out of checksum coverage, and a
		// disagreement falls through to the checksum check rather than
		// skipping it.
		declaredGo := strings.HasPrefix(name, "go:")
		resolvedGo := regexp.MustCompile(`(?m)^backend = "go:`).MatchString(keys)
		switch {
		case declaredGo != resolvedGo:
			t.Errorf("mise.lock and .mise.toml disagree on whether %q is a source-built go: tool; regenerate the lockfile", name)
		case declaredGo:
			continue
		}

		// linux-x64 is the platform every CI job runs on, so its checksum is
		// the one that gates releases. The checksum has to sit in that
		// platform's own subtable: matching one from a sibling platform would
		// pass a lockfile that leaves the CI download unverified.
		platform, ok := tomlSection(header, `[tools.`+tool+`."platforms.linux-x64"]`, "[")
		if !ok || !regexp.MustCompile(`(?m)^checksum = "sha256:[0-9a-f]{64}"`).MatchString(platform) {
			t.Errorf("mise.lock has no linux-x64 sha256 checksum for %q; CI would install it unverified", name)
		}
	}
}

// tomlSection returns the section of body that starts at header and ends
// before the next line beginning with nextPrefix (or the end of body). It
// exists so lockfile assertions cannot match a key belonging to another tool
// or another platform.
func tomlSection(body, header, nextPrefix string) (string, bool) {
	_, section, ok := strings.Cut(body, header)
	if !ok {
		return "", false
	}
	if next := strings.Index(section, "\n"+nextPrefix); next >= 0 {
		section = section[:next]
	}
	return header + section, true
}

// TestCOPRInvariants checks that jwtd ships a Fedora COPR RPM that repackages
// the prebuilt release binaries (rather than compiling from source), built and
// submitted by the release workflow on the same terms as the other channels:
// sources verified against the signed checksums.txt and publication gated to
// stable releases.
func TestCOPRInvariants(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("copr", "jwtd.spec"))
	if err != nil {
		t.Fatalf("copr/jwtd.spec template must exist: %v", err)
	}
	body := string(spec)

	if !regexp.MustCompile(`(?m)^Name:\s+jwtd\b`).MatchString(body) {
		t.Error("copr/jwtd.spec must define Name: jwtd")
	}
	for _, want := range []string{
		"VERSION",                      // rendered by the workflow
		"ExclusiveArch:",               // the package is arch-specific
		"x86_64 aarch64",               // the two release arches
		"%global debug_package %{nil}", // no debuginfo for a prebuilt binary
		"%{_bindir}/jwtd",              // installs the binary
		"%license",                     // ships the license
		"jwtd-linux-amd64.tar.gz",      // wraps the prebuilt archives
		"jwtd-linux-arm64.tar.gz",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("copr/jwtd.spec must contain %q", want)
		}
	}
	// A binary-repackage spec must not compile from source.
	for _, forbidden := range []string{"go build", "golang", "BuildRequires"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("copr/jwtd.spec repackages the prebuilt binary and must not contain %q", forbidden)
		}
	}

	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}
	var wf releaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing release workflow: %v", err)
	}

	coprJob, ok := wf.Jobs["update-copr"]
	if !ok {
		t.Fatal("release workflow must define an update-copr job")
	}
	if !slices.Contains(workflowNeeds(t, coprJob.Needs), "release") {
		t.Error("update-copr must run only after a successfully published release")
	}
	if want := "needs.validate.outputs.prerelease == 'false'"; !strings.Contains(coprJob.If, want) {
		t.Errorf("update-copr must be gated on %q so prereleases never update COPR, got %q", want, coprJob.If)
	}
	// The archives must be verified against the signed checksums.txt before the
	// SRPM wraps them, so COPR can only build the exact release binaries.
	srpmStep := findStepContainingRun(coprJob.Steps, "rpmbuild")
	if srpmStep == nil {
		t.Fatal("update-copr must build an SRPM with rpmbuild")
	}
	if !strings.Contains(srpmStep.Run, "checksums.txt") {
		t.Error("update-copr must verify the archives against checksums.txt before packaging")
	}
	submitStep := findStepContainingRun(coprJob.Steps, "copr-cli")
	if submitStep == nil {
		t.Fatal("update-copr must submit the build to COPR via copr-cli")
	}
	if !strings.Contains(submitStep.Run, "webcodr/jwtd") {
		t.Error("update-copr must submit to the webcodr/jwtd COPR project")
	}
	if got := submitStep.Env["COPR_CONFIG"]; !strings.Contains(got, "COPR_API_TOKEN") {
		t.Errorf("update-copr must authenticate with the COPR_API_TOKEN secret, got %q", got)
	}
	// This step holds the COPR API token, so the tool it installs must be
	// version-pinned rather than resolved at release time.
	if !regexp.MustCompile(`pip['"]? install[^\n]*copr-cli==\d`).MatchString(submitStep.Run) {
		t.Error("update-copr must install a pinned copr-cli version, not whatever pip resolves at release time")
	}
}

// TestWinGetInvariants checks that jwtd ships a WinGet manifest set that
// installs the release zip as a portable package, and that the update-winget
// job submits it to the moderated microsoft/winget-pkgs repository on the same
// terms as the other channels: installers verified against the signed
// checksums.txt, a pinned+checksummed submission tool, and publication gated to
// stable releases.
func TestWinGetInvariants(t *testing.T) {
	manifests := map[string]string{}
	for _, name := range []string{
		"WebCodr.jwtd.yaml",
		"WebCodr.jwtd.installer.yaml",
		"WebCodr.jwtd.locale.en-US.yaml",
	} {
		data, err := os.ReadFile(filepath.Join("winget", name))
		if err != nil {
			t.Fatalf("winget/%s template must exist: %v", name, err)
		}
		manifests[name] = string(data)
	}

	// Every manifest must agree on the package identity and carry the version
	// placeholder the workflow fills.
	for name, body := range manifests {
		if !strings.Contains(body, "PackageIdentifier: WebCodr.jwtd") {
			t.Errorf("winget/%s must declare PackageIdentifier WebCodr.jwtd", name)
		}
		if !strings.Contains(body, "PackageVersion: VERSION") {
			t.Errorf("winget/%s must carry the VERSION placeholder", name)
		}
	}

	installer := manifests["WebCodr.jwtd.installer.yaml"]
	// jwtd ships as a zip consumed as a portable nested installer (WinGet cannot
	// consume the tar.gz archives), pointing at the exact release zips with
	// per-arch hash placeholders the workflow fills from checksums.txt.
	if !strings.Contains(installer, "InstallerType: zip") {
		t.Error("winget installer manifest must use InstallerType: zip")
	}
	if !strings.Contains(installer, "NestedInstallerType: portable") {
		t.Error("winget installer manifest must install jwtd.exe as a portable nested installer")
	}
	for _, want := range []string{
		"SHA256_WINDOWS_AMD64", "SHA256_WINDOWS_ARM64",
		"jwtd-windows-amd64.zip", "jwtd-windows-arm64.zip",
	} {
		if !strings.Contains(installer, want) {
			t.Errorf("winget installer manifest must contain %q", want)
		}
	}

	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}
	var wf releaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing release workflow: %v", err)
	}

	wingetJob, ok := wf.Jobs["update-winget"]
	if !ok {
		t.Fatal("release workflow must define an update-winget job")
	}
	if !slices.Contains(workflowNeeds(t, wingetJob.Needs), "release") {
		t.Error("update-winget must run only after a successfully published release")
	}
	if want := "needs.validate.outputs.prerelease == 'false'"; !strings.Contains(wingetJob.If, want) {
		t.Errorf("update-winget must be gated on %q so prereleases never update WinGet, got %q", want, wingetJob.If)
	}
	// The installers are verified against the signed checksums.txt before the
	// manifest is built from the same release URLs.
	if findStepContainingRun(wingetJob.Steps, "checksums.txt") == nil {
		t.Error("update-winget must verify the installers against checksums.txt")
	}
	// The submission tool is pinned and checksum-verified so the release-publish
	// path pulls in no unpinned third party.
	installStep := findStepContainingRun(wingetJob.Steps, "komac")
	if installStep == nil {
		t.Fatal("update-winget must install komac")
	}
	if findStepContainingRun(wingetJob.Steps, "sha256sum -c") == nil {
		t.Error("update-winget must verify the komac binary against a pinned sha256")
	}
	submitStep := findStepContainingRun(wingetJob.Steps, "update WebCodr.jwtd")
	if submitStep == nil {
		t.Fatal("update-winget must submit the manifest via komac update")
	}
	if !strings.Contains(submitStep.Run, "--submit") {
		t.Error("update-winget must open the winget-pkgs PR via komac --submit")
	}
	if got := submitStep.Env["KOMAC_FORK_OWNER"]; got != "webcodr" {
		t.Errorf("update-winget must submit from the webcodr fork, got KOMAC_FORK_OWNER=%q", got)
	}
	if got := submitStep.Env["GITHUB_TOKEN"]; !strings.Contains(got, "WINGET_TOKEN") {
		t.Errorf("update-winget must authenticate with the WINGET_TOKEN secret, got %q", got)
	}

	// The first WebCodr.jwtd submission is moderated out of band, and komac
	// update has no base manifest until it merges. A guard step checks whether
	// the package is already in winget-pkgs and gates the submission on it, so a
	// release cut during the first-submission window neither fails the job nor
	// opens a duplicate "New package" PR.
	guardStep := findStepContainingRun(wingetJob.Steps, "manifests/w/WebCodr/jwtd")
	if guardStep == nil {
		t.Fatal("update-winget must check whether WebCodr.jwtd exists in winget-pkgs before submitting")
	}
	if guardStep.ID == "" {
		t.Fatal("the winget-pkgs existence check must have an id so later steps can gate on its output")
	}
	gate := "steps." + guardStep.ID + ".outputs.exists == 'true'"
	for _, step := range []*releaseWorkflowStep{installStep, submitStep} {
		if !strings.Contains(step.If, gate) {
			t.Errorf("update-winget step %q must be gated on %q so it is skipped until the first submission merges, got if=%q", step.Name, gate, step.If)
		}
	}
}

// TestReleaseWorkflowSecurityInvariants checks the durable security
// properties of the release workflow: actions pinned to commit SHAs,
// least-privilege default permissions, workflow inputs reaching shell
// scripts only through environment variables, and every release job gated
// on the validate job.
func TestReleaseWorkflowSecurityInvariants(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}

	var wf releaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing release workflow: %v", err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatal("release workflow defines no jobs")
	}

	shaPinned := regexp.MustCompile(`@[0-9a-f]{40}$`)
	expression := regexp.MustCompile(`\$\{\{([^}]*)\}\}`)

	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = step.Uses
			}
			if step.Uses != "" && !shaPinned.MatchString(step.Uses) {
				t.Errorf("job %q step %q: action %q must be pinned to a full commit SHA", jobName, stepName, step.Uses)
			}
			for _, match := range expression.FindAllStringSubmatch(step.Run, -1) {
				t.Errorf("job %q step %q: run script interpolates %q; pass untrusted values through env instead", jobName, stepName, match[0])
			}
		}
	}

	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Errorf("workflow permissions must be exactly {contents: read}, got %v", wf.Permissions)
	}

	if got, want := wf.Env["VERSION"], "${{ inputs.version }}"; got != want {
		t.Errorf("root env.VERSION must be %q so scripts read the version via env, got %q", want, got)
	}

	if _, ok := wf.Jobs["validate"]; !ok {
		t.Error("release workflow must define a validate job")
	}
	for jobName, job := range wf.Jobs {
		if jobName == "validate" {
			continue
		}
		if !slices.Contains(workflowNeeds(t, job.Needs), "validate") {
			t.Errorf("job %q must depend on the validate job", jobName)
		}
	}
}

// findStepByUsesPrefix returns the first step whose uses value starts with
// prefix, or nil if none matches.
func findStepByUsesPrefix(steps []releaseWorkflowStep, prefix string) *releaseWorkflowStep {
	for i := range steps {
		if strings.HasPrefix(steps[i].Uses, prefix) {
			return &steps[i]
		}
	}
	return nil
}

// findStepContainingRun returns the first step whose run script contains
// substr, or nil if none matches.
func findStepContainingRun(steps []releaseWorkflowStep, substr string) *releaseWorkflowStep {
	for i := range steps {
		if strings.Contains(steps[i].Run, substr) {
			return &steps[i]
		}
	}
	return nil
}

// findStepByExactRun returns the first step whose trimmed run script exactly
// equals run, or nil if none matches.
func findStepByExactRun(steps []releaseWorkflowStep, run string) *releaseWorkflowStep {
	for i := range steps {
		if strings.TrimSpace(steps[i].Run) == run {
			return &steps[i]
		}
	}
	return nil
}

// extractBashArray extracts the double-quoted elements of a
// `name=(...)` bash array literal from a run script.
func extractBashArray(t *testing.T, script, name string) []string {
	t.Helper()
	arrayRe := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(name) + `=\((.*?)\)`)
	match := arrayRe.FindStringSubmatch(script)
	if match == nil {
		t.Fatalf("could not find bash array %q in script", name)
	}
	itemRe := regexp.MustCompile(`"([^"]*)"`)
	var items []string
	for _, m := range itemRe.FindAllStringSubmatch(match[1], -1) {
		items = append(items, m[1])
	}
	return items
}

// TestGoReleaserReleaseWorkflowMigrationInvariants checks that the release
// workflow's build job packages archives with GoReleaser instead of a
// hand-written matrix, without granting GoReleaser a write-capable token or
// letting it publish anything itself.
func TestGoReleaserReleaseWorkflowMigrationInvariants(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("reading release workflow: %v", err)
	}
	var wf releaseWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parsing release workflow: %v", err)
	}

	goreleaserData, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	var cfg goReleaserConfig
	if err := yaml.Unmarshal(goreleaserData, &cfg); err != nil {
		t.Fatalf("parsing .goreleaser.yaml: %v", err)
	}
	if !cfg.Release.Disable {
		t.Error(".goreleaser.yaml release.disable must remain true throughout the migration")
	}

	buildJob, ok := wf.Jobs["build"]
	if !ok {
		t.Fatal("release workflow must define a build job")
	}

	if !slices.Contains(workflowNeeds(t, buildJob.Needs), "validate") {
		t.Error("build job must depend on the validate job")
	}
	if buildJob.Strategy != nil && len(buildJob.Strategy.Matrix) > 0 {
		t.Errorf("build job must not use a build matrix; GoReleaser owns cross-compilation, got matrix %v", buildJob.Strategy.Matrix)
	}
	// Keyless Cosign needs an OIDC token, so the build job carries exactly
	// contents: read plus id-token: write and nothing else. In particular it
	// must never gain contents: write, which would let GoReleaser publish.
	wantBuildPermissions := map[string]string{"contents": "read", "id-token": "write"}
	if !maps.Equal(buildJob.Permissions, wantBuildPermissions) {
		t.Errorf("build job permissions must be exactly %v, got %v", wantBuildPermissions, buildJob.Permissions)
	}

	checkoutStep := findStepByUsesPrefix(buildJob.Steps, "actions/checkout")
	if checkoutStep == nil {
		t.Error("build job must check out the repository")
	} else if fd := checkoutStep.With["fetch-depth"]; fmt.Sprint(fd) != "0" {
		t.Errorf("build job checkout must set fetch-depth: 0 for GoReleaser's version discovery, got %v", fd)
	}

	if findStepByUsesPrefix(buildJob.Steps, "jdx/mise-action") == nil {
		t.Error("build job must install the mise-pinned GoReleaser version")
	}

	tagStep := findStepContainingRun(buildJob.Steps, "git tag --force")
	if tagStep == nil {
		t.Error("build job must establish a local version tag at GITHUB_SHA for GoReleaser's version discovery")
	} else {
		if !strings.Contains(tagStep.Run, "GITHUB_SHA") {
			t.Error("local tag must be created at GITHUB_SHA")
		}
		if strings.Contains(tagStep.Run, "git push") {
			t.Error("local tag step must never push to the remote")
		}
	}

	goreleaserStep := findStepByExactRun(buildJob.Steps, "goreleaser release --clean --skip=publish")
	if goreleaserStep == nil {
		t.Error(`build job must run exactly "goreleaser release --clean --skip=publish"`)
	} else {
		if want := "v${{ env.VERSION }}"; goreleaserStep.Env["GORELEASER_CURRENT_TAG"] != want {
			t.Errorf("GoReleaser step must set GORELEASER_CURRENT_TAG to %q, got %q", want, goreleaserStep.Env["GORELEASER_CURRENT_TAG"])
		}
		for key := range goreleaserStep.Env {
			if strings.Contains(strings.ToUpper(key), "TOKEN") {
				t.Errorf("GoReleaser step must not receive a token env var %q; the workflow, not GoReleaser, publishes releases", key)
			}
		}
	}

	if findStepByUsesPrefix(buildJob.Steps, "actions/upload-artifact") == nil {
		t.Error("build job must upload the GoReleaser archives and checksums for the release job")
	}

	for _, step := range buildJob.Steps {
		if strings.Contains(step.Run, "go build ") {
			t.Error("build job must not contain hand-written go build commands; GoReleaser owns compilation")
		}
		if strings.Contains(step.Run, "tar --sort") {
			t.Error("build job must not contain hand-written tar packaging commands; GoReleaser owns archiving")
		}
	}

	releaseJob, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("release workflow must define a release job")
	}
	assetsStep := findStepContainingRun(releaseJob.Steps, "expected_assets=(")
	if assetsStep == nil {
		t.Fatal("release job must define the expected_assets allowlist")
	}
	assets := extractBashArray(t, assetsStep.Run, "expected_assets")
	wantAssets := append([]string{"checksums.txt", cosignBundleName}, releaseArchiveNames...)
	wantAssets = append(wantAssets, windowsZipNames...)
	wantAssets = append(wantAssets, sbomNames()...)
	wantAssets = append(wantAssets, sbomSignatureNames()...)
	wantAssets = append(wantAssets, linuxPackageNames()...)
	if !slices.Equal(slices.Sorted(slices.Values(assets)), slices.Sorted(slices.Values(wantAssets))) {
		t.Errorf("release job expected_assets must be exactly %v, got %v", wantAssets, assets)
	}

	// Keyless Cosign bundles embed a fresh certificate and timestamp, and
	// Syft SBOMs embed a random UUID and creation timestamp, so neither is
	// byte-reproducible across reruns. They are verified by presence and
	// exact count (and, for the bundle, by cryptographic validity) instead of
	// byte equality. Every other asset keeps the strict cmp check, so the six
	// archives and checksums.txt remain provably immutable.
	nonReproducible := extractBashArray(t, assetsStep.Run, "nonreproducible_assets")
	wantNonReproducible := append([]string{cosignBundleName}, sbomNames()...)
	wantNonReproducible = append(wantNonReproducible, sbomSignatureNames()...)
	if !slices.Equal(slices.Sorted(slices.Values(nonReproducible)), slices.Sorted(slices.Values(wantNonReproducible))) {
		t.Errorf("release job nonreproducible_assets must be exactly %v, got %v", wantNonReproducible, nonReproducible)
	}
	reproducible := append([]string{"checksums.txt"}, releaseArchiveNames...)
	reproducible = append(reproducible, windowsZipNames...)
	reproducible = append(reproducible, linuxPackageNames()...)
	for _, asset := range reproducible {
		if slices.Contains(nonReproducible, asset) {
			t.Errorf("asset %q must stay in the byte-comparison tier; it is reproducible and its immutability is load-bearing", asset)
		}
	}
	if !strings.Contains(assetsStep.Run, "cosign verify-blob") {
		t.Error("release job must verify the Cosign bundle against checksums.txt with cosign verify-blob")
	}

	// The Scoop manifest is a downstream manifest, not a release asset. It
	// reaches update-scoop through a separate artifact so the release job
	// cannot upload it to the GitHub release even by accident.
	if slices.Contains(assets, "jwtd.json") {
		t.Error("the Scoop manifest must not be a release asset; it belongs in the manifests artifact")
	}
	releaseDownload := findStepByUsesPrefix(releaseJob.Steps, "actions/download-artifact")
	if releaseDownload == nil {
		t.Fatal("release job must download the build artifact")
	}
	if got := fmt.Sprint(releaseDownload.With["name"]); got != releaseAssetsArtifact {
		t.Errorf("release job must download only the %q artifact so manifests cannot leak into the release, got %q", releaseAssetsArtifact, got)
	}

	// Auto-generated notes list only PR titles, so hand-written prose reaches
	// the published release only if RELEASE_NOTES.md is prepended at creation.
	createStep := findStepContainingRun(releaseJob.Steps, "gh release create")
	if createStep == nil {
		t.Fatal("release job must create the release")
	}
	if !strings.Contains(createStep.Run, "RELEASE_NOTES.md") {
		t.Error("release create must prepend RELEASE_NOTES.md so hand-written notes are not lost")
	}
	if !strings.Contains(createStep.Run, "--generate-notes") {
		t.Error("release create must keep --generate-notes")
	}

	brewJob, ok := wf.Jobs["update-homebrew"]
	if !ok {
		t.Fatal("release workflow must define an update-homebrew job")
	}
	if !slices.Contains(workflowNeeds(t, brewJob.Needs), "release") {
		t.Error("update-homebrew must run only after a successfully published release")
	}
	// The formula's hashes are taken from the signed checksums.txt, so the tap
	// can only point at the exact archives this release published and verified.
	renderStep := findStepContainingRun(brewJob.Steps, "checksums.txt")
	if renderStep == nil {
		t.Error("update-homebrew must derive the formula hashes from checksums.txt")
	}
	pushStep := findStepContainingRun(brewJob.Steps, "git push")
	if pushStep == nil {
		t.Fatal("update-homebrew must push the formula to the tap")
	}
	if !strings.Contains(pushStep.Run, "Formula/jwtd.rb") {
		t.Error("update-homebrew must publish the formula to Formula/jwtd.rb in the tap")
	}
	// The tap held a cask at 4.0.0; the transition back to a formula must
	// remove it so the tap does not expose both.
	if !strings.Contains(pushStep.Run, "Casks/jwtd.rb") {
		t.Error("update-homebrew must remove the superseded Casks/jwtd.rb from the tap")
	}
	if !strings.Contains(pushStep.Run, "Gem::Version") {
		t.Error("update-homebrew must keep the version-downgrade guard")
	}

	scoopJob, ok := wf.Jobs["update-scoop"]
	if !ok {
		t.Fatal("release workflow must define an update-scoop job")
	}
	if !slices.Contains(workflowNeeds(t, scoopJob.Needs), "release") {
		t.Error("update-scoop must run only after a successfully published release")
	}
	scoopPush := findStepContainingRun(scoopJob.Steps, "git push")
	if scoopPush == nil {
		t.Fatal("update-scoop must push the manifest to the bucket")
	}
	if !strings.Contains(scoopPush.Run, "bucket/jwtd.json") {
		t.Error("update-scoop must publish the manifest to bucket/jwtd.json")
	}
	if !strings.Contains(scoopPush.Run, "Gem::Version") {
		t.Error("update-scoop must keep the version-downgrade guard")
	}
	if got := scoopPush.Env["GH_TOKEN"]; !strings.Contains(got, "SCOOP_BUCKET_TOKEN") {
		t.Errorf("update-scoop must push with the dedicated SCOOP_BUCKET_TOKEN, got %q", got)
	}

	// Both downstream channels publish only for stable releases.
	for _, name := range []string{"update-homebrew", "update-scoop"} {
		job := wf.Jobs[name]
		if want := "needs.validate.outputs.prerelease == 'false'"; !strings.Contains(job.If, want) {
			t.Errorf("job %q must be gated on %q so prereleases never update a channel, got %q", name, want, job.If)
		}
	}
	// update-scoop consumes the Scoop manifest from the manifests artifact;
	// update-homebrew renders the formula from the in-repo template instead.
	var scoopHasManifests bool
	for _, step := range scoopJob.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact") && fmt.Sprint(step.With["name"]) == manifestsArtifact {
			scoopHasManifests = true
		}
	}
	if !scoopHasManifests {
		t.Errorf("update-scoop must download the %q artifact", manifestsArtifact)
	}
}
