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
	Builds      []struct {
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
	} `yaml:"nfpms"`
	Sboms []struct {
		ID        string   `yaml:"id"`
		Artifacts string   `yaml:"artifacts"`
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

// releaseArchiveNames are the six archives jwtd has always shipped.
var releaseArchiveNames = []string{
	"jwtd-linux-amd64.tar.gz",
	"jwtd-linux-arm64.tar.gz",
	"jwtd-darwin-amd64.tar.gz",
	"jwtd-darwin-arm64.tar.gz",
	"jwtd-windows-amd64.tar.gz",
	"jwtd-windows-arm64.tar.gz",
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

	if len(cfg.Builds) != 1 {
		t.Fatalf("expected exactly one build, got %d", len(cfg.Builds))
	}
	build := cfg.Builds[0]
	if build.ID != "jwtd" {
		t.Errorf("build id must be %q, got %q", "jwtd", build.ID)
	}
	if build.Binary != "jwtd" {
		t.Errorf("build binary must be %q, got %q", "jwtd", build.Binary)
	}
	if build.Main != "." {
		t.Errorf("build main must be %q, got %q", ".", build.Main)
	}
	if !slices.Contains(build.Env, "CGO_ENABLED=0") {
		t.Errorf("build env must contain %q, got %v", "CGO_ENABLED=0", build.Env)
	}
	if wantGoos := []string{"linux", "darwin", "windows"}; !slices.Equal(slices.Sorted(slices.Values(build.Goos)), slices.Sorted(slices.Values(wantGoos))) {
		t.Errorf("build goos must be exactly %v, got %v", wantGoos, build.Goos)
	}
	if wantGoarch := []string{"amd64", "arm64"}; !slices.Equal(slices.Sorted(slices.Values(build.Goarch)), slices.Sorted(slices.Values(wantGoarch))) {
		t.Errorf("build goarch must be exactly %v, got %v", wantGoarch, build.Goarch)
	}
	if !slices.Contains(build.Flags, "-trimpath") {
		t.Errorf("build flags must contain %q, got %v", "-trimpath", build.Flags)
	}
	if wantLdflags := "-s -w -X main.version={{ .Version }}"; !slices.Contains(build.Ldflags, wantLdflags) {
		t.Errorf("build ldflags must contain %q, got %v", wantLdflags, build.Ldflags)
	}
	if want := "{{ .CommitTimestamp }}"; build.ModTimestamp != want {
		t.Errorf("build mod_timestamp must be %q, got %q", want, build.ModTimestamp)
	}

	if len(cfg.Archives) != 1 {
		t.Fatalf("expected exactly one archive definition, got %d", len(cfg.Archives))
	}
	archive := cfg.Archives[0]
	if !slices.Contains(archive.Formats, "tar.gz") || len(archive.Formats) != 1 {
		t.Errorf("archive formats must be exactly [tar.gz], got %v", archive.Formats)
	}
	if want := "jwtd-{{ .Os }}-{{ .Arch }}"; archive.NameTemplate != want {
		t.Errorf("archive name_template must be %q, got %q", want, archive.NameTemplate)
	}
	if len(archive.Files) == 0 {
		t.Fatal("archive files glob must be set so README/LICENSE are not implicitly added")
	}
	for _, glob := range archive.Files {
		for _, extra := range []string{"README.md", "LICENSE"} {
			if matched, err := filepath.Match(glob, extra); err != nil {
				t.Fatalf("invalid archive files glob %q: %v", glob, err)
			} else if matched {
				t.Errorf("archive files glob %q must not match %q; archives must stay binary-only", glob, extra)
			}
		}
	}
	if archive.BuildsInfo.Owner != "root" || archive.BuildsInfo.Group != "root" {
		t.Errorf("archive builds_info owner/group must be root/root, got %q/%q", archive.BuildsInfo.Owner, archive.BuildsInfo.Group)
	}
	if want := "1970-01-01T00:00:00Z"; archive.BuildsInfo.Mtime != want {
		t.Errorf("archive builds_info mtime must be the fixed epoch %q, got %q", want, archive.BuildsInfo.Mtime)
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

	// Syft SBOMs embed a random documentNamespace UUID and a creation
	// timestamp, so they are not byte-reproducible. Restricting the checksum
	// file to the "jwtd" id keeps checksums.txt itself reproducible. Without
	// this, every rerun would produce a different checksums.txt and the
	// release job's byte-for-byte verification of the signed file would fail.
	//
	// The archives and the nfpm packages both carry the "jwtd" id, so both are
	// covered by checksums.txt, while the SBOMs (id "archive") are excluded.
	if want := []string{"jwtd"}; !slices.Equal(cfg.Checksum.IDs, want) {
		t.Errorf("checksum.ids must be exactly %v so non-reproducible SBOMs stay out of checksums.txt, got %v", want, cfg.Checksum.IDs)
	}
	if cfg.Sboms[0].ID == "jwtd" {
		t.Error(`sboms id must not be "jwtd"; that would pull non-reproducible SBOMs into checksums.txt`)
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

	if len(cfg.Signs) != 1 {
		t.Fatalf("expected exactly one signs entry, got %d", len(cfg.Signs))
	}
	sign := cfg.Signs[0]
	if sign.Cmd != "cosign" {
		t.Errorf("signs cmd must be %q, got %q", "cosign", sign.Cmd)
	}
	if want := "checksum"; sign.Artifacts != want {
		t.Errorf("signs artifacts must be %q; signing the checksum file covers all listed artifacts, got %q", want, sign.Artifacts)
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

// releaseWorkflowStep models one step of a job in
// .github/workflows/release.yml.
type releaseWorkflowStep struct {
	Name string            `yaml:"name"`
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
	wantAssets = append(wantAssets, sbomNames()...)
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
	if !slices.Equal(slices.Sorted(slices.Values(nonReproducible)), slices.Sorted(slices.Values(wantNonReproducible))) {
		t.Errorf("release job nonreproducible_assets must be exactly %v, got %v", wantNonReproducible, nonReproducible)
	}
	reproducible := append([]string{"checksums.txt"}, releaseArchiveNames...)
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
