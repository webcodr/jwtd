package main

import (
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
		NameTemplate string `yaml:"name_template"`
		Algorithm    string `yaml:"algorithm"`
	} `yaml:"checksum"`
	Changelog struct {
		Disable bool `yaml:"disable"`
	} `yaml:"changelog"`
	Release struct {
		Disable bool `yaml:"disable"`
	} `yaml:"release"`
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

// releaseWorkflow models the subset of .github/workflows/release.yml needed
// to check the release security invariants.
type releaseWorkflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Jobs        map[string]struct {
		Needs yaml.Node `yaml:"needs"`
		Steps []struct {
			Name string `yaml:"name"`
			Uses string `yaml:"uses"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
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
				if expr := strings.TrimSpace(match[1]); !strings.HasPrefix(expr, "matrix.") {
					t.Errorf("job %q step %q: run script interpolates %q; pass untrusted values through env instead", jobName, stepName, match[0])
				}
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
