package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readInstallScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("reading install.sh: %v", err)
	}
	return string(data)
}

// runInstallScript executes install.sh with the given arguments and an
// optional directory prepended to PATH, so stubbed uname binaries can drive
// the platform detection without touching the network.
func runInstallScript(t *testing.T, pathPrefix string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{"install.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "JWTD_VERSION=", "JWTD_INSTALL_DIR=")
	if pathPrefix != "" {
		cmd.Env = append(cmd.Env, "PATH="+pathPrefix+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// stubUname writes a uname replacement reporting the given `uname -s` and
// `uname -m` values.
func stubUname(t *testing.T, kernel, machine string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\n-s) echo " + kernel + " ;;\n-m) echo " + machine + " ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "uname"), []byte(script), 0o755); err != nil {
		t.Fatalf("writing uname stub: %v", err)
	}
	return dir
}

func TestInstallScriptContract(t *testing.T) {
	info, err := os.Stat("install.sh")
	if err != nil {
		t.Fatalf("install.sh must exist: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("install.sh must be executable, got mode %v", info.Mode().Perm())
	}

	script := readInstallScript(t)
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Error("install.sh must run under POSIX sh, not bash: it is piped into whatever /bin/sh users have")
	}
	if !strings.Contains(script, "set -eu") {
		t.Error("install.sh must set -eu so a failed step aborts instead of continuing")
	}

	for label, required := range map[string]string{
		"default install directory": `install_dir="$HOME/.local/bin"`,
		"repository":                `REPO="webcodr/jwtd"`,
		"latest release URL":        "releases/latest/download",
		"pinned release URL":        "releases/download/$version",
		"checksum file":             "checksums.txt",
		"cosign bundle":             "checksums.txt.sigstore.json",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.sh is missing %s marker %q", label, required)
		}
	}

	// The installer writes into a user directory only. A sudo call would make
	// piping it into a shell a privilege-escalation decision.
	if strings.Contains(script, "sudo") {
		t.Error("install.sh must never invoke sudo; it installs into a user-writable directory")
	}
}

// TestInstallScriptTargetsReleaseArchives pins the archive naming to
// .goreleaser.yaml. A rename there would otherwise leave the installer
// requesting assets no release publishes.
func TestInstallScriptTargetsReleaseArchives(t *testing.T) {
	config, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	if !strings.Contains(string(config), `name_template: "jwtd-{{ .Os }}-{{ .Arch }}"`) {
		t.Fatal(".goreleaser.yaml archive name template changed; install.sh builds asset names from it")
	}

	script := readInstallScript(t)
	if !strings.Contains(script, `archive="jwtd-$os-$arch.tar.gz"`) {
		t.Error("install.sh must request jwtd-<os>-<arch>.tar.gz, matching the GoReleaser archive names")
	}
	// Only the four macOS/Linux targets are reachable; windows archives exist
	// but are served by Scoop and WinGet.
	for _, mapping := range []string{"Linux) printf 'linux\\n'", "Darwin) printf 'darwin\\n'"} {
		if !strings.Contains(script, mapping) {
			t.Errorf("install.sh is missing the OS mapping %q", mapping)
		}
	}
	for _, mapping := range []string{"x86_64 | amd64) printf 'amd64\\n'", "aarch64 | arm64) printf 'arm64\\n'"} {
		if !strings.Contains(script, mapping) {
			t.Errorf("install.sh is missing the architecture mapping %q", mapping)
		}
	}
}

// TestInstallScriptVerifiesBeforeInstalling holds down the property that makes
// a curl-into-shell installer defensible: nothing reaches the install
// directory before the archive has been checked against checksums.txt, and the
// Cosign identity is the one the release workflow signs with.
func TestInstallScriptVerifiesBeforeInstalling(t *testing.T) {
	script := readInstallScript(t)

	verify := strings.Index(script, `verify_checksum "$archive"`)
	if verify < 0 {
		t.Fatal("install.sh must verify the downloaded archive against checksums.txt")
	}
	extract := strings.Index(script, `tar -xzf "$archive" jwtd`)
	if extract < 0 {
		t.Fatal("install.sh must extract the binary from the release archive")
	}
	stage := strings.Index(script, `cp jwtd "$staged"`)
	if stage < 0 {
		t.Fatal("install.sh must stage the binary inside the install directory before renaming it into place")
	}
	if verify > extract || verify > stage {
		t.Error("install.sh must verify the checksum before extracting or installing the binary")
	}

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	for label, identity := range map[string]string{
		"certificate identity": `^https://github.com/webcodr/jwtd/\.github/workflows/release\.yml@`,
		"OIDC issuer":          "https://token.actions.githubusercontent.com",
	} {
		if !strings.Contains(script, identity) {
			t.Errorf("install.sh Cosign %s must be %q", label, identity)
		}
		if !strings.Contains(string(readme), identity) {
			t.Errorf("README.md Cosign %s must stay %q so both document the same trust root", label, identity)
		}
	}

	// cosign is optional, but when present its verdict is fatal.
	if !strings.Contains(script, `die "cosign could not verify checksums.txt`) {
		t.Error("install.sh must abort when cosign is installed and verification fails")
	}
}

func TestInstallScriptRejectsUnsupportedPlatforms(t *testing.T) {
	for name, testCase := range map[string]struct {
		kernel  string
		machine string
		want    string
	}{
		"unsupported kernel":       {kernel: "SunOS", machine: "x86_64", want: "unsupported operating system"},
		"windows kernel":           {kernel: "MINGW64_NT-10.0", machine: "x86_64", want: "unsupported operating system"},
		"unsupported architecture": {kernel: "Linux", machine: "mips64", want: "unsupported architecture"},
	} {
		t.Run(name, func(t *testing.T) {
			output, err := runInstallScript(t, stubUname(t, testCase.kernel, testCase.machine))
			if err == nil {
				t.Fatalf("install.sh must fail on %s/%s, got output %q", testCase.kernel, testCase.machine, output)
			}
			if !strings.Contains(output, testCase.want) {
				t.Errorf("install.sh must report %q for %s/%s, got %q", testCase.want, testCase.kernel, testCase.machine, output)
			}
			if strings.Contains(output, "Installing") {
				t.Errorf("install.sh must reject the platform before downloading anything, got %q", output)
			}
		})
	}
}

func TestInstallScriptUsage(t *testing.T) {
	output, err := runInstallScript(t, "", "--help")
	if err != nil {
		t.Fatalf("install.sh --help must exit zero: %v (%s)", err, output)
	}
	for _, required := range []string{"--version", "--dir", "JWTD_VERSION", "JWTD_INSTALL_DIR", "~/.local/bin"} {
		if !strings.Contains(output, required) {
			t.Errorf("install.sh --help must document %q, got %q", required, output)
		}
	}

	if output, err := runInstallScript(t, "", "--not-a-flag"); err == nil {
		t.Errorf("install.sh must reject unknown options, got %q", output)
	}
	if output, err := runInstallScript(t, "", "--dir"); err == nil {
		t.Errorf("install.sh must reject --dir without a value, got %q", output)
	}
}

// TestInstallScriptPublication covers the delivery path: the script is hosted
// at https://jwtd.sh/install.sh by copying the repository copy into the Pages
// artifact, so the documented one-liner cannot drift from the reviewed file.
func TestInstallScriptPublication(t *testing.T) {
	pages, err := os.ReadFile(filepath.Join(".github", "workflows", "pages.yml"))
	if err != nil {
		t.Fatalf("reading Pages workflow: %v", err)
	}
	if !strings.Contains(string(pages), "install -m 0755 install.sh site/install.sh") {
		t.Error("Pages workflow must copy install.sh into the site artifact so jwtd.sh/install.sh serves it")
	}
	if !strings.Contains(string(pages), `- "install.sh"`) {
		t.Error("Pages workflow must redeploy when install.sh changes")
	}

	const oneLiner = "curl -fsSL https://jwtd.sh/install.sh | sh"
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	if !strings.Contains(string(readme), oneLiner) {
		t.Errorf("README.md must document %q", oneLiner)
	}

	index, err := os.ReadFile(filepath.Join("site", "index.html"))
	if err != nil {
		t.Fatalf("reading site/index.html: %v", err)
	}
	for _, id := range []string{"macos-script-command", "linux-script-command"} {
		block := `<code id="` + id + `">` + oneLiner + `</code>`
		if !strings.Contains(string(index), block) {
			t.Errorf("site/index.html must offer the install script in the %s block: %q", id, block)
		}
	}
}
