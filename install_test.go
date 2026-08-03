package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

func readPowerShellInstallScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("reading install.ps1: %v", err)
	}
	return string(data)
}

// powerShellCodeLines drops comment lines so that assertions about what the
// installer must not call are not satisfied by a comment explaining why it does
// not call it.
func powerShellCodeLines(script string) []string {
	var code []string
	for line := range strings.SplitSeq(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		code = append(code, line)
	}
	return code
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

func TestPowerShellInstallScriptContract(t *testing.T) {
	script := readPowerShellInstallScript(t)

	for label, required := range map[string]string{
		"parameter block":           "param(",
		"repository":                `$Repo = 'webcodr/jwtd'`,
		"default install directory": `Join-Path $env:LOCALAPPDATA 'Programs\jwtd'`,
		"latest release URL":        "releases/latest/download",
		"pinned release URL":        "releases/download/$releaseVersion",
		"checksum file":             "checksums.txt",
		"cosign bundle":             "checksums.txt.sigstore.json",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.ps1 is missing %s marker %q", label, required)
		}
	}

	// The script is piped into Invoke-Expression in an interactive session,
	// where `exit` terminates the user's shell rather than the installation.
	// Errors are raised with `throw` instead.
	if regexp.MustCompile(`(?m)^\s*exit\b`).MatchString(script) {
		t.Error("install.ps1 must not call exit: under `irm | iex` that closes the user's PowerShell session")
	}
	if !strings.Contains(script, "throw $Message") {
		t.Error("install.ps1 must abort by throwing so the failure does not close the caller's session")
	}

	// Preference variables are dynamically scoped. Setting them at the top
	// level of a script that is invoked through Invoke-Expression would leave
	// the user's own session with them applied afterwards.
	body := script[strings.Index(script, "function Install-Jwtd"):]
	if !strings.Contains(body, "$ErrorActionPreference = 'Stop'") {
		t.Error("install.ps1 must set $ErrorActionPreference = 'Stop' inside Install-Jwtd, not at script scope")
	}

	// The installer writes into a user-scoped directory and HKCU only. Any
	// elevation would make piping it into a shell a privilege decision, and a
	// machine-wide registry write would need that elevation.
	for _, line := range powerShellCodeLines(script) {
		for _, forbidden := range []string{"RunAs", "runas"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("install.ps1 must never elevate, found %q in %q", forbidden, strings.TrimSpace(line))
			}
		}
		if strings.Contains(line, "Set-ItemProperty") && !strings.Contains(line, "$UserEnvironmentKey") {
			t.Errorf("install.ps1 may only write to the user environment key, found %q", strings.TrimSpace(line))
		}
	}
}

// TestPowerShellInstallScriptTargetsReleaseArchives pins the asset naming to
// .goreleaser.yaml. The windows zips exist for WinGet; the installer consumes
// them because Expand-Archive is built in while tar.gz is not.
func TestPowerShellInstallScriptTargetsReleaseArchives(t *testing.T) {
	config, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatalf("reading .goreleaser.yaml: %v", err)
	}
	if !strings.Contains(string(config), "id: jwtd-zip") {
		t.Fatal(".goreleaser.yaml must publish the windows zip archives install.ps1 downloads")
	}
	if !strings.Contains(string(config), `name_template: "jwtd-{{ .Os }}-{{ .Arch }}"`) {
		t.Fatal(".goreleaser.yaml archive name template changed; install.ps1 builds asset names from it")
	}

	script := readPowerShellInstallScript(t)
	if !strings.Contains(script, `$archive = "jwtd-windows-$architecture.zip"`) {
		t.Error("install.ps1 must request jwtd-windows-<arch>.zip, matching the GoReleaser archive names")
	}
	for _, mapping := range []string{"'X64' { return 'amd64' }", "'Arm64' { return 'arm64' }"} {
		if !strings.Contains(script, mapping) {
			t.Errorf("install.ps1 is missing the architecture mapping %q", mapping)
		}
	}
	if !strings.Contains(script, "unsupported architecture:") {
		t.Error("install.ps1 must reject architectures with no release binary")
	}
	// PowerShell 7 also runs on macOS and Linux, which install.sh serves.
	if !strings.Contains(script, "unsupported operating system:") {
		t.Error("install.ps1 must reject non-Windows hosts and point at install.sh")
	}
}

// TestPowerShellInstallScriptVerifiesBeforeInstalling is the Windows half of
// TestInstallScriptVerifiesBeforeInstalling: nothing reaches the installation
// directory before the archive matches checksums.txt, and both installers trust
// exactly the same signing identity.
func TestPowerShellInstallScriptVerifiesBeforeInstalling(t *testing.T) {
	script := readPowerShellInstallScript(t)

	verify := strings.Index(script, "Test-Checksum -Archive $archive")
	if verify < 0 {
		t.Fatal("install.ps1 must verify the downloaded archive against checksums.txt")
	}
	extract := strings.Index(script, "Expand-Archive -Path $archive")
	if extract < 0 {
		t.Fatal("install.ps1 must extract the binary from the release archive")
	}
	stage := strings.Index(script, "Copy-Item -Path $binary -Destination $staged")
	if stage < 0 {
		t.Fatal("install.ps1 must stage the binary inside the install directory before renaming it into place")
	}
	if verify > extract || verify > stage {
		t.Error("install.ps1 must verify the checksum before extracting or installing the binary")
	}

	shell := readInstallScript(t)
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	for label, identity := range map[string]string{
		"certificate identity": `^https://github.com/webcodr/jwtd/\.github/workflows/release\.yml@`,
		"OIDC issuer":          "https://token.actions.githubusercontent.com",
	} {
		if !strings.Contains(script, identity) {
			t.Errorf("install.ps1 Cosign %s must be %q", label, identity)
		}
		if !strings.Contains(shell, identity) || !strings.Contains(string(readme), identity) {
			t.Errorf("install.sh and README.md Cosign %s must stay %q so every installer documents one trust root", label, identity)
		}
	}

	if !strings.Contains(script, "Write-Die 'cosign could not verify checksums.txt") {
		t.Error("install.ps1 must abort when cosign is installed and verification fails")
	}
}

// TestPowerShellInstallScriptUpgradesRunningBinary covers the one thing the
// Unix installer does not have to handle: Windows refuses to overwrite a
// running .exe, so an upgrade renames the old binary aside first.
func TestPowerShellInstallScriptUpgradesRunningBinary(t *testing.T) {
	script := readPowerShellInstallScript(t)

	retire := strings.Index(script, "Move-Item -Path $installed -Destination $retired")
	if retire < 0 {
		t.Fatal("install.ps1 must move an existing jwtd.exe aside; Windows cannot overwrite a running binary")
	}
	install := strings.Index(script, "Move-Item -Path $staged -Destination $installed")
	if install < 0 {
		t.Fatal("install.ps1 must move the staged binary into place")
	}
	if retire > install {
		t.Error("install.ps1 must retire the old binary before moving the new one into place")
	}
	if !strings.Contains(script, "Remove-Item -Path $retired -Force -ErrorAction SilentlyContinue") {
		t.Error("deleting the retired binary must be best-effort: it fails while an older jwtd is still running")
	}
}

// TestPowerShellInstallScriptEditsUserPathSafely holds down the registry
// handling. [Environment]::SetEnvironmentVariable expands %USERPROFILE%-style
// entries and writes the expanded text back as a plain string, corrupting parts
// of the PATH the installer never touched.
func TestPowerShellInstallScriptEditsUserPathSafely(t *testing.T) {
	script := readPowerShellInstallScript(t)

	for _, line := range powerShellCodeLines(script) {
		if strings.Contains(line, "SetEnvironmentVariable") {
			t.Errorf("install.ps1 must not use [Environment]::SetEnvironmentVariable for PATH - it expands and rewrites unrelated entries - found %q", strings.TrimSpace(line))
		}
	}
	for label, required := range map[string]string{
		"user environment key": `$UserEnvironmentKey = 'HKCU:\Environment'`,
		"unexpanded read":      "[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames",
		"expandable write":     "-Type ExpandString",
		"opt-out":              "$skipPath",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.ps1 PATH handling is missing the %s marker %q", label, required)
		}
	}
}

// TestPowerShellInstallScriptPublication covers the delivery path, mirroring
// TestInstallScriptPublication.
func TestPowerShellInstallScriptPublication(t *testing.T) {
	pages, err := os.ReadFile(filepath.Join(".github", "workflows", "pages.yml"))
	if err != nil {
		t.Fatalf("reading Pages workflow: %v", err)
	}
	if !strings.Contains(string(pages), "install -m 0644 install.ps1 site/install.ps1") {
		t.Error("Pages workflow must copy install.ps1 into the site artifact so jwtd.sh/install.ps1 serves it")
	}
	if !strings.Contains(string(pages), `- "install.ps1"`) {
		t.Error("Pages workflow must redeploy when install.ps1 changes")
	}

	const oneLiner = "irm https://jwtd.sh/install.ps1 | iex"
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
	block := `<code id="windows-script-command">` + oneLiner + `</code>`
	if !strings.Contains(string(index), block) {
		t.Errorf("site/index.html must offer the install script in the Windows panel: %q", block)
	}

	// The copy lives in the Pages artifact only; a committed one would be a
	// second source of truth that could drift from the reviewed script.
	ignore, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("reading .gitignore: %v", err)
	}
	if !strings.Contains(string(ignore), "site/install.ps1") {
		t.Error(".gitignore must exclude site/install.ps1; it is generated by the Pages workflow")
	}
}
