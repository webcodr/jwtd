package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFlakeInvariants checks that the Nix flake builds jwtd from source with a
// pinned (non-placeholder) vendor hash and the same version/ldflags contract as
// the release build, and that the lock file is committed for reproducibility.
func TestFlakeInvariants(t *testing.T) {
	flake, err := os.ReadFile("flake.nix")
	if err != nil {
		t.Fatalf("flake.nix must exist: %v", err)
	}
	body := string(flake)

	for _, marker := range []string{
		"buildGoModule",        // build from source, as a nixpkgs package would
		"src = self;",          // build the repository checkout
		"main.version=",        // stamp the version like GoReleaser's ldflags
		`mainProgram = "jwtd"`, // so nix run resolves the jwtd binary
		"licenses.mit",         // metadata mirrors the project license
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("flake.nix must contain %q", marker)
		}
	}

	// The vendor hash must be pinned to a real value; the all-A placeholder
	// (lib.fakeHash) never builds, so a flake shipped with it is broken.
	if strings.Contains(body, "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Error("flake.nix vendorHash is still the fakeHash placeholder; fill it from the nix build error")
	}
	if !strings.Contains(body, `vendorHash = "sha256-`) {
		t.Error("flake.nix must pin vendorHash to a sha256- value")
	}

	// The lock file pins nixpkgs so flake builds are reproducible.
	if _, err := os.Stat("flake.lock"); err != nil {
		t.Errorf("flake.lock must be committed for reproducible builds: %v", err)
	}

	// CI must build the flake so a stale vendorHash (or any other flake
	// regression) fails the run instead of silently rotting until someone
	// builds it locally.
	testWorkflow, err := os.ReadFile(filepath.Join(".github", "workflows", "test.yml"))
	if err != nil {
		t.Fatalf("reading test workflow: %v", err)
	}
	tw := string(testWorkflow)
	if !strings.Contains(tw, "nix flake check") {
		t.Error("test workflow must run `nix flake check` to build and validate the flake")
	}
	if !strings.Contains(tw, "cachix/install-nix-action@") {
		t.Error("test workflow must install Nix via a pinned install-nix-action")
	}
}
