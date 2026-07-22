{
  description = "Decode and pretty-print JSON Web Tokens with syntax highlighting";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # nixpkgs unstable has dropped x86_64-darwin, so the source build targets
      # Linux (amd64/arm64) and Apple Silicon; Intel macOS users have Homebrew
      # and the release archives.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
      # Source builds report the commit they were built from; tagged release
      # binaries carry the semantic version via GoReleaser's ldflags.
      version = self.shortRev or self.dirtyShortRev or "dev";
    in
    {
      packages = forAllSystems (system: pkgs: rec {
        jwtd = pkgs.buildGoModule {
          pname = "jwtd";
          inherit version;
          src = self;
          vendorHash = "sha256-GZq7U30h1fOrHcDZ+6BPrC6sgIr6u4deGMz5vC/lqFU=";
          # Match the release build: strip symbols and stamp main.version.
          ldflags = [
            "-s"
            "-w"
            "-X"
            "main.version=${version}"
          ];
          meta = {
            description = "Decode and pretty-print JSON Web Tokens with syntax highlighting";
            homepage = "https://github.com/webcodr/jwtd";
            license = pkgs.lib.licenses.mit;
            mainProgram = "jwtd";
          };
        };
        default = jwtd;
      });

      apps = forAllSystems (system: pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/jwtd";
        };
      });

      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.goreleaser
          ];
        };
      });

      formatter = forAllSystems (system: pkgs: pkgs.nixfmt-rfc-style);
    };
}
