## Install script

jwtd can now be installed on macOS and Linux without a package manager:

```sh
curl -fsSL https://jwtd.sh/install.sh | sh
```

The script picks the release archive matching your OS and architecture, verifies it against the release's `checksums.txt` — and, when `cosign` is installed, verifies the keyless signature over that checksum file — then installs the binary into `~/.local/bin`. No root privileges are involved. Pin a release with `--version v5.3.0` or install elsewhere with `--dir /usr/local/bin`.

## WinGet is no longer updated

jwtd is no longer published to WinGet. The `WebCodr.jwtd` manifests already in `winget-pkgs` stay there but stop receiving new versions, so `winget install WebCodr.jwtd` will keep serving 5.2.0. On Windows, use the install script (`irm https://jwtd.sh/install.ps1 | iex`) or Scoop instead.
