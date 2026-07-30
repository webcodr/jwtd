## Install script

jwtd can now be installed on macOS and Linux without a package manager:

```sh
curl -fsSL https://jwtd.sh/install.sh | sh
```

The script picks the release archive matching your OS and architecture, verifies it against the release's `checksums.txt` — and, when `cosign` is installed, verifies the keyless signature over that checksum file — then installs the binary into `~/.local/bin`. No root privileges are involved. Pin a release with `--version v5.3.0` or install elsewhere with `--dir /usr/local/bin`.
