#!/bin/sh
#
# jwtd installer for macOS and Linux.
#
# Downloads the release archive matching the detected OS and architecture,
# verifies it against the release's checksums.txt (and, when cosign is
# installed, verifies the keyless signature over that checksum file), then
# installs the binary into ~/.local/bin. No root privileges are required.
#
#   curl -fsSL https://jwtd.sh/install.sh | sh
#   curl -fsSL https://jwtd.sh/install.sh | sh -s -- --version v5.3.0
#   curl -fsSL https://jwtd.sh/install.sh | sh -s -- --dir /usr/local/bin
#
# Windows is served by Scoop and WinGet instead; see the README.

set -eu

REPO="webcodr/jwtd"
CERTIFICATE_IDENTITY_REGEXP="^https://github.com/webcodr/jwtd/\.github/workflows/release\.yml@"
CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"

info() {
	printf '%s\n' "$*" >&2
}

warn() {
	printf 'warning: %s\n' "$*" >&2
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

have() {
	command -v "$1" >/dev/null 2>&1
}

usage() {
	cat <<'EOF'
Install jwtd, a CLI that decodes and pretty-prints JWT, JWS, and JWE tokens.

Usage:
  install.sh [--version <tag>] [--dir <path>]

Options:
  -v, --version <tag>   Release to install (default: the latest release).
                        Accepts "5.3.0" or "v5.3.0".
  -d, --dir <path>      Installation directory (default: ~/.local/bin).
  -h, --help            Show this help.

Environment:
  JWTD_VERSION          Same as --version.
  JWTD_INSTALL_DIR      Same as --dir.

The archive is always verified against the release's checksums.txt. When
cosign is installed, the keyless Cosign bundle over checksums.txt is verified
as well.
EOF
}

# detect_os and detect_arch map uname output onto the GOOS/GOARCH pair used in
# the release archive names (jwtd-<os>-<arch>.tar.gz).
detect_os() {
	kernel=$(uname -s)
	case "$kernel" in
	Linux) printf 'linux\n' ;;
	Darwin) printf 'darwin\n' ;;
	*) die "unsupported operating system: $kernel (this script installs on Linux and macOS; on Windows use 'winget install WebCodr.jwtd' or Scoop)" ;;
	esac
}

detect_arch() {
	machine=$(uname -m)
	case "$machine" in
	x86_64 | amd64) printf 'amd64\n' ;;
	aarch64 | arm64) printf 'arm64\n' ;;
	*) die "unsupported architecture: $machine (release binaries are built for amd64 and arm64)" ;;
	esac
}

# Under Rosetta 2 a translated shell reports x86_64, which would install the
# Intel binary on Apple silicon. sysctl.proc_translated is set only in that
# case, so it distinguishes translation from a genuine Intel Mac.
correct_rosetta_arch() {
	if [ "$1" = "darwin" ] && [ "$2" = "amd64" ] && have sysctl &&
		[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0\n')" = "1" ]; then
		printf 'arm64\n'
	else
		printf '%s\n' "$2"
	fi
}

download() {
	url=$1
	destination=$2
	if have curl; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$destination" "$url" ||
			die "could not download $url (check the release tag and your network connection)"
	elif have wget; then
		wget -q --https-only -O "$destination" "$url" ||
			die "could not download $url (check the release tag and your network connection)"
	else
		die "neither curl nor wget is available; install one of them and re-run"
	fi
}

# verify_checksum matches the archive against its checksums.txt entry. The
# entry is selected by exact file name and written out verbatim so the
# checksum tool sees the original "<hash>  <name>" formatting.
verify_checksum() {
	archive=$1
	if ! awk -v want="$archive" '$2 == want { print $0; found = 1 } END { exit !found }' \
		checksums.txt >"$archive.sha256"; then
		die "checksums.txt has no entry for $archive"
	fi

	if have sha256sum; then
		sha256sum -c "$archive.sha256" >/dev/null ||
			die "checksum mismatch for $archive; refusing to install"
	elif have shasum; then
		shasum -a 256 -c "$archive.sha256" >/dev/null ||
			die "checksum mismatch for $archive; refusing to install"
	else
		die "neither sha256sum nor shasum is available; cannot verify the download"
	fi
	info "Checksum verified: $archive"
}

# verify_signature is best-effort by design: cosign is not a dependency most
# machines have, and the checksum above already pins the archive bytes. When
# cosign is present the bundle is verified and a failure is fatal.
verify_signature() {
	base_url=$1
	if ! have cosign; then
		info "cosign not found - skipping signature verification (install cosign to verify the release signature)"
		return
	fi

	download "$base_url/checksums.txt.sigstore.json" checksums.txt.sigstore.json
	cosign verify-blob \
		--bundle checksums.txt.sigstore.json \
		--certificate-identity-regexp "$CERTIFICATE_IDENTITY_REGEXP" \
		--certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER" \
		checksums.txt >/dev/null 2>&1 ||
		die "cosign could not verify checksums.txt against the jwtd release workflow; refusing to install"
	info "Signature verified: checksums.txt (cosign, keyless)"
}

# report_path_hint keeps the installer honest about the one thing it cannot do
# for the user: ~/.local/bin is not on every PATH by default.
report_path_hint() {
	directory=$1
	case ":$PATH:" in
	*":$directory:"*) return ;;
	esac

	warn "$directory is not on your PATH. Add it with one of:"
	# $PATH stays literal here: the hint is a command for the user to run.
	# shellcheck disable=SC2016
	printf '  bash/zsh: echo '\''export PATH="%s:$PATH"'\'' >> ~/.profile\n' "$directory" >&2
	printf '  fish:     fish_add_path %s\n' "$directory" >&2
}

version=${JWTD_VERSION-}
install_dir=${JWTD_INSTALL_DIR-}

while [ $# -gt 0 ]; do
	case "$1" in
	-v | --version)
		[ $# -ge 2 ] || die "--version requires a release tag"
		version=$2
		shift 2
		;;
	-d | --dir)
		[ $# -ge 2 ] || die "--dir requires a path"
		install_dir=$2
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "unknown option: $1 (run with --help for usage)"
		;;
	esac
done

[ -n "$install_dir" ] || install_dir="$HOME/.local/bin"
# The download happens from a temporary working directory, so a relative --dir
# has to be anchored to the caller's directory before that cd.
case "$install_dir" in
/*) ;;
*) install_dir="$PWD/$install_dir" ;;
esac

os=$(detect_os)
arch=$(detect_arch)
arch=$(correct_rosetta_arch "$os" "$arch")
archive="jwtd-$os-$arch.tar.gz"

if [ -n "$version" ]; then
	case "$version" in
	v*) ;;
	*) version="v$version" ;;
	esac
	base_url="https://github.com/$REPO/releases/download/$version"
	info "Installing jwtd $version ($os/$arch)"
else
	base_url="https://github.com/$REPO/releases/latest/download"
	info "Installing the latest jwtd release ($os/$arch)"
fi

work_dir=$(mktemp -d 2>/dev/null || mktemp -d -t jwtd-install)
staged=""
trap 'rm -rf "$work_dir"; [ -z "$staged" ] || rm -f "$staged"' EXIT INT HUP TERM
cd "$work_dir"

download "$base_url/$archive" "$archive"
download "$base_url/checksums.txt" checksums.txt
verify_checksum "$archive"
verify_signature "$base_url"

tar -xzf "$archive" jwtd
[ -f jwtd ] || die "the release archive did not contain a jwtd binary"

mkdir -p "$install_dir" || die "could not create $install_dir"

# Copy into the target directory first, then rename within it. A cross-device
# mv would rewrite the destination in place, which fails with ETXTBSY when the
# running shell's jwtd is being upgraded; rename(2) inside one filesystem
# replaces the old binary atomically instead.
installed="$install_dir/jwtd"
staged="$install_dir/.jwtd.install.$$"
cp jwtd "$staged" || die "could not write to $install_dir (choose another directory with --dir)"
chmod 0755 "$staged"
mv -f "$staged" "$installed" || die "could not install into $install_dir (choose another directory with --dir)"
staged=""

info "Installed $("$installed" --version 2>/dev/null || printf 'jwtd\n') to $installed"
report_path_hint "$install_dir"
