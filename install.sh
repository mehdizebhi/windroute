#!/bin/sh
# windroute installer / updater for Linux.
#
# Install or update with a single command:
#
#   curl -fsSL https://raw.githubusercontent.com/mehdizebhi/windroute/main/install.sh | sh
#
# Environment variables:
#   WINDROUTE_VERSION       release tag to install (default: latest release)
#   WINDROUTE_PREFIX        install prefix (default: /usr/local)
#   WINDROUTE_DOWNLOAD_BASE override the download base URL (mirrors, testing)
#
# Examples:
#   # install a specific version
#   curl -fsSL .../install.sh | WINDROUTE_VERSION=v0.1.0 sh
#
#   # install into your home without sudo
#   curl -fsSL .../install.sh | WINDROUTE_PREFIX="$HOME/.local" sh
set -eu

REPO="mehdizebhi/windroute"
BIN="windroute"

say() { printf '%s\n' "$*"; }
die() { printf 'windroute-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# --- platform ---------------------------------------------------------------
os=$(uname -s)
[ "$os" = "Linux" ] || die "windroute only supports Linux (detected: $os)"

case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture: $(uname -m) (only amd64 and arm64 are built)" ;;
esac

# --- tools ------------------------------------------------------------------
need curl
need tar

sha_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
	sha_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	sha_cmd="shasum -a 256"
fi

# --- resolve version --------------------------------------------------------
version="${WINDROUTE_VERSION:-latest}"
if [ "$version" = "latest" ]; then
	version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
	[ -n "$version" ] || die "could not find the latest release for $REPO"
fi

asset="$BIN-linux-$arch.tar.gz"
base="${WINDROUTE_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download/$version}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $BIN $version (linux/$arch) ..."
curl -fsSL "$base/$asset" -o "$tmp/$asset" ||
	die "download failed: $base/$asset"

# --- verify (when possible) -------------------------------------------------
if [ -n "$sha_cmd" ] && curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" 2>/dev/null; then
	if grep " $asset\$" "$tmp/checksums.txt" > "$tmp/sum" 2>/dev/null; then
		(cd "$tmp" && $sha_cmd -c sum >/dev/null 2>&1) || die "checksum verification failed"
		say "Checksum verified."
	fi
fi

# --- extract ----------------------------------------------------------------
tar -xzf "$tmp/$asset" -C "$tmp" || die "failed to extract $asset"
[ -f "$tmp/$BIN" ] || die "archive did not contain the $BIN binary"
chmod 0755 "$tmp/$BIN"

# --- install ----------------------------------------------------------------
prefix="${WINDROUTE_PREFIX:-/usr/local}"
bindir="$prefix/bin"
target="$bindir/$BIN"

sudo_cmd=""
if [ "$(id -u)" -eq 0 ]; then
	sudo_cmd=""
elif mkdir -p "$bindir" 2>/dev/null && [ -w "$bindir" ]; then
	sudo_cmd=""
elif command -v sudo >/dev/null 2>&1; then
	sudo_cmd="sudo"
else
	die "$bindir is not writable; re-run as root or set WINDROUTE_PREFIX"
fi

$sudo_cmd mkdir -p "$bindir"

replaced="installed"
if [ -e "$target" ]; then
	replaced="updated"
fi

if command -v install >/dev/null 2>&1; then
	$sudo_cmd install -m 0755 "$tmp/$BIN" "$target"
else
	$sudo_cmd cp "$tmp/$BIN" "$target"
	$sudo_cmd chmod 0755 "$target"
fi

installed_version=$("$target" version 2>/dev/null || echo "$BIN $version")
say "$replaced: $installed_version -> $target"

case ":${PATH:-}:" in
	*":$bindir:"*) ;;
	*) say "note: $bindir is not in your PATH; add it to use the '$BIN' command" ;;
esac

say ""
say "Next steps:"
say "  $BIN doctor --proxy socks5://127.0.0.1:10808"
say "  sudo $BIN start --proxy socks5://127.0.0.1:10808 --connect wstunnel"
