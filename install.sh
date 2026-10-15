#!/bin/sh
# windroute installer / updater / uninstaller for Linux.
#
# Install or update with a single command:
#
#   curl -fsSL https://raw.githubusercontent.com/mehdizebhi/windroute/main/install.sh | sh
#
# Uninstall (removes the binary, windroute's nftables rules and its state):
#
#   curl -fsSL https://raw.githubusercontent.com/mehdizebhi/windroute/main/install.sh | sh -s -- --uninstall
#
# Environment variables:
#   WINDROUTE_VERSION       release tag to install (default: latest release)
#   WINDROUTE_PREFIX        install prefix (default: /usr/local)
#   WINDROUTE_STATE_DIR     state directory (default: /run/windroute)
#   WINDROUTE_DOWNLOAD_BASE override the download base URL (mirrors, testing)
#
# Examples:
#   # install a specific version
#   curl -fsSL .../install.sh | WINDROUTE_VERSION=v0.2.0 sh
#
#   # install into your home without sudo
#   curl -fsSL .../install.sh | WINDROUTE_PREFIX="$HOME/.local" sh
set -eu

REPO="mehdizebhi/windroute"
BIN="windroute"

say() { printf '%s\n' "$*"; }
die() { printf 'windroute-install: error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

usage() {
	cat <<'EOF'
windroute installer / updater / uninstaller

Usage:
  install.sh                 install or update windroute
  install.sh --uninstall     remove windroute

Environment:
  WINDROUTE_VERSION          release tag to install (default: latest)
  WINDROUTE_PREFIX           install prefix (default: /usr/local)
  WINDROUTE_STATE_DIR        state directory (default: /run/windroute)
  WINDROUTE_DOWNLOAD_BASE    override the download base URL
EOF
}

# Pick the command prefix needed to write to a directory ("" when already
# writable, "sudo" otherwise). Fails when neither is possible.
root_cmd_for() {
	dir="$1"
	if [ "$(id -u)" -eq 0 ]; then
		printf ''
	elif mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then
		printf ''
	elif command -v sudo >/dev/null 2>&1; then
		printf 'sudo'
	else
		die "$dir is not writable; re-run as root or set WINDROUTE_PREFIX"
	fi
}

# try_as_root runs a command directly and falls back to sudo only if needed.
try_as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
		return $?
	fi
	if "$@" 2>/dev/null; then
		return 0
	fi
	if command -v sudo >/dev/null 2>&1; then
		sudo "$@"
		return $?
	fi
	return 1
}

# --- uninstall --------------------------------------------------------------
do_uninstall() {
	prefix="${WINDROUTE_PREFIX:-/usr/local}"
	bindir="$prefix/bin"
	target="$bindir/$BIN"
	statedir="${WINDROUTE_STATE_DIR:-/run/windroute}"

	# Undo networking changes and stop the proxy using the installed binary.
	if [ -x "$target" ]; then
		try_as_root "$target" stop >/dev/null 2>&1 || true
	elif command -v "$BIN" >/dev/null 2>&1; then
		try_as_root "$BIN" stop >/dev/null 2>&1 || true
	fi

	if [ -e "$statedir" ]; then
		try_as_root rm -rf "$statedir" || die "could not remove $statedir"
		say "removed state directory $statedir"
	fi

	if [ -e "$target" ]; then
		try_as_root rm -f "$target" || die "could not remove $target"
		say "removed $target"
	else
		say "no binary found at $target"
	fi

	say "windroute uninstalled"
}

# --- argument handling ------------------------------------------------------
case "${1:-}" in
	--uninstall | -u)
		do_uninstall
		exit 0
		;;
	--help | -h)
		usage
		exit 0
		;;
	"") ;;
	*) die "unknown argument: $1 (try --help)" ;;
esac

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

sudo_cmd=$(root_cmd_for "$bindir")
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
say ""
say "Uninstall with:  $BIN uninstall   (or re-run this script with --uninstall)"
