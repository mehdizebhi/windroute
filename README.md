# windroute

Route the **Windscribe Desktop GUI** VPN through an existing **SOCKS5 / HTTP**
proxy on Linux — no second VPN, no system-wide TUN.

```text
Apps → Windscribe VPN → windroute → SOCKS5/HTTP proxy → Windscribe server → Internet
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/mehdizebhi/windroute/main/install.sh | sh
```

Re-run the same command any time to **update**. Installs prebuilt `linux/amd64`
and `linux/arm64` binaries from [GitHub Releases](https://github.com/mehdizebhi/windroute/releases).

To **uninstall** (removes the binary, windroute's nftables rules and its state):

```bash
curl -fsSL https://raw.githubusercontent.com/mehdizebhi/windroute/main/install.sh | sh -s -- --uninstall
```

<details>
<summary>Install options</summary>

```bash
# specific version
curl -fsSL .../install.sh | WINDROUTE_VERSION=v0.2.0 sh
# install to ~/.local/bin (no sudo)
curl -fsSL .../install.sh | WINDROUTE_PREFIX="$HOME/.local" sh
```
</details>

## Requirements

Linux with `nftables` and **cgroup v2**, the Windscribe Desktop app, a running
SOCKS5/HTTP proxy, and a **TCP** Windscribe protocol (`tcp`, `wstunnel` or
`stealth`). UDP/WireGuard is **not** supported in v0.1.

## Use

```bash
windroute doctor --proxy socks5://127.0.0.1:10808            # check the system
windroute test-proxy --proxy socks5://127.0.0.1:10808        # check the proxy
sudo windroute start --proxy socks5://127.0.0.1:10808 --connect wstunnel
windroute status
sudo windroute stop                                          # undo everything
```

Skip `--connect` to connect from the Windscribe GUI instead (use a TCP protocol).

## Commands

| Command | Description |
| --- | --- |
| `start --proxy <url>` | Start the redirect proxy and install nftables rules |
| `stop` | Remove the rules and stop the proxy (idempotent) |
| `status` | Show whether windroute is running |
| `inspect` | Show Windscribe processes/endpoints and the interception plan |
| `doctor` | Check the system for everything windroute needs |
| `test-proxy --proxy <url>` | Verify a proxy reaches a target (with a TLS probe) |
| `logs` | Show the redirect proxy log (`-f` to follow) |
| `uninstall` | Remove windroute's rules, state and the executable |

Proxy URLs: `socks5://`, `socks5h://`, `http://`, `https://` (optional `user:pass@`).
Key `start` flags: `--port` (default `10800`), `--connect`, `--location`,
`--cgroup`, `--exclude`, `--no-rules`.

## How it works

1. **Detect** — Windscribe's root `windscribe-helper.service` spawns the VPN
   daemon. windroute reads its **cgroup v2** path from `/proc`.
2. **Redirect** — one dedicated nftables table sends only that cgroup's **IPv4
   TCP** traffic to `127.0.0.1:<port>`, skipping loopback/private ranges so
   Windscribe's own control channel keeps working.
3. **Forward** — a tiny transparent proxy recovers the original destination
   with `SO_ORIGINAL_DST` and dials it through your proxy.

**No routing loop:** the redirect is scoped to Windscribe's cgroup, and
windroute's own process is in a different cgroup, so its proxy connection can
never be redirected back into itself. All changes live in one nftables table
plus one child process, which is why `stop` (and recovery after a crash) is
just removing them.

## Limitations (v0.1)

Windscribe TCP protocols only; UDP/WireGuard, IPv6 transports, TUN mode and a
GUI are out of scope for now.

## Build from source

```bash
go build -o windroute ./cmd/windroute     # or: make install
```

Tagging `vX.Y.Z` triggers the release workflow, which builds and publishes the
Linux binaries and checksums.

## Layout

```text
cmd/windroute/    thin entrypoint
internal/cli/     commands (start/stop/status/inspect/doctor/test-proxy)
internal/detect/  Windscribe process, cgroup and socket detection
internal/nft/     nftables ruleset generation and (un)install
internal/proxy/   SOCKS5/HTTP CONNECT dialing + transparent redirect server
internal/state/   runtime state under /run/windroute
internal/util/    small shared helpers
```
