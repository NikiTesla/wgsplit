# wgsplit

A macOS CLI for using WireGuard as the default sing-box route and sending selected hostnames directly. It uses the installed sing-box binary.

## Install

### 1. Install wgsplit once

On macOS with Go 1.26 or newer, run this from the cloned repository:

```sh
go install .
wgsplit --help
```

If your shell cannot find `wgsplit`, add Go’s install directory to your PATH. For zsh, put these lines in `~/.zshrc` and open a new terminal:

```sh
go_bin="$(go env GOBIN)"
export PATH="${go_bin:-$(go env GOPATH)/bin}:$PATH"
```

### 2. Set up sing-box

```sh
wgsplit setup
```

Setup uses the `sing-box` executable already on your PATH. It must be version 1.13.0 or newer and built with WireGuard support (`with_wireguard`); wgsplit refuses an older or unsupported build. If it is missing, setup uses Go to build sing-box v1.14.4 with WireGuard and gVisor support. Run setup as your regular user with Go’s binary directory on PATH (see step 1). The first build downloads dependencies and may take a few minutes. [Upstream build options](https://sing-box.sagernet.org/installation/build-from-source/)

### 3. Import a profile and connect

Replace the example path with your WireGuard configuration. The first imported profile becomes the default. Disconnect any active WireGuard tunnel for that profile before starting wgsplit.

```sh
wgsplit profile import ~/Downloads/example.conf
wgsplit bypass add example.org
wgsplit start
wgsplit status
```

Adding a bypass is optional. In this example, new connections to `example.org` and its subdomains go directly. Devices on the connected LAN also go directly. Other destinations use the tunnel. To remove the exception or disconnect:

```sh
wgsplit bypass remove example.org
wgsplit stop
```

## Managing profiles and bypass hosts

Import accepts a single-peer profile with an IPv4 default route, a numeric endpoint, and DNS server IP addresses. Keys and section names are matched case-insensitively, and a default route written as `0.0.0.0/1, 128.0.0.0/1` is accepted alongside `0.0.0.0/0`. Only the first `DNS` entry is used, because sing-box does not fail over between DNS servers. Importing a name that already exists fails unless you pass `--force`, so a second `wg0.conf` cannot overwrite the first profile and its private key. The first imported profile becomes the default. Use `wgsplit profile list` to see saved names and `wgsplit profile default NAME` to change the profile for the next start.

Run the CLI as your normal user. Background start and stop use sudo to manage a per-user job in the macOS system launchd domain. You can close the terminal and stop the job from another terminal. The job writes sing-box output to `/var/log/wgsplit.<uid>.log` and does not survive a reboot — run `wgsplit start` again afterwards. To switch a running background job to another profile, stop it, select the default, and start again. For interactive logs, use `wgsplit start --foreground` in the foreground; it holds the terminal until you stop it. `wgsplit start` and `wgsplit start --foreground` both refuse to start a second instance, because every generated profile claims the same tun addresses.

Both start modes register the TUN DNS address as a temporary macOS resolver. The registration expires when sing-box exits. Restart a running profile after upgrading wgsplit to activate it.

Run `wgsplit profile check` to see the IPv4 TUN address and DNS peer for the selected profile. wgsplit derives the peer from the first IPv4 TUN address. Keep a working profile as it is.

If another VPN captures **only the DNS route**, choose a subnet for your own network:

1. With wgsplit stopped and the other VPN connected, inspect `netstat -rn -f inet` and `ifconfig`. Choose an unused `/30` within `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, or the benchmarking range `198.18.0.0/15`. Check for overlap with LANs, VPN resources, and any proxy's FakeIP pool. If both VPNs claim the same default routes, disconnect one before starting the other.
2. In the selected profile under `~/.sing-box/profiles/`, edit the IPv4 entry in the **TUN inbound**'s `address` list. Use the first host in the chosen `/30`. For a block ending in `.16/30`, for example, the TUN uses `.17/30` and the DNS peer is `.18`. Leave `dns_address` unset for automatic derivation. Run `wgsplit profile check` to confirm the pair.
3. Start wgsplit. It checks for overlap with local interface addresses and waits for the DNS peer's route to use the TUN carrying the configured address. After reconnecting another VPN, check `route -n get -inet DNS_PEER` (substitute the printed IP) and `ifconfig INTERFACE` (use the interface from that route). If the interface no longer carries the configured TUN address, stop wgsplit and resolve the conflict before restarting. wgsplit checks route ownership at startup.

**Re-importing resets the TUN address.** Replacing the profile with `wgsplit profile import --force` restores `172.19.0.1/30` and its DNS peer `172.19.0.2`. If you chose a different subnet, reapply your TUN address and confirm the pair with `wgsplit profile check` before starting the tunnel.

At startup, wgsplit reads the IPv4 and IPv6 subnets on active macOS Wi-Fi and Ethernet interfaces (`en0`, `en1`, and so on). New connections to devices on those subnets go directly through the corresponding interface. For example, on `192.168.1.20/24`, a connection to `192.168.1.36` uses the LAN. Private addresses outside the connected subnets still follow your existing routing rules. IPv6 link-local addresses use interface scopes and are excluded from this bypass.

This applies to existing profiles on the next start. wgsplit writes the LAN rules separately in `~/.sing-box/runtime/lan.json`. Your profile's DNS and explicit routing rules take precedence. Restart wgsplit after switching networks to discover the new subnets.

Profiles under `~/.sing-box/profiles/` contain private keys. The shared bypass list includes each named domain and its subdomains, and bypassed names are resolved outside the tunnel as well as routed outside it. New connections pick up edits automatically. Use `wgsplit bypass list` to see shared entries, even before importing a profile, and `wgsplit profile check` to validate the default profile.

## IPv6

sing-box captures the host's IPv6 traffic whenever the tun interface has an IPv6 address, which wgsplit always assigns. For a profile whose peer has no IPv6 route, that traffic cannot be carried and is dropped, so wgsplit sets the DNS strategy to `ipv4_only` for such profiles. Clients then never receive AAAA records and never attempt the dead path for those lookups. Explicit bypasses, including directly connected LAN subnets, can still carry IPv6. IPv6-only destinations routed through WireGuard are unreachable while an IPv4-only profile is up. A profile carrying both `::/0` in `AllowedIPs` and an IPv6 `Address` tunnels IPv6 normally and gets no DNS restriction.

## Security

Generated profiles and the bypass list live under `~/.sing-box/`, which is writable by your user, and `wgsplit start` runs sing-box as root with that config. Any process running as you can therefore change what the root sing-box reads. Treat `~/.sing-box/` as trusted: it offers no protection against local code already running under your account.

## License

wgsplit is distributed under the [MIT license](LICENSE).
