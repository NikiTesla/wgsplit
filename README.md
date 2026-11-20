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

Setup uses the `sing-box` executable already on your PATH. If it is missing, setup uses Go to build sing-box v1.14.4 with WireGuard and gVisor support. Run setup as your regular user with Go’s binary directory on PATH (see step 1). The first build downloads dependencies and may take a few minutes. [Upstream build options](https://sing-box.sagernet.org/installation/build-from-source/)

### 3. Import a profile and connect

Replace the example path with your WireGuard configuration. The first imported profile becomes the default. Disconnect any active WireGuard tunnel for that profile before starting wgsplit.

```sh
wgsplit profile import ~/Downloads/example.conf
wgsplit bypass add example.org
wgsplit start
wgsplit status
```

Adding a bypass is optional. In this example, new connections to `example.org` and its subdomains go directly. Other destinations use the tunnel. To remove the exception or disconnect:

```sh
wgsplit bypass remove example.org
wgsplit stop
```

## Managing profiles and bypass hosts

Import accepts a single-peer profile with an IPv4 default route, a numeric endpoint, and DNS server IP addresses. Keys and section names are matched case-insensitively, and a default route written as `0.0.0.0/1, 128.0.0.0/1` is accepted alongside `0.0.0.0/0`. Only the first `DNS` entry is used, because sing-box does not fail over between DNS servers. Importing a name that already exists fails unless you pass `--force`, so a second `wg0.conf` cannot overwrite the first profile and its private key. The first imported profile becomes the default. Use `wgsplit profile list` to see saved names and `wgsplit profile default NAME` to change the profile for the next start.

Run the CLI as your normal user. Background start and stop use sudo to manage a per-user job in the macOS system launchd domain. You can close the terminal and stop the job from another terminal. The job writes sing-box output to `/var/log/wgsplit.<uid>.log` and does not survive a reboot — run `wgsplit start` again afterwards. To switch a running background job to another profile, stop it, select the default, and start again. For interactive logs, use `wgsplit start --foreground` in the foreground; it holds the terminal until you stop it. `wgsplit start` and `wgsplit start --foreground` both refuse to start a second instance, because every generated profile claims the same tun addresses.

Both start modes register the TUN DNS address as a temporary macOS resolver. The registration expires when sing-box exits. Restart a running profile after upgrading wgsplit to activate it.

Profiles under `~/.sing-box/profiles/` contain private keys. The shared bypass list includes each named domain and its subdomains, and bypassed names are resolved outside the tunnel as well as routed outside it. New connections pick up edits automatically. Use `wgsplit bypass list` to see shared entries, even before importing a profile, and `wgsplit profile check` to validate the default profile.

## IPv6

sing-box captures the host's IPv6 traffic whenever the tun interface has an IPv6 address, which wgsplit always assigns. For a profile whose peer has no IPv6 route, that traffic cannot be carried and is dropped, so wgsplit sets the DNS strategy to `ipv4_only` for such profiles. Clients then never receive AAAA records and never attempt the dead path, and no IPv6 traffic escapes the tunnel. The tradeoff is that IPv6-only destinations are unreachable while an IPv4-only profile is up. A profile carrying both `::/0` in `AllowedIPs` and an IPv6 `Address` tunnels IPv6 normally and gets no DNS restriction.

## Security

Generated profiles and the bypass list live under `~/.sing-box/`, which is writable by your user, and `wgsplit start` runs sing-box as root with that config. Any process running as you can therefore change what the root sing-box reads. Treat `~/.sing-box/` as trusted: it offers no protection against local code already running under your account.

## License

wgsplit is distributed under the [MIT license](LICENSE).
