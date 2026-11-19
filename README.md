# wgsplit

A macOS CLI for using WireGuard as the default sing-box route and sending selected hostnames directly. It uses the installed sing-box binary.

## Install

Install Go and sing-box with WireGuard support, then run `go install .` in this directory. Add your Go binary directory to PATH. The CLI has been tested with sing-box 1.14.4.

## Usage

```sh
wgsplit import ~/Downloads/example.conf
wgsplit add example.org
wgsplit start
wgsplit status
wgsplit remove example.org
wgsplit stop
```

Import accepts a single-peer profile with an IPv4 default route, a numeric endpoint, and DNS server IP addresses. The first imported profile becomes the default. Use `wgsplit list` to see saved names and `wgsplit default NAME` to change the profile for the next start.

Deactivate an existing tunnel before starting its replacement. Run the CLI as your normal user. Background start and stop use sudo to manage a per-user job in the macOS system launchd domain. You can close the terminal and stop the job from another terminal. To switch a running background job to another profile, stop it, select the default, and start again. For interactive logs, use `wgsplit run` in the foreground.

Profiles under `~/.sing-box/profiles/` contain private keys. The shared bypass list includes each named domain and its subdomains. New connections pick up edits automatically. Use `wgsplit show` to see profiles and bypass hostnames and `wgsplit check` to validate the default profile.
