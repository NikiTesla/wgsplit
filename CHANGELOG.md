# Changelog

## Unreleased

- Read the IPv4 TUN address from the profile and show it with its DNS peer in `wgsplit profile check`. Startup requires the first host of a /30 in an RFC 1918 range or `198.18.0.0/15` and refuses to start if the /30 overlaps a local interface subnet.
- Send connections to devices on directly connected Wi-Fi and Ethernet subnets through the LAN. Existing profiles pick this up on the next start.
- Require sing-box 1.13.0 or newer built with `with_wireguard`, and explain an unsupported build before importing or starting a profile.
- Group profile and bypass commands, support `start --foreground`, and allow editing the shared bypass list before importing a profile. Existing command spellings remain available.
- Add `wgsplit setup` for sing-box installation on macOS and license wgsplit under MIT.
- Register the tunnel DNS address as a temporary macOS resolver for both start modes. Restart a running profile after upgrading to activate it.
