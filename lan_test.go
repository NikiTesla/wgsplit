//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLANRoutes(t *testing.T) {
	const up = net.FlagUp | net.FlagBroadcast
	for _, tc := range []struct {
		name    string
		iface   string
		flags   net.Flags
		address string
		want    string
		last    string
	}{
		{"Wi-Fi", "en0", up, "192.168.1.20/24", "192.168.1.0/24", "192.168.1.255"},
		{"link-local IPv4", "en0", up, "169.254.3.10/16", "169.254.0.0/16", "169.254.255.255"},
		{"Ethernet IPv6", "en12", up, "fd12::3/64", "fd12::/64", "fd12::ffff:ffff:ffff:ffff"},
		{"VPN", "utun4", net.FlagUp | net.FlagPointToPoint, "10.0.0.1/8", "", ""},
		{"bridge", "bridge100", up, "192.168.64.1/24", "", ""},
		{"down", "en2", net.FlagBroadcast, "192.168.0.1/24", "", ""},
		{"host only", "en0", up, "10.0.0.1/32", "", ""},
		{"default", "en0", up, "10.0.0.1/0", "", ""},
		{"scoped IPv6", "en0", up, "fe80::3/64", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iface := net.Interface{Name: tc.iface, Flags: tc.flags}
			routes := lanRoutes{}
			prefix := netip.MustParsePrefix(tc.address)
			if isLANInterface(iface) {
				routes.addInterface(iface.Name, []netip.Prefix{prefix, prefix})
			}
			if tc.want == "" {
				if len(routes.Rules) != 0 || len(routes.Outbounds) != 0 {
					t.Fatalf("unexpected bypass: %+v", routes)
				}
				return
			}
			if len(routes.Rules) != 1 || len(routes.Outbounds) != 1 {
				t.Fatalf("unexpected routes: %+v", routes)
			}
			outbound := routes.Outbounds[0]
			if outbound["bind_interface"] != tc.iface || outbound["type"] != directTag || routes.Rules[0][outboundField] != outbound["tag"] {
				t.Fatalf("wrong outbound: %+v", routes)
			}
			guards := routes.Rules[0]["rules"].([]object)
			if routes.Rules[0]["mode"] != "and" || len(guards) != 2 ||
				guards[0][cidrField] != tc.want ||
				guards[0][interfaceAddressField].(object)[tc.iface] != prefix.Masked().Addr().String() ||
				guards[1][interfaceAddressField].(object)[tc.iface] != tc.last {
				t.Fatalf("wrong destination: %+v", routes.Rules)
			}
		})
	}
}

func TestLANProfileStatus(t *testing.T) {
	const profile = "/Users/Test User/.sing-box/profiles/example.json"
	for _, tc := range []struct{ extra, want string }{
		{"", profile},
		{" -c /Users/Test User/.sing-box/runtime/lan.json", profile},
		{" -c /elsewhere/runtime/lan.json", ""},
		{" -c /Users/Test User/.sing-box/runtime/lan.json -c /another.json", ""},
	} {
		path, isRun := runningConfig("sing-box run -c " + profile + tc.extra)
		if !isRun || path != tc.want {
			t.Errorf("extra %q: got (%q, %v), want (%q, true)", tc.extra, path, isRun, tc.want)
		}
	}
}

func TestMergeLANConfig(t *testing.T) {
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box is not installed")
	}

	dir := t.TempDir()
	profiles := filepath.Join(dir, "profiles")
	if err := os.Mkdir(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(profiles, "existing.json")
	const original = `{ // existing profile with an explicit route
		"outbounds": [{"type":"direct","tag":"default"}],
		"route":{"final":"default","rules":[{"protocol":"dns","action":"hijack-dns"}]}
	}`
	if err := os.WriteFile(profile, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	routes := lanRoutes{}
	if path, err := routes.save(binary, profile); err != nil || path != "" {
		t.Fatalf("empty LAN config: %q, %v", path, err)
	}
	routes.addInterface("en0", []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")})
	path, err := routes.save(binary, profile)
	if err != nil {
		t.Fatal(err)
	}
	merged := filepath.Join(dir, "merged.json")
	if out, err := exec.Command(binary, "merge", merged, "-c", profile, "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("merge: %v: %s", err, out)
	}
	data, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct {
			Final string
			Rules []struct{ Action, Outbound string }
		}
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Route.Final != "default" || len(cfg.Route.Rules) != 2 || cfg.Route.Rules[0].Action != "hijack-dns" || cfg.Route.Rules[1].Outbound != "wgsplit-lan-en0" {
		t.Fatalf("unexpected merged routing: %+v", cfg.Route)
	}
	saved, err := os.ReadFile(profile)
	if err != nil || string(saved) != original {
		t.Fatalf("saved profile changed: %v", err)
	}

	if stale, err := (&lanRoutes{}).save(binary, profile); err != nil || stale != "" {
		t.Fatalf("empty LAN config after a saved one: %q, %v", stale, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale LAN config kept: %v", err)
	}
}
