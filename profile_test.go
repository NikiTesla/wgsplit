//go:build darwin

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const samplePrivateKey = "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTI="

func writeConf(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "uk.conf")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fullProfile() map[string]string {
	return map[string]string{
		"Address":    "10.8.0.2/32",
		"PrivateKey": samplePrivateKey,
		"PublicKey":  samplePrivateKey,
		"AllowedIPs": "0.0.0.0/0",
		"Endpoint":   "1.2.3.4:51820",
		"DNS":        "10.8.0.1",
	}
}

func TestParseProfile(t *testing.T) {
	path := writeConf(t, "\ufeff[interface]\n"+
		"privatekey = "+samplePrivateKey+"   # inline comment\n"+
		"Address = 10.8.0.2/32\n"+
		"Address = fd00::2/128\n"+
		"DNS = 10.8.0.1, 10.8.0.2,\n"+
		"MTU = 1420\n"+
		"\n"+
		"[Peer]\n"+
		"PublicKey = "+samplePrivateKey+"\n"+
		"AllowedIPs = 0.0.0.0/0\n"+
		"AllowedIPs = ::/0\n"+
		"Endpoint = 1.2.3.4:51820\n")
	fields, err := parse(path)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"Address":    "10.8.0.2/32,fd00::2/128",
		"AllowedIPs": "0.0.0.0/0,::/0",
		"DNS":        "10.8.0.1, 10.8.0.2,",
		"MTU":        "1420",
		"PrivateKey": samplePrivateKey,
		"Endpoint":   "1.2.3.4:51820",
	} {
		if fields[key] != want {
			t.Errorf("%s = %q, want %q", key, fields[key], want)
		}
	}
	// A trailing comma must not survive as an empty element.
	if got := items(fields["DNS"]); len(got) != 2 || got[1] != "10.8.0.2" {
		t.Errorf("DNS items = %q", got)
	}
}

func TestParseRejections(t *testing.T) {
	base := "[Interface]\nPrivateKey = " + samplePrivateKey + "\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1\n"
	peer := "[Peer]\nPublicKey = " + samplePrivateKey + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820\n"
	for _, tc := range []struct{ name, body, wantSubstring string }{
		{"repeated section", base + peer + "[Interface]\n", "repeated [Interface]"},
		{"key outside section", "PrivateKey = x\n", "comes before any"},
		{"unknown key", "[Interface]\nTable = off\n", `unsupported key "Table"`},
		{"wrong section", "[Interface]\nPublicKey = x\n", "belongs in [Peer]"},
		{"empty value", "[Interface]\nPrivateKey =\n", "has no value"},
		{"no equals", "[Interface]\ngarbage\n", "malformed line"},
		{"unknown section", "[Fish]\n", "unsupported section"},
		{"duplicate scalar", "[Interface]\nMTU = 1\nMTU = 2\n", "duplicate MTU"},
		{"missing dns", "[Interface]\nPrivateKey = k\nAddress = 10.8.0.2/32\n" + peer, "missing DNS"},
	} {
		_, err := parse(writeConf(t, tc.body))
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSubstring) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.wantSubstring)
		}
	}
}

// These are the fields that decide where traffic goes. A change here silently
// alters which packets leave the tunnel, and sing-box check cannot catch it.
func TestConfigRoutingInvariants(t *testing.T) {
	cfg, err := config(fullProfile(), "/tmp/bypass.json")
	if err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(object)
	if route["final"] != tunnelTag {
		t.Errorf("route.final = %v, want %q", route["final"], tunnelTag)
	}
	rules := route["rules"].([]object)
	last := rules[len(rules)-1]
	if last["outbound"] != directTag {
		t.Errorf("bypass rule outbound = %v, want %q", last["outbound"], directTag)
	}
	if got := last["rule_set"].([]string); len(got) != 1 || got[0] != bypassTag {
		t.Errorf("bypass rule set = %v", got)
	}
	dns := cfg["dns"].(object)
	servers := dns["servers"].([]object)
	if servers[0]["detour"] != tunnelTag {
		t.Errorf("primary resolver detour = %v, want %q", servers[0]["detour"], tunnelTag)
	}
	if dns["final"] != servers[0]["tag"] || route["default_domain_resolver"] != servers[0]["tag"] {
		t.Errorf("resolver tag mismatch: final=%v default=%v tag=%v", dns["final"], route["default_domain_resolver"], servers[0]["tag"])
	}
	// Bypassed names must resolve outside the tunnel too.
	dnsRules := dns["rules"].([]object)
	if dnsRules[0]["server"] != localResolver {
		t.Errorf("bypass DNS rule server = %v, want %q", dnsRules[0]["server"], localResolver)
	}
}

// An IPv4-only peer cannot carry the IPv6 the tun captures, so AAAA records
// must be withheld rather than handed to clients as a dead path.
func TestConfigIPv6Strategy(t *testing.T) {
	cfg, err := config(fullProfile(), "/tmp/bypass.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg["dns"].(object)["strategy"]; got != "ipv4_only" {
		t.Errorf("IPv4-only profile strategy = %v, want ipv4_only", got)
	}

	dual := fullProfile()
	dual["Address"] = "10.8.0.2/32,fd00::2/128"
	dual["AllowedIPs"] = "0.0.0.0/0,::/0"
	cfg, err = config(dual, "/tmp/bypass.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, set := cfg["dns"].(object)["strategy"]; set {
		t.Error("dual-stack profile should not restrict DNS to IPv4")
	}
}

func TestConfigAddressNormalisation(t *testing.T) {
	bare := fullProfile()
	bare["Address"] = "10.8.0.2"
	cfg, err := config(bare, "/tmp/bypass.json")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg["endpoints"].([]object)[0]["address"].([]string)
	if len(got) != 1 || got[0] != "10.8.0.2/32" {
		t.Errorf("address = %v, want [10.8.0.2/32]", got)
	}
}

func TestConfigFullTunnelDetection(t *testing.T) {
	for _, tc := range []struct {
		allowed string
		accept  bool
	}{
		{"0.0.0.0/0", true},
		{"0.0.0.0/1,128.0.0.0/1", true},
		{"0.0.0.0/0,::/0", true},
		{"::/0", false},
		{"10.0.0.0/8", false},
		{"0.0.0.0/1", false},
		{"not-a-prefix", false},
	} {
		f := fullProfile()
		f["AllowedIPs"] = tc.allowed
		_, err := config(f, "/tmp/bypass.json")
		if tc.accept && err != nil {
			t.Errorf("AllowedIPs %q rejected: %v", tc.allowed, err)
		}
		if !tc.accept && err == nil {
			t.Errorf("AllowedIPs %q accepted", tc.allowed)
		}
	}
}

func TestConfigRejections(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"hostname endpoint", "Endpoint", "vpn.example.com:51820"},
		{"endpoint without port", "Endpoint", "1.2.3.4"},
		{"zero port", "Endpoint", "1.2.3.4:0"},
		{"non-ip dns", "DNS", "dns.example.com"},
		{"bad address", "Address", "not-an-address"},
		{"bad mtu", "MTU", "banana"},
		{"bad keepalive", "PersistentKeepalive", "banana"},
	} {
		f := fullProfile()
		f[tc.key] = tc.value
		if _, err := config(f, "/tmp/bypass.json"); err == nil {
			t.Errorf("%s: accepted %s = %q", tc.name, tc.key, tc.value)
		}
	}
}

// The generated document must satisfy the real sing-box schema, not just ours.
func TestGeneratedConfigPassesSingBoxCheck(t *testing.T) {
	binary, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box not installed")
	}
	dir := t.TempDir()
	bypass := filepath.Join(dir, "direct-domains.json")
	if err := writeJSON(bypass, bypassList{listVersion, []rule{{[]string{"myip.com"}}}}); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []map[string]string{fullProfile(), dualStackProfile()} {
		cfg, err := config(profile, bypass)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "profile.json")
		if err := writeJSON(path, cfg); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(binary, "check", "-c", path).CombinedOutput()
		if err != nil {
			pretty, _ := json.MarshalIndent(cfg, "", "  ")
			t.Fatalf("sing-box check rejected the generated config: %v\n%s\n%s", err, out, pretty)
		}
	}
}

func dualStackProfile() map[string]string {
	f := fullProfile()
	f["Address"] = "10.8.0.2/32,fd00::2/128"
	f["AllowedIPs"] = "0.0.0.0/0,::/0"
	f["MTU"] = "1420"
	f["PersistentKeepalive"] = "25"
	f["PresharedKey"] = samplePrivateKey
	return f
}

// Regression: a /1 covers the half its first bit selects, not the half implied
// by the address it is written with, so 0.0.0.0/1 + 10.0.0.0/1 is two copies of
// the lower half and must not pass as a full tunnel.
func TestCoversDefaultIgnoresUnmaskedAddress(t *testing.T) {
	for _, tc := range []struct {
		allowed string
		full    bool
	}{
		{"0.0.0.0/1,128.0.0.0/1", true},
		{"0.0.0.0/1,255.0.0.0/1", true},
		{"0.0.0.0/1,10.0.0.0/1", false},
		{"0.0.0.0/1,1.2.3.4/1", false},
		{"10.0.0.0/1,20.0.0.0/1", false},
	} {
		f := fullProfile()
		f["AllowedIPs"] = tc.allowed
		_, err := config(f, "/tmp/bypass.json")
		if tc.full && err != nil {
			t.Errorf("AllowedIPs %q rejected: %v", tc.allowed, err)
		}
		if !tc.full && err == nil {
			t.Errorf("AllowedIPs %q accepted as a full tunnel", tc.allowed)
		}
	}
}
