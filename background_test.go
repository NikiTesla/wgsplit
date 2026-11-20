//go:build darwin

package main

import (
	"encoding/xml"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestJobArguments(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "example & test.json")
	if err := os.WriteFile(profile, []byte(`{ // default profile
		"inbounds":[{"type":"tun","address":["172.19.0.1/30"]}]
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	addr, err := tunIPv4Address(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	argv := runArguments("/bin/sing-box", profile, addr)
	const logFile = "/var/log/wgsplit.501.log"
	decoder := xml.NewDecoder(strings.NewReader(string(jobPlist("test.job", argv, logFile))))
	var values []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if tag, ok := token.(xml.StartElement); ok && tag.Name.Local == "string" {
			var value string
			if err := decoder.DecodeElement(&value, &tag); err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
	}
	script := argv[2]
	want := []string{"test.job", "/bin/bash", "-c", script, "wgsplit", "/bin/sing-box", profile, "172.19.0.1", "172.19.0.2", logFile, logFile}
	if !slices.Equal(values, want) {
		t.Fatalf("unexpected plist strings %q", values)
	}
}

// Exercise the same bash and fd inheritance as launchd without changing host DNS.
func TestRunWithTemporaryDNS(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DNS_TEST_DIR", dir)
	scutil := filepath.Join(dir, "scutil")
	if err := os.WriteFile(scutil, []byte(`#!/bin/sh
if [ "$1" = -w ]; then
    if [ ! -f "$DNS_TEST_DIR/first-check" ]; then
        touch "$DNS_TEST_DIR/first-check"
        exit 1
    fi
    for i in 1 2 3 4 5 6 7 8 9 10; do
        grep -Fqx "add $2 temporary" "$DNS_TEST_DIR/commands" 2>/dev/null && exit 0
        sleep 0.1
    done
    exit 1
fi
cat > "$DNS_TEST_DIR/commands"
touch "$DNS_TEST_DIR/released"
`), 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fake sing-box")
	if err := os.WriteFile(binary, []byte(`#!/bin/bash
test "$#" = 3 && test "$1" = run && test "$2" = -c && test "$3" = 'a b.json' &&
test -p /dev/fd/9 && test ! -s "$DNS_TEST_DIR/commands" || exit 1
touch "$DNS_TEST_DIR/route-ready"
if [ "$DNS_TEST_FOREIGN_ROUTE" = 1 ]; then exec /bin/sleep 15; fi
for i in {1..30}; do
    grep -Fqx "d.add ServerAddresses * 198.18.0.2" "$DNS_TEST_DIR/commands" 2>/dev/null &&
    grep -Fqx "add State:/Network/Service/wgsplit-$$/DNS temporary" "$DNS_TEST_DIR/commands" 2>/dev/null && exit 0
    sleep 0.1
done
exit 1
`), 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if err := os.WriteFile("a b.json", []byte(`{"inbounds":[{"type":"tun","address":[
		"fd00::1/126", /* custom IPv4 subnet */ "198.18.0.1/30"
	]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	addr, err := tunIPv4Address("a b.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	args := runArguments(binary, "a b.json", addr)
	route := filepath.Join(dir, "route")
	if err := os.WriteFile(route, []byte(`#!/bin/sh
[ "$4" = 198.18.0.2 ] || exit 1
if [ "$DNS_TEST_FOREIGN_ROUTE" = 1 ]; then echo "interface: utun8"; exit 0; fi
if [ -f "$DNS_TEST_DIR/route-ready" ]; then echo "interface: utun7"; else echo "interface: en0"; fi
`), 0700); err != nil {
		t.Fatal(err)
	}
	ifconfig := filepath.Join(dir, "ifconfig")
	if err := os.WriteFile(ifconfig, []byte(`#!/bin/sh
case "$1" in
    utun7) echo " inet 198.18.0.1 --> 198.18.0.1" ;;
    utun8) echo " inet 10.0.0.1 --> 10.0.0.1" ;;
esac
`), 0700); err != nil {
		t.Fatal(err)
	}
	args[2] = strings.NewReplacer("/usr/sbin/scutil", scutil, "/sbin/route", route, "/sbin/ifconfig", ifconfig).Replace(args[2])
	t.Setenv("DNS_TEST_FOREIGN_ROUTE", "")
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("launch: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "released")); err != nil {
		t.Fatal(err)
	}

	t.Run("DNS route stays on another VPN", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("DNS_TEST_DIR", dir)
		t.Setenv("DNS_TEST_FOREIGN_ROUTE", "1")
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "DNS route to 198.18.0.2 uses utun8") {
			t.Fatalf("expected route failure, got %v: %s", err, out)
		}
		commands, err := os.ReadFile(filepath.Join(dir, "commands"))
		if err != nil || len(commands) != 0 {
			t.Fatalf("expected no resolver commands, got %q, %v", commands, err)
		}
	})
}

func TestTunIPv4Address(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		want    string
	}{
		{"single", `"198.18.4.5/30"`, "198.18.4.5"},
		{"first IPv4", `["fd00::1/126","198.18.1.1/30","198.18.2.1/30"]`, "198.18.1.1"},
		{"commented list", `[
			# IPv6 first
			"fd00::1/126", // "//" inside this comment
			"198.18.4.5/30" /* comment at end */,
		]`, "198.18.4.5"},
		{"unterminated comment", `["198.18.4.5/30" /*]`, ""},
		{"IPv6 only", `["fd00::1/126"]`, ""},
		{"invalid prefix", `["bad-prefix"]`, ""},
		{"no adjacent peer", `["198.18.1.1/32"]`, ""},
		{"network address", `"198.18.4.4/30"`, ""},
		{"broadcast peer", `"198.18.4.6/30"`, ""},
		{"large prefix", `"10.0.0.1/8"`, ""},
		{"public", `"1.1.1.1/30"`, ""},
		{"loopback", `"127.0.0.1/30"`, ""},
		{"link local", `"169.254.1.1/30"`, ""},
		{"private", `"192.168.42.1/30"`, "192.168.42.1"},
		{"last benchmarking subnet", `"198.19.255.253/30"`, "198.19.255.253"},
		{"past benchmarking range", `"198.20.0.1/30"`, ""},
		{"unsafe second IPv4", `["198.18.4.5/30","1.1.1.1/30"]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.json")
			config := `{"inbounds":[{"type":"tun"},{"type":"tun","address":` + tc.address + `}]}`
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			addr, err := tunIPv4Address(path, nil)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("accepted %s", tc.address)
				}
			} else if err != nil || addr.String() != tc.want {
				t.Fatalf("got %v, %v; want %s", addr, err, tc.want)
			}
		})
	}
}

func TestExplicitTunDNSAddress(t *testing.T) {
	for _, tc := range []struct {
		dnsAddress string
		wantError  bool
	}{
		{`"198.18.4.9"`, true},
		{`["fd00::2"]`, true},
		{`[]`, false},
		{`null`, false},
		{`["fd00::2","198.18.4.6"]`, false},
	} {
		t.Run(tc.dnsAddress, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.json")
			config := `{"inbounds":[{"type":"tun","address":"198.18.4.5/30","dns_address":` + tc.dnsAddress + `}]}`
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := tunIPv4Address(path, nil)
			if (err != nil) != tc.wantError {
				t.Fatalf("dns_address %s: got error %v", tc.dnsAddress, err)
			}
		})
	}
}

func TestTunSubnetOverlap(t *testing.T) {
	prefix := netip.MustParsePrefix("198.18.4.5/30")
	for _, tc := range []struct {
		assigned string
		overlaps bool
	}{
		{"198.18.4.5/30", true},
		{"198.18.4.6/32", true},
		{"198.18.4.42/24", true},
		{"198.18.4.9/30", false},
		{"fd00::1/126", false},
	} {
		t.Run(tc.assigned, func(t *testing.T) {
			ip, network, err := net.ParseCIDR(tc.assigned)
			if err != nil {
				t.Fatal(err)
			}
			network.IP = ip
			err = validateTunIPv4Prefix(prefix, []net.Addr{network})
			if (err != nil) != tc.overlaps {
				t.Fatalf("got %v, want overlap %v", err, tc.overlaps)
			}
		})
	}
}

// start and status both decide what to do from this parse, so a loaded job that
// is no longer running must be distinguishable from a running one.
func TestParseJobState(t *testing.T) {
	for _, tc := range []struct {
		name     string
		out      string
		running  bool
		exitCode string
	}{
		{"running", "job = {\n\tstate = running\n\tpid = 42\n}", true, ""},
		{"exited", "job = {\n\tlast exit code = 1\n\truns = 1\n}", false, "1"},
		{"exited zero", "job = {\n\tlast exit code = 0\n}", false, "0"},
		{"unrecognised", "job = {\n\tsomething = else\n}", false, ""},
		// Real launchd prints this for a healthy job that has never exited.
		// Treating it as an exit made start tear down a job that was fine.
		{"never exited", "job = {\n\tstate = running\n\tlast exit code = (never exited)\n}", true, ""},
		{"spawning, never exited", "job = {\n\tstate = spawn scheduled\n\truns = 1\n\tlast exit code = (never exited)\n}", false, ""},
	} {
		state := parseJobState([]byte(tc.out))
		if tc.name == "running" && state.pid != "42" {
			t.Fatalf("job PID = %q, want 42", state.pid)
		}
		if !state.loaded {
			t.Errorf("%s: output present but job reported unloaded", tc.name)
		}
		if state.running != tc.running || state.exitCode != tc.exitCode {
			t.Errorf("%s: got (running=%v, exit=%q)", tc.name, state.running, state.exitCode)
		}
	}
}
