//go:build darwin

package main

import (
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestJobArguments(t *testing.T) {
	const profile = "/tmp/example & test/uk.json"
	const logFile = "/var/log/wgsplit.501.log"
	decoder := xml.NewDecoder(strings.NewReader(string(jobPlist("test.job", "/bin/sing-box", profile, logFile))))
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
	script := runArguments("/bin/sing-box", profile)[2]
	want := []string{"test.job", "/bin/bash", "-c", script, "wgsplit", "/bin/sing-box", profile, logFile, logFile}
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
for i in {1..30}; do
    grep -Fqx "add State:/Network/Service/wgsplit-$$/DNS temporary" "$DNS_TEST_DIR/commands" 2>/dev/null && exit 0
    sleep 0.1
done
exit 1
`), 0700); err != nil {
		t.Fatal(err)
	}
	args := runArguments(binary, "a b.json")
	route := filepath.Join(dir, "route")
	if err := os.WriteFile(route, []byte(`#!/bin/sh
if [ -f "$DNS_TEST_DIR/route-ready" ]; then echo "interface: utun7"; else echo "interface: en0"; fi
`), 0700); err != nil {
		t.Fatal(err)
	}
	ifconfig := filepath.Join(dir, "ifconfig")
	if err := os.WriteFile(ifconfig, []byte(`#!/bin/sh
[ "$1" = utun7 ] && echo " inet 172.19.0.1 --> 172.19.0.1"
`), 0700); err != nil {
		t.Fatal(err)
	}
	args[2] = strings.NewReplacer("/usr/sbin/scutil", scutil, "/sbin/route", route, "/sbin/ifconfig", ifconfig).Replace(args[2])
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("launch: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "released")); err != nil {
		t.Fatal(err)
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
