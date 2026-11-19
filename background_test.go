//go:build darwin

package main

import (
	"encoding/xml"
	"io"
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
	want := []string{"test.job", "/bin/sing-box", "run", "-c", profile, logFile, logFile}
	if !slices.Equal(values, want) {
		t.Fatalf("unexpected plist strings %q", values)
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
		if !state.loaded {
			t.Errorf("%s: output present but job reported unloaded", tc.name)
		}
		if state.running != tc.running || state.exitCode != tc.exitCode {
			t.Errorf("%s: got (running=%v, exit=%q)", tc.name, state.running, state.exitCode)
		}
	}
}
