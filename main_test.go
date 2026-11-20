//go:build darwin

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAddPreservesUnsupportedRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domains.json")
	original := `{"version":3,"rules":[{"domain":["only.example"]}]}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := add(path, "another.example"); err == nil {
		t.Fatal("accepted unsupported rule")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatal("changed list on rejection")
	}
}

func TestShowProfileAndBypass(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".sing-box")
	profiles := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles, "uk.json"), []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "default.json"), "uk"); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "direct-domains.json"), bypassList{3, []rule{{[]string{"myip.com"}}, {[]string{"example.org"}}}}); err != nil {
		t.Fatal(err)
	}
	cmd := rootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"show"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "Profiles\n  uk (default)  " + filepath.Join(profiles, "uk.json") + "\nVPN bypass hostnames (including subdomains)\n  myip.com\n  example.org\n"
	if out.String() != want {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestRemoveHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domains.json")
	initial := bypassList{3, []rule{{[]string{"example.org"}}, {[]string{"Example.Org.", "other.example"}}}}
	if err := writeJSON(path, initial); err != nil {
		t.Fatal(err)
	}
	if err := remove(path, "EXAMPLE.ORG."); err != nil {
		t.Fatal(err)
	}
	got, err := readList(path)
	if err != nil || len(got.Rules) != 1 || len(got.Rules[0].Domains) != 1 || got.Rules[0].Domains[0] != "other.example" {
		t.Fatalf("after removal: %+v, %v", got, err)
	}
	if err := remove(path, "example.org"); err == nil {
		t.Fatal("missing hostname reported as removed")
	}
	if err := remove(path, "other.example"); err != nil {
		t.Fatal(err)
	}
	got, err = readList(path)
	if err != nil || got.Rules == nil || len(got.Rules) != 0 {
		t.Fatalf("expected empty list: %+v, %v", got, err)
	}
}

// A hand-edited entry must not produce a second copy of the same host, or add
// and remove stop inverting each other.
func TestAddIsIdempotentAcrossSpelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domains.json")
	if err := writeJSON(path, bypassList{3, []rule{{[]string{"Example.Org."}}}}); err != nil {
		t.Fatal(err)
	}
	if err := add(path, "example.org"); err != nil {
		t.Fatal(err)
	}
	got, err := readList(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || len(got.Rules[0].Domains) != 1 {
		t.Fatalf("duplicate entry created: %+v", got.Rules)
	}
}

func TestAddCreatesMissingList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domains.json")
	if err := add(path, "example.org"); err != nil {
		t.Fatal(err)
	}
	got, err := readList(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != listVersion || len(got.Rules) != 1 || got.Rules[0].Domains[0] != "example.org" {
		t.Fatalf("unexpected list %+v", got)
	}
}

func TestHostnameRejectsSingleLabel(t *testing.T) {
	for _, name := range []string{"com", "localhost", "1.2.3.4", ""} {
		if _, err := hostname(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if got, err := hostname("MyIP.com."); err != nil || got != "myip.com" {
		t.Fatalf("got (%q, %v)", got, err)
	}
}

// Older rule-set source versions are valid sing-box input, so they are read and
// normalised rather than rejected.
func TestReadListAcceptsOlderVersions(t *testing.T) {
	dir := t.TempDir()
	for _, version := range []string{"1", "2", "3"} {
		path := filepath.Join(dir, version+".json")
		if err := os.WriteFile(path, []byte(`{"version":`+version+`,"rules":[{"domain_suffix":["a.example"]}]}`), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readList(path)
		if err != nil {
			t.Fatalf("version %s: %v", version, err)
		}
		if got.Version != listVersion {
			t.Fatalf("version %s not normalised: %d", version, got.Version)
		}
	}
	path := filepath.Join(dir, "future.json")
	if err := os.WriteFile(path, []byte(`{"version":9,"rules":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readList(path); err == nil {
		t.Fatal("accepted an unsupported version")
	}
}

// The profile holds the only copy of the private key once the .conf is gone, so
// a rejected config must never replace a working one.
func TestWriteJSONCheckedKeepsOriginalOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uk.json")
	if err := os.WriteFile(path, []byte("ORIGINAL"), 0600); err != nil {
		t.Fatal(err)
	}
	err := writeJSONChecked(path, object{"a": 1}, func(string) error { return errors.New("rejected") })
	if err == nil {
		t.Fatal("validation failure not reported")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("destination was modified: %q", got)
	}
	leftovers, globErr := filepath.Glob(filepath.Join(dir, ".wgsplit-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// Regression: hostname validation tightened to reject single labels, but an
// entry an older version accepted must still be removable through the CLI.
func TestRemoveAcceptsEntriesAddDoesNot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domains.json")
	if err := writeJSON(path, bypassList{3, []rule{{[]string{"com", "a.example"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := hostname("com"); err == nil {
		t.Fatal("add should still reject a single-label host")
	}
	if err := remove(path, "COM."); err != nil {
		t.Fatalf("single-label entry not removable: %v", err)
	}
	got, err := readList(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 || len(got.Rules[0].Domains) != 1 || got.Rules[0].Domains[0] != "a.example" {
		t.Fatalf("unexpected list %+v", got.Rules)
	}
}

func TestGroupedCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	run := func(args ...string) string {
		t.Helper()
		cmd := rootCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	run("bypass", "add", "example.org")
	if got := run("bypass", "list"); got != "example.org\n" {
		t.Fatalf("bypass list: %q", got)
	}
	run("remove", "example.org")
	if got := run("bypass", "list"); got != "" {
		t.Fatalf("legacy remove left %q", got)
	}
	dir := filepath.Join(home, ".sing-box")
	if err := writeJSON(filepath.Join(dir, "profiles", "test.json"), object{}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "default.json"), "test"); err != nil {
		t.Fatal(err)
	}
	if got := run("profile", "list"); got != "test (default)\n" {
		t.Fatalf("profile list: %q", got)
	}
	if got := run("list"); got != "test\n" {
		t.Fatalf("legacy list: %q", got)
	}
}

func TestValidateSingboxBuild(t *testing.T) {
	const tags = "\nEnvironment: go1.26.10 darwin/arm64\nTags: with_gvisor,with_wireguard,with_utls\nCGO: enabled\n"
	for _, tc := range []struct {
		name    string
		output  string
		wantErr bool
	}{
		{"current", "sing-box version 1.14.4\n" + tags, false},
		{"minimum", "sing-box version 1.13.0\n" + tags, false},
		{"pre-release of minimum", "sing-box version 1.13.0-beta.2\n" + tags, false},
		{"newer major", "sing-box version 2.0.0\n" + tags, false},
		{"older minor", "sing-box version 1.12.9\n" + tags, true},
		{"older major", "sing-box version 0.99.0\n" + tags, true},
		{"without WireGuard", "sing-box version 1.14.4\n\nTags: with_gvisor,with_utls\n", true},
		{"tag as substring", "sing-box version 1.14.4\n\nTags: with_wireguard_legacy\n", true},
		{"no tags line", "sing-box version 1.14.4\n", false},
		{"unknown version", "sing-box version unknown\n" + tags, false},
		{"unrecognised output", "something else", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSingboxBuild(tc.output); (err != nil) != tc.wantErr {
				t.Fatalf("got %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
