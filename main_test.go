package main

import (
	"bytes"
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
	if err := writeJSON(filepath.Join(dir, "default.json"), "uk", nil); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "direct-domains.json"), list{3, []rule{{[]string{"myip.com"}}, {[]string{"example.org"}}}}, nil); err != nil {
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
	initial := list{3, []rule{{[]string{"example.org"}}, {[]string{"Example.Org.", "other.example"}}}}
	if err := writeJSON(path, initial, nil); err != nil {
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
