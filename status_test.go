//go:build darwin

package main

import "testing"

func TestRunningConfig(t *testing.T) {
	for _, tc := range []struct {
		args, path string
		isRun      bool
	}{
		{"/opt/homebrew/bin/sing-box run -c /Users/Test User/.sing-box/profiles/uk.json", "/Users/Test User/.sing-box/profiles/uk.json", true},
		{"sing-box run --config=/private/tmp/example.json", "/private/tmp/example.json", true},
		{"sing-box run -c /one.json -c /two.json", "", true},
		{"sing-box check -c /one.json", "", false},
		{"sing-box run", "", true},
		{"(sing-box)", "", true},
	} {
		path, isRun := runningConfig(tc.args)
		if path != tc.path || isRun != tc.isRun {
			t.Errorf("%q: got (%q,%v)", tc.args, path, isRun)
		}
	}
}

func TestDescribeProfile(t *testing.T) {
	s := store{profiles: "/home/u/.sing-box/profiles"}
	for args, want := range map[string]string{
		"":                                      "unavailable",
		"/home/u/.sing-box/profiles/uk.json":    "uk (/home/u/.sing-box/profiles/uk.json)",
		"/etc/sing-box/other.json":              "/etc/sing-box/other.json",
		"/home/u/.sing-box/profiles/notjson.tx": "/home/u/.sing-box/profiles/notjson.tx",
	} {
		if got := s.describe(args); got != want {
			t.Errorf("describe(%q) = %q, want %q", args, got, want)
		}
	}
}
