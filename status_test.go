package main

import "testing"

func TestRunningConfig(t *testing.T) {
	for _, tc := range []struct {
		args, path string
		service    bool
	}{
		{"/opt/homebrew/bin/sing-box run -c /Users/Test User/.sing-box/profiles/uk.json", "/Users/Test User/.sing-box/profiles/uk.json", true},
		{"sing-box run --config=/private/tmp/example.json", "/private/tmp/example.json", true},
		{"sing-box run -c /one.json -c /two.json", "", true},
		{"sing-box check -c /one.json", "", false},
		{"sing-box run", "", true},
		{"(sing-box)", "", true},
	} {
		path, service := runningConfig(tc.args)
		if path != tc.path || service != tc.service {
			t.Errorf("%q: got (%q,%v)", tc.args, path, service)
		}
	}
}
