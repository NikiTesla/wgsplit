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
	decoder := xml.NewDecoder(strings.NewReader(string(jobPlist("test.job", "/bin/sing-box", profile))))
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
	if !slices.Equal(values, []string{"test.job", "/bin/sing-box", "run", "-c", profile}) {
		t.Fatalf("unexpected plist strings %q", values)
	}
}
