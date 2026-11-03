package main

import (
	"bytes"
	"testing"
)

func TestStrictPrivatePipeBoundary(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"profile":"a","profile":"b"}`),
		[]byte(`{} {}`), []byte(`[]`), []byte(`null`),
		[]byte(`{"profile":null,"op":"verify"}`),
		[]byte(`{"profile":"nockapp-ticket-rsabssa-sha384-pss-randomized-v1","op":"keygen"}`),
		[]byte(`{"profile":"nockapp-ticket-rsabssa-sha384-pss-randomized-v1","op":"verify","public_key":"","prepared":"","signature":"","path":"/tmp/key"}`),
		[]byte(`{"profile":"nockapp-ticket-rsabssa-sha384-pss-randomized-v1","op":"blind-sign","private_key":null,"blinded":""}`),
		bytes.Repeat([]byte(" "), 65537),
	} {
		if _, err := operation(raw); err == nil {
			t.Fatal("accepted malformed request")
		}
	}
	for _, raw := range []string{`{"a":"YQ==\n"}`, `{"a":"YR=="}`, `{"a":1}`, `{"a":null}`, `{"a":"?"}`} {
		m, err := fields([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = binary(m, "a"); err == nil {
			t.Fatal("accepted noncanonical binary")
		}
	}
}
