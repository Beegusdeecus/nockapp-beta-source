// Linux-only, one-operation private pipe worker. No listeners, key generation,
// files, paths, endpoints or caller-selected cryptographic parameters.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	ticket "nockapp.local/ticketcrypto"
)

var invalid = errors.New("invalid request")

func fields(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) > 65536 {
		return nil, invalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	result := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, invalid
		}
		name, ok := token.(string)
		if !ok {
			return nil, invalid
		}
		if _, exists := result[name]; exists {
			return nil, invalid
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, invalid
		}
		result[name] = value
		if len(result) > 12 {
			return nil, invalid
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, invalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, invalid
	}
	return result, nil
}

func text(m map[string]json.RawMessage, k string) (string, error) {
	raw, ok := m[k]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return "", invalid
	}
	var result string
	if json.Unmarshal(raw, &result) != nil {
		return "", invalid
	}
	return result, nil
}

func binary(m map[string]json.RawMessage, k string) ([]byte, error) {
	s, err := text(m, k)
	if err != nil {
		return nil, invalid
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, invalid
	}
	return b, nil
}

func operation(raw []byte) (map[string]any, error) {
	m, err := fields(raw)
	if err != nil {
		return nil, invalid
	}
	p, err := text(m, "profile")
	if err != nil || p != ticket.Profile {
		return nil, invalid
	}
	op, err := text(m, "op")
	if err != nil {
		return nil, invalid
	}
	var names []string
	switch op {
	case "blind":
		names = []string{"public_key", "parameters", "serial"}
	case "finalize":
		names = []string{"public_key", "prepared", "blinded", "recovery", "signature"}
	case "verify":
		names = []string{"public_key", "prepared", "signature"}
	case "blind-sign":
		names = []string{"private_key", "blinded"}
	default:
		return nil, invalid
	}
	if len(m) != len(names)+2 {
		return nil, invalid
	}
	b := make(map[string][]byte)
	for _, k := range names {
		v, err := binary(m, k)
		if err != nil {
			return nil, invalid
		}
		b[k] = v
	}
	result := map[string]any{"ok": true, "profile": ticket.Profile}
	switch op {
	case "blind":
		r, err := ticket.NewRequest(b["public_key"], b["parameters"], b["serial"])
		if err != nil {
			return nil, invalid
		}
		result["request"] = r
	case "finalize":
		r := ticket.Request{Prepared: b["prepared"], Blinded: b["blinded"], Recovery: b["recovery"]}
		sig, err := ticket.Finalize(b["public_key"], r, b["signature"])
		if err != nil {
			return nil, invalid
		}
		result["signature"] = sig
	case "verify":
		if ticket.Verify(b["public_key"], b["prepared"], b["signature"]) != nil {
			return nil, invalid
		}
	case "blind-sign":
		sig, err := ticket.BlindSign(b["private_key"], b["blinded"])
		if err != nil {
			return nil, invalid
		}
		result["signature"] = sig
	}
	return result, nil
}

func main() {
	// Private keys and blinding factors pass only through inherited pipes.
	// Disable core dumps and same-user ptrace inspection before reading input.
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) != nil {
		os.Exit(2)
	}
	if syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: 2 << 30, Max: 2 << 30}) != nil {
		os.Exit(2)
	}
	if syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: 10, Max: 10}) != nil {
		os.Exit(2)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, 4, 0, 0); errno != 0 {
		os.Exit(2)
	} // PR_SET_DUMPABLE=0
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	var result map[string]any
	if err == nil && len(os.Args) == 1 {
		result, err = operation(raw)
	} else {
		err = invalid
	}
	if err != nil {
		result = map[string]any{"ok": false, "error": "ticket operation rejected"}
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(2)
	}
	if err != nil {
		os.Exit(1)
	}
}
