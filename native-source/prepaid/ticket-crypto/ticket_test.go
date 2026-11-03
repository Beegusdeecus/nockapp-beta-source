package ticketcrypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"testing"
)

func fixture(t *testing.T) (*rsa.PrivateKey, []byte, []byte, []byte, []byte) {
	t.Helper()
	sk, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	params, serial := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(params); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(serial); err != nil {
		t.Fatal(err)
	}
	return sk, pub, priv, params, serial
}

func TestRestartRecoveryAndIndependentPSSVerification(t *testing.T) {
	sk, pub, priv, params, serial := fixture(t)
	first, err := NewRequest(pub, params, serial)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRequest(pub, params, serial)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Prepared, second.Prepared) || bytes.Equal(first.Blinded, second.Blinded) {
		t.Fatal("reused randomness")
	}
	blindSig, err := BlindSign(priv, first.Blinded)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh object has only serialized bytes, no retained upstream State.
	saved, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	first = Request{}
	if err := json.Unmarshal(saved, &first); err != nil {
		t.Fatal(err)
	}
	sig, err := Finalize(pub, first, blindSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, first.Prepared, sig); err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(first.Prepared)
	if err := rsa.VerifyPSS(&sk.PublicKey, crypto.SHA384, digest[:], sig, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}); err != nil {
		t.Fatal(err)
	}
	again, err := Finalize(pub, first, blindSig)
	if err != nil || !bytes.Equal(again, sig) {
		t.Fatal("retry changed ticket")
	}
	if _, err := Finalize(pub, second, blindSig); err == nil {
		t.Fatal("crossed signer reply accepted")
	}
	if bytes.Contains(first.Prepared, first.Blinded) {
		t.Fatal("unexpected transcript overlap")
	}
}

func TestChangedRecoveryMessageAndSignaturesRejected(t *testing.T) {
	sk, pub, priv, params, serial := fixture(t)
	r, err := NewRequest(pub, params, serial)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := BlindSign(priv, r.Blinded)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Finalize(pub, r, bs)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"prepared", "blinded", "binding", "tape", "truncated", "trailing", "version"} {
		t.Run(name, func(t *testing.T) {
			bad := Request{bytes.Clone(r.Prepared), bytes.Clone(r.Blinded), bytes.Clone(r.Recovery)}
			switch name {
			case "prepared":
				bad.Prepared[len(bad.Prepared)-1] ^= 1
			case "blinded":
				bad.Blinded[1] ^= 1
			case "binding":
				bad.Recovery[1] ^= 1
			case "tape":
				bad.Recovery[len(bad.Recovery)-1] ^= 1
			case "truncated":
				bad.Recovery = bad.Recovery[:len(bad.Recovery)-1]
			case "trailing":
				bad.Recovery = append(bad.Recovery, 0)
			case "version":
				bad.Recovery[0] = 2
			}
			if _, err := Finalize(pub, bad, bs); err == nil {
				t.Fatal("accepted changed private record")
			}
		})
	}
	bad := bytes.Clone(r.Prepared)
	bad[len(bad)-1] ^= 1
	if Verify(pub, bad, sig) == nil {
		t.Fatal("changed ticket accepted")
	}
	for _, n := range []*big.Int{big.NewInt(0), sk.N, new(big.Int).Sub(sk.N, big.NewInt(1))} {
		value := n.FillBytes(make([]byte, 384))
		if Verify(pub, r.Prepared, value) == nil {
			t.Fatal("invalid signature accepted")
		}
		if _, err := Finalize(pub, r, value); err == nil {
			t.Fatal("invalid blind signature accepted")
		}
	}
	for _, n := range []*big.Int{big.NewInt(0), sk.N, sk.Primes[0]} {
		if _, err := BlindSign(priv, n.FillBytes(make([]byte, 384))); err == nil {
			t.Fatal("invalid signing representative accepted")
		}
	}
}

func TestWrongKeysAndBoundsRejected(t *testing.T) {
	_, pub, _, params, serial := fixture(t)
	if _, err := NewRequest(pub, params[:31], serial); err == nil {
		t.Fatal("short parameters accepted")
	}
	if _, err := NewRequest(pub, params, serial[:31]); err == nil {
		t.Fatal("short serial accepted")
	}
	for _, bad := range [][]byte{nil, make([]byte, 1025), append(bytes.Clone(pub), 0)} {
		if ValidatePublicKey(bad) == nil {
			t.Fatal("bad public key accepted")
		}
		if _, err := NewRequest(bad, params, serial); err == nil {
			t.Fatal("bad public key used")
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ValidatePublicKey(der) == nil {
		t.Fatal("weak key accepted")
	}
	if _, err := BlindSign(make([]byte, 4097), make([]byte, 384)); err == nil {
		t.Fatal("oversized private key accepted")
	}
	if Verify(pub, make([]byte, 100000), make([]byte, 384)) == nil {
		t.Fatal("oversized ticket accepted")
	}
}
