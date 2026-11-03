// Package ticketcrypto confines RFC 9474 to one shared ticket profile.
// Recovery contains private blinding randomness: encrypt it before storage.
package ticketcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const (
	// Profile names the exact algorithm and recovery encoding; never relabel it.
	Profile  = "nockapp-ticket-rsabssa-sha384-pss-randomized-v1"
	keyBytes = 384 // RSA-3072, public exponent 65537, PSS salt 48 bytes.
	maxTape  = 16384
	domain   = "nockapp-prepaid-ticket-v1\x00"
)

var errInvalid = errors.New("invalid ticket cryptographic input")

// Request is a client-only purchase record. Recovery must never reach the signer.
type Request struct {
	Prepared []byte `json:"prepared"`
	Blinded  []byte `json:"blinded"`
	Recovery []byte `json:"recovery"`
}

func publicKey(der []byte) (*rsa.PublicKey, error) {
	if len(der) > 1024 {
		return nil, errInvalid
	}
	v, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errInvalid
	}
	pk, ok := v.(*rsa.PublicKey)
	if !ok || pk.N == nil || pk.N.BitLen() != 3072 || pk.N.Bit(0) != 1 || pk.E != 65537 {
		return nil, errInvalid
	}
	canonical, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil || !bytes.Equal(canonical, der) {
		return nil, errInvalid
	}
	return pk, nil
}

// ValidatePublicKey checks the fixed SPKI encoding and profile key parameters.
// This cannot prove an operator generated an honest two-prime modulus.
func ValidatePublicKey(der []byte) error { _, err := publicKey(der); return err }

func preparedValid(prepared []byte) bool {
	return len(prepared) == 32+len(domain)+64 && bytes.Equal(prepared[32:32+len(domain)], []byte(domain))
}

type recordingRandom struct{ tape []byte }

func (r *recordingRandom) Read(p []byte) (int, error) {
	if len(p) > maxTape-len(r.tape) {
		return 0, errInvalid
	}
	n, err := rand.Read(p)
	r.tape = append(r.tape, p[:n]...)
	return n, err
}

func binding(der, prepared, blinded []byte) []byte {
	h := sha256.New()
	h.Write([]byte(Profile + "\x00recovery\x00"))
	h.Write(der)
	h.Write(prepared)
	h.Write(blinded)
	return h.Sum(nil)
}

// NewRequest prepares a random ticket under installer-pinned shared parameters.
// parameterHash and serial are exactly 32 bytes. The caller generates a fresh
// serial with an OS CSPRNG and durably encrypts this entire record BEFORE paying.
func NewRequest(der, parameterHash, serial []byte) (Request, error) {
	pk, err := publicKey(der)
	if err != nil || len(parameterHash) != 32 || len(serial) != 32 {
		return Request{}, errInvalid
	}
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, pk)
	if err != nil {
		return Request{}, errInvalid
	}
	message := append([]byte(domain), parameterHash...)
	message = append(message, serial...)
	prepared, err := client.Prepare(rand.Reader, message)
	if err != nil {
		return Request{}, errInvalid
	}
	random := &recordingRandom{}
	blinded, _, err := client.Blind(random, prepared)
	if err != nil {
		return Request{}, errInvalid
	}
	recovery := append([]byte{1}, binding(der, prepared, blinded)...)
	recovery = append(recovery, random.tape...)
	return Request{prepared, blinded, recovery}, nil
}

// Finalize reconstructs the exact upstream State by replaying captured CSPRNG
// bytes. It uses no new randomness. The Go toolchain and CIRCL are pinned because
// replay is implementation-specific. This wrapper never alters upstream code.
func Finalize(der []byte, request Request, blindSignature []byte) ([]byte, error) {
	pk, err := publicKey(der)
	if err != nil || !preparedValid(request.Prepared) || len(request.Blinded) != keyBytes ||
		len(blindSignature) != keyBytes || len(request.Recovery) < 33+48+keyBytes ||
		len(request.Recovery) > 33+maxTape || request.Recovery[0] != 1 ||
		!bytes.Equal(request.Recovery[1:33], binding(der, request.Prepared, request.Blinded)) {
		return nil, errInvalid
	}
	if new(big.Int).SetBytes(blindSignature).Cmp(pk.N) >= 0 {
		return nil, errInvalid
	}
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, pk)
	if err != nil {
		return nil, errInvalid
	}
	random := bytes.NewReader(request.Recovery[33:])
	blinded, state, err := client.Blind(random, request.Prepared)
	if err != nil || random.Len() != 0 || !bytes.Equal(blinded, request.Blinded) {
		return nil, errInvalid
	}
	signature, err := client.Finalize(state, blindSignature)
	if err != nil {
		return nil, errInvalid
	}
	// Finalize checks its encoded-message State. Also verify the actual stored
	// prepared message, preventing a changed-message/recovery association.
	if err := client.Verify(request.Prepared, signature); err != nil {
		return nil, errInvalid
	}
	return signature, nil
}

// Verify checks a redeemed prepared message with the fixed SHA384/PSS profile.
// The service must ALSO compare the embedded parameter hash to its pinned shared
// configuration; a valid signature alone does not establish redemption policy.
func Verify(der, prepared, signature []byte) error {
	pk, err := publicKey(der)
	if err != nil || !preparedValid(prepared) || len(signature) != keyBytes {
		return errInvalid
	}
	verifier, err := blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, pk)
	if err != nil || verifier.Verify(prepared, signature) != nil {
		return errInvalid
	}
	return nil
}

// BlindSign is an INTERNAL paid-issuance primitive, never a public signing API.
// Its caller must enforce finalized payment, the exact committed blinded pack,
// durable idempotent issuance and spending limits before calling it. The ticket
// key must be used for this protocol only, separate from gas/credential keys.
func BlindSign(privateDER, blinded []byte) ([]byte, error) {
	if len(privateDER) > 4096 || len(blinded) != keyBytes {
		return nil, errInvalid
	}
	v, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, errInvalid
	}
	sk, ok := v.(*rsa.PrivateKey)
	if !ok || sk.N == nil || sk.N.BitLen() != 3072 || sk.E != 65537 || len(sk.Primes) != 2 {
		return nil, errInvalid
	}
	if sk.Validate() != nil {
		return nil, errInvalid
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil || !bytes.Equal(canonical, privateDER) {
		return nil, errInvalid
	}
	m := new(big.Int).SetBytes(blinded)
	if m.Sign() <= 0 || m.Cmp(sk.N) >= 0 || new(big.Int).GCD(nil, nil, m, sk.N).Cmp(big.NewInt(1)) != 0 {
		return nil, errInvalid
	}
	signer := blindrsa.NewSigner(sk)
	result, err := signer.BlindSign(blinded)
	if err != nil {
		return nil, errInvalid
	}
	return result, nil
}

// Assert that capturing randomness preserves the upstream Reader interface.
var _ io.Reader = (*recordingRandom)(nil)
