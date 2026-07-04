package paseto

import (
	"encoding/base64"
	"fmt"

	gopaseto "aidanwoods.dev/go-paseto"
	"golang.org/x/crypto/blake2b"
)

const (
	PASERKHeaderPID = "k4.pid."
	PASERKHeaderLID = "k4.lid."
	PASERKHeaderSID = "k4.sid."

	paserkPublicPrefix = "k4.public."
	paserkLocalPrefix  = "k4.local."

	paserkIDHashLen = 33 // BLAKE2b-264: 33 bytes → 44 chars base64url
)

// ComputePID computes the PASERK public key ID (k4.pid.) for an Ed25519 public key.
//
// Algorithm (PASERK v4):
//
//	paserk = "k4.public." + base64url(public_key_bytes)
//	h      = "k4.pid."
//	d      = BLAKE2b(message: h || paserk, output_size: 33)
//	result = h + base64url(d)
func ComputePID(publicKey gopaseto.V4AsymmetricPublicKey) (string, error) {
	paserk := paserkPublicPrefix + base64.RawURLEncoding.EncodeToString(publicKey.ExportBytes())
	return computeID(PASERKHeaderPID, paserk)
}

// ComputeLID computes the PASERK local key ID (k4.lid.) for a symmetric key.
//
// Algorithm (PASERK v4):
//
//	paserk = "k4.local." + base64url(symmetric_key_bytes)
//	h      = "k4.lid."
//	d      = BLAKE2b(message: h || paserk, output_size: 33)
//	result = h + base64url(d)
func ComputeLID(symmetricKey gopaseto.V4SymmetricKey) (string, error) {
	paserk := paserkLocalPrefix + base64.RawURLEncoding.EncodeToString(symmetricKey.ExportBytes())
	return computeID(PASERKHeaderLID, paserk)
}

func computeID(header, paserk string) (string, error) {
	h, err := blake2b.New(paserkIDHashLen, nil)
	if err != nil {
		return "", fmt.Errorf("blake2b init: %w", err)
	}
	h.Write([]byte(header))
	h.Write([]byte(paserk))
	d := h.Sum(nil)
	return header + base64.RawURLEncoding.EncodeToString(d), nil
}
