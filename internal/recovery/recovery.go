package recovery

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// secp256k1 curve order
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
)

// RecoverFromSignatures recovers a private key from two signatures with the same nonce
// z1, r1, s1 are from the first signature; z2, r2, s2 from the second
// Both signatures must be from the same private key with the same nonce (r1 == r2)
func RecoverFromSignatures(z1, r1, s1, z2, r2, s2 *big.Int) (string, error) {
	if r1.Cmp(r2) != 0 {
		return "", errors.New("R values must match")
	}
	if s1.Cmp(s2) == 0 {
		return "", errors.New("signatures are identical")
	}

	// k = (z1 - z2) * (s1 - s2)^(-1) mod n
	zDiff := new(big.Int).Sub(z1, z2)
	zDiff.Mod(zDiff, secp256k1N)

	sDiff := new(big.Int).Sub(s1, s2)
	sDiff.Mod(sDiff, secp256k1N)

	sDiffInv := new(big.Int).ModInverse(sDiff, secp256k1N)
	if sDiffInv == nil {
		return "", errors.New("failed to compute modular inverse")
	}

	k := new(big.Int).Mul(zDiff, sDiffInv)
	k.Mod(k, secp256k1N)

	// Try both k and -k
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			k.Sub(secp256k1N, k)
		}

		// d = (s1 * k - z1) * r^(-1) mod n
		rInv := new(big.Int).ModInverse(r1, secp256k1N)
		if rInv == nil {
			continue
		}

		d := new(big.Int).Mul(s1, k)
		d.Sub(d, z1)
		d.Mul(d, rInv)
		d.Mod(d, secp256k1N)

		if d.Sign() <= 0 {
			d.Add(d, secp256k1N)
		}

		// Pad to 32 bytes
		dBytes := make([]byte, 32)
		dTmp := d.Bytes()
		copy(dBytes[32-len(dTmp):], dTmp)

		privKey, err := crypto.ToECDSA(dBytes)
		if err != nil {
			continue
		}

		return "0x" + hex.EncodeToString(crypto.FromECDSA(privKey)), nil
	}

	return "", errors.New("failed to recover private key")
}

// RecoverWithKnownNonce recovers a private key when the nonce k is known
// d = (s * k - z) * r^(-1) mod n
func RecoverWithKnownNonce(z, r, s *big.Int, kHex string) (string, error) {
	kBytes, err := hex.DecodeString(strings.TrimPrefix(kHex, "0x"))
	if err != nil {
		return "", err
	}
	k := new(big.Int).SetBytes(kBytes)

	rInv := new(big.Int).ModInverse(r, secp256k1N)
	if rInv == nil {
		return "", errors.New("failed to compute modular inverse of r")
	}

	d := new(big.Int).Mul(s, k)
	d.Sub(d, z)
	d.Mul(d, rInv)
	d.Mod(d, secp256k1N)

	if d.Sign() <= 0 {
		d.Add(d, secp256k1N)
	}

	// Pad to 32 bytes
	dBytes := make([]byte, 32)
	dTmp := d.Bytes()
	copy(dBytes[32-len(dTmp):], dTmp)

	privKey, err := crypto.ToECDSA(dBytes)
	if err != nil {
		return "", err
	}

	return "0x" + hex.EncodeToString(crypto.FromECDSA(privKey)), nil
}

// DeriveNonce derives the nonce k from a signature and known private key
// k = (z + r*d) * s^(-1) mod n
func DeriveNonce(z, r, s *big.Int, privKeyHex string) string {
	privBytes, _ := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	d := new(big.Int).SetBytes(privBytes)

	sInv := new(big.Int).ModInverse(s, secp256k1N)

	k := new(big.Int).Mul(r, d)
	k.Add(k, z)
	k.Mul(k, sInv)
	k.Mod(k, secp256k1N)

	// Pad to 32 bytes
	kBytes := make([]byte, 32)
	kTmp := k.Bytes()
	copy(kBytes[32-len(kTmp):], kTmp)

	return "0x" + hex.EncodeToString(kBytes)
}

// VerifyPrivateKey verifies that a private key corresponds to an address
func VerifyPrivateKey(privKeyHex, expectedAddr string) bool {
	privBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return false
	}

	privKey, err := crypto.ToECDSA(privBytes)
	if err != nil {
		return false
	}

	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	return strings.EqualFold(addr.Hex(), expectedAddr)
}

// GetAddressFromPrivateKey derives the address from a private key
func GetAddressFromPrivateKey(privKeyHex string) (string, error) {
	privBytes, err := hex.DecodeString(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", err
	}

	privKey, err := crypto.ToECDSA(privBytes)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	return addr.Hex(), nil
}
