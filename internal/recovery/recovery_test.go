package recovery

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// signWithNonce signs a message hash with a specific nonce k
// Returns r, s values (without low-S normalization for testing purposes)
func signWithNonce(privKey *ecdsa.PrivateKey, hash []byte, k *big.Int) (*big.Int, *big.Int) {
	curve := crypto.S256()
	N := curve.Params().N

	// R = k * G
	rx, _ := curve.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(rx, N)

	// s = k^(-1) * (z + r*d) mod n
	z := new(big.Int).SetBytes(hash)
	kInv := new(big.Int).ModInverse(k, N)

	s := new(big.Int).Mul(r, privKey.D)
	s.Add(s, z)
	s.Mul(s, kInv)
	s.Mod(s, N)

	// Note: We don't normalize s to low-S here because the recovery math
	// depends on the exact s values used. In real transactions, both
	// normalized and non-normalized s values work with the recovery algorithm
	// as long as both signatures use consistent s values.

	return r, s
}

func TestRecoverFromSignatures_SameKey(t *testing.T) {
	// Generate a random private key
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
	expectedPrivHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privKey))

	// Generate a random nonce (this is what we'll reuse)
	k, err := rand.Int(rand.Reader, secp256k1N)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Create two different message hashes
	hash1 := crypto.Keccak256([]byte("message 1"))
	hash2 := crypto.Keccak256([]byte("message 2"))

	// Sign both messages with the SAME nonce (vulnerability!)
	r1, s1 := signWithNonce(privKey, hash1, k)
	r2, s2 := signWithNonce(privKey, hash2, k)

	// Verify both signatures have the same R value
	if r1.Cmp(r2) != 0 {
		t.Fatalf("R values should match: %x vs %x", r1, r2)
	}

	// Now recover the private key
	z1 := new(big.Int).SetBytes(hash1)
	z2 := new(big.Int).SetBytes(hash2)

	recoveredPriv, err := RecoverFromSignatures(z1, r1, s1, z2, r2, s2)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}

	// Verify the recovered key matches
	if !VerifyPrivateKey(recoveredPriv, expectedAddr) {
		t.Errorf("Recovered key doesn't match expected address")
		t.Errorf("Expected: %s", expectedPrivHex)
		t.Errorf("Got: %s", recoveredPriv)
	}
}

func TestRecoverFromSignatures_MultipleRecoveries(t *testing.T) {
	// Test multiple key recoveries to ensure consistency
	for i := 0; i < 10; i++ {
		privKey, _ := crypto.GenerateKey()
		expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()

		k, _ := rand.Int(rand.Reader, secp256k1N)

		hash1 := crypto.Keccak256([]byte("test message A"))
		hash2 := crypto.Keccak256([]byte("test message B"))

		r1, s1 := signWithNonce(privKey, hash1, k)
		r2, s2 := signWithNonce(privKey, hash2, k)

		z1 := new(big.Int).SetBytes(hash1)
		z2 := new(big.Int).SetBytes(hash2)

		recoveredPriv, err := RecoverFromSignatures(z1, r1, s1, z2, r2, s2)
		if err != nil {
			t.Errorf("Iteration %d: Failed to recover: %v", i, err)
			continue
		}

		if !VerifyPrivateKey(recoveredPriv, expectedAddr) {
			t.Errorf("Iteration %d: Recovered key doesn't match", i)
		}
	}
}

func TestRecoverWithKnownNonce(t *testing.T) {
	// Generate a random private key
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()

	// Generate a random nonce
	k, err := rand.Int(rand.Reader, secp256k1N)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	kHex := "0x" + hex.EncodeToString(k.FillBytes(make([]byte, 32)))

	// Create a message and sign it
	hash := crypto.Keccak256([]byte("test message"))
	r, s := signWithNonce(privKey, hash, k)
	z := new(big.Int).SetBytes(hash)

	// Recover using the known nonce
	recoveredPriv, err := RecoverWithKnownNonce(z, r, s, kHex)
	if err != nil {
		t.Fatalf("Failed to recover with known nonce: %v", err)
	}

	if !VerifyPrivateKey(recoveredPriv, expectedAddr) {
		t.Errorf("Recovered key doesn't match expected address")
	}
}

func TestDeriveNonce(t *testing.T) {
	// Generate a random private key
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	privKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privKey))

	// Generate a random nonce
	k, err := rand.Int(rand.Reader, secp256k1N)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	expectedKHex := "0x" + hex.EncodeToString(k.FillBytes(make([]byte, 32)))

	// Create a message and sign it
	hash := crypto.Keccak256([]byte("test message"))
	r, s := signWithNonce(privKey, hash, k)
	z := new(big.Int).SetBytes(hash)

	// Derive the nonce from the signature
	derivedK := DeriveNonce(z, r, s, privKeyHex)

	if derivedK != expectedKHex {
		t.Errorf("Derived nonce doesn't match")
		t.Errorf("Expected: %s", expectedKHex)
		t.Errorf("Got: %s", derivedK)
	}
}

func TestCrossKeyRecovery(t *testing.T) {
	// Simulate cross-key nonce reuse scenario:
	// Key A uses nonce k, we recover k
	// Key B also uses nonce k, we recover Key B using known k

	// Generate two different private keys
	privKeyA, _ := crypto.GenerateKey()
	privKeyB, _ := crypto.GenerateKey()
	expectedAddrB := crypto.PubkeyToAddress(privKeyB.PublicKey).Hex()
	privKeyAHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privKeyA))

	// Same nonce used by both keys (bad RNG!)
	k, _ := rand.Int(rand.Reader, secp256k1N)

	// Key A signs two messages with the same nonce (same-key reuse)
	hashA1 := crypto.Keccak256([]byte("key A message 1"))
	hashA2 := crypto.Keccak256([]byte("key A message 2"))
	rA1, sA1 := signWithNonce(privKeyA, hashA1, k)
	_, sA2 := signWithNonce(privKeyA, hashA2, k)

	// Key B signs one message with the same nonce
	hashB := crypto.Keccak256([]byte("key B message"))
	rB, sB := signWithNonce(privKeyB, hashB, k)

	// Step 1: Recover Key A from its nonce reuse
	zA1 := new(big.Int).SetBytes(hashA1)
	zA2 := new(big.Int).SetBytes(hashA2)

	recoveredPrivA, err := RecoverFromSignatures(zA1, rA1, sA1, zA2, rA1, sA2)
	if err != nil {
		t.Fatalf("Failed to recover Key A: %v", err)
	}

	// Step 2: Derive the nonce from Key A's signature
	derivedK := DeriveNonce(zA1, rA1, sA1, privKeyAHex)

	// Verify r values match (same k means same R)
	if rA1.Cmp(rB) != 0 {
		t.Fatalf("R values should match for same nonce")
	}

	// Step 3: Use the known nonce to recover Key B
	zB := new(big.Int).SetBytes(hashB)
	recoveredPrivB, err := RecoverWithKnownNonce(zB, rB, sB, derivedK)
	if err != nil {
		t.Fatalf("Failed to recover Key B with known nonce: %v", err)
	}

	// Verify Key B was recovered correctly
	if !VerifyPrivateKey(recoveredPrivB, expectedAddrB) {
		t.Errorf("Recovered Key B doesn't match expected address")
	}

	// Also verify Key A recovery worked
	expectedAddrA := crypto.PubkeyToAddress(privKeyA.PublicKey).Hex()
	if !VerifyPrivateKey(recoveredPrivA, expectedAddrA) {
		t.Errorf("Recovered Key A doesn't match expected address")
	}
}

func TestRecoverFromSignatures_EdgeCases(t *testing.T) {
	t.Run("different R values", func(t *testing.T) {
		_, err := RecoverFromSignatures(
			big.NewInt(1), big.NewInt(100), big.NewInt(200),
			big.NewInt(2), big.NewInt(101), big.NewInt(300),
		)
		if err == nil {
			t.Error("Should fail when R values don't match")
		}
	})

	t.Run("identical signatures", func(t *testing.T) {
		_, err := RecoverFromSignatures(
			big.NewInt(1), big.NewInt(100), big.NewInt(200),
			big.NewInt(1), big.NewInt(100), big.NewInt(200),
		)
		if err == nil {
			t.Error("Should fail when signatures are identical")
		}
	})
}

func TestVerifyPrivateKey(t *testing.T) {
	// Known test case - never use this key on mainnet!
	testPrivKey := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	expectedAddr := "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"

	if !VerifyPrivateKey(testPrivKey, expectedAddr) {
		t.Error("VerifyPrivateKey failed for known key")
	}

	if VerifyPrivateKey(testPrivKey, "0x0000000000000000000000000000000000000000") {
		t.Error("VerifyPrivateKey should fail for wrong address")
	}
}

func TestGetAddressFromPrivateKey(t *testing.T) {
	testPrivKey := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	expectedAddr := "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"

	addr, err := GetAddressFromPrivateKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetAddressFromPrivateKey failed: %v", err)
	}

	if addr != expectedAddr {
		t.Errorf("Expected %s, got %s", expectedAddr, addr)
	}
}
