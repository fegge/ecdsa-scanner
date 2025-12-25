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

func TestLinearSystemMultiKeyMultiNonce(t *testing.T) {
	// Scenario: 3 different keys share 2 nonces due to bad RNG
	// Key A and Key B both use nonce k1
	// Key B and Key C both use nonce k2
	// This creates a chain that lets us recover all 3 keys

	// Generate 3 private keys
	privKeyA, _ := crypto.GenerateKey()
	privKeyB, _ := crypto.GenerateKey()
	privKeyC, _ := crypto.GenerateKey()

	// Generate 2 shared nonces
	k1, _ := rand.Int(rand.Reader, secp256k1N)
	k2, _ := rand.Int(rand.Reader, secp256k1N)

	// Create signatures:
	// Key A signs msg1 and msg2 with k1 (same-key reuse)
	// Key B signs msg3 with k1 and msg4 with k2 (cross-key bridge)
	// Key C signs msg5 and msg6 with k2 (same-key reuse)

	msg1 := crypto.Keccak256([]byte("msg1"))
	msg2 := crypto.Keccak256([]byte("msg2"))
	msg3 := crypto.Keccak256([]byte("msg3"))
	msg4 := crypto.Keccak256([]byte("msg4"))
	msg5 := crypto.Keccak256([]byte("msg5"))
	msg6 := crypto.Keccak256([]byte("msg6"))

	r1, s1 := signWithNonce(privKeyA, msg1, k1)
	_, s2 := signWithNonce(privKeyA, msg2, k1) // r2 == r1
	r3, s3 := signWithNonce(privKeyB, msg3, k1) // r3 == r1
	r4, s4 := signWithNonce(privKeyB, msg4, k2)
	_, s5 := signWithNonce(privKeyC, msg5, k2) // r5 == r4
	_, s6 := signWithNonce(privKeyC, msg6, k2) // r6 == r4

	// Verify nonce reuse creates matching R values
	if r1.Cmp(r3) != 0 {
		t.Fatal("k1 should produce same R for different keys")
	}
	if r4.Cmp(r4) != 0 {
		t.Fatal("k2 should produce same R for different keys")
	}

	// Build linear system
	// Equation: s*k - r*d = z (mod n)
	// Rearranged: s*k + (-r)*d = z

	ls := NewLinearSystem(secp256k1N)

	// Variables: k1, k2, dA, dB, dC
	k1Idx := ls.AddVariable("k1")
	k2Idx := ls.AddVariable("k2")
	dAIdx := ls.AddVariable("dA")
	dBIdx := ls.AddVariable("dB")
	dCIdx := ls.AddVariable("dC")

	negR1 := new(big.Int).Neg(r1)
	negR1.Mod(negR1, secp256k1N)
	negR4 := new(big.Int).Neg(r4)
	negR4.Mod(negR4, secp256k1N)

	z1 := new(big.Int).SetBytes(msg1)
	z2 := new(big.Int).SetBytes(msg2)
	z3 := new(big.Int).SetBytes(msg3)
	z4 := new(big.Int).SetBytes(msg4)
	z5 := new(big.Int).SetBytes(msg5)
	z6 := new(big.Int).SetBytes(msg6)

	// sig1: s1*k1 - r1*dA = z1 → Key A, nonce k1
	ls.AddEquation(map[int]*big.Int{k1Idx: s1, dAIdx: negR1}, z1)
	// sig2: s2*k1 - r1*dA = z2 → Key A, nonce k1
	ls.AddEquation(map[int]*big.Int{k1Idx: s2, dAIdx: negR1}, z2)
	// sig3: s3*k1 - r1*dB = z3 → Key B, nonce k1
	ls.AddEquation(map[int]*big.Int{k1Idx: s3, dBIdx: negR1}, z3)
	// sig4: s4*k2 - r4*dB = z4 → Key B, nonce k2
	ls.AddEquation(map[int]*big.Int{k2Idx: s4, dBIdx: negR4}, z4)
	// sig5: s5*k2 - r4*dC = z5 → Key C, nonce k2
	ls.AddEquation(map[int]*big.Int{k2Idx: s5, dCIdx: negR4}, z5)
	// sig6: s6*k2 - r4*dC = z6 → Key C, nonce k2
	ls.AddEquation(map[int]*big.Int{k2Idx: s6, dCIdx: negR4}, z6)

	t.Logf("System: %d equations, %d variables", ls.NumEquations(), ls.NumVariables())

	if !ls.CanSolve() {
		t.Fatal("System should be solvable")
	}

	solutions, err := ls.Solve()
	if err != nil {
		t.Fatalf("Failed to solve: %v", err)
	}

	// Verify recovered values match originals
	if solutions["k1"].Cmp(k1) != 0 {
		t.Errorf("k1 mismatch")
	}
	if solutions["k2"].Cmp(k2) != 0 {
		t.Errorf("k2 mismatch")
	}
	if solutions["dA"].Cmp(privKeyA.D) != 0 {
		t.Errorf("dA mismatch")
	}
	if solutions["dB"].Cmp(privKeyB.D) != 0 {
		t.Errorf("dB mismatch")
	}
	if solutions["dC"].Cmp(privKeyC.D) != 0 {
		t.Errorf("dC mismatch")
	}

	// Verify we can derive addresses from recovered keys
	dABytes := solutions["dA"].FillBytes(make([]byte, 32))
	recoveredA, _ := crypto.ToECDSA(dABytes)
	addrA := crypto.PubkeyToAddress(recoveredA.PublicKey).Hex()
	expectedAddrA := crypto.PubkeyToAddress(privKeyA.PublicKey).Hex()

	if addrA != expectedAddrA {
		t.Errorf("Recovered address A mismatch: got %s, want %s", addrA, expectedAddrA)
	}

	t.Logf("Successfully recovered 3 private keys and 2 nonces from 6 signatures!")
}
