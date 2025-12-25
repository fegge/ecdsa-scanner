package recovery

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"pgregory.net/rapid"
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

	return r, s
}

// genPrivateKey generates a random ECDSA private key
func genPrivateKey(t *rapid.T) *ecdsa.PrivateKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// genNonce generates a random valid nonce (1 < k < n)
func genNonce(t *rapid.T) *big.Int {
	// Generate random bytes and reduce mod n
	bytes := rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "nonce_bytes")
	k := new(big.Int).SetBytes(bytes)
	k.Mod(k, secp256k1N)
	// Ensure k > 0
	if k.Sign() == 0 {
		k.SetInt64(1)
	}
	return k
}

// genMessageHash generates a random 32-byte message hash
func genMessageHash(t *rapid.T) []byte {
	return rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "hash")
}

// Property: Recovering a private key from two signatures with the same nonce always works
func TestPropertySameKeyRecovery(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		k := genNonce(t)
		hash1 := genMessageHash(t)
		hash2 := genMessageHash(t)

		// Ensure different messages
		if string(hash1) == string(hash2) {
			hash2[0] ^= 0xff
		}

		r1, s1 := signWithNonce(privKey, hash1, k)
		r2, s2 := signWithNonce(privKey, hash2, k)

		// Same nonce means same R
		if r1.Cmp(r2) != 0 {
			t.Fatalf("R values should match for same nonce")
		}

		// Skip if s values are identical (degenerate case)
		if s1.Cmp(s2) == 0 {
			t.Skip("identical s values")
		}

		z1 := new(big.Int).SetBytes(hash1)
		z2 := new(big.Int).SetBytes(hash2)

		recoveredPriv, err := RecoverFromSignatures(z1, r1, s1, z2, r2, s2)
		if err != nil {
			t.Fatalf("recovery failed: %v", err)
		}

		expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
		if !VerifyPrivateKey(recoveredPriv, expectedAddr) {
			t.Fatalf("recovered key doesn't match: got %s", recoveredPriv)
		}
	})
}

// Property: Recovering with a known nonce always works
func TestPropertyKnownNonceRecovery(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		k := genNonce(t)
		hash := genMessageHash(t)

		r, s := signWithNonce(privKey, hash, k)
		z := new(big.Int).SetBytes(hash)

		kHex := "0x" + hex.EncodeToString(k.FillBytes(make([]byte, 32)))

		recoveredPriv, err := RecoverWithKnownNonce(z, r, s, kHex)
		if err != nil {
			t.Fatalf("recovery failed: %v", err)
		}

		expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
		if !VerifyPrivateKey(recoveredPriv, expectedAddr) {
			t.Fatalf("recovered key doesn't match")
		}
	})
}

// Property: Deriving nonce from signature and private key is correct
func TestPropertyDeriveNonce(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		k := genNonce(t)
		hash := genMessageHash(t)

		r, s := signWithNonce(privKey, hash, k)
		z := new(big.Int).SetBytes(hash)

		privKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privKey))
		derivedKHex := DeriveNonce(z, r, s, privKeyHex)

		expectedKHex := "0x" + hex.EncodeToString(k.FillBytes(make([]byte, 32)))
		if derivedKHex != expectedKHex {
			t.Fatalf("nonce mismatch: got %s, want %s", derivedKHex, expectedKHex)
		}
	})
}

// Property: Cross-key recovery works when nonce is shared
func TestPropertyCrossKeyRecovery(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Two different keys share the same nonce
		privKeyA := genPrivateKey(t)
		privKeyB := genPrivateKey(t)
		k := genNonce(t)

		hashA1 := genMessageHash(t)
		hashA2 := genMessageHash(t)
		hashB := genMessageHash(t)

		// Ensure different messages for key A
		if string(hashA1) == string(hashA2) {
			hashA2[0] ^= 0xff
		}

		// Key A signs two messages with same nonce (recoverable)
		rA1, sA1 := signWithNonce(privKeyA, hashA1, k)
		_, sA2 := signWithNonce(privKeyA, hashA2, k)

		// Key B signs one message with same nonce
		rB, sB := signWithNonce(privKeyB, hashB, k)

		// Skip degenerate cases
		if sA1.Cmp(sA2) == 0 {
			t.Skip("identical s values for key A")
		}

		// Step 1: Recover Key A
		zA1 := new(big.Int).SetBytes(hashA1)
		zA2 := new(big.Int).SetBytes(hashA2)

		recoveredPrivA, err := RecoverFromSignatures(zA1, rA1, sA1, zA2, rA1, sA2)
		if err != nil {
			t.Fatalf("Key A recovery failed: %v", err)
		}

		// Step 2: Derive nonce from Key A's signature
		derivedK := DeriveNonce(zA1, rA1, sA1, recoveredPrivA)

		// Step 3: Use known nonce to recover Key B
		zB := new(big.Int).SetBytes(hashB)
		recoveredPrivB, err := RecoverWithKnownNonce(zB, rB, sB, derivedK)
		if err != nil {
			t.Fatalf("Key B recovery failed: %v", err)
		}

		// Verify both recoveries
		expectedAddrA := crypto.PubkeyToAddress(privKeyA.PublicKey).Hex()
		expectedAddrB := crypto.PubkeyToAddress(privKeyB.PublicKey).Hex()

		if !VerifyPrivateKey(recoveredPrivA, expectedAddrA) {
			t.Fatalf("Key A mismatch")
		}
		if !VerifyPrivateKey(recoveredPrivB, expectedAddrB) {
			t.Fatalf("Key B mismatch")
		}
	})
}

// Property: Linear system solves multi-key multi-nonce scenarios
func TestPropertyLinearSystemMultiKey(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// 3 keys, 2 shared nonces
		privKeyA := genPrivateKey(t)
		privKeyB := genPrivateKey(t)
		privKeyC := genPrivateKey(t)

		k1 := genNonce(t)
		k2 := genNonce(t)

		// Generate 6 different message hashes
		msgs := make([][]byte, 6)
		for i := range msgs {
			msgs[i] = genMessageHash(t)
			// Ensure uniqueness
			msgs[i][0] = byte(i)
		}

		// Sign:
		// msg0, msg1: Key A with k1
		// msg2: Key B with k1
		// msg3: Key B with k2
		// msg4, msg5: Key C with k2

		r1, s1 := signWithNonce(privKeyA, msgs[0], k1)
		_, s2 := signWithNonce(privKeyA, msgs[1], k1)
		_, s3 := signWithNonce(privKeyB, msgs[2], k1)
		r4, s4 := signWithNonce(privKeyB, msgs[3], k2)
		_, s5 := signWithNonce(privKeyC, msgs[4], k2)
		_, s6 := signWithNonce(privKeyC, msgs[5], k2)

		// Build linear system
		ls := NewLinearSystem(secp256k1N)

		k1Idx := ls.AddVariable("k1")
		k2Idx := ls.AddVariable("k2")
		dAIdx := ls.AddVariable("dA")
		dBIdx := ls.AddVariable("dB")
		dCIdx := ls.AddVariable("dC")

		negR1 := new(big.Int).Neg(r1)
		negR1.Mod(negR1, secp256k1N)
		negR4 := new(big.Int).Neg(r4)
		negR4.Mod(negR4, secp256k1N)

		zs := make([]*big.Int, 6)
		for i, msg := range msgs {
			zs[i] = new(big.Int).SetBytes(msg)
		}

		// Add equations: s*k - r*d = z
		ls.AddEquation(map[int]*big.Int{k1Idx: s1, dAIdx: negR1}, zs[0])
		ls.AddEquation(map[int]*big.Int{k1Idx: s2, dAIdx: negR1}, zs[1])
		ls.AddEquation(map[int]*big.Int{k1Idx: s3, dBIdx: negR1}, zs[2])
		ls.AddEquation(map[int]*big.Int{k2Idx: s4, dBIdx: negR4}, zs[3])
		ls.AddEquation(map[int]*big.Int{k2Idx: s5, dCIdx: negR4}, zs[4])
		ls.AddEquation(map[int]*big.Int{k2Idx: s6, dCIdx: negR4}, zs[5])

		if !ls.CanSolve() {
			t.Fatalf("system should be solvable: %d eq, %d var",
				ls.NumEquations(), ls.NumVariables())
		}

		solutions, err := ls.Solve()
		if err != nil {
			t.Fatalf("solve failed: %v", err)
		}

		// Verify all recovered values
		if solutions["k1"].Cmp(k1) != 0 {
			t.Fatalf("k1 mismatch")
		}
		if solutions["k2"].Cmp(k2) != 0 {
			t.Fatalf("k2 mismatch")
		}
		if solutions["dA"].Cmp(privKeyA.D) != 0 {
			t.Fatalf("dA mismatch")
		}
		if solutions["dB"].Cmp(privKeyB.D) != 0 {
			t.Fatalf("dB mismatch")
		}
		if solutions["dC"].Cmp(privKeyC.D) != 0 {
			t.Fatalf("dC mismatch")
		}
	})
}

// Property: Recovery fails with different R values
func TestPropertyRecoveryFailsDifferentR(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		k1 := genNonce(t)
		k2 := genNonce(t)

		// Ensure different nonces
		if k1.Cmp(k2) == 0 {
			k2.Add(k2, big.NewInt(1))
			k2.Mod(k2, secp256k1N)
		}

		hash1 := genMessageHash(t)
		hash2 := genMessageHash(t)

		r1, s1 := signWithNonce(privKey, hash1, k1)
		r2, s2 := signWithNonce(privKey, hash2, k2)

		// Different nonces should produce different R values
		if r1.Cmp(r2) == 0 {
			t.Skip("rare collision")
		}

		z1 := new(big.Int).SetBytes(hash1)
		z2 := new(big.Int).SetBytes(hash2)

		_, err := RecoverFromSignatures(z1, r1, s1, z2, r2, s2)
		if err == nil {
			t.Fatalf("should fail with different R values")
		}
	})
}

// Property: Recovery fails with identical signatures
func TestPropertyRecoveryFailsIdentical(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		k := genNonce(t)
		hash := genMessageHash(t)

		r, s := signWithNonce(privKey, hash, k)
		z := new(big.Int).SetBytes(hash)

		_, err := RecoverFromSignatures(z, r, s, z, r, s)
		if err == nil {
			t.Fatalf("should fail with identical signatures")
		}
	})
}

// Property: VerifyPrivateKey correctly validates key-address pairs
func TestPropertyVerifyPrivateKey(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		privKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privKey))
		expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()

		// Should verify correctly
		if !VerifyPrivateKey(privKeyHex, expectedAddr) {
			t.Fatalf("should verify correct key-address pair")
		}

		// Should fail with wrong address
		wrongAddr := "0x0000000000000000000000000000000000000000"
		if VerifyPrivateKey(privKeyHex, wrongAddr) {
			t.Fatalf("should reject wrong address")
		}
	})
}

// Property: GetAddressFromPrivateKey is consistent
func TestPropertyGetAddress(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		privKey := genPrivateKey(t)
		privKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privKey))
		expectedAddr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()

		addr, err := GetAddressFromPrivateKey(privKeyHex)
		if err != nil {
			t.Fatalf("GetAddressFromPrivateKey failed: %v", err)
		}

		if addr != expectedAddr {
			t.Fatalf("address mismatch: got %s, want %s", addr, expectedAddr)
		}
	})
}

// Property: Linear system correctly identifies underdetermined systems
func TestPropertyLinearSystemUnderdetermined(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numVars := rapid.IntRange(2, 5).Draw(t, "numVars")
		numEqs := rapid.IntRange(1, numVars-1).Draw(t, "numEqs")

		ls := NewLinearSystem(secp256k1N)

		for i := 0; i < numVars; i++ {
			ls.AddVariable(rapid.String().Draw(t, "varName"))
		}

		for i := 0; i < numEqs; i++ {
			coeffs := make(map[int]*big.Int)
			for j := 0; j < numVars; j++ {
				coeffs[j] = big.NewInt(int64(rapid.IntRange(1, 1000).Draw(t, "coeff")))
			}
			ls.AddEquation(coeffs, big.NewInt(int64(rapid.IntRange(1, 1000).Draw(t, "const"))))
		}

		if ls.CanSolve() {
			t.Fatalf("should not be solvable: %d equations, %d variables",
				ls.NumEquations(), ls.NumVariables())
		}

		_, err := ls.Solve()
		if err == nil {
			t.Fatalf("should fail for underdetermined system")
		}
	})
}
