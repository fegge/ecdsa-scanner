package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/recovery"
)

var secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

// signWithNonce signs a message hash with a specific nonce k
func signWithNonce(privKey *ecdsa.PrivateKey, hash []byte, k *big.Int) (r, s *big.Int) {
	curve := secp256k1.S256()
	N := curve.Params().N

	// R = k * G
	rx, _ := curve.ScalarBaseMult(k.Bytes())
	r = new(big.Int).Mod(rx, N)

	// s = k^(-1) * (z + r*d) mod N
	z := new(big.Int).SetBytes(hash)
	kInv := new(big.Int).ModInverse(k, N)
	rd := new(big.Int).Mul(r, privKey.D)
	s = new(big.Int).Add(z, rd)
	s.Mul(s, kInv)
	s.Mod(s, N)

	return r, s
}

// generateKey creates a random private key
func generateKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// generateNonce creates a random nonce
func generateNonce(t *testing.T) *big.Int {
	k, err := rand.Int(rand.Reader, secp256k1N)
	if err != nil {
		t.Fatal(err)
	}
	if k.Sign() == 0 {
		k.SetInt64(1)
	}
	return k
}

// generateHash creates a random message hash
func generateHash(t *testing.T) []byte {
	hash := make([]byte, 32)
	rand.Read(hash)
	return hash
}

// mockTxData creates TxData from test parameters
func mockTxData(hash string, chainID int, from string, z, r, s *big.Int) *TxData {
	return &TxData{
		Hash:    hash,
		ChainID: chainID,
		From:    from,
		Z:       z,
		R:       r,
		S:       s,
	}
}

// TestSameKeyNonceReuseTriggersRecovery verifies that when the same address
// signs two transactions with the same nonce, key recovery is triggered.
func TestSameKeyNonceReuseTriggersRecovery(t *testing.T) {
	ctx := context.Background()
	mockDB := db.NewMock()
	log := logger.New(100)

	privKey := generateKey(t)
	addr := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
	k := generateNonce(t)

	hash1 := generateHash(t)
	hash2 := generateHash(t)

	r1, s1 := signWithNonce(privKey, hash1, k)
	_, s2 := signWithNonce(privKey, hash2, k)

	z1 := new(big.Int).SetBytes(hash1)
	z2 := new(big.Int).SetBytes(hash2)

	// Simulate same-key collision detection and recovery
	tx1 := mockTxData("0xtx1", 1, addr, z1, r1, s1)
	tx2 := mockTxData("0xtx2", 1, addr, z2, r1, s2)

	// Attempt recovery (this is what the scanner does)
	recoveredPriv, err := recovery.RecoverFromSignatures(tx1.Z, tx1.R, tx1.S, tx2.Z, tx2.R, tx2.S)
	if err != nil {
		t.Fatalf("Recovery failed: %v", err)
	}

	if !recovery.VerifyPrivateKey(recoveredPriv, addr) {
		t.Fatal("Recovered key doesn't match address")
	}

	// Save to database (simulating what scanner does)
	keyID, err := mockDB.SaveRecoveredKey(ctx, &db.RecoveredKey{
		Address:    strings.ToLower(addr),
		PrivateKey: recoveredPriv,
		ChainID:    1,
		RValues:    []string{"0x" + r1.Text(16)},
		TxHashes:   []string{tx1.Hash, tx2.Hash},
	})
	if err != nil {
		t.Fatalf("Failed to save key: %v", err)
	}
	if keyID == 0 {
		t.Fatal("Expected non-zero key ID")
	}

	// Verify key is marked as recovered
	isRecovered, _ := mockDB.IsKeyRecovered(ctx, strings.ToLower(addr), 1)
	if !isRecovered {
		t.Fatal("Key should be marked as recovered")
	}

	log.Info("Same-key recovery test passed")
}

// TestCrossKeyWithKnownNonceTriggersRecovery verifies that when we have
// a known nonce from a previously recovered key, we can recover another key.
func TestCrossKeyWithKnownNonceTriggersRecovery(t *testing.T) {
	ctx := context.Background()
	mockDB := db.NewMock()

	privKeyA := generateKey(t)
	privKeyB := generateKey(t)
	addrA := crypto.PubkeyToAddress(privKeyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(privKeyB.PublicKey).Hex()

	k1 := generateNonce(t) // Used by A twice (same-key reuse)
	k2 := generateNonce(t) // Used by A and B (cross-key)

	// A signs two messages with k1
	hashA1 := generateHash(t)
	hashA2 := generateHash(t)
	rA1, sA1 := signWithNonce(privKeyA, hashA1, k1)
	_, sA2 := signWithNonce(privKeyA, hashA2, k1)

	// A and B sign with k2
	hashA3 := generateHash(t)
	hashB := generateHash(t)
	rA3, sA3 := signWithNonce(privKeyA, hashA3, k2)
	rB, sB := signWithNonce(privKeyB, hashB, k2)

	// Step 1: Recover A's key from same-key reuse
	zA1 := new(big.Int).SetBytes(hashA1)
	zA2 := new(big.Int).SetBytes(hashA2)

	recoveredPrivA, err := recovery.RecoverFromSignatures(zA1, rA1, sA1, zA2, rA1, sA2)
	if err != nil {
		t.Fatalf("Key A recovery failed: %v", err)
	}

	if !recovery.VerifyPrivateKey(recoveredPrivA, addrA) {
		t.Fatal("Recovered key A doesn't match address")
	}

	// Save A's key
	keyID, _ := mockDB.SaveRecoveredKey(ctx, &db.RecoveredKey{
		Address:    strings.ToLower(addrA),
		PrivateKey: recoveredPrivA,
		ChainID:    1,
		RValues:    []string{"0x" + rA1.Text(16)},
		TxHashes:   []string{"0xtxA1", "0xtxA2"},
	})

	// Step 2: Derive k2 from A's signature
	zA3 := new(big.Int).SetBytes(hashA3)
	derivedK2 := recovery.DeriveNonce(zA3, rA3, sA3, recoveredPrivA)

	// Save the nonce for cross-key recovery
	mockDB.SaveRecoveredNonce(ctx, &db.RecoveredNonce{
		RValue:           "0x" + rA3.Text(16),
		KValue:           derivedK2, // Already 0x prefixed
		DerivedFromKeyID: keyID,
	})

	// Step 3: Now B's signature with k2 can be recovered
	zB := new(big.Int).SetBytes(hashB)
	recoveredPrivB, err := recovery.RecoverWithKnownNonce(zB, rB, sB, derivedK2)
	if err != nil {
		t.Fatalf("Key B recovery failed: %v", err)
	}

	if !recovery.VerifyPrivateKey(recoveredPrivB, addrB) {
		t.Fatal("Recovered key B doesn't match address")
	}

	// Save B's key
	mockDB.SaveRecoveredKey(ctx, &db.RecoveredKey{
		Address:    strings.ToLower(addrB),
		PrivateKey: recoveredPrivB,
		ChainID:    1,
		RValues:    []string{"0x" + rB.Text(16)},
		TxHashes:   []string{"0xtxB"},
	})

	// Verify both keys are recovered
	isRecoveredA, _ := mockDB.IsKeyRecovered(ctx, strings.ToLower(addrA), 1)
	isRecoveredB, _ := mockDB.IsKeyRecovered(ctx, strings.ToLower(addrB), 1)

	if !isRecoveredA || !isRecoveredB {
		t.Fatal("Both keys should be recovered")
	}
}

// TestCrossKeyWithoutKnownNonceSavesPending verifies that cross-key collisions
// without a known nonce are saved as pending components.
func TestCrossKeyWithoutKnownNonceSavesPending(t *testing.T) {
	ctx := context.Background()
	mockDB := db.NewMock()

	privKeyA := generateKey(t)
	privKeyB := generateKey(t)
	addrA := crypto.PubkeyToAddress(privKeyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(privKeyB.PublicKey).Hex()

	k := generateNonce(t)

	hashA := generateHash(t)
	hashB := generateHash(t)

	rA, _ := signWithNonce(privKeyA, hashA, k)
	rB, _ := signWithNonce(privKeyB, hashB, k)

	// R values should be the same (same nonce)
	if rA.Cmp(rB) != 0 {
		t.Fatal("R values should match for same nonce")
	}

	rValue := "0x" + rA.Text(16)

	// Check if we have a known nonce (we don't)
	_, err := mockDB.GetRecoveredNonce(ctx, rValue)
	if err == nil {
		t.Fatal("Should not have a known nonce")
	}

	// Save as pending component (this is what scanner does for unsolvable cross-key)
	err = mockDB.SavePendingComponent(ctx, &db.PendingComponent{
		RValues:   []string{rValue},
		TxHashes:  []string{"0xtxA", "0xtxB"},
		Addresses: []string{strings.ToLower(addrA), strings.ToLower(addrB)},
		ChainIDs:  []int{1, 1},
		Equations: 2,
		Unknowns:  3, // 2 keys + 1 nonce
	})
	if err != nil {
		t.Fatalf("Failed to save pending component: %v", err)
	}

	// Verify pending component exists
	comps, _ := mockDB.GetPendingComponents(ctx)
	if len(comps) != 1 {
		t.Fatalf("Expected 1 pending component, got %d", len(comps))
	}

	if comps[0].Equations != 2 || comps[0].Unknowns != 3 {
		t.Fatal("Pending component has wrong equation/unknown count")
	}
}

// TestCyclicCrossKeyRecovery verifies that cyclic cross-key scenarios
// (A-B share k1, B-C share k2, C-A share k3) can be solved via linear system.
func TestCyclicCrossKeyRecovery(t *testing.T) {
	privKeyA := generateKey(t)
	privKeyB := generateKey(t)
	privKeyC := generateKey(t)

	addrA := crypto.PubkeyToAddress(privKeyA.PublicKey).Hex()
	addrB := crypto.PubkeyToAddress(privKeyB.PublicKey).Hex()
	addrC := crypto.PubkeyToAddress(privKeyC.PublicKey).Hex()

	k1 := generateNonce(t)
	k2 := generateNonce(t)
	k3 := generateNonce(t)

	// Generate unique message hashes
	msgs := make([][]byte, 6)
	for i := range msgs {
		msgs[i] = generateHash(t)
		msgs[i][0] = byte(i)
	}

	// Sign:
	// msg0: A with k1, msg1: B with k1
	// msg2: B with k2, msg3: C with k2
	// msg4: C with k3, msg5: A with k3
	r1, sA1 := signWithNonce(privKeyA, msgs[0], k1)
	_, sB1 := signWithNonce(privKeyB, msgs[1], k1)
	r2, sB2 := signWithNonce(privKeyB, msgs[2], k2)
	_, sC2 := signWithNonce(privKeyC, msgs[3], k2)
	r3, sC3 := signWithNonce(privKeyC, msgs[4], k3)
	_, sA3 := signWithNonce(privKeyA, msgs[5], k3)

	// Build linear system
	ls := recovery.NewLinearSystem(secp256k1N)

	k1Idx := ls.AddVariable("k1")
	k2Idx := ls.AddVariable("k2")
	k3Idx := ls.AddVariable("k3")
	dAIdx := ls.AddVariable("dA")
	dBIdx := ls.AddVariable("dB")
	dCIdx := ls.AddVariable("dC")

	negR1 := new(big.Int).Neg(r1)
	negR1.Mod(negR1, secp256k1N)
	negR2 := new(big.Int).Neg(r2)
	negR2.Mod(negR2, secp256k1N)
	negR3 := new(big.Int).Neg(r3)
	negR3.Mod(negR3, secp256k1N)

	zs := make([]*big.Int, 6)
	for i, msg := range msgs {
		zs[i] = new(big.Int).SetBytes(msg)
	}

	// Add equations: s*k - r*d = z
	ls.AddEquation(map[int]*big.Int{k1Idx: sA1, dAIdx: negR1}, zs[0])
	ls.AddEquation(map[int]*big.Int{k1Idx: sB1, dBIdx: negR1}, zs[1])
	ls.AddEquation(map[int]*big.Int{k2Idx: sB2, dBIdx: negR2}, zs[2])
	ls.AddEquation(map[int]*big.Int{k2Idx: sC2, dCIdx: negR2}, zs[3])
	ls.AddEquation(map[int]*big.Int{k3Idx: sC3, dCIdx: negR3}, zs[4])
	ls.AddEquation(map[int]*big.Int{k3Idx: sA3, dAIdx: negR3}, zs[5])

	if !ls.CanSolve() {
		t.Fatalf("System should be solvable: %d eq, %d var",
			ls.NumEquations(), ls.NumVariables())
	}

	solutions, err := ls.Solve()
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Verify all recovered private keys
	recoveredA := "0x" + solutions["dA"].Text(16)
	recoveredB := "0x" + solutions["dB"].Text(16)
	recoveredC := "0x" + solutions["dC"].Text(16)

	if !recovery.VerifyPrivateKey(recoveredA, addrA) {
		t.Fatal("Recovered key A doesn't match")
	}
	if !recovery.VerifyPrivateKey(recoveredB, addrB) {
		t.Fatal("Recovered key B doesn't match")
	}
	if !recovery.VerifyPrivateKey(recoveredC, addrC) {
		t.Fatal("Recovered key C doesn't match")
	}
}

// TestMultipleCollisionsSameAddress verifies that finding multiple R-value
// collisions for the same address triggers recovery on the first collision.
func TestMultipleCollisionsSameAddress(t *testing.T) {
	ctx := context.Background()
	mockDB := db.NewMock()

	privKey := generateKey(t)
	addr := strings.ToLower(crypto.PubkeyToAddress(privKey.PublicKey).Hex())

	k1 := generateNonce(t)
	k2 := generateNonce(t)

	// First collision with k1
	hash1 := generateHash(t)
	hash2 := generateHash(t)
	r1, s1 := signWithNonce(privKey, hash1, k1)
	_, s2 := signWithNonce(privKey, hash2, k1)

	// Second collision with k2
	hash3 := generateHash(t)
	hash4 := generateHash(t)
	r3, s3 := signWithNonce(privKey, hash3, k2)
	_, s4 := signWithNonce(privKey, hash4, k2)

	// First collision should trigger recovery
	z1 := new(big.Int).SetBytes(hash1)
	z2 := new(big.Int).SetBytes(hash2)

	recoveredPriv, err := recovery.RecoverFromSignatures(z1, r1, s1, z2, r1, s2)
	if err != nil {
		t.Fatalf("First recovery failed: %v", err)
	}

	mockDB.SaveRecoveredKey(ctx, &db.RecoveredKey{
		Address:    addr,
		PrivateKey: recoveredPriv,
		ChainID:    1,
		RValues:    []string{"0x" + r1.Text(16)},
		TxHashes:   []string{"0xtx1", "0xtx2"},
	})

	// Key should be marked as recovered
	isRecovered, _ := mockDB.IsKeyRecovered(ctx, addr, 1)
	if !isRecovered {
		t.Fatal("Key should be recovered after first collision")
	}

	// Second collision should be skipped (key already recovered)
	// This is the check the scanner does before attempting recovery
	isRecovered2, _ := mockDB.IsKeyRecovered(ctx, addr, 1)
	if !isRecovered2 {
		t.Fatal("Key should still be marked as recovered")
	}

	// But we can still verify the second collision would give same key
	z3 := new(big.Int).SetBytes(hash3)
	z4 := new(big.Int).SetBytes(hash4)

	recoveredPriv2, err := recovery.RecoverFromSignatures(z3, r3, s3, z4, r3, s4)
	if err != nil {
		t.Fatalf("Second recovery failed: %v", err)
	}

	if recoveredPriv != recoveredPriv2 {
		t.Fatal("Both collisions should recover the same key")
	}
}
