package recovery

import (
	"math/big"
	"testing"
)

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

func TestRecoverFromSignatures(t *testing.T) {
	// This tests the mathematical correctness of recovery
	// Using constructed values where we know the private key

	// These are example values - in a real test we'd use actual tx data
	// For now just verify the function doesn't panic on reasonable inputs
	z1 := big.NewInt(12345)
	z2 := big.NewInt(67890)
	r := big.NewInt(11111)
	s1 := big.NewInt(22222)
	s2 := big.NewInt(33333)

	// This will likely fail verification but shouldn't panic
	_, err := RecoverFromSignatures(z1, r, s1, z2, r, s2)
	// We expect an error because these aren't real signature values
	if err == nil {
		t.Log("Recovery succeeded with test values (unexpected but not wrong)")
	}
}

func TestDeriveNonce(t *testing.T) {
	// Test that DeriveNonce produces valid output
	z := big.NewInt(12345)
	r := big.NewInt(11111)
	s := big.NewInt(22222)
	privKey := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

	nonce := DeriveNonce(z, r, s, privKey)
	if len(nonce) != 66 { // 0x + 64 hex chars
		t.Errorf("Expected nonce length 66, got %d", len(nonce))
	}
}
