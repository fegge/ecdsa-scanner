package recovery

import (
	"testing"
)

func TestVerifyPrivateKey(t *testing.T) {
	// Known test case: private key and corresponding address
	// This private key is for testing only - never use on mainnet!
	testPrivKey := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	expectedAddr := "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"

	if !VerifyPrivateKey(testPrivKey, expectedAddr) {
		t.Errorf("VerifyPrivateKey failed for known good key/address pair")
	}

	// Wrong address should fail
	if VerifyPrivateKey(testPrivKey, "0x0000000000000000000000000000000000000000") {
		t.Errorf("VerifyPrivateKey should fail for wrong address")
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

func TestGetPublicKey(t *testing.T) {
	testPrivKey := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

	pubKey, err := GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}

	// Public key should be 65 bytes (0x04 prefix + 64 bytes)
	if len(pubKey) != 132 { // "0x" + 130 hex chars
		t.Errorf("Expected public key length 132, got %d", len(pubKey))
	}
}
