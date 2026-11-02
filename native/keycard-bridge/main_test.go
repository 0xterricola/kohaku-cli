package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const testAddress = "0x1111111111111111111111111111111111111111"

func TestArgumentValidation(t *testing.T) {
	cases := [][]string{
		{},
		{"unknown"},
		{"get-address", "--hex", "0x01"},
		{"get-address", "--path", "../unsafe"},
		{"sign-digest"},
		{"sign-digest", "--hex", "0x12"},
		{"sign-digest", "--hex", "0x" + strings.Repeat("00", 32)},
		{"get-address", "--unexpected"},
	}

	for _, args := range cases {
		if _, err := parseOptions(args); err == nil {
			t.Errorf("unexpected success: %q", args)
		}
	}
}

func TestValidArguments(t *testing.T) {
	if _, err := parseOptions([]string{"get-address"}); err != nil {
		t.Fatal(err)
	}

	_, err := parseOptions([]string{
		"sign-digest",
		"--hex", "0x" + strings.Repeat("ab", 32),
		"--expected-address", testAddress,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignatureRecovery(t *testing.T) {
	// Disposable known test key, never a funded wallet.
	priv, err := crypto.HexToECDSA(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}

	digest := crypto.Keccak256([]byte("v2-test"))
	sig, err := crypto.Sign(digest, priv)
	if err != nil {
		t.Fatal(err)
	}

	expected := crypto.PubkeyToAddress(priv.PublicKey)

	result, err := recoverSignature(
		digest,
		sig[:32],
		sig[32:64],
		sig[64],
		expected,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result["signature_v"] != int(sig[64]) {
		t.Fatal("recovery parity mismatch")
	}

	r, err := hex.DecodeString(
		strings.TrimPrefix(result["signature_r"].(string), "0x"),
	)
	if err != nil || len(r) != 32 {
		t.Fatal("invalid r serialization")
	}

	modified := crypto.Keccak256([]byte("modified"))
	if _, err := recoverSignature(
		modified,
		sig[:32],
		sig[32:64],
		sig[64],
		expected,
	); err == nil {
		t.Fatal("modified digest accepted")
	}
}

func TestLegacyPINEnvironmentRejected(t *testing.T) {
	t.Setenv("KEYCARD_PIN", "test-secret")

	if err := rejectLegacySecrets(); err == nil {
		t.Fatal("legacy PIN environment accepted")
	}
}
