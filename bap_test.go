package bap

import (
	"testing"

	"github.com/libsv/libsv/transaction"
)

// Identity Private Key
const privateKey = "xprv9s21ZrQH143K2beTKhLXFRWWFwH8jkwUssjk3SVTiApgmge7kNC3jhVc4NgHW8PhW2y7BCDErqnKpKuyQMjqSePPJooPJowAz5BVLThsv6c"
const idKey = "8bafa4ca97d770276253585cb2a49da1775ec7aeed3178e346c8c1b55eaf5ca2"

// TestCreateIdentity will test the method CreateIdentity()
func TestCreateIdentity(t *testing.T) {
	tx, err := CreateIdentity(privateKey, idKey, 0)
	if err != nil {
		t.Fatalf("failed to create identity: %s", err.Error())
	}

	if tx.GetTxID() != "e6b6aad0cd2d1c0aa0a854e7acc0e9b164e722bf041fb24c48a3998da1e1e463" {
		t.Fatalf("failed to create identity, got: %s", tx.GetTxID())
	}
}

// TestCreateAttestation will test the method CreateAttestation()
func TestCreateAttestation(t *testing.T) {

	// Entity / Service Provider's Identity Private Key
	entityPk := "xprv9s21ZrQH143K3PZSwbEeXEYq74EbnfMngzAiMCZcfjzyRpUvt2vQJnaHRTZjeuEmLXeN6BzYRoFsEckfobxE9XaRzeLGfQoxzPzTRyRb6oE"

	// Derive the keys
	entitySigningKey, entitySigningAddress, err := deriveKeys(entityPk, 0)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	t.Log(entitySigningKey)
	t.Log(entitySigningAddress)

	attributeName := "internal-wallet-address"
	attributeValue := "1Jipv1nANv5JKdZYEU7yNxKcs7WjB5NnTn"
	identityAttributeSecret := "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"

	var attestation *transaction.Transaction
	if attestation, err = CreateAttestation(
		idKey,
		entitySigningKey,
		entitySigningAddress,
		attributeName,
		attributeValue,
		identityAttributeSecret,
	); err != nil {
		t.Fatalf("failed to create attestation: %s", err.Error())
	}

	// Log out the tx
	t.Log(attestation.ToString())
	t.Log(attestation.GetTxID())

	// Check the tx id
	if attestation.GetTxID() != "f1126889e3873150d4ca93753b0f67ae338db4f725cc05390cd285bfac25ef8e" {
		t.Fatalf("failed to create attestation - unexpected tx_id: %s", attestation.GetTxID())
	}
}

// todo: mature the tests, examples & benchmarks
