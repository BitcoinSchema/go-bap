package bap

import (
	"os"
	"testing"
)

// Identity Private Key
const pk = "xprv9s21ZrQH143K2beTKhLXFRWWFwH8jkwUssjk3SVTiApgmge7kNC3jhVc4NgHW8PhW2y7BCDErqnKpKuyQMjqSePPJooPJowAz5BVLThsv6c"
const idKey = "8bafa4ca97d770276253585cb2a49da1775ec7aeed3178e346c8c1b55eaf5ca2"

func TestCreateIdentity(t *testing.T) {
	var currentCounter uint32
	tx, err := CreateIdentity(pk, idKey, currentCounter)
	if err != nil {
		t.Error("Failed to create identity:", err)
	}

	if tx.GetTxID() != "e6b6aad0cd2d1c0aa0a854e7acc0e9b164e722bf041fb24c48a3998da1e1e463" {
		t.Error("Failed to create identity")
	}
}

func TestCreateAttestation(t *testing.T) {

	// Entity / Service Provider's Identity Private Key
	entityPk := os.Getenv("BAP_ENTITY_XPRIV")
	t.Log("pk", entityPk)
	var currentCounter uint32
	// Create an attestation
	entitySigningKey, entitySigningAddress, err := deriveKeys(entityPk, currentCounter)

	attributeName := "internal-wallet-address"
	attributeValue := "1Jipv1nANv5JKdZYEU7yNxKcs7WjB5NnTn"
	identityAttributeSecret := "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"

	// key := hex.EncodeToString(entitySigningKey.Serialize())
	// log.Println("BAP ENTITY XPRIV", key)

	attestation, err := CreateAttestation(idKey, entitySigningKey, entitySigningAddress, attributeName, attributeValue, identityAttributeSecret)
	if err != nil {
		t.Error("Failed to create attestation", err)
	}

	if attestation.GetTxID() != "d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43" {
		t.Error("Failed to craete attestation. Unexpected TXID", attestation.GetTxID())
	}
}
