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

	if tx.GetTxID() != "e97ed4acb8d01a822dd5070e6addf762949f48a696311a954b85cd4a9c993a23" {
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
	attestation, err := CreateAttestation(idKey, entitySigningKey, entitySigningAddress)
	if err != nil {
		t.Error("Failed to create attestation", err)
	}

	if attestation.GetTxID() != "d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43" {
		t.Error("Attestation", attestation.GetTxID())
	}
}
