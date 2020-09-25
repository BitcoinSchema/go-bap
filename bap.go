package bap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/libsv/libsv/script/address"
	"github.com/libsv/libsv/transaction"
	"github.com/libsv/libsv/transaction/output"
	"github.com/rohenaz/go-aip"
	"github.com/rohenaz/go-bob"
)

// Prefix is the bitcom prefix for Bitcoin Attestation Protocol
const Prefix = "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT"

// Types is an enum for Bap Type Constants
type Types string

// Bap Type Constants
const (
	ID     Types = "ID"
	REVOKE Types = "REVOKE"
	ATTEST Types = "ATTEST"
)

// Data is Bitcoin Attestation Protocol data
type Data struct {
	Type     Types  `json:"type,omitempty" bson:"type,omitempty"`
	URNHash  string `json:"urnHash,omitempty" bson:"urnHash,omitempty"`
	IDKey    string `json:"IDKey,omitempty" bson:"IDKey,omitempty"`
	Address  string `json:"address,omitempty" bson:"address,omitempty"`
	Sequence uint8  `json:"sequence" bson:"sequence"`
}

// New created a new Bap structure
func New() *Data {
	return &Data{}
}

// FromTape takes a BOB Tape and returns a Bap data structure
func (b *Data) FromTape(tape bob.Tape) error {

	b.Type = Types(tape.Cell[1].S)

	switch Types(b.Type) {
	case ATTEST:
		fallthrough
	case REVOKE:
		if len(tape.Cell) < 4 {
			return fmt.Errorf("Invalid attest or revoke record %+v", tape.Cell)
		}
		b.URNHash = tape.Cell[2].S
		seq, _ := strconv.ParseUint(tape.Cell[3].S, 10, 64)
		b.Sequence = uint8(seq)
	case ID:
		if len(tape.Cell) < 4 {
			return fmt.Errorf("Invalid Identity record %+v", tape.Cell)
		}
		b.Address = tape.Cell[3].S
		b.IDKey = tape.Cell[2].S
	}
	return nil
}

// CreateIdentity creates an identity from a private key, an id key, and a counter
func CreateIdentity(pk string, idKey string, currentCounter uint32) (tx *transaction.Transaction, err error) {
	// lastSigningKey, lastAddress, err := deriveKeys(pk, currentCounter)
	// if err != nil {
	// 	log.Println("err7", err)
	// 	return
	// }

	newSigningPrivateKey, newAddress, err := deriveKeys(pk, currentCounter+1)
	if err != nil {
		log.Println("err7", err)
		return
	}

	// Create a transaction
	t := transaction.New()

	var data [][]byte
	data = append(data, []byte(Prefix))
	data = append(data, []byte("ID"))
	data = append(data, []byte(idKey)) // is this right? might be doing something weird here
	data = append(data, []byte(newAddress.AddressString))
	data = append(data, []byte("|"))

	// Generate a signature from this point
	aipSig := aip.New()
	// Get private key in string format
	privKey := hex.EncodeToString(newSigningPrivateKey.Serialize())
	// Sign with AIP
	aipSig.Sign(privKey, string(bytes.Join(data, []byte{})))
	if newAddress.AddressString != aipSig.Address {
		return nil, fmt.Errorf("Addresses dont match %s vs %s", newAddress.AddressString, aipSig.Address)
	}
	data = append(data, []byte(aip.Prefix))
	data = append(data, []byte(aipSig.Algorithm))
	data = append(data, []byte(aipSig.Signature))
	data = append(data, []byte(aipSig.Signature))

	// Add the OP_RETURN output to the transaction
	newOutput, err := output.NewOpReturnParts(data)
	if err != nil {
		log.Println("err7", err)
		return
	}
	t.Outputs = append(t.Outputs, newOutput)

	// Write this on chain to establish the current Identity

	// ToDo - Broadcast t
	log.Println("TxID:", t.GetTxID())

	return t, nil
}

// CreateAttestation creates an attestation transaction from an id key, signing key, and signing address
func CreateAttestation(idKey string, attestorSigningKey *bsvec.PrivateKey, attestorSigningAddress *address.Address, attributeName string, attributeValue string, identityAttributeSecret string) (attestation *transaction.Transaction, err error) {

	// Attest that an internal wallet address is associated with our identity key
	idUrn := fmt.Sprintf("urn:bap:id:%s:%s:%s", attributeName, attributeValue, identityAttributeSecret)
	idUrnHash := sha256.Sum256([]byte(idUrn))
	attestationUrn := fmt.Sprintf("urn:bap:attest:%s:%s", idUrnHash, idKey)
	attestationHash := sha256.Sum256([]byte(attestationUrn))

	// Create a transaction
	ta := transaction.New()

	var attestData [][]byte
	attestData = append(attestData, []byte(Prefix))
	attestData = append(attestData, []byte("ATTEST"))
	attestData = append(attestData, []byte(attestationHash[0:]))
	attestData = append(attestData, []byte("|"))

	// Generate a signature
	aipSig := aip.New()
	aipSig.Sign(hex.EncodeToString(attestorSigningKey.Serialize()), string(bytes.Join(attestData, []byte{})))

	if attestorSigningAddress.AddressString != aipSig.Address {
		log.Printf("Failed addresses dont match! %s %s\n", attestorSigningAddress.AddressString, aipSig.Address)
		return
	}

	attestData = append(attestData, []byte(aip.Prefix))
	attestData = append(attestData, []byte(aipSig.Algorithm))
	attestData = append(attestData, []byte(attestorSigningAddress.AddressString))
	attestData = append(attestData, []byte(aipSig.Signature))

	return ta, nil
}
