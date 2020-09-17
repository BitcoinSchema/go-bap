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

// Bap Type Constants
const (
	ID     = "ID"
	REVOKE = "REVOKE"
	ATTEST = "ATTEST"
)

// {
//   "tx": {
//     "h": "26b754e6fdf04121b8d91160a0b252a22ae30204fc552605b7f6d3f08419f29e"
//   },
//   "in": [
//     {
//       "i": 0,
//       "e": {
//         "h": "744a55a8637aa191aa058630da51803abbeadc2de3d65b4acace1f5f10789c5b",
//         "i": 1,
//         "a": "1LC16EQVsqVYGeYTCrjvNf8j28zr4DwBuk"
//       },
//       "seq": 4294967295
//     }
//   ],
//   "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT": [
//     {
//       "b": "MUJBUFN1YVBuZkduU0JNM0dMVjl5aHhVZFllNHZHYmRNVA==",
//       "s": "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT",
//       "ii": 2,
//       "i": 0
//     },
//     {
//       "b": "QVRURVNU",
//       "s": "ATTEST",
//       "ii": 3,
//       "i": 1
//     },
//     {
//       "b": "MTZjYTkwY2UzYzYzNDcxMzJhZGJhNDBhYTBkNWZhYTNiMmJmMjAxNTY3OGZmYzYzZGIxNTExYjY3Njg4NWUyNQ==",
//       "s": "16ca90ce3c6347132adba40aa0d5faa3b2bf2015678ffc63db1511b676885e25",
//       "ii": 4,
//       "i": 2
//     },
//     {
//       "b": "MA==",
//       "s": "0",
//       "ii": 5,
//       "i": 3
//     }
//   ],
//   "AIP": {
//     "algorithm": "BITCOIN_ECDSA",
//     "address": "134a6TXxzgQ9Az3w8BcvgdZyA5UqRL89da",
//     "signature": "H8dWw/zHantrzxDSladRQe9du9OaYDdOp5brkthehKCjKVnOkx9A3HFXY0h956hWrMpZ/BlGg0O0VpNA0g2XYe0="
//   },
//   "out": [
//     {
//       "i": 1,
//       "e": {
//         "v": 14491552,
//         "i": 1,
//         "a": "1LC16EQVsqVYGeYTCrjvNf8j28zr4DwBuk"
//       }
//     }
//   ],
//   "lock": 0
// }
// Data is Bitcoin Attestation Protocol data
type Data struct {
	Type     string `json:"type,omitempty" bson:"type,omitempty"`
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
func (b *Data) FromTape(tape bob.Tape) {
	b.Type = tape.Cell[1].S

	switch b.Type {
	case ATTEST:
		fallthrough
	case REVOKE:
		b.URNHash = tape.Cell[2].S
		seq, _ := strconv.ParseUint(tape.Cell[3].S, 10, 64)
		b.Sequence = uint8(seq)
	case ID:
		b.Address = tape.Cell[3].S
		b.IDKey = tape.Cell[2].S
	}
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
