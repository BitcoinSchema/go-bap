// Package bap is a library for working with Bitcoin Attestation Protocol (BAP) in Go
//
// If you have any suggestions or comments, please feel free to open an issue on
// this GitHub repository!
//
// By BitcoinSchema Organization (https://bitcoinschema.org)
package bap

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/bitcoinschema/go-aip"
	"github.com/libsv/libsv/transaction"
	"github.com/libsv/libsv/transaction/output"
)

// Prefix is the bitcom prefix for Bitcoin Attestation Protocol (BAP)
const Prefix = "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT"
const pipe string = "|"

// AttestationType is an enum for BAP Type Constants
type AttestationType string

// BAP attestation type constants
const (
	ATTEST AttestationType = "ATTEST"
	ID     AttestationType = "ID"
	REVOKE AttestationType = "REVOKE"
)

// New creates a new BAP structure
func New() *Data {
	return &Data{}
}

// CreateIdentity creates an identity from a private key, an id key, and a counter
func CreateIdentity(privateKey, idKey string, currentCounter uint32) (*transaction.Transaction, error) {

	// Test for id key
	if len(idKey) == 0 {
		return nil, fmt.Errorf("missing required field: %s", "idKey")
	}

	// Derive the keys
	newSigningPrivateKey, newAddress, err := deriveKeys(privateKey, currentCounter+1) // Increment the next key
	if err != nil {
		return nil, err
	}

	// Create the identity attestation op_return data
	var data [][]byte
	data = append(
		data,
		[]byte(Prefix),
		[]byte(ID),
		[]byte(idKey), // todo: is this right? might be doing something weird here
		[]byte(newAddress),
		[]byte(pipe),
	)

	// Generate a signature from this point
	var finalOutput *output.Output
	finalOutput, err = createAIPSignature(newSigningPrivateKey, newAddress, data)
	if err != nil {
		return nil, err
	}

	// Return the transaction
	return returnTx(finalOutput), nil
}

// CreateAttestation creates an attestation transaction from an id key, signing key, and signing address
func CreateAttestation(idKey, attestorSigningKey,
	attestorSigningAddress, attributeName,
	attributeValue, identityAttributeSecret string) (*transaction.Transaction, error) {

	// Attest that an internal wallet address is associated with our identity key
	idUrn := fmt.Sprintf("urn:bap:id:%s:%s:%s", attributeName, attributeValue, identityAttributeSecret)
	attestationUrn := fmt.Sprintf("urn:bap:attest:%v:%s", sha256.Sum256([]byte(idUrn)), idKey)
	attestationHash := sha256.Sum256([]byte(attestationUrn))

	// Create op_return attestation
	var data [][]byte
	data = append(
		data,
		[]byte(Prefix),
		[]byte(ATTEST),
		attestationHash[0:],
		[]byte(pipe),
	)

	// Generate a signature from this point
	finalOutput, err := createAIPSignature(attestorSigningKey, attestorSigningAddress, data)
	if err != nil {
		return nil, err
	}

	// Return the transaction
	return returnTx(finalOutput), nil
}

// createAIPSignature will create an AIP signature and return a valid output
func createAIPSignature(privateKey, address string, data [][]byte) (*output.Output, error) {

	// Generate a signature from this point
	aipSig := aip.New()

	// Sign with AIP
	aipSig.Sign(privateKey, string(bytes.Join(data, []byte{})), aip.BITCOIN_ECDSA, "")
	if address != aipSig.Address {
		return nil, fmt.Errorf("failed signing, addresses don't match %s vs %s", address, aipSig.Address)
	}

	// Add AIP signature
	data = append(
		data,
		[]byte(aip.Prefix),
		[]byte(aipSig.Algorithm),
		[]byte(aipSig.Address),
		[]byte(aipSig.Signature),
	)

	// Create the OP_RETURN
	return output.NewOpReturnParts(data)
}

// returnTx will add the output and return a tx
func returnTx(out *output.Output) (t *transaction.Transaction) {

	// Create a transaction
	// todo: replace with bitcoin.CreateTx()
	t = transaction.New()

	// Add the output
	t.AddOutput(out)
	return
}
