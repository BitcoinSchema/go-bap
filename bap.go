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

	"github.com/libsv/libsv/transaction"
	"github.com/libsv/libsv/transaction/output"
	"github.com/rohenaz/go-aip"
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

// CreateIdentity creates an identity from a private key, an id key, and a counter
func CreateIdentity(privateKey, idKey string, currentCounter uint32) (*transaction.Transaction, error) {

	// Derive the keys
	newSigningPrivateKey, newAddress, err := deriveKeys(privateKey, currentCounter+1) // todo: why plus 1?
	if err != nil {
		return nil, err
	}

	var data [][]byte
	data = append(
		data,
		[]byte(Prefix),
		[]byte(ID),
		[]byte(idKey), // is this right? might be doing something weird here
		[]byte(newAddress),
		[]byte(pipe),
	)

	// Generate a signature from this point
	aipSig := aip.New()

	// Sign with AIP
	aipSig.Sign(newSigningPrivateKey, string(bytes.Join(data, []byte{})))
	if newAddress != aipSig.Address {
		return nil, fmt.Errorf("failed signing, addresses don't match %s vs %s", newAddress, aipSig.Address)
	}

	// Add AIP signature
	data = append(
		data,
		[]byte(aip.Prefix),
		[]byte(aipSig.Algorithm),
		[]byte(aipSig.Signature),
		[]byte(aipSig.Signature),
	)

	// Create the OP_RETURN
	var newOutput *output.Output
	if newOutput, err = output.NewOpReturnParts(data); err != nil {
		return nil, err
	}

	// Create a transaction
	t := transaction.New()

	// Add the output
	t.Outputs = append(t.Outputs, newOutput)

	// Return the transaction
	return t, nil
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

	// Generate a signature
	aipSig := aip.New()
	aipSig.Sign(attestorSigningKey, string(bytes.Join(data, []byte{})))
	if attestorSigningAddress != aipSig.Address {
		return nil, fmt.Errorf("failed signing, addresses don't match: %s vs %s", attestorSigningAddress, aipSig.Address)
	}

	// Add signature
	data = append(data,
		[]byte(aip.Prefix),
		[]byte(aipSig.Algorithm),
		[]byte(attestorSigningAddress),
		[]byte(aipSig.Signature),
	)

	// Add op_return to the transaction
	out, err := output.NewOpReturnParts(data)
	if err != nil {
		return nil, err
	}

	// Create a transaction
	t := transaction.New()

	// Add the output
	t.AddOutput(out)

	// Return the transaction
	return t, nil
}
