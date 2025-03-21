// Package bap is a library for working with Bitcoin Attestation Protocol (BAP) in Go
//
// Protocol: https://github.com/icellan/bap
//
// If you have any suggestions or comments, please feel free to open an issue on
// this GitHub repository!
//
// By BitcoinSchema Organization (https://bitcoinschema.org)
package bap

import (
	"crypto/sha256"
	"errors"
	"fmt"

	hd "github.com/bsv-blockchain/go-sdk/compat/bip32"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
	"github.com/bitcoinschema/go-aip"
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
	ALIAS  AttestationType = "ALIAS"
)

// CreateIdentity creates an identity from a private key, an id key, and a counter
//
// Source: https://github.com/icellan/bap
func CreateIdentity(xPrivateKey, idKey string, currentCounter uint32) (*transaction.Transaction, error) {

	// Test for id key
	if len(idKey) == 0 {
		return nil, fmt.Errorf("missing required field: %s", "idKey")
	}

	hdKey, err := hd.NewKeyFromString(xPrivateKey)
	if err != nil {
		return nil, err
	}
	signingHdKey, err := hdKey.DeriveChildFromPath(fmt.Sprintf("%d/%d", 0, currentCounter))
	if err != nil {
		return nil, err
	}
	signingKey, err := signingHdKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	// Create the identity attestation op_return data
	var data [][]byte
	data = append(
		data,
		[]byte(Prefix),
		[]byte(ID),
		[]byte(idKey),
		[]byte(signingHdKey.Address(&chaincfg.MainNet)),
		[]byte(pipe),
	)

	// Generate a signature from this point
	var finalOutput [][]byte
	if finalOutput, _, err = aip.SignOpReturnData(signingKey, aip.BitcoinECDSA, data); err != nil {
		return nil, err
	}

	// Return the transaction
	return returnTx(finalOutput)
}

// CreateAttestation creates an attestation transaction from an id key, signing key, and signing address
//
// Source: https://github.com/icellan/bap
func CreateAttestation(idKey string, attestorSigningKey *ec.PrivateKey, attributeName,
	attributeValue, identityAttributeSecret string) (*transaction.Transaction, error) {

	// ID key is required
	if len(idKey) == 0 {
		return nil, errors.New("missing required field: idKey")
	}

	// Attribute secret and name
	if len(attributeName) == 0 {
		return nil, errors.New("missing required field: attributeName")
	} else if len(identityAttributeSecret) == 0 {
		return nil, errors.New("missing required field: identityAttributeSecret")
	}

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
	finalOutput, _, err := aip.SignOpReturnData(attestorSigningKey, aip.BitcoinECDSA, data)
	if err != nil {
		return nil, err
	}

	// Return the transaction
	return returnTx(finalOutput)
}

// returnTx will add the output and return a new tx
func returnTx(outBytes [][]byte) (t *transaction.Transaction, err error) {
	t = transaction.NewTransaction()
	err = t.AddOpReturnPartsOutput(outBytes)
	return
}
