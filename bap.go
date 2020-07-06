package bap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/bitcoinsv/bsvutil/hdkeychain"
	"github.com/libsv/libsv/script/address"
	"github.com/libsv/libsv/transaction"
	"github.com/libsv/libsv/transaction/output"
	"github.com/rohenaz/go-aip"
	"github.com/rohenaz/go-bob"
)

// BapPrefix is the bitcom prefix for Bitcoin Attestation Protocol
const BapPrefix = "1BAPSuaPnfGnSBM3GLV9yhxUdYe4vGbdMT"

// Bap Type Constants
const (
	ID     = "ID"
	REVOKE = "REVOKE"
	ATTEST = "ATTEST"
)

// Data is Bitcoin Attestation Protocol data
type Data struct {
	Type     string `json:"type,omitempty" bson:"type,omitempty"`
	URNHash  string `json:"urnHash,omitempty" bson:"urnHash,omitempty"`
	IDKey string `json:"IDKey,omitempty" bson:"IDKey,omitempty"`
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

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func example() {

	// TonicPow Identity Private Key
	const tppk = "xprv9s21ZrQH143K4Mfe5DzuAGxtPGNAVJpQK5MCBrgGTZrd7g72mFihvQb51xtRm6PdNCLjpJdCQSDoYGmPWkHaQQ8AEPKhSYie5ADoFrDqTgn"

	// Identity Private Key
	const pk = "xprv9s21ZrQH143K2beTKhLXFRWWFwH8jkwUssjk3SVTiApgmge7kNC3jhVc4NgHW8PhW2y7BCDErqnKpKuyQMjqSePPJooPJowAz5BVLThsv6c"

	// Create ID
	// Generate a random ID key
	idKey, _ := randomHex(64)
	fmt.Println(idKey)

	var currentCounter uint32
	tx, err := createIdentity(pk, idKey, currentCounter)
	if err != nil {
		return
	}

	log.Println(tx.GetTxID())

	// Create an attestation
	tonicpowSigningKey, tonicpowSigningAddress, err := deriveKeys(tppk, currentCounter)
	attestation, err := createAttestation(idKey, tonicpowSigningKey, tonicpowSigningAddress)
	if err != nil {
		return
	}

	log.Println("Attestation", attestation)
}

func deriveKeys(hdpk string, currentCounter uint32) (*bsvec.PrivateKey, *address.Address, error) {
	hdPrivateKey, err := hdkeychain.NewKeyFromString(hdpk)
	if err != nil {
		return nil, nil, err
	}

	// Root ID Key is m/0/0
	var basePath uint32 // m/0

	baseChild, err := hdPrivateKey.Child(basePath)
	if err != nil {
		return nil, nil, err
	}

	lastExtendedIDKey, err := baseChild.Child(currentCounter) // m/0/N
	if err != nil {
		log.Panicln("err", err)
		return nil, nil, err
	}

	idPrivateKey, err := lastExtendedIDKey.ECPrivKey()
	if err != nil {
		log.Panicln("err2", err)
		return nil, nil, err
	}

	address, err := address.NewFromPublicKey(idPrivateKey.PubKey(), true)
	if err != nil {
		log.Panicln("err3", err)
		return nil, nil, err
	}

	return idPrivateKey, address, nil
}

func createIdentity(pk string, idKey string, currentCounter uint32) (tx *transaction.Transaction, err error) {
	_, lastAddress, err := deriveKeys(pk, currentCounter)
	if err != nil {
		log.Println("err7", err)
		return
	}

	newSigningPrivateKey, newAddress, err := deriveKeys(pk, currentCounter+1)
	if err != nil {
		log.Println("err7", err)
		return
	}

	// Create a transaction
	t := transaction.New()

	var data [][]byte
	data = append(data, []byte(BapPrefix))
	data = append(data, []byte("ID"))
	data = append(data, []byte(idKey)) // is this right? might be doing something weird here
	data = append(data, []byte(newAddress.AddressString))
	data = append(data, []byte("|"))

	// Generate a signature from this point
	aipSignature, err := bsvec.SignCompact(bsvec.S256(), newSigningPrivateKey, bytes.Join(data, []byte{}), false)
	data = append(data, []byte(aip.Prefix))
	data = append(data, []byte("BITCOIN_ECDSA"))
	data = append(data, []byte(lastAddress.AddressString))
	data = append(data, []byte(aipSignature))

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

func createAttestation(idKey string, tonicpowSigningKey *bsvec.PrivateKey, tonicpowSigningAddress *address.Address) (attestation *transaction.Transaction, err error) {

	// Attest that an internal wallet address is associated with our identity key
	attributeName := "internal-wallet-address"
	attributeValue := "1Jipv1nANv5JKdZYEU7yNxKcs7WjB5NnTn"
	identityAttributeSecret := "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa" // I forgot what this is for?
	idUrn := fmt.Sprintf("urn:bap:id:%s:%s:%s", attributeName, attributeValue, identityAttributeSecret)
	idUrnHash := sha256.Sum256([]byte(idUrn))
	attestationUrn := fmt.Sprintf("urn:bap:attest:%s:%s", idUrnHash, idKey)
	attestationHash := sha256.Sum256([]byte(attestationUrn))

	// Create a transaction
	ta := transaction.New()

	var attestData [][]byte
	attestData = append(attestData, []byte(BapPrefix))
	attestData = append(attestData, []byte("ATTEST"))
	attestData = append(attestData, []byte(attestationHash[0:]))

	// Generate a signature from this point
	aipAttestSignature, err := bsvec.SignCompact(bsvec.S256(), tonicpowSigningKey, bytes.Join(attestData, []byte{}), false)

	attestData = append(attestData, []byte(aip.Prefix))
	attestData = append(attestData, []byte("BITCOIN_ECDSA"))
	attestData = append(attestData, []byte(tonicpowSigningAddress.AddressString))
	attestData = append(attestData, []byte(aipAttestSignature))

	return ta, nil
}
