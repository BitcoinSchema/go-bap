package main

import (
	"encoding/hex"
	"log"

	ec "github.com/bitcoin-sv/go-sdk/primitives/ec"
	"github.com/bitcoinschema/go-bap"
)

func main() {
	// examplePrivateKey := "xprv9s21ZrQH143K2beTKhLXFRWWFwH8jkwUssjk3SVTiApgmge7kNC3jhVc4NgHW8PhW2y7BCDErqnKpKuyQMjqSePPJooPJowAz5BVLThsv6c"
	exampleIdKey := "8bafa4ca97d770276253585cb2a49da1775ec7aeed3178e346c8c1b55eaf5ca2"

	exampleAttributeName := "legal-name"
	exampleAttributeValue := "John Adams"
	exampleIdentityAttributeSecret := "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"

	privBuf, _ := hex.DecodeString("127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c")
	priv, _ := ec.PrivateKeyFromBytes(privBuf)

	tx, err := bap.CreateAttestation(
		exampleIdKey,
		priv,
		exampleAttributeName,
		exampleAttributeValue,
		exampleIdentityAttributeSecret,
	)
	if err != nil {
		log.Fatalf("failed to create attestation: %s", err.Error())
	}

	log.Printf("attestation tx created: %s", tx.String())
}
