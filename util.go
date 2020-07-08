package bap

import (
	"crypto/rand"
	"encoding/hex"
	"log"

	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/bitcoinsv/bsvutil/hdkeychain"
	"github.com/libsv/libsv/script/address"
)

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
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
