package bap

import (
	"encoding/hex"
	"fmt"

	hd "github.com/bitcoin-sv/go-sdk/compat/bip32"
	chaincfg "github.com/bitcoin-sv/go-sdk/transaction/chaincfg"
)

// deriveKeys will return the xPriv for the identity key and the corresponding address
func deriveKeys(xPrivateKey string, currentCounter uint32) (xPriv string, address string, err error) {

	// Get the raw private key from string into an HD key
	var hdKey *hd.ExtendedKey
	if hdKey, err = hd.NewKeyFromString(xPrivateKey); err != nil {
		return
	}

	// Get id key
	var idKey *hd.ExtendedKey // m/0/N
	if idKey, err = hdKey.DeriveChildFromPath(fmt.Sprintf("%d/%d", 0, currentCounter)); err != nil {
		return
	}

	// Get the address
	address = idKey.Address(&chaincfg.MainNet)
	// if address, err = idKey.Address(); err != nil {
	// 	return
	// }

	// Get the private key from the identity key
	idPriv, err := idKey.ECPrivKey()
	xPriv = hex.EncodeToString(idPriv.Serialize())

	return
}
