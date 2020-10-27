package bap

import (
	"encoding/hex"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/bitcoinsv/bsvutil"
	"github.com/bitcoinsv/bsvutil/hdkeychain"
)

// deriveKeys will return the xPriv for the identity key and the corresponding address
func deriveKeys(xPrivateKey string, currentCounter uint32) (xPriv string, address string, err error) {

	// Get the raw private key from string into an HD key
	var hdKey *hdkeychain.ExtendedKey
	if hdKey, err = bitcoin.GenerateHDKeyFromString(xPrivateKey); err != nil {
		return
	}

	// Get id key
	var idKey *hdkeychain.ExtendedKey // m/0/N
	if idKey, err = bitcoin.GetHDKeyByPath(hdKey, 0, currentCounter); err != nil {
		return
	}

	// Get the address
	var addr *bsvutil.LegacyAddressPubKeyHash
	if addr, err = bitcoin.GetAddressFromHDKey(idKey); err != nil {
		return
	}
	address = addr.String()

	// Get the private key from the identity key
	var idPrivateKey *bsvec.PrivateKey
	if idPrivateKey, err = bitcoin.GetPrivateKeyFromHDKey(idKey); err != nil {
		return
	}
	xPriv = hex.EncodeToString(idPrivateKey.Serialize())

	return
}
