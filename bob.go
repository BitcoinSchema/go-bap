package bap

import (
	"fmt"
	"strconv"

	"github.com/bitcoinschema/go-bob"
)

// Data is BAP data object from the bob.Tape
type Data struct {
	Address  string          `json:"address,omitempty" bson:"address,omitempty"`
	IDKey    string          `json:"id_key,omitempty" bson:"id_key,omitempty"`
	Sequence uint64          `json:"sequence" bson:"sequence"`
	Type     AttestationType `json:"type,omitempty" bson:"type,omitempty"`
	URNHash  string          `json:"urn_hash,omitempty" bson:"urn_hash,omitempty"`
}

// FromTape takes a bob.Tape and returns a BAP data structure
func (d *Data) FromTape(tape *bob.Tape) (err error) {
	d.Type = AttestationType(tape.Cell[1].S)

	// Invalid length
	if len(tape.Cell) < 4 {
		err = fmt.Errorf("invalid %s record %+v", d.Type, tape.Cell)
		return
	}

	switch d.Type {
	case REVOKE, ATTEST:
		d.URNHash = tape.Cell[2].S
		if d.Sequence, err = strconv.ParseUint(tape.Cell[3].S, 10, 64); err != nil {
			return err
		}
	case ID:
		d.Address = tape.Cell[3].S
		d.IDKey = tape.Cell[2].S
	}
	return
}

// NewFromTape takes a bob.Tape and returns a BAP data structure
func NewFromTape(tape *bob.Tape) (bapData *Data, err error) {
	bapData = new(Data)
	err = bapData.FromTape(tape)
	return
}
