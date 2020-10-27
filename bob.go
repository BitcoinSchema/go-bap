package bap

import (
	"fmt"
	"strconv"

	"github.com/rohenaz/go-bob"
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
func FromTape(tape *bob.Tape) (*Data, error) {
	data := new(Data)
	data.Type = AttestationType(tape.Cell[1].S)

	switch data.Type {
	case ATTEST:
		fallthrough
	case REVOKE:
		if len(tape.Cell) < 4 {
			return nil, fmt.Errorf("invalid %s or %s record %+v", ATTEST, REVOKE, tape.Cell)
		}
		data.URNHash = tape.Cell[2].S
		seq, err := strconv.ParseUint(tape.Cell[3].S, 10, 64)
		if err != nil {
			return nil, err
		}
		data.Sequence = seq
	case ID:
		if len(tape.Cell) < 4 {
			return nil, fmt.Errorf("invalid %s record %+v", ID, tape.Cell)
		}
		data.Address = tape.Cell[3].S
		data.IDKey = tape.Cell[2].S
	}
	return data, nil
}
