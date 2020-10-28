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
func (a *Data) FromTape(tape *bob.Tape) error {
	a.Type = AttestationType(tape.Cell[1].S)

	switch a.Type {
	case ATTEST:
		fallthrough
	case REVOKE:
		if len(tape.Cell) < 4 {
			return fmt.Errorf("invalid %s or %s record %+v", ATTEST, REVOKE, tape.Cell)
		}
		a.URNHash = tape.Cell[2].S
		seq, err := strconv.ParseUint(tape.Cell[3].S, 10, 64)
		if err != nil {
			return err
		}
		a.Sequence = seq
	case ID:
		if len(tape.Cell) < 4 {
			return fmt.Errorf("invalid %s record %+v", ID, tape.Cell)
		}
		a.Address = tape.Cell[3].S
		a.IDKey = tape.Cell[2].S
	}
	return nil
}

// NewFromTape takes a bob.Tape and returns a BAP data structure
func NewFromTape(tape *bob.Tape) (a *Data, err error) {
	a = new(Data)
	err = a.FromTape(tape)
	return
}
