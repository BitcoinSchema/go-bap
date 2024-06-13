package bap

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/bitcoinschema/go-bpu"
)

// Bap is BAP data object from the bob.Tape
type Bap struct {
	Address  string          `json:"address,omitempty" bson:"address,omitempty"`
	IDKey    string          `json:"id_key,omitempty" bson:"id_key,omitempty"`
	Sequence uint64          `json:"sequence" bson:"sequence"`
	Type     AttestationType `json:"type,omitempty" bson:"type,omitempty"`
	URNHash  string          `json:"urn_hash,omitempty" bson:"urn_hash,omitempty"`
	Profile  string          `json:"profile,omitempty" bson:"profile,omitempty"`
}

// FromTape takes a bob.Tape and returns a BAP data structure
func (b *Bap) FromTape(tape *bpu.Tape) (err error) {
	if len(tape.Cell) < 2 || tape.Cell[1].S == nil {
		err = fmt.Errorf("invalid %s record %+v", b.Type, tape.Cell)
		return
	}

	b.Type = AttestationType(*tape.Cell[1].S)

	// Invalid length
	if len(tape.Cell) < 4 {
		err = fmt.Errorf("invalid %s record %+v", b.Type, tape.Cell)
		return
	}

	switch b.Type {
	case REVOKE, ATTEST:
		if tape.Cell[2].S == nil {
			return fmt.Errorf("invalid urn hash")
		}
		b.URNHash = *tape.Cell[2].S
		if b.Sequence, err = strconv.ParseUint(*tape.Cell[3].S, 10, 64); err != nil {
			return err
		}
	case ID:
		b.Address = *tape.Cell[3].S
		b.IDKey = *tape.Cell[2].S
	case ALIAS:
		b.IDKey = *tape.Cell[2].S
		b.Profile = *tape.Cell[3].S
	}
	return
}

// NewFromTapes will create a new BAP object from a []bob.Tape
func NewFromTapes(tapes []bpu.Tape) (*Bap, error) {
	// Loop tapes -> cells (only supporting 1 BAP record right now)
	for index, t := range tapes {
		for _, cell := range t.Cell {
			if cell.S != nil && *cell.S == Prefix {
				return NewFromTape(&tapes[index])
			}
		}
	}
	return nil, errors.New("no BAP record found")
}

// NewFromTape takes a bob.Tape and returns a BAP data structure
func NewFromTape(tape *bpu.Tape) (b *Bap, err error) {
	b = new(Bap)
	if tape == nil {
		err = fmt.Errorf("tape is nil %x", tape)
		return
	}
	err = b.FromTape(tape)
	return
}
