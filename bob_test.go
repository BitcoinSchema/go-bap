package bap

import (
	"fmt"
	"testing"

	"github.com/bitcoinschema/go-bob"
)

// TestFromTape will test the method NewFromTape()
func TestNewFromTape(t *testing.T) {

	// Get BOB data from string
	bobData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	// Get from tape
	var b *Bap
	b, err = NewFromTape(&bobData.Out[0].Tape[1])
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	} else if b.Type != ATTEST {
		t.Fatalf("expected: %s got: %s", ATTEST, b.Type)
	}

	// Wrong tape
	_, err = NewFromTape(&bobData.Out[0].Tape[0])
	if err == nil {
		t.Fatalf("error should have occurred")
	}

	// Revoke
	bobData.Out[0].Tape[1].Cell[1].S = string(REVOKE)
	_, err = NewFromTape(&bobData.Out[0].Tape[1])
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	// ID tape
	bobData.Out[0].Tape[1].Cell[1].S = string(ID)
	bobData.Out[0].Tape[1].Cell[2].S = "idKey"
	bobData.Out[0].Tape[1].Cell[3].S = "Address"
	_, err = NewFromTape(&bobData.Out[0].Tape[1])
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}
}

// ExampleNewFromTape example using NewFromTape()
func ExampleNewFromTape() {

	// Get BOB data from string
	bobData, err := bob.NewFromString(sampleValidBobTx)
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}

	// Get from tape
	var b *Bap
	b, err = NewFromTape(&bobData.Out[0].Tape[1])
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("BAP type: %s", b.Type)
	// Output:BAP type: ATTEST
}

// BenchmarkNewFromTape benchmarks the method NewFromTape()
func BenchmarkNewFromTape(b *testing.B) {
	bobData, _ := bob.NewFromString(sampleValidBobTx)
	for i := 0; i < b.N; i++ {
		_, _ = NewFromTape(&bobData.Out[0].Tape[1])
	}
}

// TestFromTapePanic tests for nil case in NewFromTape()
func TestNewFromTapePanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("the code did not panic")
		}
	}()

	_, err := NewFromTape(nil)
	if err == nil {
		t.Fatalf("error expected")
	}
}
