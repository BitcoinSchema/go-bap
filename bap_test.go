package bap

import (
	"fmt"
	"testing"
)

// Examples
const privateKey = "xprv9s21ZrQH143K2beTKhLXFRWWFwH8jkwUssjk3SVTiApgmge7kNC3jhVc4NgHW8PhW2y7BCDErqnKpKuyQMjqSePPJooPJowAz5BVLThsv6c"
const idKey = "8bafa4ca97d770276253585cb2a49da1775ec7aeed3178e346c8c1b55eaf5ca2"

// TestCreateIdentity will test the method CreateIdentity()
func TestCreateIdentity(t *testing.T) {

	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputPrivateKey string
			inputIDKey      string
			inputCounter    uint32
			expectedTxID    string
			expectedNil     bool
			expectedError   bool
		}{
			{
				privateKey,
				idKey,
				0,
				"49957864306b123c3cca8711635ba88890bb334eb3e9f21553b118eb4d66cc62",
				false,
				false,
			},
			{
				"",
				idKey,
				0,
				"49957864306b123c3cca8711635ba88890bb334eb3e9f21553b118eb4d66cc62",
				true,
				true,
			},
			{
				"invalid-key",
				idKey,
				0,
				"49957864306b123c3cca8711635ba88890bb334eb3e9f21553b118eb4d66cc62",
				true,
				true,
			},
			{
				privateKey,
				"",
				0,
				"49957864306b123c3cca8711635ba88890bb334eb3e9f21553b118eb4d66cc62",
				true,
				true,
			},
			{
				privateKey,
				idKey,
				1,
				"d820499a7fb3561d91d71d4eb8de636ae3bb1b7eca97497d7b6fbc3b164ea5b1",
				false,
				false,
			},
			{
				privateKey,
				idKey,
				100,
				"e0c569310c5066dbda4ccdf25c2c7591f2dcb246528d2763ca5167b0f37d71b4",
				false,
				false,
			},
		}
	)

	// Run tests
	for _, test := range tests {
		if tx, err := CreateIdentity(test.inputPrivateKey, test.inputIDKey, test.inputCounter); err != nil && !test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%d] inputted and error not expected but got: %s", t.Name(), test.inputPrivateKey, test.inputIDKey, test.inputCounter, err.Error())
		} else if err == nil && test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%d] inputted and error was expected", t.Name(), test.inputPrivateKey, test.inputIDKey, test.inputCounter)
		} else if tx == nil && !test.expectedNil {
			t.Errorf("%s Failed: [%s] [%s] [%d] inputted and nil was not expected", t.Name(), test.inputPrivateKey, test.inputIDKey, test.inputCounter)
		} else if tx != nil && test.expectedNil {
			t.Errorf("%s Failed: [%s] [%s] [%d] inputted and nil was expected", t.Name(), test.inputPrivateKey, test.inputIDKey, test.inputCounter)
		} else if tx != nil && tx.GetTxID() != test.expectedTxID {
			t.Errorf("%s Failed: [%s] [%s] [%d] inputted and expected [%s] but got [%s]", t.Name(), test.inputPrivateKey, test.inputIDKey, test.inputCounter, test.expectedTxID, tx.GetTxID())
		}
	}
}

// ExampleCreateIdentity example using CreateIdentity()
func ExampleCreateIdentity() {
	tx, err := CreateIdentity(privateKey, idKey, 0)
	if err != nil {
		fmt.Printf("failed to create identity: %s", err.Error())
		return
	}

	fmt.Printf("tx generated: %s", tx.GetTxID())
	// Output:tx generated: 49957864306b123c3cca8711635ba88890bb334eb3e9f21553b118eb4d66cc62
}

// BenchmarkCreateIdentity benchmarks the method CreateIdentity()
func BenchmarkCreateIdentity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = CreateIdentity(privateKey, idKey, 0)
	}
}

// TestDeriveKeys will test the method deriveKeys()
func TestDeriveKeys(t *testing.T) {

	// Derive the keys
	_, _, err := deriveKeys("", 0)
	if err == nil {
		t.Fatalf("error should have occurred")
	}

	// Entity / Service Provider's Identity Private Key
	entityPk := "xprv9s21ZrQH143K3PZSwbEeXEYq74EbnfMngzAiMCZcfjzyRpUvt2vQJnaHRTZjeuEmLXeN6BzYRoFsEckfobxE9XaRzeLGfQoxzPzTRyRb6oE"

	// Derive the keys
	var entitySigningAddress, entitySigningKey string
	entitySigningKey, entitySigningAddress, err = deriveKeys(entityPk, 0)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}
	if entitySigningKey != "127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c" {
		t.Fatalf("signing key does not match: %s vs %s", entitySigningKey, "")
	}
	if entitySigningAddress != "1AFc9feffQmxT61iEftzkaYvWTgLCyU6j" {
		t.Fatalf("signing address does not match: %s vs %s", entitySigningAddress, "")
	}
}

// TestCreateAttestation will test the method CreateAttestation()
func TestCreateAttestation(t *testing.T) {
	t.Parallel()

	var (
		// Testing private methods
		tests = []struct {
			inputIDKey           string
			inputSigningKey      string
			inputAttributeName   string
			inputAttributeValue  string
			inputAttributeSecret string
			expectedTxID         string
			expectedNil          bool
			expectedError        bool
		}{
			{
				idKey,
				"127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c",
				"person",
				"john",
				"some-secret-hash",
				"dbf8105dab52332bd7921f5d09cffb107c40947bf283d960ce84a15ccc894197",
				false,
				false,
			},
			{
				"",
				"127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c",
				"person",
				"john",
				"some-secret-hash",
				"1930299d3c1f05155aa9f2c1c6cac6f18c5e6e213bbffb728665ba3bfa7e528d",
				true,
				true,
			},
			{
				idKey,
				"127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c",
				"",
				"john",
				"some-secret-hash",
				"1930299d3c1f05155aa9f2c1c6cac6f18c5e6e213bbffb728665ba3bfa7e528d",
				true,
				true,
			},
			{
				idKey,
				"127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c",
				"person",
				"john",
				"",
				"1930299d3c1f05155aa9f2c1c6cac6f18c5e6e213bbffb728665ba3bfa7e528d",
				true,
				true,
			},
			{
				idKey,
				"",
				"person",
				"john",
				"some-secret-hash",
				"1930299d3c1f05155aa9f2c1c6cac6f18c5e6e213bbffb728665ba3bfa7e528d",
				true,
				true,
			},
		}
	)

	// Run tests
	for _, test := range tests {
		if tx, err := CreateAttestation(test.inputIDKey, test.inputSigningKey,
			test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret); err != nil && !test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%s] [%s] [%s] inputted and error not expected but got: %s", t.Name(), test.inputIDKey, test.inputSigningKey,
				test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret, err.Error())
		} else if err == nil && test.expectedError {
			t.Errorf("%s Failed: [%s] [%s] [%s] [%s] [%s] inputted and error was expected", t.Name(), test.inputIDKey, test.inputSigningKey,
				test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret)
		} else if tx == nil && !test.expectedNil {
			t.Errorf("%s Failed: [%s] [%s] [%s] [%s] [%s] inputted and nil was not expected", t.Name(), test.inputIDKey, test.inputSigningKey,
				test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret)
		} else if tx != nil && test.expectedNil {
			t.Errorf("%s Failed: [%s] [%s] [%s] [%s] [%s] inputted and nil was expected", t.Name(), test.inputIDKey, test.inputSigningKey,
				test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret)
		} else if tx != nil && tx.GetTxID() != test.expectedTxID {
			t.Errorf("%s Failed: [%s] [%s] [%s] [%s] [%s] inputted and expected [%s] but got [%s]", t.Name(), test.inputIDKey, test.inputSigningKey,
				test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret, test.expectedTxID, tx.GetTxID())
		}
	}
}

// ExampleCreateAttestation example using CreateAttestation()
func ExampleCreateAttestation() {
	tx, err := CreateAttestation(
		idKey,
		"127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c",
		"person",
		"john doe",
		"some-secret-hash",
	)
	if err != nil {
		fmt.Printf("failed to create attestation: %s", err.Error())
		return
	}

	fmt.Printf("tx generated: %s", tx.GetTxID())
	// Output:tx generated: 655c3931dbf9c5f52a95b150957db7c3a1d7ee2ba13732ca01ed03cc884170ae
}

// BenchmarkCreateAttestation benchmarks the method CreateAttestation()
func BenchmarkCreateAttestation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = CreateAttestation(
			idKey,
			"127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c",
			"person",
			"john doe",
			"some-secret-hash",
		)
	}
}

// TestNew will test the method New()
func TestNew(t *testing.T) {
	data := New()
	if data == nil {
		t.Fatalf("new should not return nil")
	} else if data.Type != "" {
		t.Fatalf("type should not be set")
	} else if data.URNHash != "" {
		t.Fatalf("URNHash should not be set")
	} else if data.Address != "" {
		t.Fatalf("Address should not be set")
	} else if data.Sequence != 0 {
		t.Fatalf("Sequence should not be set")
	}
}

// ExampleNew example using New()
func ExampleNew() {
	data := New()
	data.Type = ATTEST

	fmt.Printf("BAP type: %s", data.Type)
	// Output:BAP type: ATTEST
}

// BenchmarkNew benchmarks the method New()
func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New()
	}
}
