package bap

import (
	"fmt"
	"testing"

	"github.com/libsv/libsv/transaction"
)

// Identity Private Key
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

// TestCreateAttestation will test the method CreateAttestation()
func TestCreateAttestation(t *testing.T) {
	t.Parallel()

	// Entity / Service Provider's Identity Private Key
	entityPk := "xprv9s21ZrQH143K3PZSwbEeXEYq74EbnfMngzAiMCZcfjzyRpUvt2vQJnaHRTZjeuEmLXeN6BzYRoFsEckfobxE9XaRzeLGfQoxzPzTRyRb6oE"

	// Derive the keys
	entitySigningKey, entitySigningAddress, err := deriveKeys(entityPk, 0)
	if err != nil {
		t.Fatalf("error occurred: %s", err.Error())
	}

	t.Log(entitySigningKey)
	t.Log(entitySigningAddress)

	attributeName := "internal-wallet-address"
	attributeValue := "1Jipv1nANv5JKdZYEU7yNxKcs7WjB5NnTn"
	identityAttributeSecret := "e2c6fb4063cc04af58935737eaffc938011dff546d47b7fbb18ed346f8c4d4fa"

	var attestation *transaction.Transaction
	if attestation, err = CreateAttestation(
		idKey,
		entitySigningKey,
		entitySigningAddress,
		attributeName,
		attributeValue,
		identityAttributeSecret,
	); err != nil {
		t.Fatalf("failed to create attestation: %s", err.Error())
	}

	// Log out the tx
	t.Log(attestation.ToString())
	t.Log(attestation.GetTxID())

	// Check the tx id
	if attestation.GetTxID() != "f1126889e3873150d4ca93753b0f67ae338db4f725cc05390cd285bfac25ef8e" {
		t.Fatalf("failed to create attestation - unexpected tx_id: %s", attestation.GetTxID())
	}
}

// todo: mature the tests, examples & benchmarks
