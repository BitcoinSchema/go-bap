package bap

import (
	"encoding/hex"
	"fmt"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
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
				"187a4133bf007ca0aae2b31b0600772fa93eab33aa0ed9f05e94b5415523224c",
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
				"c4296095a0f7066e0aa4b902fea66493967cc91c772a2f10869e014ef9d11c42",
				false,
				false,
			},
			{
				privateKey,
				idKey,
				100,
				"4332af03917a86de66ca2b4467150284efd1a2f3c0878c291d48ebc9dfc429b6",
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
		} else if tx != nil && tx.TxID().String() != test.expectedTxID {
			t.Errorf("%s Failed: [%s] [%s] [%d] inputted and expected [%s] but got [%s]", t.Name(), test.inputPrivateKey, test.inputIDKey, test.inputCounter, test.expectedTxID, tx.TxID())
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

	fmt.Printf("tx generated: %s", tx.TxID())
	// Output:tx generated: 187a4133bf007ca0aae2b31b0600772fa93eab33aa0ed9f05e94b5415523224c
}

// BenchmarkCreateIdentity benchmarks the method CreateIdentity()
func BenchmarkCreateIdentity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = CreateIdentity(privateKey, idKey, 0)
	}
}

// TestDeriveKeys will test the method deriveKeys()
// func TestDeriveKeys(t *testing.T) {

// 	// Derive the keys
// 	_, _, err := deriveKeys("", 0)
// 	if err == nil {
// 		t.Fatalf("error should have occurred")
// 	}

// 	// Entity / Service Provider's Identity Private Key
// 	entityPk := "xprv9s21ZrQH143K3PZSwbEeXEYq74EbnfMngzAiMCZcfjzyRpUvt2vQJnaHRTZjeuEmLXeN6BzYRoFsEckfobxE9XaRzeLGfQoxzPzTRyRb6oE"

// 	hdKey, _ := hd.NewKeyFromString(entityPk)
// 	signingHdKey, _ := hdKey.DeriveChildFromPath(fmt.Sprintf("%d/%d", 0, 0))
// 	signingKey, err := signingHdKey.ECPrivKey()

// 	// Derive the keys
// 	// var entitySigningAddress, entitySigningKey string
// 	// entitySigningKey, entitySigningAddress, err = deriveKeys(entityPk, 0)
// 	// if err != nil {
// 	// 	t.Fatalf("error occurred: %s", err.Error())
// 	// }
// 	if entitySigningKey != "127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c" {
// 		t.Fatalf("signing key does not match: %s vs %s", entitySigningKey, "")
// 	}
// 	if entitySigningAddress != "1AFc9feffQmxT61iEftzkaYvWTgLCyU6j" {
// 		t.Fatalf("signing address does not match: %s vs %s", entitySigningAddress, "")
// 	}
// }

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
				"a9d35aecc3f864c238c95a08c40e0c9f9353610e8632234839c012f2b3d6eabf",
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
		}
	)

	// Run tests
	for _, test := range tests {
		if privBuf, err := hex.DecodeString(test.inputSigningKey); err != nil {
			t.Errorf("%s Failed: [%s] inputted and error not expected but got: %s", t.Name(), test.inputSigningKey, err.Error())
		} else {
			priv, _ := ec.PrivateKeyFromBytes(privBuf)
			if tx, err := CreateAttestation(test.inputIDKey, priv,
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
			} else if tx != nil && tx.TxID().String() != test.expectedTxID {
				t.Errorf("%s Failed: [%s] [%s] [%s] [%s] [%s] inputted and expected [%s] but got [%s]", t.Name(), test.inputIDKey, test.inputSigningKey,
					test.inputAttributeName, test.inputAttributeValue, test.inputAttributeSecret, test.expectedTxID, tx.TxID())
			}
		}
	}
}

// ExampleCreateAttestation example using CreateAttestation()
func ExampleCreateAttestation() {
	privBuf, _ := hex.DecodeString("127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c")
	priv, _ := ec.PrivateKeyFromBytes(privBuf)
	tx, err := CreateAttestation(
		idKey,
		priv,
		"person",
		"john doe",
		"some-secret-hash",
	)
	if err != nil {
		fmt.Printf("failed to create attestation: %s", err.Error())
		return
	}

	fmt.Printf("tx generated: %s", tx.TxID().String())
	// Output:tx generated: afa78310343de3a8b23703c1556ff587ea8839eb8f224b31ce76155d1b8cd6c4
}

// BenchmarkCreateAttestation benchmarks the method CreateAttestation()
func BenchmarkCreateAttestation(b *testing.B) {
	privBuf, _ := hex.DecodeString("127d0ab318252b4622d8eac61407359a4cab7c1a5d67754b5bf9db910eaf052c")
	priv, _ := ec.PrivateKeyFromBytes(privBuf)
	for i := 0; i < b.N; i++ {
		_, _ = CreateAttestation(
			idKey,
			priv,
			"person",
			"john doe",
			"some-secret-hash",
		)
	}
}
