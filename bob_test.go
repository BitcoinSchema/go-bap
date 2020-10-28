package bap

import "testing"

// TestFromTape will test the method FromTape()
func TestNewFromTape(t *testing.T) {

	// todo: create tests, examples & benchmarks
}

// TestFromTapePanic tests for nil case in FromTape()
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
