package recovery

import (
	"math/big"
	"testing"
)

func TestLinearSystemSimple(t *testing.T) {
	// Test with a simple modulus
	n := big.NewInt(97) // small prime for testing

	ls := NewLinearSystem(n)

	// Variables: x, y
	xIdx := ls.AddVariable("x")
	yIdx := ls.AddVariable("y")

	// Equation 1: 2x + 3y = 8 (mod 97)
	ls.AddEquation(map[int]*big.Int{
		xIdx: big.NewInt(2),
		yIdx: big.NewInt(3),
	}, big.NewInt(8))

	// Equation 2: x + y = 3 (mod 97)
	ls.AddEquation(map[int]*big.Int{
		xIdx: big.NewInt(1),
		yIdx: big.NewInt(1),
	}, big.NewInt(3))

	// Solution should be x=1, y=2 (since 2*1 + 3*2 = 8 and 1+2 = 3)
	solutions, err := ls.Solve()
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if solutions["x"].Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected x=1, got x=%s", solutions["x"].String())
	}
	if solutions["y"].Cmp(big.NewInt(2)) != 0 {
		t.Errorf("Expected y=2, got y=%s", solutions["y"].String())
	}
}

func TestLinearSystemSecp256k1(t *testing.T) {
	// Test with secp256k1 curve order
	ls := NewLinearSystem(secp256k1N)

	// Create a simple 2x2 system
	xIdx := ls.AddVariable("k")
	yIdx := ls.AddVariable("d")

	// Known values for testing
	a1 := big.NewInt(12345)
	b1 := big.NewInt(67890)
	c1 := big.NewInt(111111)

	a2 := big.NewInt(22222)
	b2 := big.NewInt(33333)
	c2 := big.NewInt(55555)

	ls.AddEquation(map[int]*big.Int{xIdx: a1, yIdx: b1}, c1)
	ls.AddEquation(map[int]*big.Int{xIdx: a2, yIdx: b2}, c2)

	solutions, err := ls.Solve()
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Verify solutions satisfy the equations
	// a1*k + b1*d = c1 (mod n)
	check1 := new(big.Int).Mul(a1, solutions["k"])
	temp := new(big.Int).Mul(b1, solutions["d"])
	check1.Add(check1, temp)
	check1.Mod(check1, secp256k1N)

	if check1.Cmp(c1) != 0 {
		t.Errorf("Equation 1 not satisfied: got %s, expected %s", check1.String(), c1.String())
	}

	// a2*k + b2*d = c2 (mod n)
	check2 := new(big.Int).Mul(a2, solutions["k"])
	temp = new(big.Int).Mul(b2, solutions["d"])
	check2.Add(check2, temp)
	check2.Mod(check2, secp256k1N)

	if check2.Cmp(c2) != 0 {
		t.Errorf("Equation 2 not satisfied: got %s, expected %s", check2.String(), c2.String())
	}
}

func TestLinearSystemUnderdetermined(t *testing.T) {
	n := big.NewInt(97)
	ls := NewLinearSystem(n)

	ls.AddVariable("x")
	ls.AddVariable("y")
	ls.AddVariable("z")

	// Only 2 equations for 3 variables
	ls.AddEquation(map[int]*big.Int{0: big.NewInt(1), 1: big.NewInt(1)}, big.NewInt(5))
	ls.AddEquation(map[int]*big.Int{1: big.NewInt(1), 2: big.NewInt(1)}, big.NewInt(7))

	_, err := ls.Solve()
	if err == nil {
		t.Error("Expected error for underdetermined system")
	}
}

func TestCanSolve(t *testing.T) {
	n := big.NewInt(97)
	ls := NewLinearSystem(n)

	ls.AddVariable("x")
	ls.AddVariable("y")

	if ls.CanSolve() {
		t.Error("Should not be solvable with 0 equations")
	}

	ls.AddEquation(map[int]*big.Int{0: big.NewInt(1)}, big.NewInt(1))
	if ls.CanSolve() {
		t.Error("Should not be solvable with 1 equation and 2 variables")
	}

	ls.AddEquation(map[int]*big.Int{1: big.NewInt(1)}, big.NewInt(2))
	if !ls.CanSolve() {
		t.Error("Should be solvable with 2 equations and 2 variables")
	}
}
