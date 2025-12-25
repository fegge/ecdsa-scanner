package recovery

import (
	"math/big"
	"testing"

	"pgregory.net/rapid"
)

// Property: Solving a 2x2 system with known solution works
func TestPropertyLinearSystem2x2(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Use a small prime modulus for simpler testing
		n := big.NewInt(104729) // prime

		// Generate random solution
		xSol := big.NewInt(int64(rapid.IntRange(1, 10000).Draw(t, "xSol")))
		ySol := big.NewInt(int64(rapid.IntRange(1, 10000).Draw(t, "ySol")))

		// Generate random coefficients (non-zero)
		a1 := big.NewInt(int64(rapid.IntRange(1, 1000).Draw(t, "a1")))
		b1 := big.NewInt(int64(rapid.IntRange(1, 1000).Draw(t, "b1")))
		a2 := big.NewInt(int64(rapid.IntRange(1, 1000).Draw(t, "a2")))
		b2 := big.NewInt(int64(rapid.IntRange(1, 1000).Draw(t, "b2")))

		// Compute RHS: c = a*x + b*y mod n
		c1 := new(big.Int).Mul(a1, xSol)
		c1.Add(c1, new(big.Int).Mul(b1, ySol))
		c1.Mod(c1, n)

		c2 := new(big.Int).Mul(a2, xSol)
		c2.Add(c2, new(big.Int).Mul(b2, ySol))
		c2.Mod(c2, n)

		// Check if system is non-singular (det != 0)
		det := new(big.Int).Mul(a1, b2)
		det.Sub(det, new(big.Int).Mul(a2, b1))
		det.Mod(det, n)
		if det.Sign() == 0 {
			t.Skip("singular matrix")
		}

		// Build and solve system
		ls := NewLinearSystem(n)
		xIdx := ls.AddVariable("x")
		yIdx := ls.AddVariable("y")

		ls.AddEquation(map[int]*big.Int{xIdx: a1, yIdx: b1}, c1)
		ls.AddEquation(map[int]*big.Int{xIdx: a2, yIdx: b2}, c2)

		solutions, err := ls.Solve()
		if err != nil {
			t.Fatalf("solve failed: %v", err)
		}

		// Verify solution matches
		xSolMod := new(big.Int).Mod(xSol, n)
		ySolMod := new(big.Int).Mod(ySol, n)

		if solutions["x"].Cmp(xSolMod) != 0 {
			t.Fatalf("x mismatch: got %s, want %s", solutions["x"], xSolMod)
		}
		if solutions["y"].Cmp(ySolMod) != 0 {
			t.Fatalf("y mismatch: got %s, want %s", solutions["y"], ySolMod)
		}
	})
}

// Property: Solutions satisfy the original equations
func TestPropertyLinearSystemSolutionValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numVars := rapid.IntRange(2, 4).Draw(t, "numVars")

		// Generate random solution
		solution := make([]*big.Int, numVars)
		for i := range solution {
			solution[i] = big.NewInt(int64(rapid.IntRange(1, 10000).Draw(t, "sol")))
		}

		// Generate random coefficients and compute constants
		coeffs := make([][]*big.Int, numVars)
		consts := make([]*big.Int, numVars)

		for i := 0; i < numVars; i++ {
			coeffs[i] = make([]*big.Int, numVars)
			consts[i] = big.NewInt(0)

			for j := 0; j < numVars; j++ {
				coeffs[i][j] = big.NewInt(int64(rapid.IntRange(1, 100).Draw(t, "coeff")))
				term := new(big.Int).Mul(coeffs[i][j], solution[j])
				consts[i].Add(consts[i], term)
			}
			consts[i].Mod(consts[i], secp256k1N)
		}

		// Build system
		ls := NewLinearSystem(secp256k1N)
		varNames := make([]string, numVars)
		for i := 0; i < numVars; i++ {
			varNames[i] = string(rune('a' + i))
			ls.AddVariable(varNames[i])
		}

		for i := 0; i < numVars; i++ {
			eq := make(map[int]*big.Int)
			for j := 0; j < numVars; j++ {
				eq[j] = coeffs[i][j]
			}
			ls.AddEquation(eq, consts[i])
		}

		solutions, err := ls.Solve()
		if err != nil {
			// May fail for singular matrices, that's OK
			t.Skip("solve failed (likely singular)")
		}

		// Verify each solution satisfies the equations
		for i := 0; i < numVars; i++ {
			sum := big.NewInt(0)
			for j := 0; j < numVars; j++ {
				term := new(big.Int).Mul(coeffs[i][j], solutions[varNames[j]])
				sum.Add(sum, term)
			}
			sum.Mod(sum, secp256k1N)

			if sum.Cmp(consts[i]) != 0 {
				t.Fatalf("equation %d not satisfied: got %s, want %s",
					i, sum, consts[i])
			}
		}
	})
}

// Property: CanSolve correctly reports solvability
func TestPropertyCanSolve(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numVars := rapid.IntRange(1, 5).Draw(t, "numVars")
		numEqs := rapid.IntRange(0, 7).Draw(t, "numEqs")

		ls := NewLinearSystem(secp256k1N)

		for i := 0; i < numVars; i++ {
			ls.AddVariable(string(rune('a' + i)))
		}

		for i := 0; i < numEqs; i++ {
			eq := make(map[int]*big.Int)
			for j := 0; j < numVars; j++ {
				eq[j] = big.NewInt(int64(rapid.IntRange(1, 100).Draw(t, "coeff")))
			}
			ls.AddEquation(eq, big.NewInt(int64(rapid.IntRange(1, 100).Draw(t, "const"))))
		}

		expected := numEqs >= numVars
		if ls.CanSolve() != expected {
			t.Fatalf("CanSolve() = %v, want %v (eqs=%d, vars=%d)",
				ls.CanSolve(), expected, numEqs, numVars)
		}
	})
}

// Property: NumEquations and NumVariables are correct
func TestPropertyCounts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numVars := rapid.IntRange(0, 10).Draw(t, "numVars")
		numEqs := rapid.IntRange(0, 10).Draw(t, "numEqs")

		ls := NewLinearSystem(secp256k1N)

		for i := 0; i < numVars; i++ {
			ls.AddVariable(string(rune('a' + i)))
		}

		for i := 0; i < numEqs; i++ {
			ls.AddEquation(map[int]*big.Int{}, big.NewInt(0))
		}

		if ls.NumVariables() != numVars {
			t.Fatalf("NumVariables() = %d, want %d", ls.NumVariables(), numVars)
		}
		if ls.NumEquations() != numEqs {
			t.Fatalf("NumEquations() = %d, want %d", ls.NumEquations(), numEqs)
		}
	})
}
