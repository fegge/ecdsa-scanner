package recovery

import (
	"errors"
	"math/big"
)

// LinearSystem represents a system of linear equations over a finite field
// Each equation is of the form: sum(coeffs[i] * vars[i]) = constant (mod n)
type LinearSystem struct {
	coeffs    [][]*big.Int // coefficient matrix
	constants []*big.Int   // right-hand side constants
	vars      []string     // variable names (e.g., "k:0x...", "d:0x...")
	n         *big.Int     // modulus (curve order)
}

// NewLinearSystem creates a new linear system
func NewLinearSystem(n *big.Int) *LinearSystem {
	return &LinearSystem{
		n: n,
	}
}

// AddVariable adds a variable to the system
func (ls *LinearSystem) AddVariable(name string) int {
	ls.vars = append(ls.vars, name)
	return len(ls.vars) - 1
}

// AddEquation adds an equation to the system
// coeffs maps variable index to coefficient, constant is the RHS
func (ls *LinearSystem) AddEquation(coeffs map[int]*big.Int, constant *big.Int) {
	row := make([]*big.Int, len(ls.vars))
	for i := range row {
		row[i] = big.NewInt(0)
	}
	for idx, coeff := range coeffs {
		if idx < len(row) {
			row[idx] = new(big.Int).Mod(coeff, ls.n)
		}
	}
	ls.coeffs = append(ls.coeffs, row)
	ls.constants = append(ls.constants, new(big.Int).Mod(constant, ls.n))
}

// Solve attempts to solve the system using Gaussian elimination
// Returns a map of variable name to value
func (ls *LinearSystem) Solve() (map[string]*big.Int, error) {
	if len(ls.coeffs) == 0 || len(ls.vars) == 0 {
		return nil, errors.New("empty system")
	}

	rows := len(ls.coeffs)
	cols := len(ls.vars)

	if rows < cols {
		return nil, errors.New("underdetermined system")
	}

	// Create augmented matrix [A|b]
	matrix := make([][]*big.Int, rows)
	for i := range matrix {
		matrix[i] = make([]*big.Int, cols+1)
		for j := 0; j < cols; j++ {
			matrix[i][j] = new(big.Int).Set(ls.coeffs[i][j])
		}
		matrix[i][cols] = new(big.Int).Set(ls.constants[i])
	}

	// Forward elimination
	for col := 0; col < cols; col++ {
		// Find pivot
		pivotRow := -1
		for row := col; row < rows; row++ {
			if matrix[row][col].Sign() != 0 {
				pivotRow = row
				break
			}
		}
		if pivotRow == -1 {
			return nil, errors.New("singular matrix")
		}

		// Swap rows
		matrix[col], matrix[pivotRow] = matrix[pivotRow], matrix[col]

		// Scale pivot row
		pivotInv := new(big.Int).ModInverse(matrix[col][col], ls.n)
		if pivotInv == nil {
			return nil, errors.New("non-invertible pivot")
		}
		for j := col; j <= cols; j++ {
			matrix[col][j].Mul(matrix[col][j], pivotInv)
			matrix[col][j].Mod(matrix[col][j], ls.n)
		}

		// Eliminate below
		for row := col + 1; row < rows; row++ {
			if matrix[row][col].Sign() == 0 {
				continue
			}
			factor := new(big.Int).Set(matrix[row][col])
			for j := col; j <= cols; j++ {
				temp := new(big.Int).Mul(factor, matrix[col][j])
				matrix[row][j].Sub(matrix[row][j], temp)
				matrix[row][j].Mod(matrix[row][j], ls.n)
			}
		}
	}

	// Back substitution
	solutions := make([]*big.Int, cols)
	for i := cols - 1; i >= 0; i-- {
		solutions[i] = new(big.Int).Set(matrix[i][cols])
		for j := i + 1; j < cols; j++ {
			temp := new(big.Int).Mul(matrix[i][j], solutions[j])
			solutions[i].Sub(solutions[i], temp)
			solutions[i].Mod(solutions[i], ls.n)
		}
	}

	// Build result map
	result := make(map[string]*big.Int)
	for i, name := range ls.vars {
		result[name] = solutions[i]
	}

	return result, nil
}

// CanSolve returns true if the system has enough equations
func (ls *LinearSystem) CanSolve() bool {
	return len(ls.coeffs) >= len(ls.vars)
}

// NumEquations returns the number of equations
func (ls *LinearSystem) NumEquations() int {
	return len(ls.coeffs)
}

// NumVariables returns the number of variables
func (ls *LinearSystem) NumVariables() int {
	return len(ls.vars)
}
