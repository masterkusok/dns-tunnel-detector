// Package math contains common math functions and utilities.
package math

import (
	"cmp"
	"math"
)

// Max returns maximum of two numbers.
func Max[T cmp.Ordered](x, y T) (res T) {
	if x > y {
		return x
	}

	return y
}

// Min returns minimum of two numbers.
func Min[T cmp.Ordered](x, y T) (res T) {
	if x < y {
		return x
	}

	return y
}

// CalculateShannonEntropy calculates shannon entropy based for given string.
func CalculateShannonEntropy(s string) (e float64) {
	frequency := make(map[rune]float64)
	for _, char := range s {
		frequency[char]++
	}

	total := float64(len(s))

	var entropy float64
	for _, count := range frequency {
		probability := count / total
		entropy += probability * math.Log2(probability)
	}

	return -entropy
}
