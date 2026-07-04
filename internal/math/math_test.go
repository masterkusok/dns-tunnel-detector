package math_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/masterkusok/dns-tunnel-detector/internal/math"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDelta is a common delta for float comparison in tests.
const testDelta = 1e-6

func TestCalculateShannonEntropy(t *testing.T) {
	s := "hello"
	want := 1.921928
	got := math.CalculateShannonEntropy(s)

	assert.InDelta(t, want, got, testDelta)
}

func BenchmarkCalculateShannonEntropy(b *testing.B) {
	len := 8
	for range 5 {
		len *= 2

		input := make([]byte, len)

		_, err := rand.Read(input)
		require.NoError(b, err)

		b.Run(fmt.Sprintf("len_%d", len), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				math.CalculateShannonEntropy(string(input))
			}
		})
	}

	// TODO: Make more efficient?

	// Most recent results:
	//
	//	BenchmarkCalculateShannonEntropy/len_16-14         	 6107577	       183.5 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkCalculateShannonEntropy/len_32-14         	 1525309	       785.7 ns/op	     936 B/op	       5 allocs/op
	//	BenchmarkCalculateShannonEntropy/len_64-14         	 1000000	      1175 ns/op	    1000 B/op	       6 allocs/op
	//	BenchmarkCalculateShannonEntropy/len_128-14        	  483666	      2489 ns/op	    2248 B/op	       8 allocs/op
	//	BenchmarkCalculateShannonEntropy/len_256-14        	  241406	      4869 ns/op	    4712 B/op	      10 allocs/op
}
