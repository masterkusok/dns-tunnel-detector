package algorithm_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/masterkusok/dns-tunnel-detector/internal/algorithm"
	"github.com/stretchr/testify/require"
)

func TestHyperLogLog(t *testing.T) {
	hll, err := algorithm.NewHyperLogLog(&algorithm.HyperLogLogConfig{
		RegisterBits: 16,
	})
	require.NoError(t, err)

	seen := map[string]struct{}{}
	count := 0

	current := 100
	i := 0

	for range 5 {
		current *= 10
		for i < current {
			input := make([]byte, 15)

			_, err := rand.Read(input)
			require.NoError(t, err)

			s := string(input)
			if _, ok := seen[s]; !ok {
				count++
				seen[s] = struct{}{}
			}

			i++
			hll.Add(string(input))
		}

		t.Run(fmt.Sprintf("fault_%d", current), func(t *testing.T) {
			gotCount := hll.CountUnique()
			fault := 100.00 - (float64(count)/float64(gotCount))*100

			t.Logf("FAULT: %.2fproc\n", fault)
		})
	}

	// Most recent results:
	//
	//	=== RUN   TestHyperLogLog
	//	=== RUN   TestHyperLogLog/fault_1000
	//	    hll_test.go:45: FAULT: 30.65proc
	//	=== RUN   TestHyperLogLog/fault_10000
	//	    hll_test.go:45: FAULT: 30.62proc
	//	=== RUN   TestHyperLogLog/fault_100000
	//	    hll_test.go:45: FAULT: 30.53proc
	//	=== RUN   TestHyperLogLog/fault_1000000
	//	    hll_test.go:45: FAULT: -0.50proc
	//	=== RUN   TestHyperLogLog/fault_10000000
	//	    hll_test.go:45: FAULT: -0.04proc
}

func BenchmarkHyperLogLog(b *testing.B) {
	hll, err := algorithm.NewHyperLogLog(&algorithm.HyperLogLogConfig{
		RegisterBits: 16,
	})
	require.NoError(b, err)

	l := 1_000_000
	randValues := make([]string, l)
	for i := range l {
		input := make([]byte, 15)

		_, err := rand.Read(input)
		require.NoError(b, err)

		randValues[i] = string(input)
	}

	b.ReportAllocs()
	for b.Loop() {
		for _, val := range randValues {
			hll.Add(val)
		}
	}

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/masterkusok/dns-tunnel-detector/internal/algorithm
	//	cpu: Apple M4 Pro
	//	BenchmarkHyperLogLog-14    	     225	   5322682 ns/op	       0 B/op	       0 allocs/op
}
