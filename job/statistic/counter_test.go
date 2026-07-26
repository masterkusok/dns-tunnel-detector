package statistic_test

import (
	"testing"

	"github.com/masterkusok/dns-tunnel-detector/job/statistic"
	"github.com/stretchr/testify/assert"
)

func TestMapCounter(t *testing.T) {
	t.Parallel()

	counter := statistic.NewMapCounter()
	names := []string{
		"1",
		"2",
		"3",
		"4",
		"5",
		"1",
		"1",
		"5",
	}

	for _, n := range names {
		counter.Add("example.org", n)
	}

	assert.Equal(t, int64(5), counter.Count("example.org"))
}
