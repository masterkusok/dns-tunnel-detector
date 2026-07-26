package statistic

import (
	"fmt"

	"github.com/masterkusok/dns-tunnel-detector/internal/algorithm"
)

// CardinalityCounter is an interface for counting subdomain cardinality.
type CardinalityCounter interface {
	// Add adds subdomain to counter.  Implementations must ensure that
	// non-unique elements are ignored.
	Add(tld, subdomain string)

	// Count returns number of unique elements in counter.
	Count(subdomain string) (res int64)
}

// MapCounter is the [CardinalityCounter] implementation that uses hash map for
// tracking exact number if unique subdomains.  This implementation can work
// fine for small amount of traffic because of suboptimal memory usage.  Unlike
// [HLLCounter], this implementation always returns the exact number of unique
// subdomains.
type MapCounter struct {
	data map[string]map[string]struct{}
}

// NewMapCounter returns properly initialized *MapCounter.
func NewMapCounter() (m *MapCounter) {
	return &MapCounter{
		data: map[string]map[string]struct{}{},
	}
}

// type check
var _ CardinalityCounter = (*MapCounter)(nil)

// Add implements the [CardinalityCounter] for MapCounter.
func (m *MapCounter) Add(tld, subdomain string) {
	_, ok := m.data[tld]
	if !ok {
		m.data[tld] = map[string]struct{}{}
	}

	m.data[tld][subdomain] = struct{}{}
}

// Count implements the [CardinalityCounter] for MapCounter.
func (m *MapCounter) Count(tld string) (res int64) {
	for range m.data[tld] {
		res++
	}

	return res
}

// hllFactory is used to create new [algorithm.HyperLogLog] instances.
type hllFactory struct {
	conf *algorithm.HyperLogLogConfig
}

// newHLLFactory returns properly initialized *hllFactory.
func newHLLFactory(conf *algorithm.HyperLogLogConfig) (hf *hllFactory, err error) {
	err = conf.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating hll config: %w", err)
	}

	return &hllFactory{
		conf: conf,
	}, nil
}

// new returns new hyper log log.
func (hf *hllFactory) new() (hll *algorithm.HyperLogLog) {
	hll, _ = algorithm.NewHyperLogLog(hf.conf)

	return hll
}

// HLLCounterConfig is the configuration structure for [*HLLCounter].
type HLLCounterConfig struct {
	HLLRegisterBits uint8
}

// HLLCounter is the [CardinalityCounter] implementation, that uses HyperLogLog
// data structure, for tracking uniqueness.  Note that this counter is based on
// probability theory, and can be very inaccurate, it will never return the real
// number of unique elements, and it is very bad for small sets.  This
// implementation will use constant and very small amount of memory for any
// number of subdomains.
type HLLCounter struct {
	factory *hllFactory
	data    map[string]*algorithm.HyperLogLog
}

// NewHLLCounter returns properly initialized *HLLCounter.
func NewHLLCounter() (h *HLLCounter, err error) {
	factory, err := newHLLFactory(&algorithm.HyperLogLogConfig{})
	if err != nil {
		return nil, fmt.Errorf("creating factory: %w", err)
	}

	return &HLLCounter{
		factory: factory,
		data:    map[string]*algorithm.HyperLogLog{},
	}, nil
}

// type check
var _ CardinalityCounter = (*HLLCounter)(nil)

// Add implements the [CardinalityCounter] for HLLCounter.
func (h *HLLCounter) Add(tld, subdomain string) {
	sketch, ok := h.data[tld]
	if !ok {
		h.data[tld] = h.factory.new()
		sketch = h.data[tld]
	}

	sketch.Add(tld)
}

// Count implements the [CardinalityCounter] for HLLCounter.
func (h *HLLCounter) Count(tld string) (res int64) {
	return int64(h.data[tld].CountUnique())
}
