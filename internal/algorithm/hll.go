package algorithm

import (
	"cmp"
	"fmt"
	"math"
	"math/bits"

	"github.com/masterkusok/dns-tunnel-detector/internal/errors"
	dnsmath "github.com/masterkusok/dns-tunnel-detector/internal/math"
	"github.com/masterkusok/dns-tunnel-detector/internal/validate"
	"github.com/twmb/murmur3"
)

// HyperLogLogConfig is the configuration structure for [*HyperLogLog].
type HyperLogLogConfig struct {
	// RegisterBits determines number of bits from start of hash which will be
	// used to determine number of register entry.
	RegisterBits uint8
}

// type check
var _ validate.Interface = (*HyperLogLogConfig)(nil)

// Validate implements the [validate.Interface] for *HyperLogLogConfig.
func (c *HyperLogLogConfig) Validate() (err error) {
	// TODO: Consider removing those constraints.
	return errors.Annotate(validate.InRange(c.RegisterBits, 4, 16), "register bits: %w")
}

// HyperLogLog is the implementation of the HyperLogLog data structure.
//
// See https://algo.inria.fr/flajolet/Publications/FlFuGaMe07.pdf.
type HyperLogLog struct {
	powTable     [65]float64
	registers    []uint8
	alpha        float64
	registerBits uint8
}

// defaultRegisterBits is the default value for
// [HyperLogLogConfig.RegisterBits].
const defaultRegisterBits = 4

// NewHyperLogLog returns properly initialized *HyperLogLog.  If conf is nil,
// default values will be used for initialization.
func NewHyperLogLog(conf *HyperLogLogConfig) (hll *HyperLogLog, err error) {
	conf = cmp.Or(conf, &HyperLogLogConfig{})
	conf.RegisterBits = cmp.Or(conf.RegisterBits, uint8(defaultRegisterBits))

	if err = conf.Validate(); err != nil {
		return nil, fmt.Errorf("validating conf: %w", err)
	}

	registersNum := 1 << conf.RegisterBits

	registers := make([]uint8, registersNum)

	var alpha float64
	switch registersNum {
	case 16:
		alpha = 0.673
	case 32:
		alpha = 0.697
	case 64:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1.0 + 1.079/float64(registersNum))
	}

	hll = &HyperLogLog{
		alpha:        alpha,
		registers:    registers,
		registerBits: conf.RegisterBits,
	}

	for i := range 65 {
		hll.powTable[i] = 1.0 / float64(uint64(1<<i))
	}

	return hll, nil
}

// Add adds new entry to current HLL sketch.
//
// TODO: Make it generic.
func (hll *HyperLogLog) Add(s string) {
	hash := murmur3.StringSum64(s)

	idx := hash >> (64 - hll.registerBits)
	suffix := hash << hll.registerBits
	zeroes := bits.LeadingZeros64(suffix)
	val := uint8(zeroes + 1)

	maxVal := uint8(64 - hll.registerBits + 1)
	if val > maxVal {
		val = maxVal
	}

	hll.registers[idx] = dnsmath.Max(hll.registers[idx], val)
}

// CountUnique returns number of unique entries in current HLL sketch.
func (hll *HyperLogLog) CountUnique() (res int) {
	sum := 0.0
	for _, r := range hll.registers {
		sum += hll.powTable[r]
	}

	m := float64(len(hll.registers))

	estimate := hll.alpha * m * m / sum
	if estimate < 2.5*float64(len(hll.registers)) {
		return int(m * math.Log2(m/hll.countZeroRegisters()))
	}

	return int(estimate)
}

// countZeroRegisters returns number of zero registers in current sketch.
func (hll *HyperLogLog) countZeroRegisters() (res float64) {
	for _, reg := range hll.registers {
		if reg == 0 {
			res++
		}
	}

	return res
}
