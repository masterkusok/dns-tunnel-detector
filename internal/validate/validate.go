// Package validate contains useful utilities for property validation.
package validate

import (
	"cmp"
	"fmt"
)

// Interface is the interface for object supporting validation.
type Interface interface {
	Validate() (err error)
}

// InRange makes sure that given val is in range [min, max].
func InRange[T cmp.Ordered](val, min, max T) (err error) {
	if val < min || val > max {
		return fmt.Errorf("given value is out of range")
	}

	return nil
}
