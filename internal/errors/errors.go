// Package errors contains utilities for working with errors
package errors

import "fmt"

// Annotate wraps the error if it is not nil.
func Annotate(orig error, format string, a ...any) (err error) {
	if orig == nil {
		return nil
	}

	return fmt.Errorf(format, orig, a)
}
