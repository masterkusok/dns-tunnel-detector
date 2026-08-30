// Package testutil contains useful utilities for testing.
package testutil

import "log/slog"

// NewDiscardLogger returns [slog.Logger] with [slog.DiscardHandler].
func NewDiscardLogger() (logger *slog.Logger) {
	return slog.New(slog.DiscardHandler)
}
