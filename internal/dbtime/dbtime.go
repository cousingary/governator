// Package dbtime is the single authority for timestamps stored in the
// Governator ledger. Authoritative comparisons use signed Unix nanoseconds;
// RFC3339Nano text is retained only for compatibility, display, and export.
package dbtime

import (
	"fmt"
	"math"
	"time"
)

// UnsetUnixNano is the numeric counterpart of the ledger's historical empty
// string sentinel. It deliberately reserves one int64 value so zero remains
// available for the real Unix epoch instant (1970-01-01T00:00:00Z).
const UnsetUnixNano int64 = math.MinInt64

// FormatLegacy formats a timestamp for the ledger's compatibility text
// columns. New comparisons must use ToUnixNano instead of this text.
func FormatLegacy(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ParseLegacy parses a compatibility text timestamp. The historical empty
// string sentinel maps to time.Time's zero value.
func ParseLegacy(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse ledger timestamp %q: %w", value, err)
	}
	return t.UTC(), nil
}

// ToUnixNano converts a timestamp to its authoritative database value. Times
// outside UnixNano's signed 64-bit range fail instead of wrapping. The zero
// time maps to UnsetUnixNano.
func ToUnixNano(t time.Time) (int64, error) {
	if t.IsZero() {
		return UnsetUnixNano, nil
	}
	t = t.UTC()
	nanos := t.UnixNano()
	if nanos == UnsetUnixNano || !time.Unix(0, nanos).UTC().Equal(t) {
		return 0, fmt.Errorf("ledger timestamp %s is outside the signed Unix-nanosecond range", t.Format(time.RFC3339Nano))
	}
	return nanos, nil
}

// FromUnixNano converts an authoritative database value back to time.Time.
// UnsetUnixNano maps to the zero time.
func FromUnixNano(nanos int64) time.Time {
	if nanos == UnsetUnixNano {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}

// LegacyToUnixNano parses a compatibility text value and converts it to the
// authoritative numeric representation.
func LegacyToUnixNano(value string) (int64, error) {
	t, err := ParseLegacy(value)
	if err != nil {
		return 0, err
	}
	return ToUnixNano(t)
}

// UnixNanoToLegacy converts an authoritative value to compatibility text.
func UnixNanoToLegacy(nanos int64) string {
	return FormatLegacy(FromUnixNano(nanos))
}
