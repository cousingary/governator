// Package dbtime is the single authority for timestamps stored in the
// Governator ledger. Authoritative comparisons use signed Unix nanoseconds;
// RFC3339Nano text is retained only for compatibility, display, and export.
package dbtime

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// UnsetUnixNano is the numeric counterpart of the ledger's historical empty
// string sentinel. It deliberately reserves one int64 value so zero remains
// available for the real Unix epoch instant (1970-01-01T00:00:00Z).
const UnsetUnixNano int64 = math.MinInt64

// MinSupportedTime and MaxSupportedTime are the inclusive bounds ToUnixNano
// accepts (Sol15 P0-3: named so every caller's error text and every
// config-load-time range check quotes the same values instead of
// hardcoding dates). MinSupportedTime is one nanosecond above
// math.MinInt64's instant because that exact instant collides with
// UnsetUnixNano, which is reserved for the zero-time sentinel.
var (
	MinSupportedTime = time.Unix(0, math.MinInt64+1).UTC()
	MaxSupportedTime = time.Unix(0, math.MaxInt64).UTC()
)

// SupportedRangeString formats the supported range for operator-facing
// error text.
func SupportedRangeString() string {
	return fmt.Sprintf("%s to %s", MinSupportedTime.Format(time.RFC3339Nano), MaxSupportedTime.Format(time.RFC3339Nano))
}

// ErrCorruptTimestamp reports a stored ledger timestamp that cannot be
// trusted as-is (Sol15 P0-3, "database values outside the valid range" /
// "corrupt database numeric timestamp"). Note what this is NOT: a raw int64
// numeric column can never itself be "out of range" — MinSupportedTime and
// MaxSupportedTime, above, span every value but one that int64 can hold (the
// UnsetUnixNano sentinel), so a bare range check on the number can never
// fail. The only way a numeric ledger column is genuinely corrupt is if it
// disagrees with the legacy text column it was written from — see
// VerifyLegacyRoundTrip.
var ErrCorruptTimestamp = errors.New("dbtime: corrupt ledger timestamp")

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
		return 0, fmt.Errorf("ledger timestamp %s is outside the signed Unix-nanosecond range (supported range %s)", t.Format(time.RFC3339Nano), SupportedRangeString())
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

// VerifyLegacyRoundTrip reports whether a numeric ledger column agrees with
// the legacy text column it was derived from (Sol15 P0-3). Every writer in
// this codebase sets both columns from the same time.Time in the same
// statement, so the two must always independently convert to the same
// Unix-nanosecond value; disagreement means the row was altered outside the
// application (hand edit, bad migration, storage-level corruption) rather
// than written by anything this codebase's own write paths produced. A
// legacy text value that itself fails to convert (unparseable, or parseable
// but outside the supported range — the migration path in
// internal/observability already fails Open() closed on this, so a
// live row reaching this check should never hit it, but a read path must
// not assume that) is reported the same way.
func VerifyLegacyRoundTrip(legacyText string, nanos int64) error {
	want, err := LegacyToUnixNano(legacyText)
	if err != nil {
		return fmt.Errorf("%w: legacy text %q does not itself convert: %v", ErrCorruptTimestamp, legacyText, err)
	}
	if want != nanos {
		return fmt.Errorf("%w: numeric value %d disagrees with legacy text %q (recomputed %d)", ErrCorruptTimestamp, nanos, legacyText, want)
	}
	return nil
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
