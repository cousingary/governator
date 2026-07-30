package dbtime

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLegacyAndUnixNanoRoundTrip(t *testing.T) {
	const value = "2026-07-28T00:00:00.5Z"
	nanos, err := LegacyToUnixNano(value)
	if err != nil {
		t.Fatal(err)
	}
	if nanos == 0 || nanos == UnsetUnixNano {
		t.Fatalf("real timestamp mapped to a sentinel: %d", nanos)
	}
	if got := UnixNanoToLegacy(nanos); got != value {
		t.Fatalf("round trip = %q, want %q", got, value)
	}
}

func TestEmptyStringUsesNonzeroNumericSentinel(t *testing.T) {
	nanos, err := LegacyToUnixNano("")
	if err != nil {
		t.Fatal(err)
	}
	if nanos != UnsetUnixNano {
		t.Fatalf("empty timestamp = %d, want UnsetUnixNano", nanos)
	}
	if nanos == 0 {
		t.Fatal("empty timestamp must not consume the real Unix epoch")
	}
	if got := UnixNanoToLegacy(nanos); got != "" {
		t.Fatalf("sentinel formatted as %q, want empty string", got)
	}

	epoch, err := ToUnixNano(time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 0 {
		t.Fatalf("Unix epoch = %d, want 0", epoch)
	}
}

func TestInvalidAndOutOfRangeTimesFailClosed(t *testing.T) {
	if _, err := LegacyToUnixNano("not-a-time"); err == nil {
		t.Fatal("expected invalid legacy timestamp to fail")
	}
	if _, err := ToUnixNano(time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected timestamp outside int64 Unix-nanosecond range to fail")
	}
}

func TestVerifyLegacyRoundTripDetectsDisagreement(t *testing.T) {
	value := "2026-07-28T00:00:00Z"
	nanos, err := LegacyToUnixNano(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLegacyRoundTrip(value, nanos); err != nil {
		t.Fatalf("agreeing text/numeric pair rejected: %v", err)
	}
	if err := VerifyLegacyRoundTrip(value, nanos+1); err == nil {
		t.Fatal("expected disagreeing numeric value to be reported as corrupt")
	} else if !errors.Is(err, ErrCorruptTimestamp) {
		t.Fatalf("expected ErrCorruptTimestamp, got %v", err)
	}
	if err := VerifyLegacyRoundTrip("not-a-time", nanos); err == nil || !errors.Is(err, ErrCorruptTimestamp) {
		t.Fatalf("expected unparseable legacy text to be reported as ErrCorruptTimestamp, got %v", err)
	}
}

func TestSupportedRangeStringNamesBothBounds(t *testing.T) {
	s := SupportedRangeString()
	if !strings.Contains(s, MinSupportedTime.Format(time.RFC3339Nano)) || !strings.Contains(s, MaxSupportedTime.Format(time.RFC3339Nano)) {
		t.Fatalf("SupportedRangeString() = %q, want both bounds", s)
	}
}
