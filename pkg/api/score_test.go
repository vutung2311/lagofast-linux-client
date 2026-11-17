package api

import (
	"testing"
	"time"
)

func TestDurationMsKeepsSubMillisecondPrecision(t *testing.T) {
	if got := durationMs(1900 * time.Microsecond); got != 1.9 {
		t.Fatalf("durationMs(1.9ms) = %v", got)
	}
	// 31.9 ms avg / 0.9 ms jitter must score worse than 31.0 ms / 0.2 ms.
	a := durationMs(31900*time.Microsecond) + 2.5*durationMs(900*time.Microsecond)
	b := durationMs(31000*time.Microsecond) + 2.5*durationMs(200*time.Microsecond)
	if !(b < a) {
		t.Fatalf("expected b (%v) < a (%v)", b, a)
	}
}
