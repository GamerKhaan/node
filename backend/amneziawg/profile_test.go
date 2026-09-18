package amneziawg

import (
	"runtime"
	"testing"
)

// Observation only. Three tunnels and admission limits are not a production
// capacity claim and do not close ARCH-01 upstream pooled-buffer retention.
func TestN08ResourceEnvelopeObservation(t *testing.T) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("NumCPU=%d GOMAXPROCS=%d Goroutines=%d Alloc=%d TotalAlloc=%d Sys=%d ARCH-01=OPEN", runtime.NumCPU(), runtime.GOMAXPROCS(0), runtime.NumGoroutine(), m.Alloc, m.TotalAlloc, m.Sys)
}
