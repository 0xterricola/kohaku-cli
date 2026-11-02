package main

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCardCleanupOrderAndIdempotence(t *testing.T) {
	var calls []string

	cleanup := makeCardCleanup(
		func() { calls = append(calls, "disconnect") },
		func() { calls = append(calls, "release") },
	)

	cleanup()
	cleanup()

	want := []string{"disconnect", "release"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup order: got %v, want %v", calls, want)
	}
}

func TestCardCleanupReleasesAfterDisconnectPanic(t *testing.T) {
	releases := 0

	cleanup := makeCardCleanup(
		func() { panic("simulated disconnect failure") },
		func() { releases++ },
	)

	func() {
		defer func() {
			if got := recover(); got != "simulated disconnect failure" {
				t.Errorf("unexpected panic: %v", got)
			}
		}()
		cleanup()
	}()

	// Repeated cleanup must be safe after the interrupted first call.
	cleanup()

	if releases != 1 {
		t.Fatalf("context released %d times, want 1", releases)
	}
}

func TestCardCleanupConcurrentCalls(t *testing.T) {
	var disconnects atomic.Int32
	var releases atomic.Int32

	cleanup := makeCardCleanup(
		func() { disconnects.Add(1) },
		func() { releases.Add(1) },
	)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cleanup()
		}()
	}
	wg.Wait()

	if disconnects.Load() != 1 || releases.Load() != 1 {
		t.Fatalf(
			"disconnects=%d releases=%d, want 1 each",
			disconnects.Load(), releases.Load(),
		)
	}
}
