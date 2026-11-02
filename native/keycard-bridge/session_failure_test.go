package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestConnectionFailureReleasesContext(t *testing.T) {
	failure := errors.New("simulated PC/SC connection failure")
	var events []string

	err := runWithFailureCleanup(
		func() error {
			events = append(events, "connect")
			return failure
		},
		func() {
			events = append(events, "release-context")
		},
	)

	if !errors.Is(err, failure) {
		t.Fatalf("connection error lost: %v", err)
	}

	want := []string{"connect", "release-context"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%v, want %v", events, want)
	}
}

func TestAppletSelectionFailureCleansSession(t *testing.T) {
	failure := errors.New("simulated applet selection failure")
	var events []string

	cleanup := makeCardCleanup(
		func() { events = append(events, "disconnect") },
		func() { events = append(events, "release-context") },
	)

	err := runWithFailureCleanup(
		func() error {
			events = append(events, "select")
			return failure
		},
		cleanup,
	)

	cleanup()

	if !errors.Is(err, failure) {
		t.Fatalf("selection error lost: %v", err)
	}

	want := []string{
		"select", "disconnect", "release-context",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%v, want %v", events, want)
	}
}

func TestSuccessfulOperationRetainsSession(t *testing.T) {
	cleanups := 0

	err := runWithFailureCleanup(
		func() error { return nil },
		func() { cleanups++ },
	)

	if err != nil || cleanups != 0 {
		t.Fatalf("err=%v cleanups=%d", err, cleanups)
	}
}

func TestInterruptedOperationCleansSession(t *testing.T) {
	cleanups := 0

	func() {
		defer func() {
			if got := recover(); got != "interrupted" {
				t.Errorf("unexpected panic: %v", got)
			}
		}()

		_ = runWithFailureCleanup(
			func() error { panic("interrupted") },
			func() { cleanups++ },
		)
	}()

	if cleanups != 1 {
		t.Fatalf("cleanups=%d, want 1", cleanups)
	}
}
