package main

import (
	"strings"
	"testing"

	"github.com/ebfe/scard"
)

func TestSelectPresentReader(t *testing.T) {
	present := func(name string) scard.ReaderState {
		return scard.ReaderState{
			Reader:     name,
			EventState: scard.StatePresent,
		}
	}
	absent := func(name string) scard.ReaderState {
		return scard.ReaderState{Reader: name}
	}

	tests := []struct {
		name   string
		states []scard.ReaderState
		want   string
		err    string
	}{
		{"no readers", nil, "", "no card inserted"},
		{"empty reader", []scard.ReaderState{
			absent("OMNIKEY"),
		}, "", "no card inserted"},
		{"one card", []scard.ReaderState{
			present("OMNIKEY"),
		}, "OMNIKEY", ""},
		{"one of two", []scard.ReaderState{
			absent("YubiKey"),
			present("OMNIKEY"),
		}, "OMNIKEY", ""},
		{"ambiguous cards", []scard.ReaderState{
			present("YubiKey"),
			present("OMNIKEY"),
		}, "", "multiple cards present"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectPresentReader(tc.states)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("expected %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
