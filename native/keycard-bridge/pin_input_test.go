package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPINInput(t *testing.T) {
	tty, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()

	tests := []struct {
		name    string
		input   string
		readErr error
		wantErr string
	}{
		{"valid", "123456", nil, ""},
		{"empty", "", nil, "invalid PIN length"},
		{"too long", strings.Repeat("1", 65), nil, "invalid PIN length"},
		{"cancelled", "123456", errors.New("sensitive input"), "PIN entry cancelled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input)

			got, err := readPINFrom(tty, func(int) ([]byte, error) {
				return input, tc.readErr
			})

			if tc.wantErr == "" {
				if err != nil || got != tc.input {
					t.Fatalf("unexpected PIN result: %v", err)
				}
			} else {
				if err == nil || err.Error() != tc.wantErr || got != "" {
					t.Fatalf("unexpected rejection: %v", err)
				}
			}

			for _, b := range input {
				if b != 0 {
					t.Fatal("PIN input buffer not cleared")
				}
			}
		})
	}
}
