package main

import "testing"

func TestCardInfoOptions(t *testing.T) {
	for _, args := range [][]string{
		{"card-info"},
		{"card-info", "--reader", "OMNIKEY"},
	} {
		opts, err := parseOptions(args)
		if err != nil {
			t.Fatalf("args=%v: %v", args, err)
		}
		if opts.action != "card-info" {
			t.Fatalf("unexpected action: %s", opts.action)
		}
	}

	for _, args := range [][]string{
		{"card-info", "--path", defaultPath},
		{"card-info", "--hex", "0x1234"},
		{"card-info", "--expected-address", "0x1234"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Fatalf("unexpectedly accepted %v", args)
		}
	}
}

func TestCardInfoResult(t *testing.T) {
	legacy := cardInfoResult(0x0301, []byte{4})

	if legacy["applet_version"] != "0x0301" ||
		legacy["free_pairing_slots"] != 4 {
		t.Fatalf("unexpected legacy information: %v", legacy)
	}

	modern := cardInfoResult(0x0400, nil)

	if modern["applet_version"] != "0x0400" ||
		modern["free_pairing_slots"] != nil {
		t.Fatalf("unexpected modern information: %v", modern)
	}
}
