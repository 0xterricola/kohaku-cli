package main

import "fmt"

// cardInfoResult reports application information obtained from SELECT.
// V4+ cards omit the legacy pairing-slot field.
func cardInfoResult(version uint16, slots []byte) map[string]any {
	var freeSlots any

	if len(slots) > 0 {
		freeSlots = int(slots[0])
	}

	return map[string]any{
		"applet_version":     fmt.Sprintf("0x%04x", version),
		"free_pairing_slots": freeSlots,
	}
}
