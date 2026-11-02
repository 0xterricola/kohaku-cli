package main

import "sync"

// makeCardCleanup disconnects the card before releasing its PC/SC context.
// Cleanup runs at most once, even after an interrupted operation.
func makeCardCleanup(disconnect, release func()) func() {
	var once sync.Once

	return func() {
		once.Do(func() {
			defer release()
			disconnect()
		})
	}
}
