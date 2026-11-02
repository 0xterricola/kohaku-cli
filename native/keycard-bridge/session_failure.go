package main

// runWithFailureCleanup releases acquired resources when an operation
// fails or panics. Successful operations retain their resources.
func runWithFailureCleanup(
	operation func() error,
	cleanup func(),
) (err error) {
	success := false

	defer func() {
		if !success {
			cleanup()
		}
	}()

	if err := operation(); err != nil {
		return err
	}

	success = true
	return nil
}
