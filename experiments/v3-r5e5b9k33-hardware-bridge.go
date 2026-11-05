package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ebfe/scard"
	keycard "github.com/keycard-tech/keycard-go/v4"
	keycardio "github.com/keycard-tech/keycard-go/v4/io"
	"golang.org/x/term"
)

const (
	reader       = "HID Global OMNIKEY 3x21 Smart Card Reader"
	testCA       = "025877220AAAE6E54A6F974602D5995C0FE24A3EA7DDABD8644BEC795B9DA00743"
	cardIdentity = "03475c427cea8ec434adc771c3424a3d31f49c2b89f98db530e845461c285ebf09"
	bip85Path    = "m/83696968'/128169'/32'/0'"
)

func acquire() (root [32]byte, err error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return root, errors.New("PC/SC unavailable")
	}
	defer ctx.Release()

	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return root, errors.New("card connection failed")
	}
	defer card.Disconnect(scard.ResetCard)

	rawCA, err := hex.DecodeString(testCA)
	if err != nil || len(rawCA) != 33 {
		return root, errors.New("invalid test CA")
	}

	var ca [33]byte
	copy(ca[:], rawCA)

	kc := keycard.NewCommandSetWithCA(
		keycardio.NewNormalChannel(card), ca,
	)

	if err := kc.Select(); err != nil {
		return root, errors.New("certificate authentication failed")
	}

	info := kc.ApplicationInfo
	identity, err := hex.DecodeString(cardIdentity)
	if err != nil {
		return root, errors.New("invalid identity configuration")
	}

	if info == nil || info.AppVersion() != 0x0400 ||
		len(info.CertData) < 33 ||
		!bytes.Equal(info.CertData[:33], identity) {
		return root, errors.New("unexpected card identity or version")
	}

	if err := kc.AutoOpenSecureChannel(); err != nil {
		return root, errors.New("secure channel failed")
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return root, errors.New("interactive terminal required")
	}
	defer tty.Close()

	fmt.Fprint(tty, "Keycard 4.0 PIN: ")
	pin, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)

	if err != nil || len(pin) == 0 || len(pin) > 64 {
		clear(pin)
		return root, errors.New("PIN entry cancelled or invalid")
	}

	// PIN is never supplied via argv, env, or files.
	err = kc.VerifyPIN(string(pin))
	clear(pin)
	if err != nil {
		return root, errors.New("PIN verification failed; no retry attempted")
	}

	material, err := kc.ExportBIP85(bip85Path, 32)
	if err != nil || len(material) != 32 {
		clear(material)
		return root, errors.New("BIP-85 derivation failed")
	}

	copy(root[:], material)
	clear(material)
	return root, nil
}

// Node recovery source is loaded from a public test file.
func runNode(first, second *[32]byte) error {
	probeHome, err := os.UserHomeDir()
	if err != nil {
		return errors.New("home directory unavailable")
	}
	probe, err := os.ReadFile(filepath.Join(
		probeHome,
		"Developer/kohaku-cli/experiments/v3-r5e5b9k33-hardware-recovery.mjs",
	))
	if err != nil {
		return errors.New("snapshot recovery source unavailable")
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return errors.New("anonymous pipe creation failed")
	}
	defer readEnd.Close()
	defer writeEnd.Close()

	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("home directory unavailable")
	}

	cmd := exec.Command(
		"node",
		"--import", "tsx",
		"--input-type=module",
		"--eval", string(probe),
	)
	cmd.Dir = filepath.Join(home, "Developer/kohaku-cli")
	cmd.ExtraFiles = []*os.File{readEnd}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Prevent inherited Node debugging flags.
	cmd.Env = append(os.Environ(), "NODE_OPTIONS=")

	if err := cmd.Start(); err != nil {
		return errors.New("Node adapter startup failed")
	}

	readEnd.Close()

	payload := make([]byte, 64)
	copy(payload[:32], first[:])
	copy(payload[32:], second[:])

	_, writeErr := writeEnd.Write(payload)
	clear(payload)
	writeEnd.Close()

	waitErr := cmd.Wait()
	if writeErr != nil || waitErr != nil {
		return errors.New("Node credential adapter failed")
	}
	return nil
}

func run() error {
	for _, name := range []string{
		"KEYCARD_PIN", "KEYCARD_PUK", "KEYCARD_PAIRING_PASSWORD",
	} {
		if _, exists := os.LookupEnv(name); exists {
			return errors.New("legacy secret environment variable must be unset")
		}
	}

	fmt.Println("=== Authenticated hardware session 1 ===")
	first, err := acquire()
	if err != nil {
		return err
	}
	defer clear(first[:])
	fmt.Println("PASS: BIP-85 root acquired in memory")

	fmt.Println("=== Authenticated hardware session 2 ===")
	second, err := acquire()
	if err != nil {
		return err
	}
	defer clear(second[:])

	if !bytes.Equal(first[:], second[:]) {
		return errors.New("hardware root mismatch")
	}
	fmt.Println("PASS: Hardware root reconstructed across sessions")

	fmt.Println("=== Privacy Pools SDK reconstruction ===")
	return runNode(&first, &second)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
