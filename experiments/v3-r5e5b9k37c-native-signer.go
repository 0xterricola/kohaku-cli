package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

const expectedSigner = "0x155a8332a3504d5f532742ae6531cd0e28035972"

func signDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("invalid signing digest")
	}

	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, errors.New("PC/SC unavailable")
	}
	defer ctx.Release()

	card, err := ctx.Connect(
		reader, scard.ShareShared, scard.ProtocolAny,
	)
	if err != nil {
		return nil, errors.New("card connection failed")
	}
	defer card.Disconnect(scard.ResetCard)

	rawCA, err := hex.DecodeString(testCA)
	if err != nil || len(rawCA) != 33 {
		return nil, errors.New("invalid test CA")
	}

	var ca [33]byte
	copy(ca[:], rawCA)

	kc := keycard.NewCommandSetWithCA(
		keycardio.NewNormalChannel(card), ca,
	)

	if err := kc.Select(); err != nil {
		return nil, errors.New("certificate authentication failed")
	}

	identity, err := hex.DecodeString(cardIdentity)
	if err != nil {
		return nil, errors.New("invalid card identity configuration")
	}

	info := kc.ApplicationInfo
	if info == nil ||
		info.AppVersion() != 0x0400 ||
		len(info.CertData) < 33 ||
		!bytes.Equal(info.CertData[:33], identity) {
		return nil, errors.New("unexpected card identity")
	}

	if err := kc.AutoOpenSecureChannel(); err != nil {
		return nil, errors.New("secure channel failed")
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("interactive terminal required")
	}
	defer tty.Close()

	fmt.Fprint(tty, "Keycard 4.0 PIN: ")
	pin, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)

	if err != nil || len(pin) == 0 || len(pin) > 64 {
		clear(pin)
		return nil, errors.New("PIN entry invalid")
	}

	err = kc.VerifyPIN(string(pin))
	clear(pin)
	if err != nil {
		return nil, errors.New("PIN verification failed; no retry")
	}

	sig, err := kc.SignWithPath(
		digest, "m/44'/60'/0'/0/0",
	)
	if err != nil {
		return nil, errors.New("physical signing failed")
	}

	if len(sig.R()) != 32 ||
		len(sig.S()) != 32 ||
		len(sig.PubKey()) != 65 ||
		sig.V() > 1 {
		return nil, errors.New("invalid hardware signature")
	}

	pub, err := crypto.UnmarshalPubkey(sig.PubKey())
	if err != nil {
		return nil, errors.New("invalid hardware public key")
	}

	if !strings.EqualFold(
		crypto.PubkeyToAddress(*pub).Hex(),
		expectedSigner,
	) {
		return nil, errors.New("hardware signer mismatch")
	}

	r := new(big.Int).SetBytes(sig.R())
	s := new(big.Int).SetBytes(sig.S())

	if !ecdsa.Verify(pub, digest, r, s) {
		return nil, errors.New("ECDSA verification failed")
	}

	signature := make([]byte, 65)
	copy(signature[:32], sig.R())
	copy(signature[32:64], sig.S())
	signature[64] = sig.V()

	recovered, err := crypto.Ecrecover(digest, signature)
	if err != nil ||
		!bytes.Equal(recovered, sig.PubKey()) {
		return nil, errors.New("ECDSA recovery failed")
	}

	fmt.Println("PASS: Physical ECDSA signature verified")
	fmt.Println("PASS: Correct hardware account verified")

	return signature, nil
}

func approveDigest(digest []byte) error {
	if len(digest) != 32 {
		return errors.New("invalid signing digest")
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("interactive approval required")
	}
	defer tty.Close()

	fmt.Fprintln(tty)
	fmt.Fprintln(tty, "=== K37-C PHYSICAL WITHDRAWAL SIGNING APPROVAL ===")
	fmt.Fprintln(tty, "Review the real Sepolia transaction above.")
	fmt.Fprintln(tty, "Chain ID: 11155111")
	fmt.Fprintln(tty, "Withdrawal amount: 0.00099 Sepolia ETH")
	fmt.Fprintln(tty, "Remaining private change note: 0.00099 Sepolia ETH")
	fmt.Fprintln(tty, "Pool: 0x644d5A2554d36e27509254F32ccfeBe8cd58861f")
	fmt.Fprintf(tty, "Signing digest: 0x%x\n", digest)
	fmt.Fprintln(tty, "Broadcasting: DISABLED in K37-C")
	fmt.Fprintln(tty)
	fmt.Fprint(tty, "Type SIGN to authorize physical signing: ")

	response, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil || strings.TrimSpace(response) != "SIGN" {
		return errors.New("hardware signing authorization declined")
	}

	return nil
}

func runNode(first, second *[32]byte) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("home directory unavailable")
	}

	path := filepath.Join(
		home,
		"Developer/kohaku-cli/experiments/v3-r5e5b9k37c-offline-signing.mjs",
	)

	probe, err := os.ReadFile(path)
	if err != nil {
		return errors.New("offline verifier source unavailable")
	}

	rootRead, rootWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer rootRead.Close()
	defer rootWrite.Close()

	digestRead, digestWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer digestRead.Close()
	defer digestWrite.Close()

	sigRead, sigWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer sigRead.Close()
	defer sigWrite.Close()

	cmd := exec.Command(
		"node",
		"--import", "tsx",
		"--input-type=module",
		"--eval", string(probe),
	)

	cmd.Dir = filepath.Join(home, "Developer/kohaku-cli")
	cmd.ExtraFiles = []*os.File{
		rootRead,
		digestWrite,
		sigRead,
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "NODE_OPTIONS=")

	if err := cmd.Start(); err != nil {
		return errors.New("offline verifier failed to start")
	}

	rootRead.Close()
	digestWrite.Close()
	sigRead.Close()

	payload := make([]byte, 64)
	copy(payload[:32], first[:])
	copy(payload[32:], second[:])

	count, writeErr := rootWrite.Write(payload)
	clear(payload)
	rootWrite.Close()

	if writeErr != nil || count != 64 {
		sigWrite.Close()
		_ = cmd.Wait()
		return errors.New("credential IPC failed")
	}

	var digest [32]byte
	_, err = io.ReadFull(digestRead, digest[:])

	if err != nil {
		sigWrite.Close()
		_ = cmd.Wait()
		return errors.New("validated signing digest unavailable")
	}

	fmt.Println("PASS: Offline digest received over FD4")

	if err := approveDigest(digest[:]); err != nil {
		sigWrite.Close()
		_ = cmd.Wait()
		return err
	}

	fmt.Println("PASS: Explicit signing authorization")

	signature, err := signDigest(digest[:])
	if err != nil {
		sigWrite.Close()
		_ = cmd.Wait()
		return err
	}

	count, writeErr = sigWrite.Write(signature)
	clear(signature)
	sigWrite.Close()

	if writeErr != nil || count != 65 {
		_ = cmd.Wait()
		return errors.New("signature IPC failed")
	}

	if err := cmd.Wait(); err != nil {
		return errors.New("independent transaction verification failed")
	}

	fmt.Println("PASS: K37-C physical transaction signature verified")
	return nil
}

func run() error {
	for _, name := range []string{
		"KEYCARD_PIN",
		"KEYCARD_PUK",
		"KEYCARD_PAIRING_PASSWORD",
	} {
		if _, exists := os.LookupEnv(name); exists {
			return errors.New(
				"legacy secret environment variable must be unset",
			)
		}
	}

	fmt.Println("=== Authenticated hardware session 1 ===")
	first, err := acquire()
	if err != nil {
		return err
	}
	defer clear(first[:])

	fmt.Println("PASS: First BIP-85 root acquired in memory")

	fmt.Println("=== Authenticated hardware session 2 ===")
	second, err := acquire()
	if err != nil {
		return err
	}
	defer clear(second[:])

	if !bytes.Equal(first[:], second[:]) {
		return errors.New("independent hardware roots differ")
	}

	fmt.Println("PASS: Two physical credential sessions agree")
	return runNode(&first, &second)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
