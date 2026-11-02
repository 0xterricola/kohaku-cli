package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ebfe/scard"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/keycard-tech/keycard-go/v4"
	keycardio "github.com/keycard-tech/keycard-go/v4/io"
	"golang.org/x/term"
)

const defaultPath = "m/44'/60'/0'/0/0"
const defaultPairing = "KeycardDefaultPairing"

type options struct {
	action   string
	path     string
	reader   string
	digest   string
	expected string
}

func parseOptions(args []string) (options, error) {
	var opts options

	if len(args) == 0 {
		return opts, errors.New("expected card-info, get-address, or sign-digest")
	}

	opts.action = args[0]

	if opts.action != "card-info" &&
		opts.action != "get-address" &&
		opts.action != "sign-digest" {
		return opts, errors.New("unsupported operation")
	}

	fs := flag.NewFlagSet(opts.action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&opts.path, "path", defaultPath, "derivation path")
	fs.StringVar(&opts.reader, "reader", "", "smartcard reader")
	fs.StringVar(&opts.digest, "hex", "", "32-byte signing digest")
	fs.StringVar(&opts.expected, "expected-address", "", "expected signer")

	if err := fs.Parse(args[1:]); err != nil {
		return opts, errors.New("invalid command options")
	}

	if len(fs.Args()) != 0 {
		return opts, errors.New("unexpected positional arguments")
	}

	if opts.action == "card-info" {
		invalid := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name != "reader" {
				invalid = true
			}
		})
		if invalid {
			return opts, errors.New(
				"card-info accepts only --reader",
			)
		}
		return opts, nil
	}

	if !strings.HasPrefix(opts.path, "m/") {
		return opts, errors.New("absolute derivation path required")
	}

	if opts.action == "get-address" {
		if opts.digest != "" || opts.expected != "" {
			return opts, errors.New("unexpected signing arguments")
		}
		return opts, nil
	}

	if _, err := decodeDigest(opts.digest); err != nil {
		return opts, err
	}

	if !common.IsHexAddress(opts.expected) {
		return opts, errors.New("valid expected address required")
	}

	return opts, nil
}

func decodeDigest(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "0x") || len(value) != 66 {
		return nil, errors.New("digest must be 32-byte 0x hex")
	}

	digest, err := hex.DecodeString(value[2:])
	if err != nil || len(digest) != 32 {
		return nil, errors.New("invalid digest")
	}

	return digest, nil
}

func rejectLegacySecrets() error {
	for _, name := range []string{
		"KEYCARD_PIN",
		"KEYCARD_PUK",
		"KEYCARD_PAIRING_PASSWORD",
	} {
		if _, present := os.LookupEnv(name); present {
			return fmt.Errorf("%s must be unset", name)
		}
	}
	return nil
}

func readPIN() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("interactive terminal required")
	}
	defer tty.Close()

	return readPINFrom(tty, term.ReadPassword)
}

func readPINFrom(
	tty *os.File,
	readPassword func(int) ([]byte, error),
) (string, error) {
	if _, err := fmt.Fprint(tty, "Keycard PIN: "); err != nil {
		return "", errors.New("PIN prompt unavailable")
	}

	pin, err := readPassword(int(tty.Fd()))
	defer clear(pin)
	fmt.Fprintln(tty)

	if err != nil {
		return "", errors.New("PIN entry cancelled")
	}
	if len(pin) == 0 || len(pin) > 64 {
		return "", errors.New("invalid PIN length")
	}

	return string(pin), nil
}

func publicAddress(raw []byte) (common.Address, error) {
	var address common.Address

	switch len(raw) {
	case 65:
		pub, err := crypto.UnmarshalPubkey(raw)
		if err != nil {
			return address, errors.New("invalid public key")
		}
		return crypto.PubkeyToAddress(*pub), nil
	case 33:
		pub, err := crypto.DecompressPubkey(raw)
		if err != nil {
			return address, errors.New("invalid public key")
		}
		return crypto.PubkeyToAddress(*pub), nil
	default:
		return address, errors.New("unsupported public key length")
	}
}

func recoverSignature(
	digest, r, s []byte,
	v byte,
	expected common.Address,
) (map[string]any, error) {
	if len(digest) != 32 ||
		len(r) == 0 || len(r) > 32 ||
		len(s) == 0 || len(s) > 32 ||
		v > 1 {
		return nil, errors.New("invalid ECDSA signature fields")
	}

	raw := make([]byte, 65)
	copy(raw[32-len(r):32], r)
	copy(raw[64-len(s):64], s)
	raw[64] = v

	pub, err := crypto.SigToPub(digest, raw)
	if err != nil {
		return nil, errors.New("signature recovery failed")
	}

	if crypto.PubkeyToAddress(*pub) != expected {
		return nil, errors.New("signature address mismatch")
	}

	return map[string]any{
		"signature_r": "0x" + hex.EncodeToString(raw[:32]),
		"signature_s": "0x" + hex.EncodeToString(raw[32:64]),
		"signature_v": int(v),
	}, nil
}

func selectPresentReader(
	states []scard.ReaderState,
) (string, error) {
	var selected string

	for _, state := range states {
		if state.EventState&scard.StatePresent == 0 {
			continue
		}
		if selected != "" {
			return "", errors.New(
				"multiple cards present; specify --reader",
			)
		}
		selected = state.Reader
	}

	if selected == "" {
		return "", errors.New("no card inserted")
	}
	return selected, nil
}

func connectCard(readerName string) (
	*keycard.CommandSet,
	func(),
	error,
) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, nil, errors.New("smartcard context unavailable")
	}

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		ctx.Release()
		return nil, nil, errors.New("no smartcard readers")
	}

	if readerName == "" {
		states := make([]scard.ReaderState, len(readers))
		for i, name := range readers {
			states[i] = scard.ReaderState{
				Reader:       name,
				CurrentState: scard.StateUnaware,
			}
		}

		if err := ctx.GetStatusChange(states, 0); err != nil {
			ctx.Release()
			return nil, nil, fmt.Errorf("reader status: %w", err)
		}

		readerName, err = selectPresentReader(states)
		if err != nil {
			ctx.Release()
			return nil, nil, err
		}
	} else {
		found := false
		for _, name := range readers {
			if name == readerName {
				found = true
				break
			}
		}
		if !found {
			ctx.Release()
			return nil, nil, errors.New("requested reader unavailable")
		}
	}

	var card *scard.Card
	err = runWithFailureCleanup(
		func() error {
			var connectErr error
			card, connectErr = ctx.Connect(
				readerName, scard.ShareShared, scard.ProtocolAny,
			)
			return connectErr
		},
		func() { ctx.Release() },
	)
	if err != nil {
		return nil, nil, errors.New("cannot connect to card")
	}

	cleanup := makeCardCleanup(
		func() { card.Disconnect(scard.ResetCard) },
		func() { ctx.Release() },
	)

	kc := keycard.NewCommandSet(
		keycardio.NewNormalChannel(card),
	)

	if err := runWithFailureCleanup(kc.Select, cleanup); err != nil {
		return nil, nil, err
	}

	return kc, cleanup, nil
}

func execute(opts options) error {
	kc, cleanup, err := connectCard(opts.reader)
	if err != nil {
		return err
	}
	defer cleanup()

	if opts.action == "card-info" {
		if kc.ApplicationInfo == nil {
			return errors.New("card application info unavailable")
		}
		info := kc.ApplicationInfo
		return json.NewEncoder(os.Stdout).Encode(
			cardInfoResult(info.AppVersion(), info.AvailableSlots),
		)
	}

	version, known := kc.SecureChannelVersion()
	legacy := !known || version != keycard.VersionV2

	if legacy {
		secret := keycard.PairingPasswordToSecret(defaultPairing)

		if err := kc.AutoPairWithSecret(secret); err != nil {
			return err
		}

		defer func() {
			if pairing := kc.Pairing(); pairing != nil {
				if err := kc.Unpair(pairing.Index()); err != nil {
					fmt.Fprintln(os.Stderr,
						"warning: card pairing cleanup failed")
				}
			}
		}()
	}

	if err := kc.AutoOpenSecureChannel(); err != nil {
		return err
	}

	pin, err := readPIN()
	if err != nil {
		return err
	}

	err = kc.VerifyPIN(pin)
	pin = ""

	if err != nil {
		return err
	}

	// Always export public-only key material.
	exported, err := kc.ExportKeyWithP2(
		true,
		false,
		keycard.P2ExportKeyPublicOnly,
		opts.path,
	)
	if err != nil {
		return err
	}

	if len(exported.PrivKey()) != 0 {
		return errors.New("unexpected private key in response")
	}

	publicKey := exported.PubKey()
	address, err := publicAddress(publicKey)
	if err != nil {
		return err
	}

	var result any

	switch opts.action {
	case "get-address":
		result = map[string]any{
			"address":    address.Hex(),
			"public_key": "0x" + hex.EncodeToString(publicKey),
		}

	case "sign-digest":
		expected := common.HexToAddress(opts.expected)
		if address != expected {
			return errors.New("connected card address mismatch")
		}

		digest, _ := decodeDigest(opts.digest)

		sig, err := kc.SignWithPath(digest, opts.path)
		if err != nil {
			return err
		}

		result, err = recoverSignature(
			digest, sig.R(), sig.S(), sig.V(), expected,
		)
		if err != nil {
			return err
		}

	default:
		return errors.New("unsupported operation")
	}

	return json.NewEncoder(os.Stdout).Encode(result)
}

func run(args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}

	if err := rejectLegacySecrets(); err != nil {
		return err
	}

	return execute(opts)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keycard-bridge:", err)
		os.Exit(1)
	}
}
