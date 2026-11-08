# Kohaku Key V4 — Privacy Pools V1 Demo

## Purpose

Demonstrate the Privacy Pools deposit-to-withdrawal lifecycle
using Keycard Shell credentials and locally generated Groth16 proofs.

The CLI presents deliberate, documented checkpoints instead of
automatically advancing through the flow.

## Safety contract

- No transaction signing or broadcasting.
- No real deposits or withdrawals.
- No private credentials or witnesses in logs or persistent files.
- Use synthetic pool state for the initial withdrawal demonstration.
- Keep the real blockchain-state experiments separate.
- Distinguish physical hardware checks from simulated checks.
- Never report an unexecuted checkpoint as passing.

## Running the demo

Review the planned stages:

    npm run demo:shell -- --plan

Start the interactive walkthrough:

    npm run demo:shell

Press Enter to advance or q to stop.

Checkpoint 1 uses the QR-backed SDK SecretManager to request the
two deposit credential paths. The provider clears raw credential
buffers after deriving SDK secret values.

Derived SDK secret values remain in process memory during the demo.
JavaScript BigInt values cannot be reliably zeroized.

Checkpoint 2 constructs genuine Sepolia SDK deposit calldata
locally, using 0.002 ETH as the example amount. The destination,
value, decoded function and precommitment are checked.

No transaction is signed or broadcast. No RPC call is required.
Checkpoint 6B local EVM execution remains unimplemented.

The --plan option never activates the camera or hardware.

## Checkpoint 1 — Hardware credential exchange

Camera capture scans automatically at approximately four frames per second with a 120-second timeout. Progress reports elapsed time, processed frames, detected QR frames, and Shell-format QR frames. No QR payloads or credentials are logged.

The Shell approves the requested derivation paths and returns
an encrypted QR response.

The Mac authenticates and decrypts the response.

Security boundary: decrypted credentials exist on the host.
This does not establish Shell-contained proving.

Existing implementation:
`src/commands/keycard-shell-qr.ts`

## Checkpoint 2 — Deposit construction

Use the derived credential to construct a Privacy Pools
deposit commitment and SDK calldata.

Do not sign or broadcast.

Existing test:
`tests/keycard-shell-v4-deposit.test.ts`

## Checkpoint 3 — Simulated deposit

The CLI builds a synthetic deposit event using the
hardware-derived precommitment.

The illustrative gross amount is 0.002 ETH, with an assumed net note
balance of 0.00198 ETH. This is a test fixture, not verified fee
accounting.

The SDK commitment is inserted into a synthetic Merkle tree alongside
two fixture leaves. The state membership proof has depth 32.

No actual contract event exists. No RPC, signing, or broadcasting occurs.

Create a synthetic deposit event and corresponding state tree.

No actual pool deposit occurs.

## Checkpoint 4 — Withdrawal witness

The CLI constructs the synthetic state membership proof and
ASP membership proof using the same Merkle utilities as the existing
V4 Groth16 experiment.

The state proof uses the synthetic deposit commitment. The ASP proof
uses the synthetic label. Both contain 32 sibling entries.

These are membership witnesses, not the complete private withdrawal
circuit witness. That requires additional withdrawal credentials and
private inputs during the proving checkpoint.

No real ASP approval or on-chain state is claimed.

Construct the note, state membership, and ASP membership
witnesses from synthetic state.

Keep private witness values in process memory.

## Checkpoint 5 — Groth16 proving and verification

A second approved Shell QR exchange obtains withdrawal/change
credentials at withdrawal index 1.

The CLI combines these hardware-derived values with the synthetic
deposit and membership witnesses prepared in earlier checkpoints.

Pinned local withdrawal circuit artifacts are checked using SHA-256.
The private circuit witness is calculated in process memory.

A genuine Groth16 withdrawal proof is generated, its public signals
are validated, and verification runs independently.

The simulated withdrawal amount is 0.00099 ETH.

The host receives derived private inputs. JavaScript BigInt values
cannot be reliably zeroized. This demonstration does not claim
Shell-contained witness calculation or proving.

The synthetic state does not establish on-chain withdrawal validity.

Use the pinned withdrawal circuit artifacts.

Calculate the witness, generate a real Groth16 proof, and verify
the proof against its public signals and verification key.

Existing experiment:
`experiments/v4-shell-qr-withdraw-proof.mjs`

A valid proof against synthetic state does not establish that
an actual on-chain withdrawal is possible.

## Checkpoint 6 — Offline withdrawal encoding

The SDK encodes a direct pool.withdraw call from the verified
Groth16 proof and public signals.

The CLI decodes the calldata independently, checks all eight
public signals, checks the synthetic withdrawal context, and
verifies withdrawal and change balances.

This is an ABI round-trip check, not simulated EVM execution.
The matching test uses deliberately non-cryptographic fixture
coordinates. Cryptographic validity was established separately
by Checkpoint 5.

Local EVM execution remains pending. No RPC calls are made.

Construct the withdrawal calldata and validate the intended
effect in a simulated EVM or equivalent offline test.

No transaction is signed or submitted.

## Checkpoint 7 — Evidence review

The final checkpoint verifies that the earlier hardware-derived
deposit, synthetic witnesses, verified Groth16 proof, and offline
withdrawal calldata are available.

Evidence is classified as physical hardware authentication,
cryptographic verification, SDK calldata validation, or synthetic
simulation. No private credential, nullifier, salt, witness, or
private key is printed or included in the evidence summary.

The Groth16 witness and proof generation run on the Mac, not inside
the Keycard Shell. Host memory contains derived private inputs;
JavaScript BigInt zeroization cannot be guaranteed.

The demonstration does not execute a withdrawal in an EVM or
establish acceptance against live Privacy Pools state. It makes
no RPC calls and performs no signing or broadcasting.

Local EVM execution remains a separate, uncompleted milestone.


Report each checkpoint as PASS, FAIL, or NOT RUN, with evidence.

Document hardware verification, synthetic inputs, proving,
verification, and host-side credential exposure separately.

## Completion gate

Real Sepolia transactions remain out of scope until the complete
simulated demonstration and its documentation have been reviewed
and explicitly approved for a separate execution phase.
