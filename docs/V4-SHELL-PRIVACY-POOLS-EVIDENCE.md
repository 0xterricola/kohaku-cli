# Kohaku Key V4 — Keycard Shell Privacy Pools V1 Evidence

**Date:** November 8, 2026
**Result:** PASS — 7/7 guided offline checkpoints
**Network context:** Sepolia, chain ID 11155111
**Execution:** Offline demonstration; no transactions submitted

## Summary

A physical Keycard Shell supplied Privacy Pools V1 credentials
through two authenticated encrypted-QR exchanges.

The Mac used hardware-derived credentials to construct deposit
calldata, create synthetic deposit and withdrawal membership
state, generate a genuine Groth16 withdrawal proof, independently
verify the proof, and validate encoded withdrawal calldata.

No real deposits or withdrawals occurred.

## Verified checkpoints

| Checkpoint | Result |
|---|---|
| 1. Physical Shell credential exchange | PASS |
| 2. SDK deposit calldata construction | PASS |
| 3. Synthetic deposit and Merkle state | PASS |
| 4. State and ASP membership witnesses | PASS |
| 5. Groth16 generation and independent verification | PASS |
| 6. Offline withdrawal calldata validation | PASS |
| 7. Evidence and security-boundary review | PASS |

## Hardware evidence

Two physical Shell response QRs were captured and authenticated.

- Account index: 0
- Deposit index: 15
- Withdrawal/change index: 1
- Deposit credentials: SDK-derived successfully
- Withdrawal/change credentials: SDK-derived successfully

Private credential values were not printed in the evidence.

## Cryptographic evidence

- Pinned withdrawal circuit artifacts passed SHA-256 checks.
- Private circuit witness calculated in host memory.
- Genuine Groth16 withdrawal proof generated.
- Independent Groth16 verification passed.
- All eight public signals validated.
- SDK withdrawal calldata ABI round-trip passed.
- Encoded withdrawal calldata: 644 bytes.

## Illustrative amounts

| Operation | Amount |
|---|---:|
| Unsigned deposit calldata | 0.002 ETH |
| Synthetic net deposit balance | 0.00198 ETH |
| Simulated withdrawal amount | 0.00099 ETH |
| Simulated remaining note | 0.00099 ETH |

These values do not establish blockchain activity.

## Security boundaries

Credential derivation and QR response authentication were
performed using physical Keycard Shell hardware.

The Mac received derived private inputs and calculated the
circuit witness and Groth16 proof.

Private proving inputs therefore crossed the hardware boundary.
JavaScript BigInt memory cannot be reliably zeroized.

The demonstration does not establish Shell-contained proving.

## Explicit limitations

- Synthetic pool state, not live Sepolia state.
- No real deposit or withdrawal.
- No RPC calls during the guided demo.
- No transaction signing or broadcasting.
- No local EVM contract execution.
- No demonstrated live contract acceptance.
- No private credential or witness values included in this report.

## Reproduction

Repository: kohaku-cli

CLI command: npm run demo:shell
Plan command: npm run demo:shell -- --plan
Typecheck command: npm run typecheck

The interactive demonstration requires the physical Shell,
compatible firmware and applet, and a camera.

Implementation:
- src/commands/keycard-shell-demo.ts
- src/utils/keycard-shell-demo-prover.mjs
- src/utils/keycard-shell-demo-withdrawal.ts
- src/utils/keycard-shell-demo-synthetic.ts
- src/utils/keycard-shell-qr-exchange.ts
- docs/V4-SHELL-PRIVACY-POOLS-DEMO.md

Source implementation commit: 2fbae75 — feat: add Keycard Shell Privacy Pools V1 offline demo.

## Remaining milestone

Execute and validate the withdrawal against an isolated local
EVM with appropriate Privacy Pools contract state.

The present result establishes an offline hardware-to-Groth16
demonstration, not on-chain withdrawal acceptance.
