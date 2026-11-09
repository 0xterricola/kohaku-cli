# Kohaku Key V4 — Physical Hardware Local EVM Evidence

Date: November 8, 2026
Repository: 0xterricola/kohaku-cli
Branch: research/v4-shell-qr-bridge

## Scope

Physical Keycard Shell integration with the official 0xbow
Privacy Pools V1 contracts on an isolated, nonforking Anvil
blockchain (chain ID 31337).

The CLI orchestrated all blockchain operations.

## Verified execution

- Deployed PoseidonT3, PoseidonT4, WithdrawalVerifier,
  CommitmentVerifier, Entrypoint, ERC1967Proxy and PrivacyPoolSimple
- Registered the native ETH pool
- Authenticated two encrypted Shell QR credential exchanges
- Derived deposit and change credentials using the physical Shell
- Submitted a 0.002 ETH local deposit
- Verified the 0.00198 ETH net commitment and deposit label
- Reconstructed the on-chain Merkle root using SDK witnesses
- Registered a local ASP fixture root through the authorized postman
- Verified both state and ASP membership witnesses
- Generated a Groth16 withdrawal proof using pinned artifacts
- Independently verified the proof
- Obtained acceptance from the deployed Solidity verifier
- Executed a 0.00099 ETH local withdrawal
- Verified recipient balance adjustment for gas
- Verified the remaining 0.00099 ETH pool balance
- Verified change commitment insertion and spent nullifier
- Confirmed replay rejection: NullifierAlreadySpent
- Confirmed exactly 11 local transaction blocks

## Reproduction

From kohaku-cli, with the sibling privacy-pools-core
contract artifacts already built, start a fresh Anvil chain:

    anvil --host 127.0.0.1 --port 18545 --chain-id 31337

Run the interactive hardware demonstration:

    npm run demo:shell -- --local-evm --hardware

Two physical Keycard Shell QR approvals are required.

## Regression validation

- TypeScript: passed
- Tests: 806 passed, 0 failed, 1 skipped
- Git diff integrity: passed

## Security boundaries and limitations

- All blockchain transactions used disposable local Anvil accounts
  and test ETH, not the user's external wallet
- Hardware-derived privacy credentials crossed an authenticated,
  encrypted QR exchange
- Private Groth16 witness construction and proving occurred on
  the Mac, not inside the Keycard Shell
- The local ASP was a test fixture, not independent ASP vetting
- The upstream contract clone has local build/import workarounds;
  bytecode equivalence with public Sepolia deployments is unverified
- No public Sepolia transactions were submitted
- This demonstrates a local proof of concept, not public-network
  deployment readiness
- No private roots, nullifiers, salts, PINs or witness data are
  included in this report
