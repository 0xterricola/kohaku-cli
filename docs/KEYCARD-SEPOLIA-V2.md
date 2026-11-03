# Kohaku Key V2 — Sepolia proof of concept

## Result

A physical Keycard authorized an EIP-7702 account delegation
and signed an ERC-4337 UserOperation containing two calls.

The UserOperation was submitted through Kohaku CLI and confirmed
on Ethereum Sepolia. The EntryPoint event independently verified
successful execution.

## Verified on-chain evidence

- Network: Ethereum Sepolia (11155111)
- Owner: `0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa`
- Implementation: `0xe6Cae83BdE06E4c305530e199D7217f42808555B`
- EntryPoint v0.8: `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`
- Two calls: zero-value calls to `0x...dEaD` and `0x...bEEF`
- UserOperation hash: `0xea69d1531960e45aaf74709ee329a88545c6bb0f55abac820d150d3283f7e944`
- Transaction hash: `0xf243d837e507b6b1365b3f99424d40a7e8146648cf440cac1b3f65b7aeed3282`
- Block: `12052649`
- Actual UserOperation gas cost: `418717528912422` wei
- EIP-7702 delegation: verified on-chain
- ERC-4337 UserOperationEvent: `success = true`

Explorer:
https://sepolia.etherscan.io/tx/0xf243d837e507b6b1365b3f99424d40a7e8146648cf440cac1b3f65b7aeed3282

## Security boundaries demonstrated

- Physical Keycard address verification
- Separate explicit approvals for EIP-7702 and ERC-4337 signatures
- Fresh chain-state and nonce checks
- Signing digest and reviewed batch calldata validation
- Explicit approval before bundler submission
- Journal persisted before submission
- No automatic resubmission after uncertain outcomes
- Receipt-based reconciliation of confirmed execution
- Private journal directory and file permissions

## Recovery behavior

A recorded attempt begins in `outcome-unknown`.

If execution is confirmed, reconciliation checks the Sepolia
transaction receipt and matching successful EntryPoint event
before marking the journal `confirmed`.

If execution is interrupted or reconciliation fails, the record
remains `outcome-unknown`. The same UserOperation hash cannot
be submitted again through the existing journal path.

The CLI does not automatically retry uncertain submissions.
A fresh transaction with a different nonce is a distinct
operation and requires its own deliberate review and approval.

## Scope

This is a Sepolia hardware-execution proof of concept, not a
production security audit or a mainnet deployment.

Privacy Pools, RAILGUN, and air-gapped Keycard Shell integrations
are future research and development milestones.
