# Keycard-Backed Privacy Pools V1
## Hardware Credential Recovery and Withdrawal Research

**Status:** Verified Sepolia research proof of concept
**Date:** November 2026
**Scope:** Privacy Pools V1 / Kohaku CLI / Keycard applet 4.0

### Summary

This research demonstrates a hardware-backed credential and
transaction-signing workflow integrated with Privacy Pools V1.

Using a physical Keycard, the experiment completed an on-chain
deposit and partial withdrawal, verified the resulting change
commitment, independently recovered the change-note credentials
in fresh authenticated hardware sessions, and generated a second
valid withdrawal proof.

The second withdrawal was accepted in EVM simulation by two
independent Sepolia RPC providers. It was not broadcast.

### Architecture

The workflow combines two hardware capabilities:

1. BIP-85 entropy derivation for reproducible privacy credentials.
2. Hardware ECDSA signing for Ethereum transactions.

The Keycard exports BIP-85-derived root material into a volatile
host process through an anonymous pipe. A versioned,
domain-separated credential adapter derives Privacy Pools
credentials from that material.

Credential separation includes chain, entrypoint, account,
deposit index, and withdrawal index.

This is a research-specific derivation contract, not a claim of
standard BIP-32 wallet compatibility.

The host performs credential reconstruction, Merkle witness
preparation, Groth16 witness generation, and proof generation.

Withdrawal artifacts are loaded from locally pinned circuit
files. Groth16 proofs are independently checked using a
single-thread BN128 pairing verification implementation.

For real execution, an EIP-1559 transaction digest is signed by
the physical Keycard after explicit interactive approval.

Transaction broadcasting requires a separate approval.

### Verified results

**On-chain deposit**

A real Sepolia deposit was completed using credentials
reproducible from the physical Keycard.

**Withdrawal proof**

The recovered note was used to construct a Groth16 withdrawal
proof. Independent verification passed, and the Sepolia pool
accepted the calldata in EVM simulation.

**On-chain withdrawal**

A physical Keycard signed the transaction after explicit
approval. The withdrawal was broadcast following a separate
confirmation and mined successfully.

The transaction receipt's spent nullifier and new commitment
matched the Groth16 public signals.

**Change-note recovery**

Fresh authenticated Keycard sessions reproduced the change-note
credentials. The recovered commitment matched the commitment
emitted by the mined withdrawal.

**Updated Merkle inclusion**

The change note was located in the updated pool LeanIMT.
A new inclusion proof reproduced the current on-chain state
root using the circuit-compatible compressed path index.

**Second withdrawal simulation**

The recovered change note generated a second valid Groth16
withdrawal proof. Two Sepolia RPC providers accepted the
simulated withdrawal.

No second withdrawal transaction was signed or broadcast.

### Security boundaries

The Keycard anchors reproducible credential material and
provides physical transaction signing.

**It does not currently contain the entire privacy workflow.**

BIP-85-derived root material crosses into host memory.
Privacy credential operations, ZK witness construction, and
Groth16 proving occur on the host.

The experiments avoided persisting private witnesses or
hardware-derived credentials to local evidence files.

Groth16 proofs submitted with real Ethereum transactions are
necessarily visible in public transaction calldata.

This is not a demonstration of security against a compromised
host or a complete side-channel security evaluation.

### Privacy limitations

The demonstrated direct-withdrawal flow uses the original
depositor account as the transaction sender and withdrawal
processor.

This creates observable account linkage.

The experiment establishes contract interoperability,
cryptographic correctness, and hardware recoverability.
It does not establish transaction unlinkability.

### Compatibility limitations

The verified integration targets Privacy Pools V1.

Privacy Pools V2 compatibility remains unverified.

The experimental Keycard environment and custom versioned
derivation adapter require separate security, compatibility,
and recovery reviews before broader deployment.

The implementation has not undergone an independent
security audit.

### Follow-up research

The next areas are stable credential-identifier mapping,
versioned hardware recovery, Privacy Pools V2 integration,
and reducing the amount of secret material exposed to the host.

Another major research question is whether Keycard Shell or
a dedicated coprocessor can support additional private
credential operations or proof-generation workloads within a
stronger trusted boundary.

### Conclusion

The research establishes a reproducible Privacy Pools V1
lifecycle across actual Ethereum testnet transactions,
hardware-backed signing, recovery of an on-chain change note,
and a subsequent verified withdrawal simulation.

The main remaining questions concern host trust, privacy
unlinkability, versioned recovery interoperability, and
Privacy Pools V2 integration.
