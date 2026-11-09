# Kohaku Key V4 — Privacy Pools V1 Demo

## Live Sepolia — guided eight-checkpoint demo

A single interactive command now sequences the already-proven live Sepolia paths:
public preflight, encrypted Shell privacy credentials, deposit simulation,
ERC-4527 Shell signing and **explicit** deposit broadcast, genuine 0xBow ASP
membership, host-side Groth16 partial withdrawal, Shell-signed withdrawal,
and independent Shell change-note recovery.

The previously recorded deposit/withdrawal used index 15; it is **not** reused.
A fresh run requires operator confirmation of a *reviewed unused index range*.
The first execution creates one canonical public-only journal; subsequently
choose **n** for a fresh run, or paste a printed run UUID to resume. Every
transaction additionally requires the operator to type `BROADCAST <hash-prefix>`
for that exact signed transaction; pressing Enter alone never sends funds.

**Read-only preview (no RPC, QR, journal, signing, or broadcast):**

```sh
npm run demo:shell -- --sepolia-live --plan
```

**Actual interactive public Sepolia run (Shell fingerprint is public):**

```sh
npm run demo:shell -- --sepolia-live --hardware
```

The command prompts for the public eight-character Shell fingerprint (or pass
`--fingerprint 2550f83e` if using this same card). It then narrates all eight
checkpoints and lets you select a new run or resume an existing run.

Keep the Keycard inside the Shell. There is no OMNIKEY, Anvil, synthetic ASP
approval, or native signing bridge in this mode. The same command resumes the
same run after ASP approval; enter its UUID at the run-selection prompt.

**Status:** implementation packaged for local testing. The original standalone
scripts were exercised with physical Shell and real Sepolia; **this new unified
command has not itself been physically rehearsed**. Before a recording or live
send, run `npm run typecheck`, focused tests, preview, and a supervised first
full pass. Its first-run unused-index declaration requires your actual review.

The default seven-checkpoint offline demonstration remains available without
`--sepolia-live`; the old `--local-evm` and `--sepolia-fork` paths remain separate.

## Previously proven live evidence

These are the recorded results supplied for this work, supported by the existing
one-off scripts. They were not freshly queried or reproduced by the plan update.

| Operation | Recorded result |
| --- | --- |
| Shell QR-signed deposit | 0.002 ETH, block 12099272, [Sepolia receipt](https://sepolia.etherscan.io/tx/0x8ebe5b4a9fa5ae098516673a6eee7663c7d07966827b933683c7be69e351b9e5) |
| Real 0xBow ASP inclusion | Published tree reconstructed and checked against Sepolia; deposit label included |
| Shell QR-signed partial withdrawal | 0.00099 ETH, block 12099665, [Sepolia receipt](https://sepolia.etherscan.io/tx/0x7c7428ca3067ba4080b563ee007303fc4c577274917cf0da7801bf429f6716c3) |
| Independent Shell recovery | 0.00099 ETH change, commitment below |

```text
19918947501690874005633747296991198167662124583305934861285704698798944284450
```

That run used account 0, deposit index 15, and change/withdrawal index 1. The
original deposit note has been spent by the partial withdrawal. Its change is a
separate note. These coordinates and historical hashes are evidence, not defaults
for a fresh rehearsal. Do not rerun the hardcoded scripts as a new live demo.

## Live safety and narration contract

- Shell QR only: no Anvil, OMNIKEY, alternate signer, or synthetic ASP substitution
  in the live path. The existing offline/fork tools are not live fallbacks.
- Default to no broadcast. The live executor requires typing
  `BROADCAST <hash-prefix>` after showing the exact signed transaction; it
  durably commits `send-started` before calling the existing sender. Merely
  pressing Enter to advance narration never authorizes a transaction.
- Explain what will happen before each checkpoint, then report only observed
  results as `PASS`, `PENDING`, `UNVERIFIED`, `FAIL`, or `NOT RUN`.
- Keep the target amounts at 0.002 ETH deposited, 0.00099 ETH withdrawn, and
  0.00099 ETH change. The proven net note was 0.00198 ETH. Check fees, simulation,
  and actual receipt values each time; stop if those amounts no longer reconcile.
  Transaction gas is additional and paid separately.
- Persist public run metadata only. Never log or persist PIN, seed, BIP-85 private
  entropy, privacy credentials, private nullifier/salt, or witness material.
  Public metadata still links this demonstration's activity and needs care.
- A one-command flow may span multiple sessions. Real 0xBow approval is external
  and may take time; do not promise an uninterrupted one-take completion.

## Checkpoint 1 / 8 — Preflight and reserve a fresh run

**Say:** “We are preparing a real Sepolia demonstration. Before asking the card
for anything, we check the network, the amount, the expected costs, and which
recovery coordinates belong to this run.”

**What happens:** Validate chain 11155111, the configured entrypoint and pool,
public sender and signing path, current/pending nonce, balance including gas,
and pinned local proving artifacts. Reserve a unique deposit index exclusively
in a public run registry before the first credential request. Display the run ID,
public derivation coordinates, and intended amounts. Never blindly default to
index 15 or assume the next integer is unused.

**What this proves:** The run targets the intended network and contracts, has
its own recovery coordinates, and can afford the proposed operation. It does
not establish that any deposit has happened.

**Pause/resume:** Loading an existing run must retain its index. Reconcile any
recorded transaction with receipts and pending nonce before choosing the next
checkpoint. Missing, corrupt, or conflicting registry data must stop execution.

## Checkpoint 2 / 8 — Shell credentials, BIP-85, and encrypted QR

**Say:** “BIP-85 gives us reproducible derived entropy. It is not the encryption
protocol. The card supplies derived entropy to Shell, and Shell derives the
specific privacy credentials we requested. The QR response protects those
credentials in transit, but the Mac decrypts them to prepare the proof.”

**What happens:** The card's master seed and Ethereum signing key stay on the
card. In the inspected firmware, BIP-85 root material passes over the card's
secure channel into Shell memory. Shell uses the versioned HMAC derivation
contract to produce per-path credentials. The current privacy QR response carries
those credentials, not the BIP-85 root itself.

The Mac creates a fresh session. Review its fingerprint and requested paths on
Shell before approving. The QR protocol uses secp256k1 ECDH, HKDF-SHA256, and
AES-128-CCM with request/challenge binding. This authenticates the session
response; it is not independent hardware attestation. Camera scanning reports
progress automatically, with a 120-second timeout and no Enter key required.

For account 0, the existing privacy path contract is
`m/28784'/1'/0'/1'/<depositIndex>'/<withdrawIndex>'` and
`m/28784'/1'/0'/0'/<depositIndex>'/<withdrawIndex>'`.
The deposit uses withdrawal index 0; its first change uses index 1.

**What this proves:** The matching session delivered the requested credentials.
The Mac decrypts them into volatile memory and derives SDK secrets. Mutable
buffers are cleared when possible, but JavaScript strings/BigInts cannot be
reliably zeroized. Never say “the host has zero secrets,” “all keys never leave,”
or that witness calculation happens inside Shell.

**Pause/resume:** Request the same coordinates again in a fresh approved session.
Save the public coordinates, never the credential response or decrypted secrets.

## Checkpoint 3 / 8 — Prepare the 0.002 ETH deposit

**Say:** “We are turning the private credential into a public deposit commitment.
This transaction draft moves nothing yet. We check exactly what the contract
will receive and what the transaction could cost.”

**What happens:** Reuse the live deposit preparation checks to derive the
precommitment, construct calldata, decode it independently, and verify the
entrypoint and 0.002 ETH value. Simulate on real Sepolia, estimate gas, and check
fees, pending nonce, and the sender's balance. Show the public transaction intent
and maximum cost without printing privacy credentials.

**What this proves:** The unsigned intent is internally consistent and passes
simulation at the checked state. It is neither a signature nor a mined deposit.

**Pause/resume:** Retain the deposit index and public intent. Before refreshing
nonce or fees, reconcile any existing signed/submitted transaction. A refreshed
intent requires another explicit review and matching signature.

## Checkpoint 4 / 8 — Ethereum QR signing and live deposit

**Say:** “This is a different QR exchange: an Ethereum transaction signing
request. We review the transaction on Shell. A signature authorizes that exact
transaction; broadcasting it is a separate decision.”

**What happens:** Reuse ERC-4527 `eth-sign-request` / `eth-signature`, including
animated UR fragments when needed. Round-trip the encoded request. Check the
response request ID, recovered sender, chain, destination, value, calldata,
nonce, and fee fields against the reviewed intent. The current deposit helpers
use a single frame; the withdrawal helper contains the proven animated renderer
to generalize. Ethereum transaction QR is not the encrypted privacy transport.

Require broadcast opt-in and explicit confirmation of the exact signed deposit.
Persist its public transaction hash before sending. Verify receipt success and
this transaction's deposit event, including actual net balance, label, commitment,
and leaf index. Show the public explorer link.

**What this proves:** Only the verified receipt/event establishes a live deposit.
A prepared QR, captured signature, or send response alone is insufficient.

**Pause/resume:** If sending times out, reconcile by recorded hash and nonce.
Do not automatically sign a replacement or submit another deposit. Pending or
ambiguous outcomes pause the same run.

## Checkpoint 5 / 8 — Real 0xBow ASP inclusion, with wait/resume

**Say:** “The deposit is on-chain. Now we check whether its label belongs to the
association set published by 0xBow. The later proof shows membership in that
set without revealing the private note credentials.”

**What happens:** Fetch the published ASP leaves, reconstruct their Merkle root,
compare it with the relevant Sepolia root, and check the run's deposit label.
Build and verify the membership proof in memory using the existing SDK helper.
ASP membership is a statement about this association set, not a blanket guarantee
of privacy, origin, or immediate acceptance.

**What this proves:** `INCLUDED` requires both matching roots and label membership.
A missing label is `PENDING`. A mismatched root is `UNVERIFIED`. Neither may be
reported as passing. The existing one-off helper returns exit code 0 for pending
and unverified outcomes, so a future wrapper must use structured results.

**Pause/resume:** Persist public status and the same run ID, then stop cleanly.
On resume refresh roots and inclusion. Never make a second deposit because this
one is waiting. Approval may outlast a recording session.

## Checkpoint 6 / 8 — Groth16 partial withdrawal and change

**Say:** “The Mac now proves that we can spend this note and that it belongs to
the verified pool and association set. We withdraw 0.00099 ETH and preserve
0.00099 ETH as a new private change note.”

**What happens:** Re-derive original and change credentials through Shell. Match
the original precommitment to the mined deposit and check that the note remains
unspent. Refresh genuine pool and ASP membership. Reuse
`proveShellDemoWithdrawal` and its pinned circuit hashes. Calculate the private
witness in memory, generate the Groth16 proof, independently verify it, and check
all public signals, withdrawal context, withdrawal amount, and change amount.
Simulate the real withdrawal and recheck roots before signing.

**What this proves:** Cryptographic verification and live simulation are separate
checks. The Mac holds the private inputs and performs proving; the on-chain
verifier can check the resulting proof without receiving those note secrets.
No withdrawal transaction has been signed or broadcast at this checkpoint.

**Pause/resume:** Rebuild private material from hardware, never from a saved
witness. Changed roots require fresh checks/proving. Stop on spent-note status,
amount mismatch, or unverifiable state.

## Checkpoint 7 / 8 — Ethereum QR signing and live withdrawal

**Say:** “We review and sign the withdrawal transaction on Shell. The transaction
itself sends zero ETH to the pool; the validated call instructs the pool to
release the withdrawal amount and insert the change commitment.”

**What happens:** Review recipient/processor, pool, calldata, chain, nonce, gas,
and fees. Validate the matching ERC-4527 signature and require a separate
exact-transaction broadcast confirmation. Record the signed hash before sending.
Validate the mined transaction's `Withdrawn` and change `LeafInserted` events.
Do not infer this transaction's effects solely from aggregate block balance or
tree-size deltas, which may include other users' activity.

**What this proves:** The old note was consumed and the expected change commitment
was inserted. Display the receipt and public change commitment. Returning funds
to the original public wallet, as in the recorded demo, limits recipient
unlinkability; a proof does not hide that public address reuse.

**Pause/resume:** Reconcile transaction status and spent status before retrying.
A completed withdrawal must never attempt to spend the original note again.

## Checkpoint 8 / 8 — Independent Shell recovery

**Say:** “We start a fresh credential session and recover the remaining note from
its deterministic coordinates. We compare it with the change actually mined by
this run, without making another transaction.”

**What happens:** Use a fresh Shell provider, the run's deposit index and change
index, the original public label, and the verified change balance. Recompute the
commitment and compare it with this run's withdrawal event. Do not compare with
a hardcoded historical commitment or retain the previous proving session's
credentials as the recovery source.

**What this proves:** Independently re-derived hardware credentials reconstruct
the expected 0.00099 ETH change note. Recovery signs and broadcasts nothing.
It leaves the change note unspent.

**Pause/resume:** A final evidence review distinguishes hardware exchange,
cryptographic verification, simulation, mined receipts, and recovery. Report
unexecuted checkpoints as `NOT RUN`; keep only the public run journal.

## Integrated live implementation and interruption handling

The guided CLI is implemented in
`src/utils/keycard-shell-sepolia-live-run.mjs`. It invokes existing proven
credential, prover, and submission helpers without importing the historical
one-off scripts that hardcode index 15, hashes, or shared filenames.

| Purpose | Code reused / generalized |
| --- | --- |
| Encrypted PPv1 QR | `keycard-shell-qr-r3-provider.ts` and `keycard-shell-qr-exchange.ts` |
| ERC-4527 animated signing | `keycard-shell-sepolia-live-eth-qr.mjs` (per-run QR, signature request ID, keypair validation) |
| Real events, 0xBow ASP, current state | `keycard-shell-sepolia-live-evidence.mjs` and sibling Privacy Pools SDK |
| Pinned proof and withdrawal calldata | `keycard-shell-demo-prover.mjs`, SDK proof encoder |
| Explicit send | `keycard-sepolia-submit.ts`, after durable journal claim |
| Public-only run history | `keycard-shell-live-journal-state.ts`, `keycard-shell-live-journal.ts`, `keycard-shell-live-reconcile.ts` |

The canonical registry is at
`~/Library/Application Support/kohaku-key/v4-live-demo-journal/`.
Its snapshot stores only validated public metadata and never raw proof/witness
material. Per-run **public Ethereum artifacts**, including signed transactions
and proof calldata destined for the blockchain, reside separately under
`~/Library/Application Support/kohaku-key/v4-live-demo-runs/<run-uuid>/`
with restrictive permissions. These artifacts can reveal public transaction
linkages; keep them out of screenshots unless intended. Neither store contains
the PIN, seed, BIP-85 entropy, private root/nullifier/salt, or private witness.
Privacy material *is decrypted into Mac process memory* to generate Groth16;
JavaScript does not guarantee perfect memory erasure.

**If ASP is pending:** the script prints `PAUSE`, run UUID, and exits without a
withdrawal. Relaunch the same command, select that UUID, and it rechecks live
ASP membership without depositing again. An unchanged/incorrect ASP root does
not count as approval.

**If a send is pending/uncertain:** the journal refuses another send or
replacement. Relaunch to inspect the recorded transaction hash and canonical
chain receipt; if still unresolved, stop. Missing from a single RPC never
implies that rebroadcasting is safe. An interrupted write or stale journal lock
requires inspection; do not delete, reset, or recreate the registry to proceed.

**If state/ASP roots change after a withdrawal proof or signing:** the executor
stops instead of blindly replacing an immutable signed intent. The existing
unsigned proof may need to be refreshed under a separately reviewed recovery
procedure. This is intentionally conservative for the first live guided run.

**If another process or machine uses the same Keycard indices:** the local
journal cannot detect that. The operator must establish a genuinely unused
range before initializing, and must preserve the one canonical registry across
all rehearsals. A copied/rolled-back journal does not protect against reuse.

**What the camera should show:** Shell QR request and physical approval,
transaction review, Ethereum signature response, public Sepolia receipts,
0xBow membership, host-side proof verification, 0.00099 ETH change insertion,
and one independent recovery QR. Avoid filming the PIN, recovery phrase, QR
responses carrying secret credentials, or raw private witness outputs. The
Ethereum signature QR itself is public transaction-signature material.

## Existing seven-checkpoint offline walkthrough

The default interactive demo remains a useful separate check of host-side
construction. Press Enter to advance or `q` to stop. `--plan` skips all execution.

1. **Hardware credential exchange:** the encrypted Shell response is authenticated
   and decrypted by the Mac; private SDK values remain in memory.
2. **Deposit construction:** construct genuine 0.002 ETH Sepolia deposit calldata,
   decode the ABI, and verify destination/value/precommitment without RPC.
3. **Simulated deposit:** insert the hardware-derived commitment into a synthetic
   Merkle tree. The illustrative 0.00198 ETH balance is fixture accounting; no
   real event or live fee verification is claimed.
4. **Withdrawal membership:** build depth-32 synthetic state and ASP membership
   proofs. These are not real ASP approval or the complete private circuit witness.
5. **Groth16 proving:** request change credentials at index 1, check pinned
   artifacts, calculate the private witness in host memory, generate the proof,
   and independently verify public signals. Synthetic membership does not prove
   live withdrawal eligibility.
6. **Offline encoding:** encode/decode `pool.withdraw`, check all eight public
   signals, context, withdrawal and change values. This is an ABI round trip,
   not live EVM acceptance. Its encoding test uses non-cryptographic fixture
   coordinates; cryptographic verification belongs to checkpoint 5.
7. **Evidence review:** distinguish hardware authentication, synthetic state,
   proof verification, and calldata validation. This default flow makes no RPC
   calls, signs nothing, and broadcasts nothing. It does not reserve fresh live
   deposit indices or establish live recovery.

Existing offline tests include `tests/keycard-shell-v4-deposit.test.ts`,
`tests/keycard-shell-v4-synthetic-deposit.test.ts`, and
`tests/keycard-shell-v4-offline-withdrawal.test.mjs`. The live-plan routing and
closed execution gate are covered by `tests/keycard-shell-live-plan.test.ts`.
