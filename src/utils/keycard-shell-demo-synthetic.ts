import assert from "node:assert/strict";

import { commitment } from "../../../kohaku-sdk-research/packages/privacy-pools/src/utils";
import {
  buildMerkleTree,
  proofFromTree,
} from "../../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util";

export async function createSyntheticDeposit(precommitment: bigint) {
  const grossValue = 2_000_000_000_000_000n;
  const netValue = 1_980_000_000_000_000n;
  const label = 123456n;

  // The SDK implementation hashes only these three fields.
  // Its INote parameter type also requires unrelated note metadata.
  type CommitmentFields = Pick<
    Parameters<typeof commitment>[0],
    "balance" | "label" | "precommitment"
  >;

  const fields: CommitmentFields = {
    balance: netValue,
    label,
    precommitment,
  };

  const noteCommitment = commitment(
    fields as Parameters<typeof commitment>[0],
  );

  const event = {
    _value: netValue,
    _label: label,
    _precommitment: precommitment,
    _commitment: noteCommitment,
  };

  // Synthetic neighboring leaves, matching the existing V4 proof experiment.
  const tree = await buildMerkleTree([
    111n,
    noteCommitment,
    222n,
  ]);

  const stateProof = proofFromTree(tree, noteCommitment);

  assert.equal(stateProof.root, tree.root);
  assert.equal(stateProof.index, 1);
  assert.equal(stateProof.siblings.length, 32);
  assert.equal(event._commitment, noteCommitment);

  return {
    grossValue,
    netValue,
    label,
    noteCommitment,
    event,
    stateProof,
  };
}

export async function createSyntheticWithdrawalMembership(
  deposit: Awaited<ReturnType<typeof createSyntheticDeposit>>,
) {
  const aspTree = await buildMerkleTree([
    333n,
    deposit.label,
    444n,
  ]);

  const aspProof = proofFromTree(aspTree, deposit.label);

  assert.equal(deposit.stateProof.index, 1);
  assert.equal(deposit.stateProof.siblings.length, 32);
  assert.equal(aspProof.index, 1);
  assert.equal(aspProof.root, aspTree.root);
  assert.equal(aspProof.siblings.length, 32);

  return {
    stateProof: deposit.stateProof,
    aspProof,
  };
}
