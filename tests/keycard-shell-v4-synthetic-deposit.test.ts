import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createSyntheticDeposit,
  createSyntheticWithdrawalMembership,
} from "../src/utils/keycard-shell-demo-synthetic.js";

test("V4 synthetic deposit builds deterministic state", async () => {
  const first = await createSyntheticDeposit(123456789n);
  const second = await createSyntheticDeposit(123456789n);

  assert.equal(first.grossValue, 2_000_000_000_000_000n);
  assert.equal(first.netValue, 1_980_000_000_000_000n);
  assert.equal(first.noteCommitment, second.noteCommitment);
  assert.equal(first.stateProof.root, second.stateProof.root);
  assert.equal(first.stateProof.index, 1);
  assert.equal(first.stateProof.siblings.length, 32);
  assert.equal(first.event._commitment, first.noteCommitment);
});

test("V4 synthetic withdrawal membership witnesses", async () => {
  const deposit = await createSyntheticDeposit(123456789n);
  const membership = await createSyntheticWithdrawalMembership(deposit);
  const repeated = await createSyntheticWithdrawalMembership(deposit);

  assert.equal(membership.stateProof.root, deposit.stateProof.root);
  assert.equal(membership.stateProof.index, 1);
  assert.equal(membership.stateProof.siblings.length, 32);
  assert.equal(membership.aspProof.index, 1);
  assert.equal(membership.aspProof.siblings.length, 32);
  assert.deepEqual(membership.aspProof, repeated.aspProof);
});
