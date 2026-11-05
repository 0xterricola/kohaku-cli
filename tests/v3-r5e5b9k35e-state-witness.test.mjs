import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertContiguousEvents,
  assertTargetLeaf,
  auditedScanStartBlock,
  leafPositionFromEventIndex,
  recomputeLeanProofRoot,
  verifyDepositAccounting,
} from "../experiments/v3-r5e5b9k35e-state-witness.mjs";

const valid = [
  { index: "1", leaf: "11" },
  { index: "2", leaf: "22" },
  { index: "3", leaf: "33" },
];

test("contiguous state history accepted", () => {
  assert.equal(assertContiguousEvents(valid), true);
});

test("missing leaf index rejected", () => {
  assert.throws(
    () => assertContiguousEvents([
      valid[0], valid[2],
    ])
  );
});

test("duplicate leaf index rejected", () => {
  assert.throws(
    () => assertContiguousEvents([
      valid[0], valid[1], valid[1],
    ])
  );
});

test("correct deposited leaf accepted", () => {
  assert.equal(
    assertTargetLeaf(valid, 2n, 22n),
    true
  );
});

test("wrong deposited leaf rejected", () => {
  assert.throws(
    () => assertTargetLeaf(valid, 2n, 99n)
  );
});

test("missing deposited leaf rejected", () => {
  assert.throws(
    () => assertTargetLeaf(valid, 4n, 55n)
  );
});

test("mined K32 net deposit accounts for vetting fee", () => {
  const result = verifyDepositAccounting(
    2000000000000000n,
    1980000000000000n
  );

  assert.equal(result.vettingFeeBps, 100);
  assert.equal(result.vettingFeeWei, "20000000000000");
});

test("gross amount cannot replace net note value", () => {
  assert.throws(() => verifyDepositAccounting(
    2000000000000000n,
    2000000000000000n
  ));
});

test("unexpected fee calculation rejected", () => {
  assert.throws(() => verifyDepositAccounting(
    2000000000000000n,
    1970000000000000n
  ));
});

test("K22 audited scan starts before K32 deposit", () => {
  assert.equal(
    auditedScanStartBlock(
      "0x644d5A2554d36e27509254F32ccfeBe8cd58861f",
      12072150n
    ),
    8461453n
  );
});

test("different pool cannot reuse audited boundary", () => {
  assert.throws(() =>
    auditedScanStartBlock(
      "0x0000000000000000000000000000000000000001",
      12072150n
    )
  );
});

test("snapshot before audit boundary rejected", () => {
  assert.throws(() =>
    auditedScanStartBlock(
      "0x644d5A2554d36e27509254F32ccfeBe8cd58861f",
      8461452n
    )
  );
});

test("on-chain index 1480 means Merkle position 1479", () => {
  assert.equal(
    leafPositionFromEventIndex(1480n),
    1479
  );
});

test("first insertion has Merkle position zero", () => {
  assert.equal(
    leafPositionFromEventIndex(1n),
    0
  );
});

test("zero-based on-chain event rejected", () => {
  assert.throws(() =>
    leafPositionFromEventIndex(0n)
  );
});

test("oversized on-chain index rejected", () => {
  assert.throws(() =>
    leafPositionFromEventIndex(
      BigInt(Number.MAX_SAFE_INTEGER) + 1n
    )
  );
});

test("history beginning at zero rejected", () => {
  assert.throws(() =>
    assertContiguousEvents([
      { index: "0", leaf: "11" },
      { index: "1", leaf: "22" },
    ])
  );
});

test("LeanIMT proof index differs from leaf position", async () => {
  const { buildMerkleTree, proofFromTree } =
    await import(
      "../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts"
    );

  const tree = await buildMerkleTree([
    1n, 2n, 3n, 4n, 5n
  ]);

  const absolutePosition = tree.indexOf(5n);
  const rawProof = tree.generateProof(absolutePosition);

  assert.equal(absolutePosition, 4);
  assert.notEqual(rawProof.index, absolutePosition);

  assert.equal(
    recomputeLeanProofRoot(rawProof),
    tree.root
  );

  const circuitProof = proofFromTree(tree, 5n);

  assert.equal(circuitProof.index, rawProof.index);
  assert.equal(circuitProof.siblings.length, 32);
});

test("tampered LeanIMT proof fails root reconstruction", async () => {
  const { buildMerkleTree } =
    await import(
      "../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts"
    );

  const tree = await buildMerkleTree([
    1n, 2n, 3n, 4n, 5n
  ]);

  const proof = tree.generateProof(4);

  assert.ok(proof.siblings.length > 0);

  const tampered = {
    ...proof,
    siblings: [...proof.siblings],
  };

  tampered.siblings[0] += 1n;

  assert.notEqual(
    recomputeLeanProofRoot(tampered),
    tree.root
  );
});
