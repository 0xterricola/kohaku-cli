import assert from "node:assert/strict";
import { test } from "node:test";

import {
  verifyR3PoolHistory,
  assertR3CredentialUnused,
} from "../src/utils/keycard-r3-pool-reuse-guard.mjs";

const entrypoint =
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB";

const pool =
  "0x1111111111111111111111111111111111111111";

const source = () => ({
  entrypoint,
  sha256: "a".repeat(64),
  snapshotHead: 100n,
  snapshotKeys: ["11", "22"],
  snapshotPools: [pool],
});

const archive = () => ({
  schema: "kohaku-key/r5-e5b9k21r6/pools-v1",
  chainId: 11155111,
  entrypoint,
  snapshotSha: "a".repeat(64),
  snapshotHead: "100",
  snapshotKeys: ["11", "22"],
  poolAddresses: [pool],
  targetHead: "120",
  checkedThrough: "120",
  recentKeys: ["33", "44"],
  ranges: [
    { from: "101", to: "110", count: 1 },
    { from: "111", to: "120", count: 1 },
  ],
});

test("complete archive passes", () => {
  const result = verifyR3PoolHistory(
    archive(), source()
  );

  assert.equal(result.archiveValidated, true);
  assert.equal(result.snapshotCount, 2);
  assert.equal(result.recentCount, 2);
});

test("unused candidate passes", () => {
  assert.equal(
    assertR3CredentialUnused(
      777n,
      archive()
    ),
    true
  );
});

test("snapshot collision rejected", () => {
  assert.throws(
    () => assertR3CredentialUnused(
      22n,
      archive()
    ),
    /reuse detected/
  );
});

test("recent collision rejected", () => {
  assert.throws(
    () => assertR3CredentialUnused(
      44n,
      archive()
    ),
    /reuse detected/
  );
});

test("archive snapshot mutation rejected", () => {
  const item = archive();
  item.snapshotKeys[0] = "999";

  assert.throws(
    () => verifyR3PoolHistory(
      item, source()
    ),
    /contents mismatch/
  );
});

test("snapshot hash mismatch rejected", () => {
  const item = archive();
  item.snapshotSha = "b".repeat(64);

  assert.throws(
    () => verifyR3PoolHistory(
      item, source()
    ),
    /identity mismatch/
  );
});

test("missing pool rejected", () => {
  const item = archive();
  item.poolAddresses = [
    "0x2222222222222222222222222222222222222222"
  ];

  assert.throws(
    () => verifyR3PoolHistory(
      item, source()
    ),
    /Bundled pool missing/
  );
});

test("missing history range rejected", () => {
  const item = archive();
  item.ranges[1].from = "112";

  assert.throws(
    () => verifyR3PoolHistory(
      item, source()
    ),
    /coverage gap/
  );
});

test("incomplete target rejected", () => {
  const item = archive();
  item.targetHead = "121";

  assert.throws(
    () => verifyR3PoolHistory(
      item, source()
    ),
    /coverage incomplete/
  );
});

test("wrong event count rejected", () => {
  const item = archive();
  item.recentKeys.pop();

  assert.throws(
    () => verifyR3PoolHistory(
      item, source()
    ),
    /coverage incomplete/
  );
});

test("invalid candidate rejected", () => {
  assert.throws(
    () => assertR3CredentialUnused(
      0n,
      archive()
    ),
    /Invalid hardware precommitment/
  );
});
