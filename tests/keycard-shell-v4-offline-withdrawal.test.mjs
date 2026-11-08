import assert from "node:assert/strict";
import { test } from "node:test";

import { calculateContext } from "../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts";
import { prepareOfflineWithdrawal } from "../src/utils/keycard-shell-demo-withdrawal.ts";

const withdrawal = {
  processooor: "0x0000000000000000000000000000000000000001",
  data: "0x",
};

const fixture = {
  proof: {
    pi_a: ["1", "2", "1"],
    pi_b: [["3", "4"], ["5", "6"], ["1", "0"]],
    pi_c: ["7", "8", "1"],
  },
  publicSignals: ["1", "2", "3", "4", "5", "6", "7", "8"],
  withdrawnValue: 990000000000000n,
  changeValue: 990000000000000n,
  scope: 987654321n,
  context: BigInt(calculateContext(withdrawal, 987654321n)),
};

test("V4 offline withdrawal calldata round-trip", () => {
  const report = prepareOfflineWithdrawal(
    fixture,
    1980000000000000n,
  );

  assert.ok(report.calldataBytes > 4);
  assert.equal(report.publicSignalCount, 8);
});

test("V4 withdrawal rejects mismatched context and balance", () => {
  assert.throws(
    () => prepareOfflineWithdrawal(
      { ...fixture, context: fixture.context + 1n },
      1980000000000000n,
    ),
    /context mismatch/,
  );

  assert.throws(
    () => prepareOfflineWithdrawal(
      fixture,
      1980000000000001n,
    ),
    /balance mismatch/,
  );
});
