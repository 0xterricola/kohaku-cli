import assert from "node:assert/strict";
import { test } from "node:test";

import {
  validateExtension,
  assertUnused,
} from "../experiments/v3-r5e5b9k27-public-review.mjs";

const previous = {
  checkedThrough: "100",
  totalPublicDeposits: 10,
  entrypoint:
    "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB",
  entrypointCodeHash: `0x${"a".repeat(64)}`,
  sender:
    "0x155a8332A3504D5F532742Ae6531cd0e28035972",
  pendingNonce: "0",
  depositValueWei: "2000000000000000",
};

function current() {
  return {
    checkpoint: "R5-E5B9K27-public",
    chainId: 11155111,
    previousHead: "100",
    checkedThrough: "110",
    blockHash: `0x${"b".repeat(64)}`,
    entrypoint: previous.entrypoint,
    entrypointCodeHash: previous.entrypointCodeHash,
    sender: previous.sender,
    pendingNonce: "0",
    balanceWei: "50000000000000000",
    depositValueWei: "2000000000000000",
    suggestedGasLimit: "1000000",
    suggestedMaxFeePerGas: "100",
    suggestedPriorityFeePerGas: "10",
    newRegistrations: 0,
    newDeposits: 1,
    totalPublicDeposits: 11,
    newPrecommitments: ["123"],
    registrationRanges: [
      { from: "101", to: "110", count: 0 },
    ],
    depositRanges: [
      { from: "101", to: "110", count: 1 },
    ],
    realCalldataSent: false,
    signed: false,
    broadcast: false,
  };
}

test("valid public extension accepted", () => {
  assert.equal(
    validateExtension(previous, current()),
    true
  );
});

test("history gap rejected", () => {
  const value = current();
  value.depositRanges[0].from = "102";

  assert.throws(
    () => validateExtension(previous, value)
  );
});

test("nonce change rejected", () => {
  const value = current();
  value.pendingNonce = "1";

  assert.throws(
    () => validateExtension(previous, value)
  );
});

test("bytecode change rejected", () => {
  const value = current();
  value.entrypointCodeHash = `0x${"c".repeat(64)}`;

  assert.throws(
    () => validateExtension(previous, value)
  );
});

test("unknown pool registration rejected", () => {
  const value = current();
  value.newRegistrations = 1;

  assert.throws(
    () => validateExtension(previous, value)
  );
});

test("signed-state evidence rejected", () => {
  const value = current();
  value.signed = true;

  assert.throws(
    () => validateExtension(previous, value)
  );
});

test("local credential reuse rejected", () => {
  assert.throws(
    () => assertUnused(123n, ["123"]),
    /reuse detected/
  );
});
