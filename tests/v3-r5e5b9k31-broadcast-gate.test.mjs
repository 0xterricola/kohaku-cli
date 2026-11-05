import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertReadOnly,
  budget,
} from "../experiments/v3-r5e5b9k31-broadcast-gate.mjs";

test("public RPC reads permitted", () => {
  assert.equal(assertReadOnly("eth_getLogs"), true);
});

test("broadcast and signing methods prohibited", () => {
  for (const method of [
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "eth_sign",
    "personal_sign",
  ]) {
    assert.throws(() => assertReadOnly(method));
  }
});

test("fee budget calculated", () => {
  const result = budget(
    954080n, 100n, 3n, 50000000000000000n
  );

  assert.equal(result.maxFeePerGas, 203n);
  assert.ok(result.maximumCostWei > 2000000000000000n);
});

test("insufficient funds rejected", () => {
  assert.throws(() =>
    budget(954080n, 100n, 3n, 1n)
  );
});
