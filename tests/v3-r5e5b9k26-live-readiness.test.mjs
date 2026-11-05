import assert from "node:assert/strict";
import { test } from "node:test";

import {
  calculateFeeBudget,
  validateLogs,
} from "../experiments/v3-r5e5b9k26-live-readiness.mjs";

test("fee budget includes gas buffer and deposit", () => {
  const result = calculateFeeBudget(
    800000n,
    1000000000n,
    100000000n,
    50000000000000000n
  );

  assert.equal(result.gasLimit, 1000000n);
  assert.equal(
    result.maxFeePerGas, 2100000000n
  );
});

test("insufficient funds refused", () => {
  assert.throws(
    () => calculateFeeBudget(
      800000n, 1000000000n, 100000000n, 1n
    ),
    /Insufficient funds/
  );
});

test("malformed logs refused", () => {
  assert.throws(
    () => validateLogs(
      [{ address: "0x1234" }],
      100n, 200n,
      "0x1234",
      ["0x1111111111111111111111111111111111111111"]
    )
  );
});
