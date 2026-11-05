import assert from "node:assert/strict";
import { test } from "node:test";

import {
  verifyRanges,
  assertUnused,
} from "../experiments/v3-r5e5b9k25-public-evidence.mjs";

test("contiguous archived ranges accepted", () => {
  assert.equal(
    verifyRanges(
      [
        { from: "101", to: "600", count: 1 },
        { from: "601", to: "1000", count: 2 },
      ],
      101n, 1000n, 3, 8192n
    ),
    true
  );
});

test("coverage gap rejected", () => {
  assert.throws(() =>
    verifyRanges(
      [
        { from: "101", to: "600", count: 0 },
        { from: "602", to: "1000", count: 0 },
      ],
      101n, 1000n, 0, 8192n
    )
  );
});

test("event count mismatch rejected", () => {
  assert.throws(() =>
    verifyRanges(
      [{ from: "101", to: "200", count: 2 }],
      101n, 200n, 1, 8192n
    )
  );
});

test("unused index credential accepted", () => {
  assert.equal(
    assertUnused(777n, ["11", "22"]),
    true
  );
});

test("historical collision rejected", () => {
  assert.throws(
    () => assertUnused(22n, ["11", "22"]),
    /reuse detected/
  );
});

test("invalid credential rejected", () => {
  assert.throws(
    () => assertUnused(0n, ["11"]),
    /Invalid local credential/
  );
});
