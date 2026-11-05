import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertSamePrecommitments,
  validateAuditRanges,
} from "../experiments/v3-r5e5b9k22-historical-audit.mjs";

test("identical deposit multisets pass", () => {
  assert.equal(
    assertSamePrecommitments(
      ["1", "2", "3"],
      ["3", "1", "2"]
    ),
    true
  );
});

test("changed deposit fails", () => {
  assert.throws(
    () => assertSamePrecommitments(
      ["1", "2"],
      ["1", "3"]
    ),
    /differs/
  );
});

test("duplicate deposit cannot hide missing entry", () => {
  assert.throws(
    () => assertSamePrecommitments(
      ["1", "2"],
      ["1", "1"]
    ),
    /differs/
  );
});

test("legacy 500-block checkpoint passes", () => {
  assert.equal(
    validateAuditRanges(
      [
        { from: "100", to: "599", count: 1 },
        { from: "600", to: "1099", count: 0 },
      ],
      100n, 1099n, 1
    ),
    true
  );
});

test("8192-block checkpoint passes", () => {
  assert.equal(
    validateAuditRanges(
      [
        { from: "100", to: "8291", count: 2 },
      ],
      100n, 8291n, 2
    ),
    true
  );
});

test("coverage gap rejected", () => {
  assert.throws(
    () => validateAuditRanges(
      [
        { from: "100", to: "599", count: 0 },
        { from: "601", to: "800", count: 0 },
      ],
      100n, 800n, 0
    ),
    /coverage gap/
  );
});

test("event count mismatch rejected", () => {
  assert.throws(
    () => validateAuditRanges(
      [{ from: "100", to: "200", count: 2 }],
      100n, 200n, 1
    ),
    /checkpoint mismatch/
  );
});
