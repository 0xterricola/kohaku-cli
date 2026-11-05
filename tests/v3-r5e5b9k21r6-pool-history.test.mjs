import assert from "node:assert/strict";
import { test } from "node:test";

import {
  decodeAuthorizedDeposit,
} from "../experiments/v3-r5e5b9k21r6-pool-history.mjs";

const pool =
  "0x1111111111111111111111111111111111111111";

const foreign =
  "0x2222222222222222222222222222222222222222";

test("foreign contract deposit event rejected", () => {
  assert.throws(
    () => decodeAuthorizedDeposit(
      { address: foreign },
      [pool],
      100n,
      200n,
    ),
    /unregistered pool/
  );
});

test("empty authorized pool set rejects logs", () => {
  assert.throws(
    () => decodeAuthorizedDeposit(
      { address: pool },
      [],
      100n,
      200n,
    ),
    /unregistered pool/
  );
});
