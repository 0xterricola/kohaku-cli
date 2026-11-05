import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertRpcMethod,
  requireBroadcastWord,
} from "../experiments/v3-r5e5b9k32-broadcaster.mjs";

test("public blockchain reads permitted", () => {
  assert.equal(
    assertRpcMethod("eth_getTransactionReceipt"),
    true
  );
  assert.equal(
    assertRpcMethod("eth_getLogs"),
    true
  );
});

test("broadcast prohibited before separate approval", () => {
  assert.throws(
    () => assertRpcMethod("eth_sendRawTransaction"),
    /approval/
  );
});

test("broadcast method only allowed after approval", () => {
  assert.equal(
    assertRpcMethod("eth_sendRawTransaction", true),
    true
  );
});

test("wallet signing and arbitrary RPC prohibited", () => {
  for (const method of [
    "eth_sendTransaction",
    "eth_sign",
    "personal_sign",
    "wallet_sendCalls",
    "debug_traceTransaction",
  ]) {
    assert.throws(
      () => assertRpcMethod(method, true),
      /Prohibited/
    );
  }
});

test("exact BROADCAST confirmation required", () => {
  assert.equal(
    requireBroadcastWord("BROADCAST"),
    true
  );

  for (const value of [
    "broadcast",
    "YES",
    "SIGN",
    "",
    "BROADCAST ",
  ]) {
    assert.throws(
      () => requireBroadcastWord(value),
      /declined/
    );
  }
});
