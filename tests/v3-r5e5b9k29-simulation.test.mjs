import assert from "node:assert/strict";
import { test } from "node:test";

import {
  encodeFunctionData,
  parseAbi,
} from "viem";

import {
  assertReadOnlyMethod,
  validateLocalIntent,
} from "../experiments/v3-r5e5b9k29-real-simulation.mjs";

const sender =
  "0x155a8332A3504D5F532742Ae6531cd0e28035972";

const entrypoint =
  "0x34A2068192b1297f2a7f85D7D8CdE66F8F0921cB";

const candidate = 123n;

function fixture() {
  return {
    type: "eip1559",
    chainId: 11155111,
    from: sender,
    to: entrypoint,
    nonce: 0,
    value: 2000000000000000n,
    data: encodeFunctionData({
      abi: parseAbi([
        "function deposit(uint256 _precommitment) payable",
      ]),
      functionName: "deposit",
      args: [candidate],
    }),
  };
}

const evidence = {
  observedNonce: 0,
  allPublicKeys: ["456", "789"],
};

test("read-only simulation methods allowed", () => {
  assert.equal(
    assertReadOnlyMethod("eth_call"),
    true
  );

  assert.equal(
    assertReadOnlyMethod("eth_estimateGas"),
    true
  );
});

test("signing and broadcasting methods rejected", () => {
  for (const method of [
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "personal_sign",
    "eth_sign",
    "wallet_sendCalls",
  ]) {
    assert.throws(
      () => assertReadOnlyMethod(method),
      /Prohibited/
    );
  }
});

test("real-deposit intent validated locally", () => {
  assert.equal(
    validateLocalIntent(
      fixture(), candidate, evidence
    ),
    true
  );
});

test("wrong precommitment refused", () => {
  assert.throws(
    () => validateLocalIntent(
      fixture(), 999n, evidence
    ),
    /mismatch/
  );
});

test("historical collision refused", () => {
  assert.throws(
    () => validateLocalIntent(
      fixture(), candidate, {
        ...evidence,
        allPublicKeys: ["123"],
      }
    ),
    /reuse detected/
  );
});

test("changed nonce refused", () => {
  const intent = fixture();
  intent.nonce = 1;

  assert.throws(
    () => validateLocalIntent(
      intent, candidate, evidence
    )
  );
});

test("changed amount refused", () => {
  const intent = fixture();
  intent.value = 1n;

  assert.throws(
    () => validateLocalIntent(
      intent, candidate, evidence
    )
  );
});
