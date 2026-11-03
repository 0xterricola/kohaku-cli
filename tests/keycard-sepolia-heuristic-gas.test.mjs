import assert from "node:assert/strict";
import { test } from "node:test";
import {
  previewKeycardSepoliaGas as preview,
} from "../src/utils/keycard-sepolia-heuristic-gas.ts";

const owner = "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";

const client = {
  chain: { id: 11155111 },
};

const calls = [
  { to: owner, data: "0x", value: 0n },
  { to: owner, data: "0x", value: 0n },
];

const base = {
  client,
  chainId: 11155111,
  owner,
  calls,
  rpcUrl: "https://example.invalid",
};

const fee = {
  kind: "eip7702-userop",
  estimatedMax: "316470000548000",
  estimatedMaxFormatted: "0.000316470000548 ETH",
  asset: "ETH",
  maxFeePerGasWei: "1155000002",
  gasLimit: "274000",
  note: "rough estimate; actual may differ",
};

test("preview never forwards a signer or private key", async () => {
  let captured;

  const result = await preview({
    ...base,
    estimator: async args => {
      captured = args;
      return fee;
    },
  });

  assert.equal(captured.senderAddress, owner);
  assert.equal(captured.chainId, 11155111n);
  assert.equal(captured.withoutTor, true);
  assert.equal(captured.client, client);

  assert.equal("owner" in captured, false);
  assert.equal("privateKey" in captured, false);
  assert.equal("approve" in captured, false);
  assert.equal("onSubmitted" in captured, false);

  assert.deepEqual(result.preview, fee);
  assert.equal(result.authorizationSigned, false);
  assert.equal(result.signingPerformed, false);
  assert.equal(result.submissionPerformed, false);
  assert.equal(
    result.estimateType,
    "heuristic-not-bundler-validated",
  );
});

test("wrong chain rejects before estimation", async () => {
  let invoked = false;

  await assert.rejects(
    preview({
      ...base,
      chainId: 1,
      estimator: async () => {
        invoked = true;
        return fee;
      },
    }),
    /requires Sepolia/,
  );

  assert.equal(invoked, false);
});

test("wrong client chain rejects before estimation", async () => {
  let invoked = false;

  await assert.rejects(
    preview({
      ...base,
      client: { chain: { id: 1 } },
      estimator: async () => {
        invoked = true;
        return fee;
      },
    }),
    /requires Sepolia/,
  );

  assert.equal(invoked, false);
});

test("insufficient calls reject before estimation", async () => {
  let invoked = false;

  await assert.rejects(
    preview({
      ...base,
      calls: [calls[0]],
      estimator: async () => {
        invoked = true;
        return fee;
      },
    }),
    /requires two calls/,
  );

  assert.equal(invoked, false);
});
