import assert from "node:assert/strict";
import { test } from "node:test";
import { privateKeyToAccount } from "viem/accounts";
import {
  inspectSignedSepoliaTransaction,
} from "../src/utils/keycard-sepolia-broadcast.ts";

const account = privateKeyToAccount(`0x${"11".repeat(32)}`);

const tx = {
  type: "eip1559",
  chainId: 11155111,
  nonce: 0,
  to: account.address,
  data: "0x",
  value: 0n,
  gas: 21000n,
  maxFeePerGas: 1000000000n,
  maxPriorityFeePerGas: 100000000n,
};

function mockClient(overrides = {}) {
  const calls = [];
  return {
    calls,
    client: {
      getChainId: async () => {
        calls.push("chain");
        return 11155111;
      },
      getTransactionCount: async () => {
        calls.push("nonce");
        return 0;
      },
      getBlock: async () => {
        calls.push("block");
        return { baseFeePerGas: 14n };
      },
      estimateGas: async () => {
        calls.push("estimate");
        return 21000n;
      },
      getBalance: async () => {
        calls.push("balance");
        return 5000000000000000n;
      },
      ...overrides,
    },
  };
}

test("valid signed Sepolia transaction passes eligibility", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient();

  const result = await inspectSignedSepoliaTransaction(
    client, signed, account.address,
  );

  assert.equal(result.from, account.address);
  assert.equal(result.nonce, 0);
  assert.deepEqual(calls, [
    "chain", "nonce", "block", "estimate", "balance",
  ]);
});

test("wrong signer rejected without RPC access", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient();

  await assert.rejects(
    inspectSignedSepoliaTransaction(
      client,
      signed,
      "0x000000000000000000000000000000000000dEaD",
    ),
    /Unexpected hardware signer/,
  );

  assert.deepEqual(calls, []);
});

test("wrong transaction chain rejected without RPC access", async () => {
  const signed = await account.signTransaction({
    ...tx,
    chainId: 1,
  });

  const { client, calls } = mockClient();

  await assert.rejects(
    inspectSignedSepoliaTransaction(
      client, signed, account.address,
    ),
    /Only signed Sepolia/,
  );

  assert.deepEqual(calls, []);
});

test("stale nonce rejected before broadcast", async () => {
  const signed = await account.signTransaction(tx);
  const { client } = mockClient({
    getTransactionCount: async () => 1,
  });

  await assert.rejects(
    inspectSignedSepoliaTransaction(
      client, signed, account.address,
    ),
    /Nonce mismatch/,
  );
});
