import assert from "node:assert/strict";
import { test } from "node:test";
import {
  preflightSepoliaTransaction,
} from "../src/utils/keycard-sepolia-preflight.ts";

const tx = {
  from: "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa",
  to: "0x000000000000000000000000000000000000dEaD",
  data: "0x",
  value: 0n,
  nonce: 7,
  gas: 21000n,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
};

function mockClient(overrides = {}) {
  const calls = [];

  const client = {
    getChainId: async () => {
      calls.push("chain");
      return 11155111;
    },
    getTransactionCount: async () => {
      calls.push("nonce");
      return 7;
    },
    getBlock: async () => {
      calls.push("block");
      return { baseFeePerGas: 2n };
    },
    estimateGas: async () => {
      calls.push("estimate");
      return 21000n;
    },
    getBalance: async () => {
      calls.push("balance");
      return 1000000n;
    },
    ...overrides,
  };

  return { client, calls };
}

test("valid Sepolia transaction passes preflight", async () => {
  const { client, calls } = mockClient();

  const result = await preflightSepoliaTransaction(client, tx);

  assert.equal(result.chainId, 11155111);
  assert.equal(result.nonce, 7);
  assert.equal(result.estimatedGas, 21000n);
  assert.equal(result.maximumCost, 63000n);
  assert.deepEqual(calls, [
    "chain", "nonce", "block", "estimate", "balance",
  ]);
});

test("wrong chain rejected before transaction RPC", async () => {
  const { client, calls } = mockClient({
    getChainId: async () => {
      calls.push("chain");
      return 1;
    },
  });

  await assert.rejects(
    preflightSepoliaTransaction(client, tx),
    /Wrong network/,
  );

  assert.deepEqual(calls, ["chain"]);
});

test("pending nonce mismatch rejected", async () => {
  const { client } = mockClient({
    getTransactionCount: async () => 8,
  });

  await assert.rejects(
    preflightSepoliaTransaction(client, tx),
    /Nonce mismatch/,
  );
});

test("fee below base fee rejected", async () => {
  const { client } = mockClient({
    getBlock: async () => ({ baseFeePerGas: 4n }),
  });

  await assert.rejects(
    preflightSepoliaTransaction(client, tx),
    /below the current base fee/,
  );
});

test("underestimated gas limit rejected", async () => {
  const { client } = mockClient({
    estimateGas: async () => 25000n,
  });

  await assert.rejects(
    preflightSepoliaTransaction(client, tx),
    /Gas limit too low/,
  );
});

test("insufficient balance rejected", async () => {
  const { client } = mockClient({
    getBalance: async () => 100n,
  });

  await assert.rejects(
    preflightSepoliaTransaction(client, tx),
    /Insufficient balance/,
  );
});

test("invalid priority fee rejected", async () => {
  const { client } = mockClient();

  await assert.rejects(
    preflightSepoliaTransaction(client, {
      ...tx,
      maxPriorityFeePerGas: 4n,
    }),
    /Invalid transaction parameters/,
  );
});
