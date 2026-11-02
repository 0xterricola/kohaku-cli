import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  submitSignedSepoliaTransaction,
  SepoliaSubmissionUncertainError,
} from "../src/utils/keycard-sepolia-submit.ts";

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

  const client = {
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
    sendRawTransaction: async ({ serializedTransaction }) => {
      calls.push("send");
      return keccak256(serializedTransaction);
    },
    waitForTransactionReceipt: async ({ hash }) => {
      calls.push("receipt");
      return {
        transactionHash: hash,
        status: "success",
        blockNumber: 123n,
      };
    },
    ...overrides,
  };

  return { client, calls };
}

test("broadcast requires independent approval", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient();

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client,
      signed,
      account.address,
      async () => false,
    ),
    /broadcast rejected/,
  );

  assert.ok(!calls.includes("send"));
  assert.ok(!calls.includes("receipt"));
});

test("approved transaction submits exact signed bytes once", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient();

  let approvals = 0;

  const result = await submitSignedSepoliaTransaction(
    client,
    signed,
    account.address,
    async (review) => {
      approvals++;
      assert.equal(review.transactionHash, keccak256(signed));
      assert.equal(review.chainId, 11155111);
      assert.equal(review.nonce, 0);
      assert.equal(review.value, 0n);
      assert.equal(review.gas, 21000n);
      assert.equal(review.maximumCost, 21000000000000n);
      return true;
    },
  );

  assert.equal(approvals, 1);
  assert.equal(result.transactionHash, keccak256(signed));
  assert.equal(result.blockNumber, 123n);
  assert.equal(result.status, "success");

  assert.equal(calls.filter(call => call === "send").length, 1);
  assert.equal(calls.filter(call => call === "receipt").length, 1);
});

test("wrong chain never reaches approval or broadcast", async () => {
  const signed = await account.signTransaction({
    ...tx,
    chainId: 1,
  });
  const { client, calls } = mockClient();
  let approved = false;

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client,
      signed,
      account.address,
      async () => {
        approved = true;
        return true;
      },
    ),
    /Only signed Sepolia/,
  );

  assert.equal(approved, false);
  assert.ok(!calls.includes("send"));
});

test("stale nonce never broadcasts", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient({
    getTransactionCount: async () => 1,
  });

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client,
      signed,
      account.address,
      async () => true,
    ),
    /Nonce mismatch/,
  );

  assert.ok(!calls.includes("send"));
});

test("reverted receipt is reported as submitted failure", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient({
    waitForTransactionReceipt: async ({ hash }) => {
      calls.push("receipt");
      return {
        transactionHash: hash,
        status: "reverted",
        blockNumber: 123n,
      };
    },
  });

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client,
      signed,
      account.address,
      async () => true,
    ),
    /broadcast but reverted/,
  );

  assert.equal(calls.filter(call => call === "send").length, 1);
});

test("broadcast timeout never triggers automatic resend", async () => {
  const signed = await account.signTransaction(tx);
  const expectedHash = keccak256(signed);
  const { client, calls } = mockClient({
    sendRawTransaction: async () => {
      calls.push("send");
      throw new Error("simulated RPC timeout");
    },
  });

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client, signed, account.address,
      async () => true,
    ),
    (error) => {
      assert.ok(error instanceof SepoliaSubmissionUncertainError);
      assert.equal(error.phase, "broadcast");
      assert.equal(error.transactionHash, expectedHash);
      return true;
    },
  );

  assert.equal(calls.filter(x => x === "send").length, 1);
  assert.equal(calls.filter(x => x === "receipt").length, 0);
});

test("receipt timeout preserves submitted transaction hash", async () => {
  const signed = await account.signTransaction(tx);
  const expectedHash = keccak256(signed);
  const { client, calls } = mockClient({
    waitForTransactionReceipt: async () => {
      calls.push("receipt");
      throw new Error("simulated receipt timeout");
    },
  });

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client, signed, account.address,
      async () => true,
    ),
    (error) => {
      assert.ok(error instanceof SepoliaSubmissionUncertainError);
      assert.equal(error.phase, "receipt");
      assert.equal(error.transactionHash, expectedHash);
      return true;
    },
  );

  assert.equal(calls.filter(x => x === "send").length, 1);
  assert.equal(calls.filter(x => x === "receipt").length, 1);
});

test("unexpected RPC hash is rejected without receipt polling", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient({
    sendRawTransaction: async () => {
      calls.push("send");
      return `0x${"aa".repeat(32)}`;
    },
  });

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client, signed, account.address,
      async () => true,
    ),
    /unexpected transaction hash/,
  );

  assert.equal(calls.filter(x => x === "send").length, 1);
  assert.equal(calls.filter(x => x === "receipt").length, 0);
});

test("mismatched receipt hash is rejected", async () => {
  const signed = await account.signTransaction(tx);
  const { client, calls } = mockClient({
    waitForTransactionReceipt: async () => {
      calls.push("receipt");
      return {
        transactionHash: `0x${"bb".repeat(32)}`,
        status: "success",
        blockNumber: 123n,
      };
    },
  });

  await assert.rejects(
    submitSignedSepoliaTransaction(
      client, signed, account.address,
      async () => true,
    ),
    /receipt hash mismatch/,
  );

  assert.equal(calls.filter(x => x === "send").length, 1);
  assert.equal(calls.filter(x => x === "receipt").length, 1);
});
