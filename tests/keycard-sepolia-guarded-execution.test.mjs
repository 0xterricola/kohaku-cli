import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toAccount, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import {
  createApprovedKeycardSepoliaOwner,
} from "../src/utils/keycard-sepolia-approved-owner.ts";

import {
  sendKeycardSepoliaUserOperation,
} from "../src/utils/keycard-sepolia-userop-execution.ts";

const software = privateKeyToAccount(
  `0x${"33".repeat(32)}`,
);

const txHash = `0x${"ab".repeat(32)}`;
const intent = `0x${"22".repeat(32)}`;

function fixture(directory, deniedStage = null) {
  const events = [];
  let approvedHash;
  let sendCount = 0;

  const hardware = toAccount({
    address: software.address,

    async signAuthorization(args) {
      events.push("hardware-authorization");
      return software.signAuthorization(args);
    },

    async signTypedData(args) {
      events.push("hardware-userop");
      return software.signTypedData(args);
    },

    signMessage: args => software.signMessage(args),
    signTransaction: (tx, opts) =>
      software.signTransaction(tx, opts),
  });

  const owner = createApprovedKeycardSepoliaOwner({
    owner: hardware,
    expectedOwner: software.address,
    unsignedIntentDigest: intent,

    approve: async review => {
      events.push(`approve:${review.stage}`);
      return review.stage !== deniedStage;
    },

    // Mock-only revalidation.
    // Production must independently recompute digests
    // and fetch fresh nonce/delegation state.
    revalidate: async review => {
      events.push(`revalidate:${review.stage}`);

      return {
        nonce: review.nonce,
        digest: review.digest,
        unsignedIntentDigest: review.unsignedIntentDigest,
      };
    },
  });

  const client = {
    chain: sepolia,

    async getChainId() {
      return sepolia.id;
    },

    async getCode() {
      return "0x";
    },

    async getDelegation() {
      return undefined;
    },

    async getTransactionCount() {
      return 1;
    },

    async waitForTransactionReceipt() {
      events.push("chain-receipt");
      return { status: "success" };
    },
  };

  const bundlerClientOverride = {
    async prepareUserOperation({
      account,
      calls,
      authorization,
    }) {
      events.push("prepare");

      assert.equal(calls.length, 2);
      assert.ok(authorization);

      return {
        sender: software.address,
        nonce: 0n,
        callData: await account.encodeCalls(calls),
        callGasLimit: 100000n,
        verificationGasLimit: 150000n,
        preVerificationGas: 50000n,
        maxFeePerGas: 1000000000n,
        maxPriorityFeePerGas: 100000000n,
        signature: "0x",
        eip7702Auth: authorization,
      };
    },

    async request({ method }, options) {
      events.push("send");
      sendCount++;

      assert.equal(method, "eth_sendUserOperation");
      assert.equal(options?.retryCount, 0);
      assert.ok(approvedHash);

      return approvedHash;
    },

    async waitForUserOperationReceipt({ hash }) {
      events.push("bundler-receipt");

      assert.equal(hash, approvedHash);

      return {
        success: true,
        receipt: { transactionHash: txHash },
      };
    },
  };

  const options = {
    client,
    owner,
    expectedOwner: software.address,
    chainId: BigInt(sepolia.id),
    journalDirectory: directory,
    rpcUrl: "http://127.0.0.1:9",
    withoutTor: true,
    bundlerClientOverride,

    calls: [
      { to: software.address, data: "0x", value: 0n },
      { to: software.address, data: "0x", value: 0n },
    ],

    approve: async hash => {
      events.push("approve:submission");
      approvedHash = hash;
      return true;
    },
  };

  return {
    options,
    events,
    getSendCount: () => sendCount,
  };
}

async function withFixture(fn) {
  const directory = mkdtempSync(
    join(tmpdir(), "kohaku-guarded-execution-"),
  );

  try {
    await fn(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("guarded signer completes mocked UserOp execution", async () => {
  await withFixture(async directory => {
    const f = fixture(directory);

    const result = await sendKeycardSepoliaUserOperation(
      f.options,
    );

    assert.equal(result.txHash, txHash);
    assert.equal(f.getSendCount(), 1);
    assert.equal(readdirSync(directory).length, 1);

    assert.deepEqual(f.events, [
      "approve:eip7702-authorization",
      "revalidate:eip7702-authorization",
      "hardware-authorization",
      "prepare",
      "approve:erc4337-userop",
      "revalidate:erc4337-userop",
      "hardware-userop",
      "approve:submission",
      "send",
      "bundler-receipt",
      "chain-receipt",
    ]);
  });
});

test("authorization denial prevents hardware signing", async () => {
  await withFixture(async directory => {
    const f = fixture(directory, "eip7702-authorization");

    await assert.rejects(
      sendKeycardSepoliaUserOperation(f.options),
      /approval declined/,
    );

    assert.deepEqual(f.events, [
      "approve:eip7702-authorization",
    ]);

    assert.equal(f.getSendCount(), 0);
    assert.equal(readdirSync(directory).length, 0);
  });
});

test("UserOp signing denial prevents submission", async () => {
  await withFixture(async directory => {
    const f = fixture(directory, "erc4337-userop");

    await assert.rejects(
      sendKeycardSepoliaUserOperation(f.options),
      /approval declined/,
    );

    assert.ok(
      f.events.includes("hardware-authorization"),
    );

    assert.ok(
      f.events.includes("approve:erc4337-userop"),
    );

    assert.equal(
      f.events.includes("hardware-userop"),
      false,
    );

    assert.equal(
      f.events.includes("approve:submission"),
      false,
    );

    assert.equal(f.getSendCount(), 0);
    assert.equal(readdirSync(directory).length, 0);
  });
});
