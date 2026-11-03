import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toAccount, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

import {
  sendKeycardSepoliaUserOperation,
} from "../src/utils/keycard-sepolia-userop-execution.ts";

const software = privateKeyToAccount(
  `0x${"33".repeat(32)}`,
);

const ownerAddress = software.address;
const txHash = `0x${"ab".repeat(32)}`;

function fixture(directory, allowSubmission) {
  const events = [];
  let approvedHash;
  let sendCount = 0;

  const owner = toAccount({
    address: ownerAddress,

    async signAuthorization(args) {
      events.push("authorization");
      return software.signAuthorization(args);
    },

    async signTypedData(args) {
      events.push("sign-userop");
      return software.signTypedData(args);
    },

    signMessage: args => software.signMessage(args),
    signTransaction: (tx, opts) =>
      software.signTransaction(tx, opts),
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

    async waitForTransactionReceipt({ hash, confirmations }) {
      events.push("chain-receipt");
      assert.equal(hash, txHash);
      assert.equal(confirmations, 1);
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
      assert.equal(authorization?.chainId, sepolia.id);
      assert.equal(authorization?.nonce, 1);
      assert.match(authorization.r, /^0x[0-9a-fA-F]{64}$/);

      return {
        sender: ownerAddress,
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

    async request({ method, params }, options) {
      events.push("send");
      sendCount++;

      assert.equal(method, "eth_sendUserOperation");
      assert.equal(options?.retryCount, 0);
      assert.equal(params.length, 2);

      const submitted = params[0];

      assert.match(
        submitted.signature,
        /^0x[0-9a-fA-F]{130}$/,
      );
      assert.ok(
        submitted.eip7702Auth,
        "EIP-7702 authorization missing from bundler payload",
      );

      const files = readdirSync(directory);
      assert.equal(files.length, 1);

      const recorded = JSON.parse(
        readFileSync(join(directory, files[0]), "utf8"),
      );

      assert.equal(recorded.userOpHash, approvedHash);
      assert.equal(recorded.status, "outcome-unknown");

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
    expectedOwner: ownerAddress,
    chainId: BigInt(sepolia.id),
    journalDirectory: directory,
    rpcUrl: "http://127.0.0.1:9",
    withoutTor: true,
    bundlerClientOverride,

    calls: [
      { to: ownerAddress, data: "0x", value: 0n },
      { to: ownerAddress, data: "0x", value: 0n },
    ],

    approve: async (hash, operation) => {
      events.push("approve");
      approvedHash = hash;

      assert.match(hash, /^0x[0-9a-fA-F]{64}$/);
      assert.equal(operation.sender, ownerAddress);
      assert.match(
        operation.signature,
        /^0x[0-9a-fA-F]{130}$/,
      );

      return allowSubmission;
    },
  };

  return {
    options,
    events,
    getSendCount: () => sendCount,
  };
}

test("complete mocked hardware-owner UserOp execution", async () => {
  const directory = mkdtempSync(
    join(tmpdir(), "kohaku-bundler-integration-"),
  );

  try {
    const { options, events, getSendCount } =
      fixture(directory, true);

    const result = await sendKeycardSepoliaUserOperation(options);

    assert.equal(result.delegatedInUserOp, true);
    assert.equal(result.txHash, txHash);
    assert.equal(getSendCount(), 1);

    assert.deepEqual(events, [
      "authorization",
      "prepare",
      "sign-userop",
      "approve",
      "send",
      "bundler-receipt",
      "chain-receipt",
    ]);

    await assert.rejects(
      sendKeycardSepoliaUserOperation(options),
      /already recorded/,
    );

    assert.equal(getSendCount(), 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejected approval never submits to mock bundler", async () => {
  const directory = mkdtempSync(
    join(tmpdir(), "kohaku-bundler-denial-"),
  );

  try {
    const { options, events, getSendCount } =
      fixture(directory, false);

    await assert.rejects(
      sendKeycardSepoliaUserOperation(options),
      /UserOperation submission rejected/,
    );

    assert.equal(getSendCount(), 0);
    assert.deepEqual(readdirSync(directory), []);

    assert.ok(events.includes("sign-userop"));
    assert.ok(events.includes("approve"));
    assert.ok(!events.includes("send"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
