import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  privateKeyToAccount,
  toAccount,
} from "viem/accounts";
import { sepolia } from "viem/chains";

import {
  sendLiveKeycardSepoliaUserOperation,
} from "../src/utils/keycard-sepolia-userop-execution.ts";

const software = privateKeyToAccount(
  `0x${"33".repeat(32)}`,
);

const txHash = `0x${"ab".repeat(32)}`;

async function fixture(tampered = false) {
  const directory = mkdtempSync(
    join(tmpdir(), "kohaku-live-execution-"),
  );

  const events = [];
  let approvedHash;
  let sendCount = 0;

  try {
    // Mock hardware only: no real card or private-key access.
    const hardware = toAccount({
      address: software.address,

      async signAuthorization(args) {
        events.push("hardware-auth");
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

    const client = {
      chain: sepolia,

      async getChainId() {
        return sepolia.id;
      },

      async getTransactionCount() {
        return 1;
      },

      async getBytecode() {
        return "0x";
      },

      async getCode() {
        return "0x";
      },

      async getDelegation() {
        return undefined;
      },

      async readContract({ args }) {
        // Emulate EntryPoint.getNonce(sender, key).
        return args[1] << 64n;
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
        assert.equal(calls.length, 2);
        assert.ok(authorization);

        return {
          sender: software.address,
          nonce: 37n << 64n,
          callData: tampered
            ? "0xdeadbeef"
            : await account.encodeCalls(calls),
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
        assert.equal(method, "eth_sendUserOperation");
        assert.equal(options?.retryCount, 0);
        assert.ok(approvedHash);

        events.push("send");
        sendCount++;
        return approvedHash;
      },

      async waitForUserOperationReceipt({ hash }) {
        assert.equal(hash, approvedHash);
        events.push("bundler-receipt");

        return {
          success: true,
          receipt: { transactionHash: txHash },
        };
      },
    };

    const execute = () => sendLiveKeycardSepoliaUserOperation({
      client,
      owner: hardware,
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

      approveSigning: async review => {
        events.push(`approve:${review.stage}`);
        return true;
      },

      approve: async hash => {
        events.push("approve:submission");
        approvedHash = hash;
        return true;
      },
    });

    if (tampered) {
      await assert.rejects(
        execute(),
        /UserOperation calldata differs from reviewed batch/,
      );

      assert.equal(sendCount, 0);
      assert.equal(events.includes("hardware-userop"), false);
      assert.equal(events.includes("approve:submission"), false);
      assert.equal(readdirSync(directory).length, 0);
    } else {
      const result = await execute();

      assert.equal(result.txHash, txHash);
      assert.equal(sendCount, 1);
      assert.equal(readdirSync(directory).length, 1);

      assert.deepEqual(events, [
        "approve:eip7702-authorization",
        "hardware-auth",
        "approve:erc4337-userop",
        "hardware-userop",
        "approve:submission",
        "send",
        "bundler-receipt",
        "chain-receipt",
      ]);
    }
  } finally {
    rmSync(directory, {
      recursive: true,
      force: true,
    });
  }
}

test("live-state adapter completes a mocked two-call UserOp", async () => {
  await fixture(false);
});

test("tampered bundler calldata fails before UserOp signing", async () => {
  await fixture(true);
});
