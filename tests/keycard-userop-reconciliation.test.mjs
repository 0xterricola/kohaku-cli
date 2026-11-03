import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  encodeAbiParameters,
  encodeEventTopics,
  parseAbiItem,
  parseAbiParameters,
} from "viem";

import {
  recordKeycardUserOpAttempt,
  reconcileKeycardUserOpReceipt,
} from "../src/utils/keycard-userop-journal.ts";

const owner = "0x1111111111111111111111111111111111111111";
const other = "0x2222222222222222222222222222222222222222";
const hash = `0x${"aa".repeat(32)}`;
const txHash = `0x${"bb".repeat(32)}`;
const entryPoint =
  "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";

const event = parseAbiItem(
  "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)",
);

const dataAbi = parseAbiParameters(
  "uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed",
);

function fixture(overrides = {}) {
  const directory = mkdtempSync(
    join(tmpdir(), "keycard-reconciliation-"),
  );

  const filename = recordKeycardUserOpAttempt({
    directory,
    userOpHash: hash,
    owner,
    chainId: 11155111,
  });

  let receiptRequests = 0;

  const client = {
    async getChainId() {
      return overrides.chainId ?? 11155111;
    },

    async getTransactionReceipt() {
      receiptRequests++;

      return {
        transactionHash: txHash,
        status: overrides.status ?? "success",
        blockNumber: 123n,
        logs: [{
          address: entryPoint,
          topics: encodeEventTopics({
            abi: [event],
            eventName: "UserOperationEvent",
            args: {
              userOpHash: overrides.userOpHash ?? hash,
              sender: overrides.sender ?? owner,
              paymaster: "0x0000000000000000000000000000000000000000",
            },
          }),
          data: encodeAbiParameters(dataAbi, [
            7n,
            overrides.success ?? true,
            418n,
            500n,
          ]),
        }],
      };
    },
  };

  return {
    directory,
    filename,
    client,
    getReceiptRequests: () => receiptRequests,
    read: () => JSON.parse(readFileSync(filename, "utf8")),
    cleanup: () =>
      rmSync(directory, { recursive: true, force: true }),
  };
}

async function reconcile(f) {
  return reconcileKeycardUserOpReceipt({
    directory: f.directory,
    userOpHash: hash,
    txHash,
    client: f.client,
  });
}

test("verified success updates journal atomically", async () => {
  const f = fixture();

  try {
    await reconcile(f);

    const record = f.read();
    assert.equal(record.status, "confirmed");
    assert.equal(record.txHash, txHash);
    assert.equal(record.blockNumber, "123");
    assert.equal(record.actualGasCostWei, "418");
    assert.equal(statSync(f.filename).mode & 0o777, 0o600);

    assert.throws(
      () => recordKeycardUserOpAttempt({
        directory: f.directory,
        userOpHash: hash,
        owner,
        chainId: 11155111,
      }),
      /already recorded/,
    );

    await reconcile(f);
    assert.equal(f.read().status, "confirmed");
  } finally {
    f.cleanup();
  }
});

test("failed transaction cannot mark confirmed", async () => {
  const f = fixture({ status: "reverted" });
  try {
    await assert.rejects(reconcile(f), /not successful/);
    assert.equal(f.read().status, "outcome-unknown");
  } finally {
    f.cleanup();
  }
});

test("failed UserOperation event cannot mark confirmed", async () => {
  const f = fixture({ success: false });
  try {
    await assert.rejects(reconcile(f), /execution failed/);
    assert.equal(f.read().status, "outcome-unknown");
  } finally {
    f.cleanup();
  }
});

test("wrong UserOperation hash cannot mark confirmed", async () => {
  const f = fixture({ userOpHash: `0x${"cc".repeat(32)}` });
  try {
    await assert.rejects(reconcile(f), /not found/);
    assert.equal(f.read().status, "outcome-unknown");
  } finally {
    f.cleanup();
  }
});

test("wrong event owner cannot mark confirmed", async () => {
  const f = fixture({ sender: other });
  try {
    await assert.rejects(reconcile(f), /owner mismatch/);
    assert.equal(f.read().status, "outcome-unknown");
  } finally {
    f.cleanup();
  }
});

test("wrong chain stops before receipt lookup", async () => {
  const f = fixture({ chainId: 1 });
  try {
    await assert.rejects(reconcile(f), /not Sepolia/);
    assert.equal(f.getReceiptRequests(), 0);
    assert.equal(f.read().status, "outcome-unknown");
  } finally {
    f.cleanup();
  }
});
