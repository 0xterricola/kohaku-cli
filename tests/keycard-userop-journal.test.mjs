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
import { getUserOperationHash } from "viem/account-abstraction";

import {
  recordKeycardUserOpAttempt,
} from "../src/utils/keycard-userop-journal.ts";

import {
  submitPreparedShieldUserOp,
} from "../src/utils/eip7702-submit.ts";

import {
  sendEip7702BatchUserOperation,
} from "../src/utils/eip7702-batch-userop.ts";

const chainId = 11155111n;
const owner = "0x1111111111111111111111111111111111111111";
const entryPointAddress =
  "0x2222222222222222222222222222222222222222";

const userOperation = {
  sender: owner,
  nonce: 0n,
  callData: "0x",
  callGasLimit: 100000n,
  verificationGasLimit: 150000n,
  preVerificationGas: 50000n,
  maxFeePerGas: 1000000000n,
  maxPriorityFeePerGas: 100000000n,
  signature: `0x${"11".repeat(65)}`,
};

const hash = getUserOperationHash({
  chainId: Number(chainId),
  entryPointAddress,
  entryPointVersion: "0.8",
  userOperation,
});

function temporaryDirectory() {
  return mkdtempSync(join(tmpdir(), "kohaku-userop-journal-"));
}

function persist(directory, userOpHash = hash) {
  return recordKeycardUserOpAttempt({
    directory,
    userOpHash,
    owner,
    chainId: Number(chainId),
  });
}

test("persists restricted metadata without signature material", () => {
  const directory = temporaryDirectory();

  try {
    const path = persist(directory);
    const record = JSON.parse(readFileSync(path, "utf8"));

    assert.equal(record.userOpHash, hash.toLowerCase());
    assert.equal(record.status, "outcome-unknown");
    assert.equal(record.owner.toLowerCase(), owner.toLowerCase());
    assert.equal(record.chainId, 11155111);
    assert.equal(statSync(path).mode & 0o777, 0o600);

    assert.equal("signature" in record, false);
    assert.equal("privateKey" in record, false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("exclusive journal creation prevents duplicate attempts", () => {
  const directory = temporaryDirectory();

  try {
    const path = persist(directory);
    const original = readFileSync(path, "utf8");

    assert.throws(
      () => persist(directory),
      /already recorded/,
    );

    assert.equal(readFileSync(path, "utf8"), original);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("external owner without persistence is rejected before RPC", async () => {
  let rpcAccesses = 0;

  const client = new Proxy({}, {
    get() {
      rpcAccesses++;
      throw new Error("Unexpected RPC access");
    },
  });

  await assert.rejects(
    sendEip7702BatchUserOperation({
      client,
      owner: { address: owner },
      approve: async () => true,
      chainId,
      calls: [{ to: owner, data: "0x", value: 0n }],
      rpcUrl: "http://127.0.0.1:9",
      withoutTor: true,
    }),
    /requires UserOperation hash persistence/,
  );

  assert.equal(rpcAccesses, 0);
});

test("uncertain send is recorded and cannot be repeated", async () => {
  const directory = temporaryDirectory();
  let sendCalls = 0;

  const attempt = () => submitPreparedShieldUserOp({
    chainId,
    entryPointAddress,
    userOperation,
    approve: async () => true,
    onSubmitted: (submittedHash) =>
      persist(directory, submittedHash),
    send: async () => {
      sendCalls++;

      throw Object.assign(
        new Error("Simulated transport timeout"),
        { submissionStatus: "unknown" },
      );
    },
    wait: async () => {
      throw new Error("Unexpected receipt wait");
    },
    confirm: async () => {
      throw new Error("Unexpected chain confirmation");
    },
  });

  try {
    await assert.rejects(
      attempt(),
      /Simulated transport timeout/,
    );

    assert.equal(sendCalls, 1);

    await assert.rejects(
      attempt(),
      /already recorded/,
    );

    assert.equal(sendCalls, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
