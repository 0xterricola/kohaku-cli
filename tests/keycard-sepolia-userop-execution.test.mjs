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
import { getUserOperationHash } from "viem/account-abstraction";

import {
  prepareKeycardSepoliaUserOpExecution,
  sendKeycardSepoliaUserOperation,
} from "../src/utils/keycard-sepolia-userop-execution.ts";

import {
  submitPreparedShieldUserOp,
} from "../src/utils/eip7702-submit.ts";

const address =
  "0x1111111111111111111111111111111111111111";
const other =
  "0x2222222222222222222222222222222222222222";

const owner = {
  address,
  signAuthorization: async () => {
    throw new Error("Unexpected hardware signing");
  },
  signTypedData: async () => {
    throw new Error("Unexpected hardware signing");
  },
};

const entryPointAddress = other;

const userOperation = {
  sender: address,
  nonce: 0n,
  callData: "0x",
  callGasLimit: 100000n,
  verificationGasLimit: 150000n,
  preVerificationGas: 50000n,
  maxFeePerGas: 1000000000n,
  maxPriorityFeePerGas: 100000000n,
  signature: `0x${"11".repeat(65)}`,
};

const expectedHash = getUserOperationHash({
  chainId: 11155111,
  entryPointAddress,
  entryPointVersion: "0.8",
  userOperation,
});

function options(directory, approve = async () => true) {
  return {
    client: {
      chain: { id: 11155111 },
      getChainId: async () => 11155111,
    },
    owner,
    expectedOwner: address,
    journalDirectory: directory,
    chainId: 11155111n,
    calls: [
      { to: address, data: "0x", value: 0n },
      { to: address, data: "0x", value: 0n },
    ],
    rpcUrl: "http://127.0.0.1:9",
    withoutTor: true,
    approve,
  };
}

function temporaryDirectory() {
  return mkdtempSync(join(tmpdir(), "kohaku-hardware-exec-"));
}

test("rejects hardware owner address mismatch", () => {
  const directory = temporaryDirectory();

  try {
    assert.throws(
      () => prepareKeycardSepoliaUserOpExecution({
        ...options(directory),
        expectedOwner: other,
      }),
      /Hardware owner address mismatch/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects wrong chain before bundler execution", async () => {
  const directory = temporaryDirectory();
  let rpcCalls = 0;

  try {
    const opts = options(directory);

    await assert.rejects(
      sendKeycardSepoliaUserOperation({
        ...opts,
        client: {
          chain: { id: 11155111 },
          getChainId: async () => {
            rpcCalls++;
            return 1;
          },
        },
      }),
      /Live RPC chain ID is not Sepolia/,
    );

    assert.equal(rpcCalls, 1);
    assert.deepEqual(readdirSync(directory), []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects missing approval callback", () => {
  const directory = temporaryDirectory();

  try {
    assert.throws(
      () => prepareKeycardSepoliaUserOpExecution({
        ...options(directory),
        approve: undefined,
      }),
      /Hardware submission approval is required/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejected approval creates no journal or send", async () => {
  const directory = temporaryDirectory();
  const events = [];

  try {
    const request = prepareKeycardSepoliaUserOpExecution(
      options(directory, async () => {
        events.push("approval");
        return false;
      }),
    );

    await assert.rejects(
      submitPreparedShieldUserOp({
        chainId: request.chainId,
        entryPointAddress,
        userOperation,
        approve: request.approve,
        onSubmitted: request.onSubmitted,
        send: async () => {
          events.push("send");
          return expectedHash;
        },
        wait: async () => {
          throw new Error("Unexpected receipt polling");
        },
        confirm: async () => {
          throw new Error("Unexpected chain confirmation");
        },
      }),
      /UserOperation submission rejected/,
    );

    assert.deepEqual(events, ["approval"]);
    assert.deepEqual(readdirSync(directory), []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("journals before send and blocks duplicate attempts", async () => {
  const directory = temporaryDirectory();
  const events = [];

  try {
    const request = prepareKeycardSepoliaUserOpExecution(
      options(directory, async (hash) => {
        assert.equal(hash, expectedHash);
        events.push("approval");
        return true;
      }),
    );

    const attempt = () => submitPreparedShieldUserOp({
      chainId: request.chainId,
      entryPointAddress,
      userOperation,
      approve: request.approve,
      onSubmitted: request.onSubmitted,
      send: async () => {
        events.push("send");

        const files = readdirSync(directory);
        assert.equal(files.length, 1);

        const record = JSON.parse(
          readFileSync(join(directory, files[0]), "utf8"),
        );

        assert.equal(record.userOpHash, expectedHash);
        assert.equal(record.status, "outcome-unknown");

        throw Object.assign(
          new Error("Simulated bundler timeout"),
          { submissionStatus: "unknown" },
        );
      },
      wait: async () => {
        throw new Error("Unexpected receipt polling");
      },
      confirm: async () => {
        throw new Error("Unexpected chain confirmation");
      },
    });

    await assert.rejects(
      attempt(),
      /Simulated bundler timeout/,
    );

    await assert.rejects(
      attempt(),
      /already recorded/,
    );

    assert.deepEqual(events, [
      "approval",
      "send",
      "approval",
    ]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
