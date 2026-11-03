import assert from "node:assert/strict";
import { test } from "node:test";
import { getUserOperationHash } from "viem/account-abstraction";
import {
  submitPreparedShieldUserOp,
} from "../src/utils/eip7702-submit.ts";

const chainId = 11155111n;
const entryPointAddress =
  "0x2222222222222222222222222222222222222222";

const userOperation = {
  sender: "0x1111111111111111111111111111111111111111",
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
  chainId: Number(chainId),
  entryPointAddress,
  entryPointVersion: "0.8",
  userOperation,
});

test("rejected approval prevents persistence and broadcast", async () => {
  const events = [];

  await assert.rejects(
    submitPreparedShieldUserOp({
      chainId,
      entryPointAddress,
      userOperation,
      approve: async (hash, operation) => {
        events.push("approval");
        assert.equal(hash, expectedHash);
        assert.equal(operation, userOperation);
        return false;
      },
      onSubmitted: () => events.push("persist"),
      send: async () => {
        events.push("send");
        return expectedHash;
      },
      wait: async () => {
        events.push("wait");
        throw new Error("Unexpected receipt polling");
      },
      confirm: async () => {
        events.push("confirm");
        throw new Error("Unexpected chain confirmation");
      },
    }),
    /UserOperation submission rejected/,
  );

  assert.deepEqual(events, ["approval"]);
});

test("approval precedes hash persistence and exactly one send", async () => {
  const events = [];
  let sendCalls = 0;

  await assert.rejects(
    submitPreparedShieldUserOp({
      chainId,
      entryPointAddress,
      userOperation,
      approve: async (hash) => {
        assert.equal(hash, expectedHash);
        events.push("approval");
        return true;
      },
      onSubmitted: (hash) => {
        assert.equal(hash, expectedHash);
        events.push("persist");
      },
      send: async () => {
        events.push("send");
        sendCalls++;
        throw Object.assign(
          new Error("Simulated uncertain transport outcome"),
          { submissionStatus: "unknown" },
        );
      },
      wait: async () => {
        events.push("wait");
        throw new Error("Unexpected receipt polling");
      },
      confirm: async () => {
        events.push("confirm");
        throw new Error("Unexpected chain confirmation");
      },
    }),
    (error) =>
      error.message === "Simulated uncertain transport outcome" &&
      error.submissionStatus === "unknown",
  );

  assert.deepEqual(events, ["approval", "persist", "send"]);
  assert.equal(sendCalls, 1);
});

test("approval callback failure prevents broadcasting", async () => {
  const events = [];

  await assert.rejects(
    submitPreparedShieldUserOp({
      chainId,
      entryPointAddress,
      userOperation,
      approve: async () => {
        events.push("approval");
        throw new Error("Approval unavailable");
      },
      onSubmitted: () => events.push("persist"),
      send: async () => {
        events.push("send");
        return expectedHash;
      },
      wait: async () => {
        events.push("wait");
        throw new Error("Unexpected receipt polling");
      },
      confirm: async () => {
        events.push("confirm");
        throw new Error("Unexpected chain confirmation");
      },
    }),
    /Approval unavailable/,
  );

  assert.deepEqual(events, ["approval"]);
});

test("external hardware owner requires approval before any RPC", async () => {
  const { sendEip7702BatchUserOperation } = await import(
    "../src/utils/eip7702-batch-userop.ts"
  );

  let rpcAccesses = 0;

  const client = new Proxy({}, {
    get() {
      rpcAccesses++;
      throw new Error("Unexpected RPC client access");
    },
  });

  await assert.rejects(
    sendEip7702BatchUserOperation({
      client,
      owner: { address: userOperation.sender },
      chainId,
      calls: [{
        to: userOperation.sender,
        data: "0x",
        value: 0n,
      }],
      rpcUrl: "http://127.0.0.1:9",
      withoutTor: true,
    }),
    /External EIP-7702 owner requires explicit UserOperation submission approval/,
  );

  assert.equal(rpcAccesses, 0);
});
