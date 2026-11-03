import assert from "node:assert/strict";
import { test } from "node:test";
import {
  signWithKeycardApproval as gate,
} from "../src/utils/keycard-sepolia-signing-gate.ts";

const owner = "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";
const other = "0x0000000000000000000000000000000000000001";

const review = {
  stage: "eip7702-authorization",
  chainId: 11155111,
  owner,
  expectedOwner: owner,
  nonce: 1n,
  digest: `0x${"11".repeat(32)}`,
  unsignedIntentDigest: `0x${"22".repeat(32)}`,
};

function fixture(overrides = {}) {
  const events = [];

  const opts = {
    review,
    approve: async () => {
      events.push("approve");
      return true;
    },
    revalidate: async snapshot => {
      events.push("revalidate");
      return {
        nonce: snapshot.nonce,
        digest: snapshot.digest,
        unsignedIntentDigest: snapshot.unsignedIntentDigest,
      };
    },
    sign: async digest => {
      events.push("sign");
      assert.equal(digest, review.digest);
      return "mock-signature";
    },
    ...overrides,
  };

  return { opts, events };
}

test("approval precedes revalidation and signing", async () => {
  const { opts, events } = fixture();

  assert.equal(await gate(opts), "mock-signature");

  assert.deepEqual(events, [
    "approve",
    "revalidate",
    "sign",
  ]);
});

test("denied approval never signs", async () => {
  const { opts, events } = fixture({
    approve: async () => {
      events.push("decline");
      return false;
    },
  });

  await assert.rejects(gate(opts), /approval declined/);
  assert.deepEqual(events, ["decline"]);
});

test("stale nonce blocks signing", async () => {
  const { opts, events } = fixture({
    revalidate: async snapshot => {
      events.push("revalidate");
      return {
        nonce: snapshot.nonce + 1n,
        digest: snapshot.digest,
        unsignedIntentDigest: snapshot.unsignedIntentDigest,
      };
    },
  });

  await assert.rejects(gate(opts), /stale/);
  assert.deepEqual(events, ["approve", "revalidate"]);
});

test("changed signing digest blocks signing", async () => {
  const { opts, events } = fixture({
    revalidate: async snapshot => {
      events.push("revalidate");
      return {
        nonce: snapshot.nonce,
        digest: `0x${"33".repeat(32)}`,
        unsignedIntentDigest: snapshot.unsignedIntentDigest,
      };
    },
  });

  await assert.rejects(gate(opts), /stale/);
  assert.deepEqual(events, ["approve", "revalidate"]);
});

test("changed unsigned intent blocks signing", async () => {
  const { opts, events } = fixture({
    revalidate: async snapshot => {
      events.push("revalidate");
      return {
        nonce: snapshot.nonce,
        digest: snapshot.digest,
        unsignedIntentDigest: `0x${"44".repeat(32)}`,
      };
    },
  });

  await assert.rejects(gate(opts), /stale/);
  assert.deepEqual(events, ["approve", "revalidate"]);
});

test("incorrect hardware owner fails before approval", async () => {
  const { opts, events } = fixture({
    review: { ...review, expectedOwner: other },
  });

  await assert.rejects(gate(opts), /owner mismatch/);
  assert.deepEqual(events, []);
});

test("invalid chain and digest fail before approval", async () => {
  const { opts, events } = fixture();

  await assert.rejects(
    gate({ ...opts, review: { ...review, chainId: 1 } }),
    /requires Sepolia/,
  );

  await assert.rejects(
    gate({ ...opts, review: { ...review, digest: "0x12" } }),
    /Invalid signing review digest/,
  );

  assert.deepEqual(events, []);
});

test("authorization and UserOp require separate approvals", async () => {
  const approvals = [];

  for (const stage of [
    "eip7702-authorization",
    "erc4337-userop",
  ]) {
    const { opts } = fixture({
      review: { ...review, stage },
      approve: async snapshot => {
        approvals.push(snapshot.stage);
        return true;
      },
    });

    await gate(opts);
  }

  assert.deepEqual(approvals, [
    "eip7702-authorization",
    "erc4337-userop",
  ]);
});

test("revalidation errors never reach signing", async () => {
  const { opts, events } = fixture({
    revalidate: async () => {
      events.push("revalidate");
      throw new Error("RPC unavailable");
    },
  });

  await assert.rejects(gate(opts), /RPC unavailable/);
  assert.deepEqual(events, ["approve", "revalidate"]);
});
