import assert from "node:assert/strict";
import { test } from "node:test";
import {
  verifyKeycardSepoliaLiveState as verify,
} from "../src/utils/keycard-sepolia-live-state.ts";
import {
  buildKeycardSepoliaUnsignedIntent,
} from "../src/utils/keycard-sepolia-unsigned-intent.ts";

const owner =
  "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";

const calls = [
  { to: owner, data: "0x", value: 0n },
  { to: owner, data: "0x", value: 0n },
];

const digest = buildKeycardSepoliaUnsignedIntent({
  owner,
  chainId: 11155111,
  pendingEoaNonce: 1,
  delegationNeeded: true,
  calls,
}).digest;

const base = {
  owner,
  calls,
  expectedEoaNonce: 1,
  expectedUserOpNonce: 0n,
  expectedDelegationNeeded: true,
  expectedIntentDigest: digest,
  review: {
    stage: "eip7702-authorization",
    chainId: 11155111,
    owner,
    expectedOwner: owner,
    nonce: 1n,
    digest: `0x${"11".repeat(32)}`,
    unsignedIntentDigest: digest,
  },
};

function fixture(overrides = {}) {
  const events = [];
  const state = {
    chainId: 11155111,
    eoaNonce: 1,
    userOpNonce: 0n,
    code: "0x",
    ...overrides,
  };

  const client = {
    async getChainId() {
      events.push("chain");
      return state.chainId;
    },
    async getTransactionCount() {
      events.push("eoa");
      return state.eoaNonce;
    },
    async readContract() {
      events.push("entrypoint");
      return state.userOpNonce;
    },
    async getBytecode() {
      events.push("code");
      return state.code;
    },
  };

  return { client, events };
}

test("fresh authorization state passes", async () => {
  const { client, events } = fixture();
  const result = await verify({ ...base, client });

  assert.equal(result.nonce, 1n);
  assert.equal(result.userOperationNonce, 0n);
  assert.equal(result.unsignedIntentDigest, digest);
  assert.deepEqual(events, [
    "chain", "eoa", "entrypoint", "code",
  ]);
});

test("fresh UserOperation state passes", async () => {
  const { client } = fixture();

  const result = await verify({
    ...base,
    client,
    review: {
      ...base.review,
      stage: "erc4337-userop",
      nonce: 0n,
    },
  });

  assert.equal(result.nonce, 0n);
});

test("stale EOA nonce fails", async () => {
  const { client } = fixture({ eoaNonce: 2 });

  await assert.rejects(
    verify({ ...base, client }),
    /Stale pending EOA nonce/,
  );
});

test("stale UserOperation nonce fails", async () => {
  const { client } = fixture({ userOpNonce: 1n });

  await assert.rejects(
    verify({ ...base, client }),
    /Stale ERC-4337 nonce/,
  );
});

test("unexpected delegation fails", async () => {
  const { client } = fixture({
    code: "0x60016000",
  });

  await assert.rejects(
    verify({ ...base, client }),
    /Incompatible account delegation/,
  );
});

test("modified intent fails", async () => {
  const { client } = fixture();

  await assert.rejects(
    verify({
      ...base,
      client,
      calls: [
        calls[0],
        { ...calls[1], value: 1n },
      ],
    }),
    /Unsigned intent changed/,
  );
});

test("wrong RPC chain fails before state reads", async () => {
  const { client, events } = fixture({
    chainId: 1,
  });

  await assert.rejects(
    verify({ ...base, client }),
    /Live RPC is not Sepolia/,
  );

  assert.deepEqual(events, ["chain"]);
});

test("incorrect review nonce fails before RPC", async () => {
  const { client, events } = fixture();

  await assert.rejects(
    verify({
      ...base,
      client,
      review: { ...base.review, nonce: 99n },
    }),
    /Signing review nonce mismatch/,
  );

  assert.deepEqual(events, []);
});
