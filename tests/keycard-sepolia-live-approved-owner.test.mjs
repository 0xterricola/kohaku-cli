import assert from "node:assert/strict";
import { test } from "node:test";
import { createPublicClient, custom } from "viem";
import { privateKeyToAccount, toAccount } from "viem/accounts";
import { toSimple7702SmartAccount } from "viem/account-abstraction";
import { sepolia } from "viem/chains";

import {
  createLiveApprovedKeycardSepoliaOwner,
} from "../src/utils/keycard-sepolia-live-approved-owner.ts";

import {
  buildKeycardSepoliaUnsignedIntent,
} from "../src/utils/keycard-sepolia-unsigned-intent.ts";

import {
  SIMPLE_7702_IMPLEMENTATION,
} from "../src/utils/simple-7702.ts";

const software = privateKeyToAccount(
  `0x${"33".repeat(32)}`,
);

const calls = [
  { to: software.address, data: "0x", value: 0n },
  { to: software.address, data: "0x", value: 0n },
];

const intent = buildKeycardSepoliaUnsignedIntent({
  owner: software.address,
  chainId: sepolia.id,
  pendingEoaNonce: 1,
  delegationNeeded: true,
  calls,
}).digest;

function fixture() {
  const events = [];
  const state = {
    eoaNonce: 1,
    userOpSequence: 0n,
  };

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
      return state.eoaNonce;
    },

    async getBytecode() {
      return "0x";
    },

    async readContract({ args }) {
      const key = args[1];
      events.push(`nonce-key:${key}`);
      return (key << 64n) | state.userOpSequence;
    },
  };

  const approved = createLiveApprovedKeycardSepoliaOwner({
    client,
    owner: hardware,
    expectedOwner: software.address,
    calls,
    expectedEoaNonce: 1,
    expectedUserOpNonce: 0n,
    expectedDelegationNeeded: true,
    expectedIntentDigest: intent,

    approve: async review => {
      events.push(`approve:${review.stage}`);
      return true;
    },
  });

  return { approved, events, state };
}

test("live authorization revalidation permits fresh nonce", async () => {
  const f = fixture();

  const result = await f.approved.signAuthorization({
    address: SIMPLE_7702_IMPLEMENTATION,
    chainId: sepolia.id,
    nonce: 1,
  });

  assert.ok(result.r);
  assert.ok(
    f.events.includes("approve:eip7702-authorization"),
  );
  assert.ok(f.events.includes("hardware-auth"));
});

test("stale live nonce rejects before hardware signing", async () => {
  const f = fixture();
  f.state.eoaNonce = 2;

  await assert.rejects(
    f.approved.signAuthorization({
      address: SIMPLE_7702_IMPLEMENTATION,
      chainId: sepolia.id,
      nonce: 1,
    }),
    /Stale pending EOA nonce/,
  );

  assert.equal(f.events.includes("hardware-auth"), false);
});

test("live UserOp uses its actual nonzero nonce key", async () => {
  const f = fixture();

  const rpc = createPublicClient({
    chain: sepolia,
    transport: custom({
      async request({ method }) {
        throw new Error(`Unexpected RPC: ${method}`);
      },
    }),
  });

  const account = await toSimple7702SmartAccount({
    client: rpc,
    owner: f.approved,
    implementation: SIMPLE_7702_IMPLEMENTATION,
  });

  const callData = await account.encodeCalls(calls);
  const nonceKey = 37n;
  const nonce = nonceKey << 64n;

  const signature = await account.signUserOperation({
    sender: software.address,
    nonce,
    callData,
    callGasLimit: 100000n,
    verificationGasLimit: 150000n,
    preVerificationGas: 50000n,
    maxFeePerGas: 1000000000n,
    maxPriorityFeePerGas: 100000000n,
    signature: "0x",
    chainId: sepolia.id,
  });

  assert.match(signature, /^0x[0-9a-f]{130}$/);
  assert.ok(f.events.includes("nonce-key:37"));
  assert.ok(f.events.includes("hardware-userop"));
});

test("changed UserOp sequence rejects before hardware", async () => {
  const f = fixture();
  f.state.userOpSequence = 1n;

  const rpc = createPublicClient({
    chain: sepolia,
    transport: custom({
      async request() {
        throw new Error("NETWORK_FORBIDDEN");
      },
    }),
  });

  const account = await toSimple7702SmartAccount({
    client: rpc,
    owner: f.approved,
    implementation: SIMPLE_7702_IMPLEMENTATION,
  });

  await assert.rejects(
    account.signUserOperation({
      sender: software.address,
      nonce: 37n << 64n,
      callData: await account.encodeCalls(calls),
      callGasLimit: 100000n,
      verificationGasLimit: 150000n,
      preVerificationGas: 50000n,
      maxFeePerGas: 1000000000n,
      maxPriorityFeePerGas: 100000000n,
      signature: "0x",
      chainId: sepolia.id,
    }),
    /Stale ERC-4337 nonce/,
  );

  assert.equal(f.events.includes("hardware-userop"), false);
});
