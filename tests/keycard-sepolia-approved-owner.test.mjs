import assert from "node:assert/strict";
import { test } from "node:test";
import { createPublicClient, custom } from "viem";
import { toAccount, privateKeyToAccount } from "viem/accounts";
import { toSimple7702SmartAccount } from "viem/account-abstraction";
import { sepolia } from "viem/chains";
import {
  createApprovedKeycardSepoliaOwner,
} from "../src/utils/keycard-sepolia-approved-owner.ts";
import { SIMPLE_7702_IMPLEMENTATION } from "../src/utils/simple-7702.ts";

const software = privateKeyToAccount(
  `0x${"33".repeat(32)}`,
);

const intent = `0x${"22".repeat(32)}`;

function fixture() {
  const events = [];
  let allow = true;
  let freshNonce;

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
    signTransaction: (tx, options) =>
      software.signTransaction(tx, options),
  });

  const approved = createApprovedKeycardSepoliaOwner({
    owner: hardware,
    expectedOwner: software.address,
    unsignedIntentDigest: intent,

    approve: async review => {
      events.push(`approve:${review.stage}`);
      return allow;
    },

    revalidate: async review => {
      events.push(`revalidate:${review.stage}`);

      // Test-only state. Production must independently
      // recompute the digest and read fresh chain state.
      return {
        nonce: freshNonce ?? review.nonce,
        digest: review.digest,
        unsignedIntentDigest: intent,
      };
    },
  });

  return {
    approved,
    events,
    deny: () => { allow = false; },
    setFreshNonce: nonce => { freshNonce = nonce; },
  };
}

test("EIP-7702 authorization requires approval", async () => {
  const f = fixture();

  const signed = await f.approved.signAuthorization({
    address: SIMPLE_7702_IMPLEMENTATION,
    chainId: sepolia.id,
    nonce: 1,
  });

  assert.ok(signed.r);
  assert.deepEqual(f.events, [
    "approve:eip7702-authorization",
    "revalidate:eip7702-authorization",
    "hardware-authorization",
  ]);
});

test("denial prevents hardware authorization", async () => {
  const f = fixture();
  f.deny();

  await assert.rejects(
    f.approved.signAuthorization({
      address: SIMPLE_7702_IMPLEMENTATION,
      chainId: sepolia.id,
      nonce: 1,
    }),
    /approval declined/,
  );

  assert.deepEqual(f.events, [
    "approve:eip7702-authorization",
  ]);
});

test("stale authorization nonce blocks hardware", async () => {
  const f = fixture();
  f.setFreshNonce(2n);

  await assert.rejects(
    f.approved.signAuthorization({
      address: SIMPLE_7702_IMPLEMENTATION,
      chainId: sepolia.id,
      nonce: 1,
    }),
    /stale/,
  );

  assert.equal(
    f.events.includes("hardware-authorization"),
    false,
  );
});

test("foreign delegation fails before approval", async () => {
  const f = fixture();

  await assert.rejects(
    f.approved.signAuthorization({
      address: "0x0000000000000000000000000000000000000001",
      chainId: sepolia.id,
      nonce: 1,
    }),
    /Unexpected EIP-7702 delegate/,
  );

  assert.deepEqual(f.events, []);
});

test("real Viem UserOp passes through approval", async () => {
  const f = fixture();
  let networkCalls = 0;

  const client = createPublicClient({
    chain: sepolia,
    transport: custom({
      async request() {
        networkCalls++;
        throw new Error("NETWORK_FORBIDDEN");
      },
    }),
  });

  const account = await toSimple7702SmartAccount({
    client,
    owner: f.approved,
    implementation: SIMPLE_7702_IMPLEMENTATION,
  });

  const callData = await account.encodeCalls([
    { to: software.address, data: "0x", value: 0n },
    { to: software.address, data: "0x", value: 0n },
  ]);

  const signature = await account.signUserOperation({
    sender: software.address,
    nonce: 0n,
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
  assert.deepEqual(f.events, [
    "approve:erc4337-userop",
    "revalidate:erc4337-userop",
    "hardware-userop",
  ]);
  assert.equal(networkCalls, 0);
});

test("EIP-191 and transaction signing are blocked", async () => {
  const f = fixture();

  await assert.rejects(
    f.approved.signMessage({ message: "test" }),
    /not permitted/,
  );

  await assert.rejects(
    f.approved.signTransaction({}),
    /not permitted/,
  );

  assert.deepEqual(f.events, []);
});
