import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createPublicClient,
  custom,
} from "viem";
import {
  privateKeyToAccount,
} from "viem/accounts";
import {
  toSimple7702SmartAccount,
} from "viem/account-abstraction";
import { sepolia } from "viem/chains";

import {
  createApprovedKeycardSepoliaOwner,
} from "../src/utils/keycard-sepolia-approved-owner.ts";

import {
  SIMPLE_7702_IMPLEMENTATION,
} from "../src/utils/simple-7702.ts";

const owner = privateKeyToAccount(
  `0x${"33".repeat(32)}`,
);

const intent = `0x${"11".repeat(32)}`;
const wrongDigest = `0x${"ff".repeat(32)}`;

function guardedOwner() {
  const approvals = [];

  const approved = createApprovedKeycardSepoliaOwner({
    owner,
    expectedOwner: owner.address,
    unsignedIntentDigest: intent,

    approve: async review => {
      approvals.push(review.stage);
      return true;
    },

    revalidate: async review => ({
      nonce: review.nonce,
      unsignedIntentDigest: review.unsignedIntentDigest,

      // Deliberately incorrect. The signing callback must
      // independently derive the digest from its payload.
      digest: wrongDigest,
    }),
  });

  return { approved, approvals };
}

test(
  "EIP-7702 digest is recomputed independently",
  async () => {
    const { approved, approvals } = guardedOwner();

    const signature = await approved.signAuthorization({
      address: SIMPLE_7702_IMPLEMENTATION,
      chainId: sepolia.id,
      nonce: 1,
    });

    assert.ok(signature.r);
    assert.ok(signature.s);
    assert.deepEqual(approvals, [
      "eip7702-authorization",
    ]);
  },
);

test(
  "ERC-4337 digest is recomputed independently",
  async () => {
    const { approved, approvals } = guardedOwner();

    const client = createPublicClient({
      chain: sepolia,
      transport: custom({
        async request({ method }) {
          throw new Error(`Unexpected RPC: ${method}`);
        },
      }),
    });

    const account = await toSimple7702SmartAccount({
      client,
      owner: approved,
      implementation: SIMPLE_7702_IMPLEMENTATION,
    });

    const calls = [
      { to: owner.address, data: "0x", value: 0n },
      { to: owner.address, data: "0x", value: 0n },
    ];

    const signature = await account.signUserOperation({
      sender: owner.address,
      nonce: 0n,
      callData: await account.encodeCalls(calls),
      callGasLimit: 100000n,
      verificationGasLimit: 150000n,
      preVerificationGas: 50000n,
      maxFeePerGas: 1000000000n,
      maxPriorityFeePerGas: 100000000n,
      signature: "0x",
      chainId: sepolia.id,
    });

    assert.match(signature, /^0x[0-9a-fA-F]{130}$/);
    assert.deepEqual(approvals, ["erc4337-userop"]);
  },
);
