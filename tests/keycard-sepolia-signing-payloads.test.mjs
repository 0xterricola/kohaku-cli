import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createPublicClient,
  custom,
  hashTypedData,
} from "viem";
import { hashAuthorization } from "viem/utils";
import { toAccount } from "viem/accounts";
import { toSimple7702SmartAccount } from "viem/account-abstraction";
import { sepolia } from "viem/chains";

const owner =
  "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";

const implementation =
  "0xe6Cae83BdE06E4c305530e199D7217f42808555B";

test("EIP-7702 digest binds chain, nonce and delegate", () => {
  const authorization = {
    contractAddress: implementation,
    chainId: sepolia.id,
    nonce: 1,
  };

  const digest = hashAuthorization(authorization);

  assert.match(digest, /^0x[0-9a-f]{64}$/);

  assert.notEqual(
    digest,
    hashAuthorization({ ...authorization, nonce: 2 }),
  );

  assert.notEqual(
    digest,
    hashAuthorization({ ...authorization, chainId: 1 }),
  );

  assert.notEqual(
    digest,
    hashAuthorization({
      ...authorization,
      contractAddress:
        "0x0000000000000000000000000000000000000001",
    }),
  );
});

test("actual Viem UserOp typed-data digest binds nonce and gas", async () => {
  const captured = [];
  let networkCalls = 0;

  const signer = toAccount({
    address: owner,

    async signTypedData(payload) {
      captured.push(payload);
      throw new Error("MOCK_SIGN_BLOCKED");
    },

    async signAuthorization() {
      throw new Error("UNEXPECTED_AUTHORIZATION");
    },

    async signMessage() {
      throw new Error("UNEXPECTED_MESSAGE_SIGNING");
    },

    async signTransaction() {
      throw new Error("UNEXPECTED_TRANSACTION_SIGNING");
    },
  });

  const client = createPublicClient({
    chain: sepolia,
    transport: custom({
      async request({ method }) {
        networkCalls++;
        throw new Error(`NETWORK_FORBIDDEN: ${method}`);
      },
    }),
  });

  const account = await toSimple7702SmartAccount({
    client,
    owner: signer,
    implementation,
  });

  const calls = [
    { to: owner, data: "0x", value: 0n },
    { to: owner, data: "0x", value: 0n },
  ];

  const callData = await account.encodeCalls(calls);

  async function captureDigest(nonce, callGasLimit) {
    const before = captured.length;

    await assert.rejects(
      account.signUserOperation({
        sender: owner,
        nonce,
        callData,
        callGasLimit,
        verificationGasLimit: 150000n,
        preVerificationGas: 50000n,
        maxFeePerGas: 1000000000n,
        maxPriorityFeePerGas: 100000000n,
        signature: "0x",
        chainId: sepolia.id,
      }),
      /MOCK_SIGN_BLOCKED/,
    );

    assert.equal(captured.length, before + 1);
    return hashTypedData(captured.at(-1));
  }

  const original = await captureDigest(0n, 100000n);
  const differentNonce = await captureDigest(1n, 100000n);
  const differentGas = await captureDigest(0n, 110000n);

  assert.match(original, /^0x[0-9a-f]{64}$/);
  assert.notEqual(original, differentNonce);
  assert.notEqual(original, differentGas);
  assert.equal(networkCalls, 0);

  console.log(JSON.stringify({
    mode: "mock-userop-signing-payload-verification",
    primaryType: captured[0].primaryType,
    domain: captured[0].domain,
    typedDataDigest: original,
    nonceMutationRejected: true,
    gasMutationRejected: true,
    actualSignaturesProduced: 0,
    networkCalls,
  }, (_, value) =>
    typeof value === "bigint" ? value.toString() : value,
  2));
});
