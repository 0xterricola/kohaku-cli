import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createPublicClient,
  custom,
  keccak256,
} from "viem";
import { sepolia, mainnet } from "viem/chains";
import {
  prepareKeycardSepoliaUnsignedDraft as prepare,
} from "../src/utils/keycard-sepolia-unsigned-draft.ts";

const owner = "0xB8A0f79E6d64c948E9F5ea32aD93647777915EBa";

const calls = [
  { to: owner, data: "0x", value: 0n },
  { to: owner, data: "0x", value: 0n },
];

function fixture(chain = sepolia) {
  const methods = [];

  const client = createPublicClient({
    chain,
    transport: custom({
      async request({ method }) {
        methods.push(method);

        if (method === "eth_call") {
          return `0x${"0".repeat(64)}`;
        }

        if (method === "eth_chainId") {
          return `0x${chain.id.toString(16)}`;
        }

        throw new Error(`Unexpected RPC: ${method}`);
      },
    }),
  });

  return { client, methods };
}

test("resolves unsigned nonce and calldata without signing", async () => {
  const { client, methods } = fixture();

  const result = await prepare({ client, owner, calls });

  assert.equal(result.sender, owner);
  assert.equal(result.entryPointVersion, "0.8");
  assert.equal(result.nonceKey, "0");
  assert.equal(result.userOperationNonce, "0");
  assert.equal(result.callDataHash, keccak256(result.callData));
  assert.equal(result.stubSignatureBytes, 65);

  assert.equal(result.authorizationSigned, false);
  assert.equal(result.signingPerformed, false);
  assert.equal(result.submissionPerformed, false);

  assert.ok(methods.includes("eth_call"));
  assert.ok(methods.every(
    method => method === "eth_call" || method === "eth_chainId"
  ));
});

test("rejects non-Sepolia chains before RPC", async () => {
  const { client, methods } = fixture(mainnet);

  await assert.rejects(
    prepare({ client, owner, calls }),
    /requires Sepolia/,
  );

  assert.equal(methods.length, 0);
});

test("rejects insufficient batch calls before RPC", async () => {
  const { client, methods } = fixture();

  await assert.rejects(
    prepare({ client, owner, calls: [calls[0]] }),
    /at least two calls/,
  );

  assert.equal(methods.length, 0);
});
