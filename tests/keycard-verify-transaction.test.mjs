import assert from "node:assert/strict";
import { test } from "node:test";
import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  verifySignedKeycardTransaction,
} from "../src/utils/keycard-verify-transaction.ts";

const account = privateKeyToAccount(`0x${"11".repeat(32)}`);

const tx = {
  type: "eip1559",
  chainId: 11155111,
  nonce: 0,
  to: "0x000000000000000000000000000000000000dEaD",
  data: "0x",
  value: 0n,
  gas: 21000n,
  maxFeePerGas: 1000000000n,
  maxPriorityFeePerGas: 100000000n,
};

const expected = {
  ...tx,
  from: account.address,
};

test("verifies complete signed Sepolia EIP-1559 payload", async () => {
  const signed = await account.signTransaction(tx);

  const hash = await verifySignedKeycardTransaction(
    signed,
    expected,
  );

  assert.equal(hash, keccak256(signed));
});

test("rejects signed transaction field mismatches", async () => {
  const signed = await account.signTransaction(tx);

  const cases = [
    [{ chainId: 31337 }, /chain ID mismatch/],
    [{ nonce: 1 }, /nonce mismatch/],
    [{ gas: 22000n }, /gas mismatch/],
    [{ value: 1n }, /value mismatch/],
    [{ data: "0x1234" }, /calldata mismatch/],
    [{
      to: "0x0000000000000000000000000000000000000001",
    }, /recipient mismatch/],
    [{ maxFeePerGas: 2000000000n }, /maximum fee mismatch/],
    [{ maxPriorityFeePerGas: 1n }, /priority fee mismatch/],
    [{
      from: "0x0000000000000000000000000000000000000001",
    }, /signer mismatch/],
  ];

  for (const [override, pattern] of cases) {
    await assert.rejects(
      verifySignedKeycardTransaction(
        signed,
        { ...expected, ...override },
      ),
      pattern,
    );
  }

  const withAccessList = await account.signTransaction({
    ...tx,
    accessList: [{
      address: tx.to,
      storageKeys: [],
    }],
  });

  await assert.rejects(
    verifySignedKeycardTransaction(
      withAccessList,
      expected,
    ),
    /access list mismatch/,
  );
});
