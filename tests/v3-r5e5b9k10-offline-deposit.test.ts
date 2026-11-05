import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  decodeFunctionData,
  defineChain,
  getAddress,
  type Hex,
  isAddressEqual,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  serializeTransaction,
} from "viem";

import { privateKeyToAccount, toAccount } from "viem/accounts";

import { buildDepositPayload } from
  "../../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.js";

import { entrypointDepositNativeAbi } from
  "../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi.js";

import { makeWalletClient } from "../src/utils/viem-tx.js";

const sdkIndex = join(
  process.env.HOME!,
  "Developer/kohaku-sdk-research/packages/privacy-pools/dist/index.js"
);

const idsPath = join(
  process.env.HOME!,
  "Developer/kohaku-key/experiments/v3-r5e3-credential-ids.mjs"
);

const { SecretManager } = await import(pathToFileURL(sdkIndex).href);
const { formatCredentialId, sdkCoordinates } =
  await import(pathToFileURL(idsPath).href);

const domain = "kohaku-key/v3-r3/privacy-pools-v1/deriveAt";

function keystore(root: Buffer) {
  return {
    async deriveAt(path: string) {
      assert.match(path, /^m\/28784'\/1'(?:\/[0-9]+')+$/);
      return "0x" + createHmac("sha256", root)
        .update(domain)
        .update("\0")
        .update(path)
        .digest("hex");
    },
  };
}

function manager(root: Buffer, accountIndex = 0) {
  return SecretManager({
    host: { keystore: keystore(root) },
    accountIndex,
  });
}

test("R3 credentials bind deterministically to SDK deposit and EIP-1559", async () => {
  // Public, deterministic research fixtures only.
  const root = createHash("sha256")
    .update("kohaku-key/r5-e5b9k10/public-test-root")
    .digest();

  const wrongRoot = createHash("sha256")
    .update("kohaku-key/r5-e5b9k10/wrong-test-root")
    .digest();

  const chainId = 987654321n;
  const entrypoint =
    0x1111111111111111111111111111111111111111n;
  const asset =
    0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeEn;
  const amount = 2000000000000000n;

  const id = formatCredentialId({
    chainId,
    entrypointAddress: entrypoint,
    accountIndex: 0,
    depositIndex: 17,
    role: "deposit",
    secretIndex: 0,
  });

  const coordinates = sdkCoordinates(id, {
    chainId,
    entrypointAddress: entrypoint,
    accountIndex: 0,
  });

  assert.equal(coordinates.depositIndex, 17);

  const first = await manager(root)
    .getDepositSecrets(coordinates);

  const second = await manager(Buffer.from(root))
    .getDepositSecrets(coordinates);

  const wrong = await manager(wrongRoot)
    .getDepositSecrets(coordinates);

  const next = await manager(root)
    .getDepositSecrets({
      ...coordinates,
      depositIndex: 18,
    });

  const otherChain = await manager(root)
    .getDepositSecrets({
      ...coordinates,
      chainId: chainId + 1n,
    });

  assert.equal(first.precommitment, second.precommitment);
  assert.notEqual(first.precommitment, wrong.precommitment);
  assert.notEqual(first.precommitment, next.precommitment);
  assert.notEqual(first.precommitment, otherChain.precommitment);

  console.log("PASS: R3 HMAC derivation reproduced");
  console.log("PASS: Credential identifier mapping");
  console.log("PASS: Root, deposit-index and chain separation");

  const payload = buildDepositPayload(
    first.precommitment,
    asset,
    amount,
    entrypoint
  );

  const repeated = buildDepositPayload(
    second.precommitment,
    asset,
    amount,
    entrypoint
  );

  const wrongPayload = buildDepositPayload(
    wrong.precommitment,
    asset,
    amount,
    entrypoint
  );

  assert.equal(payload.value, amount);
  assert.equal(payload.data, repeated.data);
  assert.notEqual(payload.data, wrongPayload.data);

  const decoded = decodeFunctionData({
    abi: entrypointDepositNativeAbi,
    data: payload.data as Hex,
  });

  assert.equal(decoded.functionName, "deposit");
  assert.deepEqual(decoded.args, [first.precommitment]);

  console.log("PASS: Native SDK deposit calldata");
  console.log("PASS: Hardware-compatible precommitment contract");

  const chain = defineChain({
    id: Number(chainId),
    name: "Kohaku Synthetic",
    nativeCurrency: {
      name: "Fixture Ether",
      symbol: "TETH",
      decimals: 18,
    },
    rpcUrls: {
      default: {
        http: ["http://127.0.0.1:8545"],
      },
    },
  });

  // Public private-key-1 software fixture.
  const software = privateKeyToAccount(
    `0x${"0".repeat(63)}1`
  );

  let signingCalls = 0;

  const external = toAccount({
    address: software.address,
    signMessage: args => software.signMessage(args),
    signTypedData: args => software.signTypedData(args),

    async signTransaction(tx, options) {
      signingCalls++;
      return software.signTransaction(tx, options);
    },
  });

  const wallet = makeWalletClient(
    external,
    { chain } as unknown as Parameters<typeof makeWalletClient>[1],
    "http://127.0.0.1:8545"
  );

  assert.strictEqual(wallet.account, external);

  const tx = {
    type: "eip1559" as const,
    chainId: Number(chainId),
    nonce: 0,
    to: getAddress(payload.to),
    data: payload.data as Hex,
    value: payload.value,
    gas: 350000n,
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
  };

  const digest = keccak256(serializeTransaction(tx));
  const signed = await external.signTransaction(tx);
  assert.match(signed, /^0x02[0-9a-f]+$/i);

  assert.equal(signingCalls, 1);

  const parsed = parseTransaction(signed);

  assert.equal(parsed.type, "eip1559");
  assert.equal(parsed.chainId, tx.chainId);
  assert.equal(parsed.nonce, tx.nonce);
  assert.equal(parsed.to?.toLowerCase(), tx.to.toLowerCase());
  assert.equal(parsed.data, tx.data);
  assert.equal(parsed.value, amount);
  assert.equal(parsed.gas, tx.gas);

  assert.ok(isAddressEqual(
    await recoverTransactionAddress({
      serializedTransaction: signed as `0x02${string}`,
    }),
    software.address
  ));

  assert.notEqual(
    digest,
    keccak256(serializeTransaction({
      ...tx,
      data: wrongPayload.data as Hex,
    }))
  );

  console.log("PASS: External viem signer delegation");
  console.log("PASS: Complete EIP-1559 serialization");
  console.log("PASS: Independent signer recovery");
  console.log("PASS: Credential mutation changes digest");
  console.log("Hardware used: NO");
  console.log("Real credentials used: NO");
  console.log("Network requests: NO");
  console.log("Broadcasting: DISABLED");
  console.log("PASS: R5-E5B9K10");
});
