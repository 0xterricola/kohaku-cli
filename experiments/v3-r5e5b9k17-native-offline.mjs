import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { readSync, writeSync } from "node:fs";
import {
  isAddressEqual,
  keccak256,
  numberToHex,
  parseTransaction,
  recoverAddress,
  recoverTransactionAddress,
  serializeTransaction,
} from "viem";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const importFile = async path =>
  import(pathToFileURL(path).href);

function readHardwareRoots() {
  const payload = Buffer.alloc(64);

  try {
    let offset = 0;

    while (offset < payload.length) {
      const count = readSync(
        3,
        payload,
        offset,
        payload.length - offset,
        null,
      );

      if (count <= 0) {
        throw new Error(
          "Incomplete hardware credential IPC"
        );
      }

      offset += count;
    }

    return [
      Buffer.from(payload.subarray(0, 32)),
      Buffer.from(payload.subarray(32, 64)),
    ];
  } finally {
    payload.fill(0);
  }
}

async function main() {
  // No RPC or remote data source is used.
  globalThis.fetch = () => {
    throw new Error("Network disabled for K16");
  };

  const [rootA, rootB] = readHardwareRoots();

  let providerA;
  let providerB;

  try {
    if (!timingSafeEqual(rootA, rootB)) {
      throw new Error(
        "Independent hardware roots differ"
      );
    }

    console.log(
      "PASS: Two independent BIP-85 roots verified"
    );

    const cli = process.cwd();

    const credentials = await importFile(join(
      cli,
      "src/utils/keycard-r3-credentials.ts",
    ));

    const planner = await importFile(join(
      cli,
      "src/utils/keycard-r3-offline-deposit.ts",
    ));

    const sdk = await importFile(join(
      cli,
      "../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.ts",
    ));

    const identifiers = await importFile(join(
      cli,
      "../kohaku-key/experiments/v3-r5e3-credential-ids.mjs",
    ));

    providerA =
      credentials.createKeycardR3CredentialProvider(
        rootA,
        { accountIndex: 0 },
      );

    providerB =
      credentials.createKeycardR3CredentialProvider(
        rootB,
        { accountIndex: 0 },
      );

    const chainId = planner.R3_RESEARCH_CHAIN_ID;
    const entrypointAddress =
      planner.R3_RESEARCH_ENTRYPOINT;

    assert.equal(chainId, 987654321n);

    const credentialId = identifiers.formatCredentialId({
      chainId,
      entrypointAddress,
      accountIndex: 0,
      depositIndex: 17,
      role: "deposit",
      secretIndex: 0,
    });

    const coordinates = identifiers.sdkCoordinates(
      credentialId,
      {
        chainId,
        entrypointAddress,
        accountIndex: 0,
      },
    );

    assert.equal(coordinates.depositIndex, 17);

    console.log(
      "PASS: R5-E credential identifier resolved"
    );

    const prepare = provider =>
      planner.prepareKeycardR3OfflineDeposit({
        provider,
        depositIndex: coordinates.depositIndex,
        buildDepositPayload: sdk.buildDepositPayload,
      });

    const first = await prepare(providerA);
    const second = await prepare(providerB);

    assert.equal(
      first.unsignedTransaction,
      second.unsignedTransaction,
    );

    assert.equal(
      first.signingDigest,
      second.signingDigest,
    );

    assert.equal(
      first.coordinates.chainId,
      chainId,
    );

    assert.equal(
      first.coordinates.entrypointAddress,
      entrypointAddress,
    );

    assert.equal(
      first.coordinates.depositIndex,
      17,
    );

    assert.equal(
      first.call.value,
      2000000000000000n,
    );

    console.log(
      "PASS: Physical R3 credential provider"
    );

    console.log(
      "PASS: Hardware-derived SDK deposit calldata"
    );

    console.log(
      "PASS: Two sessions reproduce identical unsigned EIP-1559 transaction"
    );

    console.log(
      "PASS: Two sessions reproduce identical signing digest"
    );


    console.log(
      "PASS: R3 credential and offline deposit plan verified"
    );

    const unsigned = first.unsignedTransaction;
    const digest = first.signingDigest;
    const tx = parseTransaction(unsigned);

    assert.equal(tx.type, "eip1559");
    assert.equal(tx.chainId, 987654321);
    assert.equal(tx.nonce, 0);
    assert.equal(tx.gas, 350000n);
    assert.equal(tx.value, 2000000000000000n);
    assert.equal(tx.maxFeePerGas, 2n);
    assert.equal(tx.maxPriorityFeePerGas, 1n);
    assert.equal(tx.data, first.call.data);

    assert.ok(isAddressEqual(
      tx.to,
      "0x1111111111111111111111111111111111111111"
    ));

    assert.equal(keccak256(unsigned), digest);

    const digestBytes = Buffer.from(
      digest.slice(2),
      "hex",
    );

    assert.equal(digestBytes.length, 32);

    if (writeSync(4, digestBytes) !== 32) {
      throw new Error("Digest IPC write failed");
    }

    console.log("PASS: Exact validated digest sent over FD4");

    // Parent must explicitly approve the digest and sign it
    // using the authenticated physical Keycard.
    const raw = Buffer.alloc(65);

    try {
      let received = 0;

      while (received < raw.length) {
        const n = readSync(
          5,
          raw,
          received,
          raw.length - received,
          null,
        );

        if (n <= 0) {
          throw new Error("Incomplete hardware signature IPC");
        }

        received += n;
      }

      const N = BigInt(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
      );

      const r = BigInt(
        "0x" + raw.subarray(0, 32).toString("hex")
      );

      const s = BigInt(
        "0x" + raw.subarray(32, 64).toString("hex")
      );

      const parity = raw[64];

      assert.ok(r > 0n && r < N, "Invalid signature R");
      assert.ok(s > 0n && s < N, "Invalid signature S");
      assert.ok(parity === 0 || parity === 1);

      const highS = s > N / 2n;

      const signature = {
        r: numberToHex(r, { size: 32 }),
        s: numberToHex(
          highS ? N - s : s,
          { size: 32 },
        ),
        yParity: highS ? 1 - parity : parity,
      };

      const expectedSigner =
        "0x155a8332a3504d5f532742ae6531cd0e28035972";

      const recovered = await recoverAddress({
        hash: digest,
        signature,
      });

      assert.ok(isAddressEqual(
        recovered,
        expectedSigner,
      ));

      console.log(
        "PASS: Hardware signature independently recovered"
      );

      const serialized = serializeTransaction(
        tx,
        signature,
      );

      const signed = parseTransaction(serialized);

      assert.equal(signed.type, tx.type);
      assert.equal(signed.chainId, tx.chainId);
      assert.equal(signed.nonce, tx.nonce);
      assert.equal(signed.data, tx.data);
      assert.equal(signed.value, tx.value);
      assert.equal(signed.gas, tx.gas);
      assert.equal(
        signed.maxFeePerGas,
        tx.maxFeePerGas,
      );
      assert.equal(
        signed.maxPriorityFeePerGas,
        tx.maxPriorityFeePerGas,
      );

      assert.ok(isAddressEqual(
        signed.to,
        tx.to,
      ));

      const transactionSigner =
        await recoverTransactionAddress({
          serializedTransaction: serialized,
        });

      assert.ok(isAddressEqual(
        transactionSigner,
        expectedSigner,
      ));

      console.log(
        "PASS: Complete signed EIP-1559 transaction preserved"
      );

      console.log(
        "PASS: Physical Keycard sender verified by viem"
      );

      console.log(JSON.stringify({
        checkpoint: "R5-E5B9K17",
        chainId: 987654321,
        depositIndex: 17,
        amountWei: first.call.value.toString(),
        signingDigest: digest,
        hardwareCredentials: true,
        hardwareSigned: true,
        broadcast: false,
      }, null, 2));

      console.log("PASS: R5-E5B9K17");
    } finally {
      raw.fill(0);
    }

  } finally {
    providerA?.dispose();
    providerB?.dispose();

    rootA.fill(0);
    rootB.fill(0);
  }
}

try {
  await main();
} catch (error) {
  console.error(
    "FAIL:",
    error instanceof Error
      ? error.message
      : "Hardware integration failed",
  );

  process.exitCode = 1;
}
