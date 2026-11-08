import assert from "node:assert/strict";
import {
  createHash, createCipheriv, createECDH,
  createHmac, randomBytes,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PrivacyPoolsV1_0xBow } from "@kohaku-eth/privacy-pools";
import { Prover } from "@fatsolutions/privacy-pools-core-circuits";
import { WithdrawSignalMapper } from
  "./node_modules/@fatsolutions/privacy-pools-core-circuits/dist/types.js";
import * as snarkjs from "snarkjs";
import { buildBn128, Scalar, utils as ffUtils } from "ffjavascript";

import { KEYCARD_R3_HMAC_DOMAIN } from
  "./src/utils/keycard-r3-credentials.ts";
import { createShellQrR3Provider } from
  "./src/utils/keycard-shell-qr-r3-provider.ts";
import { decodeShellBatchRequest } from
  "./src/utils/keycard-shell-qr-batch.ts";
import { deriveShellDeriveAesKey } from
  "./src/utils/keycard-shell-qr-derive-response.ts";
import {
  buildMerkleTree,
  proofFromTree,
  calculateContext,
} from "../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util.ts";
import { commitment } from
  "../kohaku-sdk-research/packages/privacy-pools/src/utils.ts";

async function verifyGroth16SingleThread(
  verificationKey,
  signals,
  groth16Proof
) {
  const vk = ffUtils.unstringifyBigInts(verificationKey);
  const inputs = ffUtils.unstringifyBigInts(signals);
  const proof = ffUtils.unstringifyBigInts(groth16Proof);

  assert.equal(vk.protocol, "groth16");
  assert.ok(
    ["bn128", "bn254", "altbn128"].includes(
      String(vk.curve).toLowerCase()
    )
  );

  assert.equal(inputs.length, 8);
  assert.equal(vk.IC.length, inputs.length + 1);

  const curve = await buildBn128(true);

  try {
    for (const input of inputs) {
      if (
        !Scalar.geq(input, 0n) ||
        !Scalar.lt(input, curve.r)
      ) {
        return false;
      }
    }

    const g1Bytes = curve.G1.F.n8 * 2;
    const scalarBytes = curve.Fr.n8;

    const points = new Uint8Array(
      g1Bytes * inputs.length
    );

    const scalars = new Uint8Array(
      scalarBytes * inputs.length
    );

    for (let i = 0; i < inputs.length; i++) {
      points.set(
        curve.G1.fromObject(vk.IC[i + 1]),
        i * g1Bytes
      );

      Scalar.toRprLE(
        scalars,
        i * scalarBytes,
        inputs[i],
        scalarBytes
      );
    }

    let publicCommitment =
      await curve.G1.multiExpAffine(
        points, scalars
      );

    publicCommitment = curve.G1.add(
      publicCommitment,
      curve.G1.fromObject(vk.IC[0])
    );

    const a = curve.G1.fromObject(proof.pi_a);
    const b = curve.G2.fromObject(proof.pi_b);
    const c = curve.G1.fromObject(proof.pi_c);

    if (
      !curve.G1.isValid(a) ||
      !curve.G2.isValid(b) ||
      !curve.G1.isValid(c)
    ) {
      return false;
    }

    return await curve.pairingEq(
      curve.G1.neg(a),
      b,
      publicCommitment,
      curve.G2.fromObject(vk.vk_gamma_2),
      c,
      curve.G2.fromObject(vk.vk_delta_2),
      curve.G1.fromObject(vk.vk_alpha_1),
      curve.G2.fromObject(vk.vk_beta_2)
    );
  } finally {
    await curve.terminate();
  }
}

const root = Buffer.alloc(32, 0x42);
const requested = [];

const exchange = async (request) => {
  const parsed = decodeShellBatchRequest(request);
  requested.push(parsed.paths);

  const shell = createECDH("secp256k1");
  shell.generateKeys();

  const publicKey = shell.getPublicKey(
    undefined, "uncompressed",
  );
  const shared = shell.computeSecret(parsed.hostPublicKey);
  const nonce = randomBytes(13);
  const key = deriveShellDeriveAesKey(
    shared, request, publicKey, nonce,
  );

  const credentials = parsed.paths.map(path =>
    createHmac("sha256", root)
      .update(KEYCARD_R3_HMAC_DOMAIN)
      .update("\0")
      .update(path)
      .digest()
  );

  const plaintext = Buffer.concat([
    Buffer.from([credentials.length]),
    ...credentials,
  ]);

  try {
    const cipher = createCipheriv(
      "aes-128-ccm",
      key,
      nonce,
      { authTagLength: 8 },
    );

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    return Buffer.concat([
      Buffer.from([0x4b, 0x4b, 0x52, 0x33, 0x03]),
      parsed.challenge,
      publicKey,
      nonce,
      ciphertext,
      cipher.getAuthTag(),
    ]);
  } finally {
    shared.fill(0);
    key.fill(0);
    plaintext.fill(0);
    credentials.forEach(value => value.fill(0));
  }
};


const provider = createShellQrR3Provider(exchange, {
  accountIndex: 0,
});

const artifactRoot = join(
  process.cwd(),
  "node_modules/kohaku-artifacts/artifacts/privacy-pools",
);

const paths = {
  withdraw: {
    wasm: "build/withdraw/withdraw_js/withdraw.wasm",
    vkey: "trusted-setup/final-keys/withdraw.vkey",
    zkey: "trusted-setup/final-keys/withdraw.zkey",
  },
  commitment: {
    wasm: "build/commitment/commitment_js/commitment.wasm",
    vkey: "trusted-setup/final-keys/commitment.vkey",
    zkey: "trusted-setup/final-keys/commitment.zkey",
  },
};

const expectedHashes = {
  [paths.withdraw.wasm]:
    "36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10",
  [paths.withdraw.zkey]:
    "2a893b42174c813566e5c40c715a8b90cd49fc4ecf384e3a6024158c3d6de677",
  [paths.withdraw.vkey]:
    "666bd0983b20c1611543b04f7712e067fbe8cad69f07ada8a310837ff398d21e",
};

const originalFetch = globalThis.fetch;
let keepAlive;

try {
  for (const [name, expected] of Object.entries(expectedHashes)) {
    const actual = createHash("sha256")
      .update(readFileSync(join(artifactRoot, name)))
      .digest("hex");
    assert.equal(actual, expected, `Artifact hash mismatch: ${name}`);
  }

  console.log("PASS: Pinned withdrawal artifacts verified");

  const coordinates = {
    chainId: 11155111n,
    entrypointAddress: BigInt(
      PrivacyPoolsV1_0xBow[11155111].entrypoint.entrypointAddress,
    ),
    depositIndex: 15,
  };

  const existing = await provider.secretManager
    .getDepositSecrets(coordinates);

  const change = await provider.secretManager
    .getSecrets({ ...coordinates, withdrawIndex: 1 });

  assert.notEqual(existing.precommitment, change.precommitment);

  assert.deepEqual(requested, [
    [
      "m/28784'/1'/0'/1'/15'/0'",
      "m/28784'/1'/0'/0'/15'/0'",
    ],
    [
      "m/28784'/1'/0'/1'/15'/1'",
      "m/28784'/1'/0'/0'/15'/1'",
    ],
  ]);

  console.log("PASS: Encrypted QR deposit and change credentials");
  console.log("PASS: Exact account 0 / deposit 15 / change 1 paths");

  const label = 123456n;
  const existingValue = 1980000000000000n;
  const withdrawnValue = 990000000000000n;
  const changeValue = existingValue - withdrawnValue;

  const existingCommitment = commitment({
    balance: existingValue,
    label,
    precommitment: existing.precommitment,
  });

  const stateTree = await buildMerkleTree([
    111n,
    existingCommitment,
    222n,
  ]);
  const state = proofFromTree(stateTree, existingCommitment);

  const aspTree = await buildMerkleTree([
    333n,
    label,
    444n,
  ]);
  const asp = proofFromTree(aspTree, label);

  assert.equal(state.siblings.length, 32);
  assert.equal(asp.siblings.length, 32);
  assert.equal(state.root, stateTree.root);
  assert.equal(asp.root, aspTree.root);

  console.log("PASS: Synthetic note and state witness");
  console.log("PASS: Synthetic ASP membership witness");

  const context = BigInt(calculateContext({
    processooor: "0x0000000000000000000000000000000000000001",
    data: "0x",
  }, 987654321n));

  const signals = {
    context,
    label,
    existingNullifier: existing.nullifier,
    existingSecret: existing.salt,
    existingValue,
    newNullifier: change.nullifier,
    newSecret: change.salt,
    withdrawnValue,
    stateIndex: BigInt(state.index),
    stateRoot: state.root,
    stateSiblings: state.siblings,
    stateTreeDepth: 32n,
    ASPIndex: BigInt(asp.index),
    ASPRoot: asp.root,
    ASPSiblings: asp.siblings,
    ASPTreeDepth: 32n,
  };

  const baseUrl =
    "https://artifacts.0000000000.org/privacy-pools/";
  const allowed = new Set(
    Object.values(paths).flatMap(x => Object.values(x)),
  );

  globalThis.fetch = async input => {
    const url = new URL(String(input));
    assert.ok(url.href.startsWith(baseUrl));
    const relative = url.href.slice(baseUrl.length);
    assert.ok(allowed.has(relative));
    return new Response(
      readFileSync(join(artifactRoot, relative)),
      { status: 200 },
    );
  };

  keepAlive = setInterval(() => {
    console.log("PROVER ACTIVE (no private inputs logged)");
  }, 30000);

  console.log("STAGE: Initialize local Groth16 prover");
  const prover = await Prover({
    baseUrl,
    ...paths,
  });

  const wasm = await prover.circuits.getWasm("withdraw");
  const witness = { type: "mem" };

  console.log("STAGE: Calculate synthetic circuit witness");
  await snarkjs.wtns.calculate(
    signals,
    wasm,
    witness,
    { memorySize: 0 },
  );

  console.log("PASS: Circuit witness calculated in memory");

  const zkey = await prover.circuits.getProvingKey("withdraw");

  console.log("STAGE: Generate Groth16 proof");
  const result = await snarkjs.groth16.prove(
    zkey,
    witness,
    undefined,
    { singleThread: true },
  );

  console.log("PASS: Groth16 proof generated");

  const mapped = WithdrawSignalMapper(result.publicSignals);
  assert.equal(mapped.withdrawnValue, withdrawnValue);
  assert.equal(mapped.stateRoot, state.root);
  assert.equal(mapped.ASPRoot, asp.root);
  assert.equal(mapped.context, context);
  assert.equal(
    mapped.existingNullifierHash,
    existing.nullifierHash,
  );
  assert.equal(
    mapped.newCommitmentHash,
    commitment({
      balance: changeValue,
      label,
      precommitment: change.precommitment,
    }),
  );

  console.log("PASS: Public signals match synthetic note");

  const vkey = JSON.parse(readFileSync(
    join(artifactRoot, paths.withdraw.vkey),
    "utf8",
  ));

  console.log("STAGE: Verify Groth16 proof");
  assert.equal(
    await verifyGroth16SingleThread(
      vkey,
      result.publicSignals,
      result.proof,
    ),
    true,
  );

  console.log("PASS: Groth16 proof independently verified");
  console.log("Account index: 0");
  console.log("Deposit index: 15");
  console.log("Change index: 1");
  console.log("Synthetic credentials: YES");
  console.log("Real wallet accessed: NO");
  console.log("Broadcast: NO");
} finally {
  if (keepAlive) clearInterval(keepAlive);
  globalThis.fetch = originalFetch;
  provider.dispose();
  root.fill(0);
}
