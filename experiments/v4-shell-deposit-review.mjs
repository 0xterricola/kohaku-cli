import assert from "node:assert/strict";
import {
  decodeFunctionData,
  getAddress,
  isAddressEqual,
  toHex,
} from "viem";
import { PrivacyPoolsV1_0xBow } from "@kohaku-eth/privacy-pools";

import { createShellQrR3Provider } from
  "./src/utils/keycard-shell-qr-r3-provider.ts";
import { exchangeShellQr } from
  "./src/utils/keycard-shell-qr-exchange.ts";
import { buildDepositPayload } from
  "../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector.ts";
import { entrypointDepositNativeAbi } from
  "../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi.ts";

const synthetic = process.argv.includes("--synthetic");
const shell = process.argv.includes("--shell");

assert.notEqual(
  synthetic, shell,
  "Specify exactly one of --synthetic or --shell",
);

const chainId = 11155111n;
const accountIndex = 0;
const depositIndex = 15;
const withdrawalIndex = 0;
const amount = 2000000000000000n;
const asset = BigInt(
  "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
);

const config = PrivacyPoolsV1_0xBow[Number(chainId)];
assert.ok(config?.entrypoint?.entrypointAddress);

const entrypointAddress = BigInt(
  config.entrypoint.entrypointAddress,
);
const entrypoint = getAddress(
  toHex(entrypointAddress, { size: 20 }),
);

const coordinates = {
  chainId,
  entrypointAddress,
  depositIndex,
};

let providerA;
let providerB;

try {
  let precommitment;

  if (synthetic) {
    // Public test value, not a wallet credential.
    precommitment = 12345678901234567890n;
    console.log("MODE: Synthetic SDK validation");
  } else {
    providerA = createShellQrR3Provider(
      exchangeShellQr,
      { accountIndex },
    );
    providerB = createShellQrR3Provider(
      exchangeShellQr,
      { accountIndex },
    );

    const first = await providerA.secretManager
      .getDepositSecrets(coordinates);

    const second = await providerB.secretManager
      .getDepositSecrets(coordinates);

    assert.equal(
      first.precommitment,
      second.precommitment,
    );
    assert.equal(first.nullifier, second.nullifier);
    assert.equal(first.salt, second.salt);

    precommitment = first.precommitment;
    console.log("PASS: Independent Shell QR recovery");
  }

  const payloadA = buildDepositPayload(
    precommitment,
    asset,
    amount,
    entrypointAddress,
  );

  const payloadB = buildDepositPayload(
    precommitment,
    asset,
    amount,
    entrypointAddress,
  );

  assert.equal(payloadA.data, payloadB.data);
  assert.equal(payloadA.value, amount);
  assert.ok(
    isAddressEqual(getAddress(payloadA.to), entrypoint),
  );

  const decoded = decodeFunctionData({
    abi: entrypointDepositNativeAbi,
    data: payloadA.data,
  });

  assert.equal(decoded.functionName, "deposit");
  assert.deepEqual(decoded.args, [precommitment]);

  console.log("PASS: SDK deposit calldata reproduced");
  console.log("PASS: Deposit ABI decoded correctly");
  console.log("PASS: Entrypoint and ETH value verified");
  console.log("Chain:", Number(chainId));
  console.log("Entrypoint:", entrypoint);
  console.log("Account index:", accountIndex);
  console.log("Deposit index:", depositIndex);
  console.log("Withdrawal index:", withdrawalIndex);
  console.log("Signed: NO");
  console.log("Broadcast: NO");
  console.log("Credentials persisted: NO");
} finally {
  providerA?.dispose();
  providerB?.dispose();
}
