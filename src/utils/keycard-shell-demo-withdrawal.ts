import assert from "node:assert/strict";

import { decodeFunctionData, getAddress } from "viem";

import { encodePoolWithdraw } from "../../../kohaku-sdk-research/packages/privacy-pools/src/paymaster/adapter-data";
import { poolAbi } from "../../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/pool.abi";
import { calculateContext } from "../../../kohaku-sdk-research/packages/privacy-pools/src/utils/proof.util";

type VerifiedWithdrawal = Parameters<typeof encodePoolWithdraw>[1] & {
  withdrawnValue: bigint;
  changeValue: bigint;
  context: bigint;
  scope: bigint;
};

export function prepareOfflineWithdrawal(
  verified: VerifiedWithdrawal,
  existingValue: bigint,
) {
  const withdrawal = {
    processooor: "0x0000000000000000000000000000000000000001",
    data: "0x",
  } as const;

  assert.equal(
    BigInt(calculateContext(withdrawal, verified.scope)),
    verified.context,
    "Withdrawal context mismatch",
  );

  assert.equal(
    verified.withdrawnValue + verified.changeValue,
    existingValue,
    "Withdrawal balance mismatch",
  );

  assert.ok(verified.withdrawnValue > 0n);
  assert.ok(verified.changeValue > 0n);
  assert.equal(verified.publicSignals.length, 8);

  const calldata = encodePoolWithdraw(withdrawal, verified);

  const decoded = decodeFunctionData({
    abi: poolAbi,
    data: calldata,
  });

  if (decoded.functionName !== "withdraw") {
    throw new Error("Unexpected withdrawal function");
  }

  assert.equal(
    getAddress(decoded.args[0].processooor),
    getAddress(withdrawal.processooor),
  );
  assert.equal(decoded.args[0].data, withdrawal.data);

  assert.equal(decoded.args[1].pubSignals.length, 8);

  for (let i = 0; i < 8; i++) {
    assert.equal(
      decoded.args[1].pubSignals[i],
      BigInt(verified.publicSignals[i]),
      "Encoded public signal mismatch",
    );
  }

  return {
    calldataBytes: (calldata.length - 2) / 2,
    publicSignalCount: decoded.args[1].pubSignals.length,
  };
}
