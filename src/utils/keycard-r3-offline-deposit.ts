import {
  decodeFunctionData,
  getAddress,
  isAddressEqual,
  keccak256,
  parseAbi,
  serializeTransaction,
  toHex,
  type Hex,
  type TransactionSerializableEIP1559,
} from "viem";

import type {
  KeycardR3CredentialProvider,
} from "./keycard-r3-credentials.js";

/**
 * Synthetic-only research environment.
 *
 * Deliberately not Sepolia or Ethereum mainnet.
 */
export const R3_RESEARCH_CHAIN_ID = 987654321n;

export const R3_RESEARCH_ENTRYPOINT =
  0x1111111111111111111111111111111111111111n;

export const R3_NATIVE_ETH_ASSET =
  0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeEn;

export const R3_RESEARCH_AMOUNT = 2000000000000000n;

const NATIVE_DEPOSIT_ABI = parseAbi([
  "function deposit(uint256 _precommitment) payable",
]);

export type R3SdkDepositBuilder = (
  precommitment: bigint,
  asset: bigint,
  amount: bigint,
  entrypointAddress: bigint,
) => {
  to: string;
  data: string;
  value: bigint;
};

export type R3OfflineDepositPlan = {
  readonly coordinates: {
    readonly chainId: bigint;
    readonly entrypointAddress: bigint;
    readonly accountIndex: number;
    readonly depositIndex: number;
    readonly role: "deposit";
    readonly secretIndex: 0;
  };

  readonly call: {
    readonly to: Hex;
    readonly data: Hex;
    readonly value: bigint;
  };

  readonly unsignedTransaction: Hex;
  readonly signingDigest: Hex;
};

/**
 * Offline, unsigned Privacy Pools deposit preparation.
 *
 * The SDK builder is supplied explicitly so there is no
 * RPC, CLI wallet, submission, or software-key fallback.
 *
 * This research function has no sign/send/broadcast method.
 */
export async function prepareKeycardR3OfflineDeposit(
  input: {
    provider: KeycardR3CredentialProvider;
    depositIndex: number;
    buildDepositPayload: R3SdkDepositBuilder;
  },
): Promise<R3OfflineDepositPlan> {
  const { provider, depositIndex, buildDepositPayload } =
    input;

  if (!Number.isSafeInteger(depositIndex) ||
      depositIndex < 0) {
    throw new Error("Invalid R3 deposit index");
  }

  if (typeof buildDepositPayload !== "function") {
    throw new Error("Privacy Pools SDK builder required");
  }

  const coordinates = {
    chainId: R3_RESEARCH_CHAIN_ID,
    entrypointAddress: R3_RESEARCH_ENTRYPOINT,
    accountIndex: provider.accountIndex,
    depositIndex,
    role: "deposit" as const,
    secretIndex: 0 as const,
  };

  const secret = await provider.secretManager
    .getDepositSecrets(coordinates);

  const payload = buildDepositPayload(
    secret.precommitment,
    R3_NATIVE_ETH_ASSET,
    R3_RESEARCH_AMOUNT,
    R3_RESEARCH_ENTRYPOINT,
  );

  const expectedTo = getAddress(
    toHex(R3_RESEARCH_ENTRYPOINT, { size: 20 }),
  );

  const actualTo = getAddress(payload.to);

  if (!isAddressEqual(actualTo, expectedTo)) {
    throw new Error("SDK deposit entrypoint mismatch");
  }

  if (payload.value !== R3_RESEARCH_AMOUNT) {
    throw new Error("SDK deposit value mismatch");
  }

  if (
    typeof payload.data !== "string" ||
    !/^0x[0-9a-f]+$/i.test(payload.data)
  ) {
    throw new Error("Invalid SDK deposit calldata");
  }

  const data = payload.data as Hex;

  let decoded: ReturnType<typeof decodeFunctionData>;

  try {
    decoded = decodeFunctionData({
      abi: NATIVE_DEPOSIT_ABI,
      data,
    });
  } catch {
    throw new Error("SDK native deposit ABI mismatch");
  }

  if (
    decoded.functionName !== "deposit" ||
    decoded.args?.[0] !== secret.precommitment
  ) {
    throw new Error(
      "SDK calldata does not bind the R3 precommitment",
    );
  }

  const tx = {
    type: "eip1559",
    chainId: Number(R3_RESEARCH_CHAIN_ID),
    nonce: 0,
    to: actualTo,
    data,
    value: payload.value,
    gas: 350000n,
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
  } satisfies TransactionSerializableEIP1559;

  const unsignedTransaction = serializeTransaction(tx);

  return {
    coordinates,
    call: {
      to: actualTo,
      data,
      value: payload.value,
    },
    unsignedTransaction,
    signingDigest: keccak256(unsignedTransaction),
  };
}
