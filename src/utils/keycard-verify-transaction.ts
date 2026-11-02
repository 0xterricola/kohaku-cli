import {
  isAddressEqual,
  keccak256,
  parseTransaction,
  recoverTransactionAddress,
  type Address,
  type Hex,
} from "viem";

export type ExpectedKeycardTransaction = {
  from: Address;
  to: Address;
  chainId: number;
  nonce: number;
  gas: bigint;
  value: bigint;
  data: Hex;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
};

export async function verifySignedKeycardTransaction(
  signed: Hex,
  expected: ExpectedKeycardTransaction,
): Promise<Hex> {
  if (!signed.startsWith("0x02")) {
    throw new Error("Expected signed EIP-1559 transaction.");
  }

  const tx = parseTransaction(signed);

  function check(condition: boolean, field: string) {
    if (!condition) {
      throw new Error(`Signed transaction ${field} mismatch.`);
    }
  }

  check(tx.type === "eip1559", "type");
  check(tx.chainId === expected.chainId, "chain ID");
  check(tx.nonce === expected.nonce, "nonce");
  check(tx.gas === expected.gas, "gas");
  check((tx.value ?? 0n) === expected.value, "value");
  check(
    (tx.data ?? "0x").toLowerCase() ===
      expected.data.toLowerCase(),
    "calldata",
  );
  check(
    !!tx.to && isAddressEqual(tx.to, expected.to),
    "recipient",
  );
  check(
    tx.maxFeePerGas === expected.maxFeePerGas,
    "maximum fee",
  );
  check(
    tx.maxPriorityFeePerGas === expected.maxPriorityFeePerGas,
    "priority fee",
  );
  check(
    (tx.accessList?.length ?? 0) === 0,
    "access list",
  );

  const recovered = await recoverTransactionAddress({
    serializedTransaction: signed as `0x02${string}`,
  });

  check(
    isAddressEqual(recovered, expected.from),
    "signer",
  );

  return keccak256(signed);
}
