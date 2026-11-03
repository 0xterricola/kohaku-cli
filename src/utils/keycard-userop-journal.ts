import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";
import { getAddress, type Address, type Hash } from "viem";

/**
 * Persist a hardware UserOperation submission attempt before broadcasting.
 *
 * The record is deliberately conservative: creation does not mean the
 * bundler received the operation. An existing record blocks resubmission
 * until its status is independently reconciled.
 */
export function recordKeycardUserOpAttempt(opts: {
  directory: string;
  userOpHash: Hash;
  owner: Address;
  chainId: number;
}): string {
  if (!isAbsolute(opts.directory)) {
    throw new Error("Submission journal requires an absolute directory.");
  }

  if (!/^0x[0-9a-fA-F]{64}$/.test(opts.userOpHash)) {
    throw new Error("Invalid UserOperation hash.");
  }

  if (opts.chainId !== 11155111) {
    throw new Error("Hardware submission journal supports Sepolia only.");
  }

  const owner = getAddress(opts.owner);
  const hash = opts.userOpHash.toLowerCase();

  mkdirSync(opts.directory, {
    recursive: true,
    mode: 0o700,
  });

  const filename = join(
    opts.directory,
    `sepolia-userop-${hash}.json`,
  );

  const record = {
    kind: "keycard-userop-submission-attempt",
    status: "outcome-unknown",
    chainId: opts.chainId,
    userOpHash: hash,
    owner,
    createdAt: new Date().toISOString(),
  };

  let fd: number;

  try {
    fd = openSync(filename, "wx", 0o600);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      error.code === "EEXIST"
    ) {
      throw new Error(
        `UserOperation already recorded: ${hash}. ` +
        "Reconcile on-chain status before another submission.",
        { cause: error },
      );
    }

    throw error;
  }

  try {
    const data = Buffer.from(
      JSON.stringify(record, null, 2) + "\n",
    );

    let offset = 0;

    while (offset < data.length) {
      const written = writeSync(
        fd,
        data,
        offset,
        data.length - offset,
      );

      if (written <= 0) {
        throw new Error("Submission journal write failed.");
      }

      offset += written;
    }

    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }

  return filename;
}

import { randomBytes } from "node:crypto";
import {
  readFileSync,
  renameSync,
  unlinkSync,
} from "node:fs";
import {
  decodeEventLog,
  isAddressEqual,
  parseAbiItem,
  type PublicClient,
} from "viem";

const KEYCARD_ENTRYPOINT_V08 =
  "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";

const KEYCARD_USEROP_EVENT = parseAbiItem(
  "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)",
);

/**
 * Reconcile an existing journal against a confirmed Sepolia
 * transaction and its exact ERC-4337 EntryPoint event.
 *
 * Never sends, signs, retries, or creates submission attempts.
 */
export async function reconcileKeycardUserOpReceipt(opts: {
  directory: string;
  userOpHash: Hash;
  txHash: Hash;
  client: Pick<PublicClient, "getChainId" | "getTransactionReceipt">;
}): Promise<string> {
  if (!isAbsolute(opts.directory)) {
    throw new Error("Journal directory must be absolute.");
  }

  if (
    !/^0x[0-9a-fA-F]{64}$/.test(opts.userOpHash) ||
    !/^0x[0-9a-fA-F]{64}$/.test(opts.txHash)
  ) {
    throw new Error("Invalid reconciliation hash.");
  }

  const hash = opts.userOpHash.toLowerCase();
  const filename = join(
    opts.directory,
    `sepolia-userop-${hash}.json`,
  );

  const original = readFileSync(filename, "utf8");
  const record = JSON.parse(original);

  if (
    record.kind !== "keycard-userop-submission-attempt" ||
    record.chainId !== 11155111 ||
    record.userOpHash?.toLowerCase() !== hash ||
    typeof record.owner !== "string" ||
    !record.createdAt
  ) {
    throw new Error("Journal identity mismatch.");
  }

  const owner = getAddress(record.owner);

  if (
    record.status !== "outcome-unknown" &&
    record.status !== "confirmed"
  ) {
    throw new Error("Unsupported journal status.");
  }

  if (
    record.status === "confirmed" &&
    record.txHash?.toLowerCase() !== opts.txHash.toLowerCase()
  ) {
    throw new Error("Conflicting confirmed transaction.");
  }

  if (await opts.client.getChainId() !== 11155111) {
    throw new Error("Reconciliation RPC is not Sepolia.");
  }

  const receipt = await opts.client.getTransactionReceipt({
    hash: opts.txHash,
  });

  if (
    receipt.transactionHash.toLowerCase() !==
      opts.txHash.toLowerCase() ||
    receipt.status !== "success"
  ) {
    throw new Error("Transaction receipt is not successful.");
  }

  let matched:
    | {
        nonce: bigint;
        actualGasCost: bigint;
        actualGasUsed: bigint;
      }
    | undefined;

  for (const log of receipt.logs) {
    if (
      log.address.toLowerCase() !==
      KEYCARD_ENTRYPOINT_V08.toLowerCase()
    ) {
      continue;
    }

    let decoded;

    try {
      decoded = decodeEventLog({
        abi: [KEYCARD_USEROP_EVENT],
        data: log.data,
        topics: log.topics,
      });
    } catch {
      continue;
    }

    if (decoded.args.userOpHash.toLowerCase() !== hash) {
      continue;
    }

    if (!isAddressEqual(decoded.args.sender, owner)) {
      throw new Error("UserOperation event owner mismatch.");
    }

    if (!decoded.args.success) {
      throw new Error("UserOperation execution failed.");
    }

    matched = {
      nonce: decoded.args.nonce,
      actualGasCost: decoded.args.actualGasCost,
      actualGasUsed: decoded.args.actualGasUsed,
    };

    break;
  }

  if (!matched) {
    throw new Error("Matching successful UserOperationEvent not found.");
  }

  if (readFileSync(filename, "utf8") !== original) {
    throw new Error("Journal changed during reconciliation.");
  }

  if (record.status === "confirmed") {
    return filename;
  }

  const confirmed = {
    ...record,
    status: "confirmed",
    txHash: receipt.transactionHash,
    blockNumber: receipt.blockNumber.toString(),
    userOperationNonce: matched.nonce.toString(),
    actualGasCostWei: matched.actualGasCost.toString(),
    actualGasUsed: matched.actualGasUsed.toString(),
    confirmedAt: new Date().toISOString(),
  };

  const temporary = `${filename}.${randomBytes(8).toString("hex")}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);

  try {
    const data = Buffer.from(
      JSON.stringify(confirmed, null, 2) + "\n",
    );

    let offset = 0;
    while (offset < data.length) {
      const written = writeSync(
        fd, data, offset, data.length - offset,
      );
      if (written <= 0) {
        throw new Error("Journal update write failed.");
      }
      offset += written;
    }

    fsyncSync(fd);
  } catch (error) {
    closeSync(fd);
    unlinkSync(temporary);
    throw error;
  }

  closeSync(fd);
  renameSync(temporary, filename);

  return filename;
}
