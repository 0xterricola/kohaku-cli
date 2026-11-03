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
