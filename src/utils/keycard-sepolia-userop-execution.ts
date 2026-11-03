import { isAbsolute } from "node:path";
import {
  getAddress,
  isAddressEqual,
  type Address,
  type Hash,
} from "viem";
import {
  sendEip7702BatchUserOperation,
} from "./eip7702-batch-userop.js";
import {
  recordKeycardUserOpAttempt,
} from "./keycard-userop-journal.js";

type SubmissionOptions =
  Parameters<typeof sendEip7702BatchUserOperation>[0];

export type KeycardSepoliaUserOpOptions = Omit<
  SubmissionOptions,
  "privateKey" | "owner" | "approve" | "onSubmitted"
> & {
  owner: NonNullable<SubmissionOptions["owner"]>;
  expectedOwner: Address;
  journalDirectory: string;
  approve: NonNullable<SubmissionOptions["approve"]>;
};

/**
 * Construct a guarded hardware submission request.
 *
 * Does not access the hardware, RPC, or bundler.
 */
export function prepareKeycardSepoliaUserOpExecution(
  opts: KeycardSepoliaUserOpOptions,
): SubmissionOptions {
  if (opts.chainId !== 11155111n) {
    throw new Error("Hardware UserOperation requires Sepolia.");
  }

  if (opts.client.chain.id !== 11155111) {
    throw new Error("Configured RPC chain must be Sepolia.");
  }

  if (
    !opts.owner ||
    !isAddressEqual(
      getAddress(opts.owner.address),
      getAddress(opts.expectedOwner),
    )
  ) {
    throw new Error("Hardware owner address mismatch.");
  }

  if (
    typeof opts.owner.signAuthorization !== "function" ||
    typeof opts.owner.signTypedData !== "function"
  ) {
    throw new Error("Hardware owner lacks required signing methods.");
  }

  if (opts.calls.length < 2) {
    throw new Error("Hardware batch requires at least two calls.");
  }

  if (!isAbsolute(opts.journalDirectory)) {
    throw new Error("Hardware journal directory must be absolute.");
  }

  if (typeof opts.approve !== "function") {
    throw new Error("Hardware submission approval is required.");
  }

  const {
    expectedOwner,
    journalDirectory,
    approve,
    ...submission
  } = opts;

  return {
    ...submission,
    approve,
    onSubmitted: (userOpHash: Hash) => {
      recordKeycardUserOpAttempt({
        directory: journalDirectory,
        userOpHash,
        owner: getAddress(expectedOwner),
        chainId: 11155111,
      });
    },
  };
}

/**
 * Validate the live chain before entering the existing
 * EIP-7702 preparation/signing/submission pipeline.
 */
export async function sendKeycardSepoliaUserOperation(
  opts: KeycardSepoliaUserOpOptions,
) {
  const submission =
    prepareKeycardSepoliaUserOpExecution(opts);

  const actualChainId = await opts.client.getChainId();

  if (actualChainId !== 11155111) {
    throw new Error("Live RPC chain ID is not Sepolia.");
  }

  return sendEip7702BatchUserOperation(submission);
}
