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

/**
 * Execute a reviewed two-call Sepolia batch using a
 * live-state-bound hardware signing account.
 *
 * Uses the existing submission journal and bundler pipeline.
 * Does not enable the command-line broadcast flag.
 */
export async function sendLiveKeycardSepoliaUserOperation(
  opts: KeycardSepoliaUserOpOptions & {
    approveSigning: (
      review: import("./keycard-sepolia-signing-gate.js").KeycardSigningReview,
    ) => Promise<boolean>;
  },
) {
  const { approveSigning, ...submissionOpts } = opts;

  // Reject invalid execution requests before RPC access.
  prepareKeycardSepoliaUserOpExecution(submissionOpts);

  if (typeof approveSigning !== "function") {
    throw new Error("Hardware signing approval is required.");
  }

  const { parseAbi } = await import("viem");
  const { toSimple7702SmartAccount } =
    await import("viem/account-abstraction");
  const { buildKeycardSepoliaUnsignedIntent } =
    await import("./keycard-sepolia-unsigned-intent.js");
  const { createLiveApprovedKeycardSepoliaOwner } =
    await import("./keycard-sepolia-live-approved-owner.js");
  const { SIMPLE_7702_IMPLEMENTATION } =
    await import("./simple-7702.js");

  const owner = getAddress(opts.expectedOwner);

  const calls = opts.calls.map(call => ({
    to: getAddress(call.to),
    data: (call.data ?? "0x") as `0x${string}`,
    value: call.value ?? 0n,
  }));

  const [chainId, pendingEoaNonce, code, userOpNonce] =
    await Promise.all([
      opts.client.getChainId(),
      opts.client.getTransactionCount({
        address: owner,
        blockTag: "pending",
      }),
      opts.client.getBytecode({ address: owner }),
      opts.client.readContract({
        address:
          "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108",
        abi: parseAbi([
          "function getNonce(address sender, uint192 key) view returns (uint256)",
        ]),
        functionName: "getNonce",
        args: [owner, 0n],
      }),
    ]);

  if (chainId !== 11155111) {
    throw new Error("Live RPC is not Sepolia.");
  }

  const expectedDelegation =
    `0xef0100${SIMPLE_7702_IMPLEMENTATION.slice(2)}`.toLowerCase();

  const currentCode = (code ?? "0x").toLowerCase();

  if (
    currentCode !== "0x" &&
    currentCode !== expectedDelegation
  ) {
    throw new Error("Incompatible account delegation.");
  }

  const delegationNeeded = currentCode === "0x";

  const intent = buildKeycardSepoliaUnsignedIntent({
    owner,
    chainId,
    pendingEoaNonce,
    delegationNeeded,
    calls,
  });

  // Use the same Simple7702 calldata encoding as the
  // eventual bundler preparation and signing pipeline.
  const encoder = await toSimple7702SmartAccount({
    client: opts.client,
    owner: opts.owner as import("viem/accounts").PrivateKeyAccount,
    implementation: SIMPLE_7702_IMPLEMENTATION,
  });

  const expectedCallData = await encoder.encodeCalls(calls);

  const guardedOwner = createLiveApprovedKeycardSepoliaOwner({
    client: opts.client,
    owner: opts.owner as Parameters<
      typeof createLiveApprovedKeycardSepoliaOwner
    >[0]["owner"],
    expectedOwner: owner,
    calls,
    expectedEoaNonce: pendingEoaNonce,
    expectedUserOpNonce: userOpNonce,
    expectedDelegationNeeded: delegationNeeded,
    expectedIntentDigest: intent.digest,
    expectedCallData,
    approve: approveSigning,
  });

  return sendKeycardSepoliaUserOperation({
    ...submissionOpts,
    owner: guardedOwner,
  });
}
