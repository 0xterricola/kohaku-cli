import { confirm } from "@inquirer/prompts";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import type { Command } from "commander";
import { createKeycardAccount } from "../utils/keycard-account.js";
import { sendLiveKeycardSepoliaUserOperation } from "../utils/keycard-sepolia-userop-execution.js";
import {
  createPublicClient,
  formatEther,
  getAddress,
  isAddressEqual,
  http,
  keccak256,
  type Hex,
} from "viem";
import { sepolia } from "viem/chains";
import { SIMPLE_7702_IMPLEMENTATION } from "../utils/simple-7702.js";
import { buildKeycardSepoliaUnsignedIntent } from "../utils/keycard-sepolia-unsigned-intent.js";
import { prepareKeycardSepoliaUnsignedDraft } from "../utils/keycard-sepolia-unsigned-draft.js";
import { previewKeycardSepoliaGas } from "../utils/keycard-sepolia-heuristic-gas.js";

type Options = {
  from: string;
  targets: string;
  payloads: string;
  values?: string;
  rpcUrl: string;
  broadcast?: boolean;
  withoutTor?: boolean;
  verifyKeycard?: boolean;
  prepareUnsigned?: boolean;
  estimateGas?: boolean;
  keycardBridge?: string;
  keycardPath?: string;
};

function split(value: string): string[] {
  return value.split(",").map(part => part.trim());
}

function parseCalls(opts: Options) {
  const targets = split(opts.targets);
  const payloads = split(opts.payloads);
  const values = opts.values
    ? split(opts.values)
    : targets.map(() => "0");

  if (
    targets.length < 2 ||
    targets.length !== payloads.length ||
    targets.length !== values.length
  ) {
    throw new Error(
      "Hardware UserOperation requires at least two calls " +
      "with matching targets, payloads, and values.",
    );
  }

  return targets.map((target, index) => {
    const data = payloads[index]!;
    const value = values[index]!;

    if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) {
      throw new Error(`Invalid calldata for call ${index + 1}.`);
    }

    if (!/^[0-9]+$/.test(value)) {
      throw new Error(`Invalid ETH value for call ${index + 1}.`);
    }

    return {
      to: getAddress(target),
      data: data as Hex,
      value: BigInt(value),
    };
  });
}

export function registerKeycardExecuteSepoliaCommand(
  program: Command,
): void {
  program
    .command("keycard-execute-sepolia")
    .description(
      "Inspect or execute a Keycard EIP-7702/ERC-4337 batch on Sepolia",
    )
    .requiredOption("--from <address>", "Expected Keycard owner address")
    .requiredOption("--targets <addresses>", "Comma-separated call targets")
    .requiredOption("--payloads <hex>", "Comma-separated calldata")
    .option("--values <wei>", "Comma-separated ETH values in wei")
    .requiredOption("--rpc-url <url>", "Sepolia JSON-RPC URL")
    .option("--broadcast", "Request live UserOperation execution")
    .option("--without-tor", "Use clearnet bundler transport on Sepolia")
    .option("--verify-keycard", "Verify physical Keycard identity without signing")
    .option("--prepare-unsigned", "Resolve unsigned UserOperation nonce and calldata")
    .option("--estimate-gas", "Read-only heuristic UserOperation fee preview")
    .option("--keycard-bridge <path>", "Native Keycard bridge executable")
    .option("--keycard-path <path>", "Hardware derivation path")
    .action(async (opts: Options) => {
      try {
        // Fail before any RPC or hardware access.
        if (opts.broadcast) {
          if (!process.stdin.isTTY || !process.stdout.isTTY) {
            throw new Error(
              "Interactive terminal required for Keycard broadcasting.",
            );
          }
          if (
            !opts.keycardBridge ||
            !isAbsolute(opts.keycardBridge)
          ) {
            throw new Error(
              "--broadcast requires an absolute --keycard-bridge path.",
            );
          }
          if (
            opts.verifyKeycard ||
            opts.prepareUnsigned ||
            opts.estimateGas
          ) {
            throw new Error(
              "Live broadcast cannot be combined with read-only modes.",
            );
          }
        }

        if (opts.verifyKeycard) {
          if (
            !opts.keycardBridge ||
            !isAbsolute(opts.keycardBridge)
          ) {
            throw new Error(
              "--verify-keycard requires an absolute --keycard-bridge path.",
            );
          }

          if (!process.stdin.isTTY) {
            throw new Error(
              "Interactive terminal required for hardware verification.",
            );
          }
        } else if (!opts.broadcast && (opts.keycardBridge || opts.keycardPath)) {
          throw new Error(
            "Hardware bridge options require --verify-keycard.",
          );
        }

        const from = getAddress(opts.from);
        const calls = parseCalls(opts);

        const client = createPublicClient({
          chain: sepolia,
          transport: http(opts.rpcUrl, {
            retryCount: 0,
            timeout: 15000,
          }),
        });

        const [
          chainId,
          implementationCode,
          senderCode,
          nonce,
          balance,
        ] = await Promise.all([
          client.getChainId(),
          client.getBytecode({
            address: SIMPLE_7702_IMPLEMENTATION,
          }),
          client.getBytecode({ address: from }),
          client.getTransactionCount({
            address: from,
            blockTag: "pending",
          }),
          client.getBalance({ address: from }),
        ]);

        if (chainId !== sepolia.id) {
          throw new Error("RPC is not Sepolia.");
        }

        if (!implementationCode || implementationCode === "0x") {
          throw new Error("Simple7702 implementation not deployed.");
        }

        const expectedDelegation =
          `0xef0100${SIMPLE_7702_IMPLEMENTATION.slice(2)}`.toLowerCase();

        const currentCode = (senderCode ?? "0x").toLowerCase();

        if (
          currentCode !== "0x" &&
          currentCode !== expectedDelegation
        ) {
          throw new Error(
            "Account has incompatible existing code or delegation.",
          );
        }

        const unsignedIntent = buildKeycardSepoliaUnsignedIntent({
          owner: from,
          chainId,
          pendingEoaNonce: nonce,
          delegationNeeded: currentCode === "0x",
          calls,
        });

        const review = {
          mode: "keycard-sepolia-userop-readiness",
          broadcast: opts.broadcast === true,
          owner: from,
          chainId,
          pendingEoaNonce: nonce,
          balanceWei: balance.toString(),
          balanceEth: formatEther(balance),
          implementation: SIMPLE_7702_IMPLEMENTATION,
          delegationNeeded: currentCode === "0x",
          unsignedIntentDigest: unsignedIntent.digest,
          digestKind: unsignedIntent.digestKind,
          userOperationNonce: null,
          userOperationGas: null,
          calls: calls.map(call => ({
            to: call.to,
            data: call.data,
            calldataHash: keccak256(call.data),
            valueWei: call.value.toString(),
          })),
          signingPerformed: false,
          submissionPerformed: false,
        };

        console.log(JSON.stringify(review, null, 2));

        if (opts.broadcast) {
          const accessApproved = await confirm({
            message:
              "Verify physical Keycard identity before live Sepolia " +
              "execution? No signing yet.",
            default: false,
          });

          if (!accessApproved) {
            throw new Error("Physical Keycard access declined.");
          }

          const authorizedDigests = new Set<string>();

          const hardware = createKeycardAccount({
            binary: opts.keycardBridge!,
            path: opts.keycardPath,
            transport: "native",
            reviewDigest: async ({ operation, digest }) => {
              if (
                operation !== "EIP-712" &&
                operation !== "EIP-7702 authorization"
              ) {
                throw new Error("Unexpected hardware signing operation.");
              }

              if (!authorizedDigests.delete(digest.toLowerCase())) {
                throw new Error(
                  "Hardware digest was not explicitly approved.",
                );
              }
            },
          });

          if (!isAddressEqual(hardware.address, from)) {
            throw new Error("Physical Keycard owner mismatch.");
          }

          const journalDirectory = join(
            homedir(),
            ".kohaku-cli",
            "keycard-sepolia-userops",
          );

          const result = await sendLiveKeycardSepoliaUserOperation({
            client: client as unknown as
              Parameters<typeof sendLiveKeycardSepoliaUserOperation>[0]["client"],
            owner: hardware,
            expectedOwner: from,
            chainId: BigInt(sepolia.id),
            calls,
            rpcUrl: opts.rpcUrl,
            withoutTor: opts.withoutTor === true,
            journalDirectory,

            approveSigning: async signingReview => {
              console.log(JSON.stringify({
                mode: "keycard-sepolia-signing-review",
                stage: signingReview.stage,
                owner: signingReview.owner,
                chainId: signingReview.chainId,
                nonce: signingReview.nonce.toString(),
                digest: signingReview.digest,
                unsignedIntentDigest:
                  signingReview.unsignedIntentDigest,
                calls: review.calls,
              }, null, 2));

              const approved = await confirm({
                message:
                  "Authorize physical Keycard signing for " +
                  signingReview.stage + "?",
                default: false,
              });

              if (approved) {
                authorizedDigests.add(
                  signingReview.digest.toLowerCase(),
                );
              }

              return approved;
            },

            approve: async (hash, operation) => {
              if (!isAddressEqual(operation.sender, from)) {
                throw new Error("Prepared UserOperation sender mismatch.");
              }

              const gasLimit =
                operation.callGasLimit +
                operation.verificationGasLimit +
                operation.preVerificationGas;

              const maximumFee =
                gasLimit * operation.maxFeePerGas;

              if (
                gasLimit <= 0n ||
                operation.maxFeePerGas <= 0n ||
                operation.maxPriorityFeePerGas >
                  operation.maxFeePerGas
              ) {
                throw new Error("Invalid prepared UserOperation fees.");
              }

              console.log(JSON.stringify({
                mode: "keycard-sepolia-submission-review",
                userOpHash: hash,
                sender: operation.sender,
                nonce: operation.nonce.toString(),
                callDataHash: keccak256(operation.callData),
                gasLimit: gasLimit.toString(),
                maxFeePerGasWei:
                  operation.maxFeePerGas.toString(),
                maximumFeeWei: maximumFee.toString(),
                maximumFeeEth: formatEther(maximumFee),
                journalDirectory,
              }, null, 2));

              return confirm({
                message:
                  "Submit this signed UserOperation to the " +
                  "Sepolia bundler? This is the final broadcast.",
                default: false,
              });
            },
          });

          console.log(JSON.stringify({
            mode: "keycard-sepolia-userop-confirmed",
            userOpHash: result.userOpHash,
            txHash: result.txHash,
            delegatedInUserOp: result.delegatedInUserOp,
            implementation: result.implementation,
            journalDirectory,
          }, null, 2));

          return;
        }


        if (opts.prepareUnsigned) {
          const draft = await prepareKeycardSepoliaUnsignedDraft({
            client,
            owner: from,
            calls,
          });

          console.log(JSON.stringify({
            mode: "keycard-sepolia-unsigned-userop-draft",
            ...draft,
            delegationNeeded: currentCode === "0x",
            userOperationGas: null,
          }, null, 2));
        }

        if (opts.estimateGas) {
          // The heuristic path uses standard PublicClient methods.
          // The legacy estimator type also includes delegation methods
          // used only by its signed-owner branch.
          const gasPreview = await previewKeycardSepoliaGas({
            client: client as unknown as
              Parameters<typeof previewKeycardSepoliaGas>[0]["client"],
            chainId,
            owner: from,
            calls,
            rpcUrl: opts.rpcUrl,
          });

          console.log(JSON.stringify(
            gasPreview,
            (_, value) =>
              typeof value === "bigint"
                ? value.toString()
                : value,
            2,
          ));
        }

        if (opts.verifyKeycard) {
          const approved = await confirm({
            message:
              "Access physical Keycard to verify owner identity? " +
              "No signing or broadcasting.",
            default: false,
          });

          if (!approved) {
            throw new Error("Hardware verification declined.");
          }

          const account = createKeycardAccount({
            binary: opts.keycardBridge!,
            path: opts.keycardPath,
            transport: "native",
          });

          if (!isAddressEqual(account.address, from)) {
            throw new Error("Physical Keycard owner mismatch.");
          }

          console.log(JSON.stringify({
            mode: "keycard-sepolia-hardware-verification",
            owner: account.address,
            identityVerified: true,
            signingPerformed: false,
            submissionPerformed: false,
          }, null, 2));
        }
      } catch (error) {
        console.error(
          "keycard-execute-sepolia:",
          error instanceof Error ? error.message : String(error),
        );
        process.exitCode = 1;
      }
    });
}
