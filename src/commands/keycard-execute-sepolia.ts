import { confirm } from "@inquirer/prompts";
import { isAbsolute } from "node:path";
import type { Command } from "commander";
import { createKeycardAccount } from "../utils/keycard-account.js";
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
      "Inspect a proposed Keycard EIP-7702/ERC-4337 batch on Sepolia",
    )
    .requiredOption("--from <address>", "Expected Keycard owner address")
    .requiredOption("--targets <addresses>", "Comma-separated call targets")
    .requiredOption("--payloads <hex>", "Comma-separated calldata")
    .option("--values <wei>", "Comma-separated ETH values in wei")
    .requiredOption("--rpc-url <url>", "Sepolia JSON-RPC URL")
    .option("--broadcast", "Request live UserOperation execution")
    .option("--verify-keycard", "Verify physical Keycard identity without signing")
    .option("--prepare-unsigned", "Resolve unsigned UserOperation nonce and calldata")
    .option("--estimate-gas", "Read-only heuristic UserOperation fee preview")
    .option("--keycard-bridge <path>", "Native Keycard bridge executable")
    .option("--keycard-path <path>", "Hardware derivation path")
    .action(async (opts: Options) => {
      try {
        // Do not enable live execution before CLI integration testing.
        // This check precedes RPC and hardware access.
        if (opts.broadcast) {
          throw new Error(
            "Live hardware UserOperation submission is not enabled " +
            "in this checkpoint.",
          );
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
        } else if (opts.keycardBridge || opts.keycardPath) {
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
          broadcast: false,
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
