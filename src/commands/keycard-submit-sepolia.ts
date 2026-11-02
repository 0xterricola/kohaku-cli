import { readFile } from "node:fs/promises";
import { confirm } from "@inquirer/prompts";
import {
  createPublicClient,
  getAddress,
  http,
  type Hex,
} from "viem";
import { sepolia } from "viem/chains";
import type { Command } from "commander";
import {
  inspectSignedSepoliaTransaction,
} from "../utils/keycard-sepolia-broadcast.js";
import {
  submitSignedSepoliaTransaction,
  type SepoliaSubmissionClient,
} from "../utils/keycard-sepolia-submit.js";

type Options = {
  signedFile: string;
  expectedFrom: string;
  rpcUrl: string;
  broadcast?: boolean;
};

const json = (value: unknown) =>
  JSON.stringify(
    value,
    (_, item) => typeof item === "bigint" ? item.toString() : item,
    2,
  );

export function registerKeycardSubmitSepoliaCommand(
  program: Command,
): void {
  program
    .command("keycard-submit-sepolia")
    .description(
      "Inspect a signed Sepolia transaction; broadcast only with explicit approval",
    )
    .requiredOption("--signed-file <path>", "File containing signed transaction hex")
    .requiredOption("--expected-from <address>", "Expected hardware signer")
    .requiredOption("--rpc-url <url>", "Sepolia JSON-RPC URL")
    .option("--broadcast", "Explicitly request live Sepolia submission")
    .action(async (opts: Options) => {
      try {
        if (opts.broadcast && !process.stdin.isTTY) {
          throw new Error(
            "Interactive terminal required for Sepolia broadcasting.",
          );
        }

        const from = getAddress(opts.expectedFrom);
        const raw = (await readFile(opts.signedFile, "utf8")).trim();

        if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(raw)) {
          throw new Error("Invalid serialized transaction hex.");
        }

        const signed = raw as Hex;
        const client = createPublicClient({
          chain: sepolia,
          transport: http(opts.rpcUrl, {
            retryCount: 0,
            timeout: 15000,
          }),
        });

        const rpc: SepoliaSubmissionClient = {
          getChainId: () => client.getChainId(),
          getTransactionCount: (args) =>
            client.getTransactionCount(args),
          getBalance: (args) => client.getBalance(args),
          getBlock: async ({ blockTag }) => ({
            baseFeePerGas:
              (await client.getBlock({ blockTag })).baseFeePerGas ?? null,
          }),
          estimateGas: (args) => client.estimateGas(args),
          sendRawTransaction: ({ serializedTransaction }) =>
            client.request({
              method: "eth_sendRawTransaction",
              params: [serializedTransaction],
            }),
          waitForTransactionReceipt: async ({ hash, confirmations }) => {
            const receipt = await client.waitForTransactionReceipt({
              hash,
              confirmations,
              timeout: 120000,
            });

            return {
              transactionHash: receipt.transactionHash,
              status: receipt.status,
              blockNumber: receipt.blockNumber,
            };
          },
        };

        if (!opts.broadcast) {
          const inspected = await inspectSignedSepoliaTransaction(
            rpc, signed, from,
          );

          console.log(json({
            mode: "keycard-sepolia-inspection",
            broadcast: false,
            ...inspected,
          }));
          return;
        }

        const result = await submitSignedSepoliaTransaction(
          rpc,
          signed,
          from,
          async (review) => {
            console.error("=== Sepolia broadcast authorization ===");
            console.error(json(review));

            return confirm({
              message: "Broadcast this exact signed transaction to Sepolia?",
              default: false,
            });
          },
        );

        console.log(json({
          mode: "keycard-sepolia-submission",
          ...result,
        }));
      } catch (error) {
        const message = error instanceof Error
          ? error.message
          : String(error);

        console.error(`keycard-submit-sepolia: ${message}`);
        process.exitCode = 1;
      }
    });
}
