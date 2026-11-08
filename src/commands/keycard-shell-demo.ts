import { createInterface } from "node:readline/promises";

import type { Command } from "commander";
import assert from "node:assert/strict";

import { PrivacyPoolsV1_0xBow } from "@kohaku-eth/privacy-pools";
import { decodeFunctionData, getAddress, isHex, toHex } from "viem";

import { exchangeShellQr } from "../utils/keycard-shell-qr-exchange.js";
import { createShellQrR3Provider } from "../utils/keycard-shell-qr-r3-provider.js";
import { proveShellDemoWithdrawal } from "../utils/keycard-shell-demo-prover.mjs";
import { prepareOfflineWithdrawal } from "../utils/keycard-shell-demo-withdrawal.js";
import {
  createSyntheticDeposit,
  createSyntheticWithdrawalMembership,
} from "../utils/keycard-shell-demo-synthetic.js";
import { buildDepositPayload } from "../../../kohaku-sdk-research/packages/privacy-pools/src/state/selectors/deposits.selector";
import { entrypointDepositNativeAbi } from "../../../kohaku-sdk-research/packages/privacy-pools/src/data/abis/entrypoint.abi";

type Options = {
  plan?: boolean;
};

const checkpoints = [
  {
    name: "Keycard Shell credential exchange",
    detail: "Review encrypted QR authentication and host-side decryption.",
  },
  {
    name: "Construct Privacy Pools deposit",
    detail: "Derive the commitment and construct deposit calldata.",
  },
  {
    name: "Simulate deposit",
    detail: "Model the deposit event and resulting pool state.",
  },
  {
    name: "Prepare withdrawal membership witnesses",
    detail: "Build note, state, and ASP membership witnesses.",
  },
  {
    name: "Generate and verify Groth16 proof",
    detail: "Run the local prover and independently verify its proof.",
  },
  {
    name: "Validate offline withdrawal calldata",
    detail: "Encode the verified proof and validate calldata without RPC.",
  },
  {
    name: "Review evidence",
    detail: "Summarize completed checks and security boundaries.",
  },
] as const;

export function registerKeycardShellDemoCommand(
  program: Command,
): void {
  program
    .command("keycard-shell-demo")
    .description("Guided Privacy Pools V1 offline demonstration")
    .option("--plan", "Display checkpoints without interactive pauses")
    .action(async (options: Options) => {
      console.log("\nKohaku Key V4 — Privacy Pools V1");
      console.log("MODE: Guided offline demonstration");
      console.log("SIGNING: DISABLED");
      console.log("BROADCASTING: DISABLED");
      console.log("TRANSACTIONS: NONE");
      console.log(
        "Guide: docs/V4-SHELL-PRIVACY-POOLS-DEMO.md",
      );

      if (!options.plan && !process.stdin.isTTY) {
        throw new Error(
          "Interactive terminal required; use --plan for review",
        );
      }

      const rl = options.plan
        ? undefined
        : createInterface({
            input: process.stdin,
            output: process.stdout,
          });

      let depositSecrets:
        Awaited<
          ReturnType<
            ReturnType<typeof createShellQrR3Provider>["secretManager"]["getDepositSecrets"]
          >
        > | undefined;

      let syntheticDeposit:
        Awaited<ReturnType<typeof createSyntheticDeposit>> | undefined;

      let syntheticMembership:
        Awaited<ReturnType<typeof createSyntheticWithdrawalMembership>>
        | undefined;

      let withdrawalProof:
        Awaited<ReturnType<typeof proveShellDemoWithdrawal>>
        | undefined;

      try {
        for (const [index, checkpoint] of checkpoints.entries()) {
          console.log(
            `\nCHECKPOINT ${index + 1}/${checkpoints.length}`,
          );
          console.log(checkpoint.name);
          console.log(checkpoint.detail);

          if (options.plan) {
            console.log("STATUS: PLANNED — execution skipped");
            continue;
          }

          if (rl) {
            const answer = await rl.question(
              "Press Enter to continue (q to quit): ",
            );

            if (answer.trim().toLowerCase() === "q") {
              console.log("Demo stopped. No transactions submitted.");
              return;
            }
          }

          if (index === 0 && !options.plan) {
            const provider = createShellQrR3Provider(
              (request, fingerprint) =>
                exchangeShellQr(request, fingerprint, {}),
            );

            try {
              depositSecrets = await provider.secretManager.getDepositSecrets({
                chainId: 11155111n,
                entrypointAddress: BigInt(
                  PrivacyPoolsV1_0xBow[11155111].entrypoint.entrypointAddress,
                ),
                depositIndex: 15,
              });
            } finally {
              provider.dispose();
            }

            console.log(
              "PASS: Hardware deposit credential pair authenticated and SDK-derived",
            );
            console.log("Account: 0 | Deposit index: 15");
            console.log("Credential values not printed or saved.");
            continue;
          }

          if (index === 1 && !options.plan) {
            if (!depositSecrets) {
              throw new Error("Hardware deposit credentials required");
            }

            const amount = 2000000000000000n;
            const asset = BigInt(
              "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
            );
            const entrypointAddress = BigInt(
              PrivacyPoolsV1_0xBow[11155111].entrypoint.entrypointAddress,
            );

            const payload = buildDepositPayload(
              depositSecrets.precommitment,
              asset,
              amount,
              entrypointAddress,
            );

            assert.equal(payload.value, amount);
            assert.equal(
              getAddress(payload.to),
              getAddress(toHex(entrypointAddress, { size: 20 })),
            );

            if (!isHex(payload.data)) {
              throw new Error("Invalid deposit calldata");
            }

            const decoded = decodeFunctionData({
              abi: entrypointDepositNativeAbi,
              data: payload.data,
            });

            assert.equal(decoded.functionName, "deposit");
            assert.deepEqual(
              decoded.args,
              [depositSecrets.precommitment],
            );

            console.log("PASS: SDK deposit calldata constructed");
            console.log("PASS: Deposit ABI decoded and validated");
            console.log("PASS: Destination and ETH value verified");
            console.log("Network: Sepolia (offline construction only)");
            console.log("Amount: 0.002 ETH (not transferred)");
            console.log("Entrypoint:", getAddress(payload.to));
            console.log("Signed: NO | Broadcast: NO");
            continue;
          }

          if (index === 2 && !options.plan) {
            if (!depositSecrets) {
              throw new Error("Hardware deposit credentials required");
            }

            syntheticDeposit = await createSyntheticDeposit(
              depositSecrets.precommitment,
            );

            console.log("PASS: Synthetic deposit event constructed");
            console.log("PASS: Synthetic Merkle state tree constructed");
            console.log("PASS: Deposit membership witness generated");
            console.log("Gross deposit: 0.002 ETH");
            console.log("Illustrative net balance: 0.00198 ETH");
            console.log("Merkle leaf index:", syntheticDeposit.stateProof.index);
            console.log("State tree depth: 32");
            console.log("Real blockchain event: NO");
            console.log("RPC calls: NONE");
            continue;
          }

          if (index === 3 && !options.plan) {
            if (!syntheticDeposit) {
              throw new Error("Synthetic deposit required");
            }

            syntheticMembership =
              await createSyntheticWithdrawalMembership(syntheticDeposit);

            console.log("PASS: Synthetic state membership prepared");
            console.log("PASS: Synthetic ASP membership prepared");
            console.log(
              "State proof depth:",
              syntheticMembership.stateProof.siblings.length,
            );
            console.log(
              "ASP proof depth:",
              syntheticMembership.aspProof.siblings.length,
            );
            console.log("Full private circuit witness: NOT YET BUILT");
            console.log("Groth16 proof: NOT YET GENERATED");
            console.log("Blockchain transactions: NONE");
            continue;
          }

          if (index === 4 && !options.plan) {
            if (
              !depositSecrets ||
              !syntheticDeposit ||
              !syntheticMembership
            ) {
              throw new Error(
                "Deposit credentials and synthetic witnesses required",
              );
            }

            console.log(
              "A second Shell QR exchange is required for change credentials.",
            );
            console.log("Account: 0 | Deposit: 15 | Withdrawal: 1");

            const provider = createShellQrR3Provider(
              (request, fingerprint) =>
                exchangeShellQr(request, fingerprint, {}),
            );

            let change;

            try {
              change = await provider.secretManager.getSecrets({
                chainId: 11155111n,
                entrypointAddress: BigInt(
                  PrivacyPoolsV1_0xBow[11155111].entrypoint.entrypointAddress,
                ),
                depositIndex: 15,
                withdrawIndex: 1,
              });
            } finally {
              provider.dispose();
            }

            console.log(
              "PASS: Hardware change credentials authenticated and derived",
            );

            withdrawalProof = await proveShellDemoWithdrawal({
              existing: depositSecrets,
              change,
              deposit: syntheticDeposit,
              membership: syntheticMembership,
            });

            console.log("Withdrawal amount: 0.00099 ETH (simulated)");
            console.log(
              "Public signals:",
              withdrawalProof.publicSignals.length,
            );
            console.log("State: SYNTHETIC");
            console.log("Proof: VERIFIED");
            console.log("Signed: NO | Broadcast: NO");
            continue;
          }

          if (index === 5 && !options.plan) {
            if (!withdrawalProof || !syntheticDeposit) {
              throw new Error("Verified proof and synthetic deposit required");
            }

            const report = prepareOfflineWithdrawal(
              withdrawalProof,
              syntheticDeposit.netValue,
            );

            console.log("PASS: SDK withdrawal calldata encoded");
            console.log("PASS: Withdrawal ABI decoded correctly");
            console.log("PASS: All eight proof public signals matched");
            console.log("PASS: Withdrawal context and balances verified");
            console.log("Calldata bytes:", report.calldataBytes);
            console.log("EVM execution: NOT RUN");
            console.log("RPC calls: NONE");
            console.log("Signed: NO | Broadcast: NO");
            continue;
          }

          if (index === 6 && !options.plan) {
            if (
              !depositSecrets ||
              !syntheticDeposit ||
              !syntheticMembership ||
              !withdrawalProof
            ) {
              throw new Error("Completed prior checkpoints required");
            }

            // Revalidate the verified proof's ABI encoding without
            // repeating hardware authentication or Groth16 proving.
            const review = prepareOfflineWithdrawal(
              withdrawalProof,
              syntheticDeposit.netValue,
            );

            assert.equal(review.publicSignalCount, 8);

            console.log("\n=== V4 DEMONSTRATION EVIDENCE ===");
            console.log(
              "HARDWARE: Two Keycard Shell QR exchanges authenticated",
            );
            console.log(
              "HARDWARE: Deposit 15 and withdrawal 1 credentials derived",
            );
            console.log(
              "SDK: Offline Sepolia deposit calldata validated",
            );
            console.log(
              "SYNTHETIC: Deposit event, Merkle state and ASP membership",
            );
            console.log(
              "CRYPTOGRAPHY: Groth16 withdrawal proof independently verified",
            );
            console.log(
              "SDK: Withdrawal calldata encoded and decoded",
            );
            console.log(
              "SDK: Eight verified public signals matched",
            );
            console.log(
              "AMOUNT: 0.00099 ETH withdrawal (illustrative only)",
            );
            console.log(
              "AMOUNT: 0.00099 ETH remaining note (illustrative only)",
            );

            console.log("\n=== SECURITY AND SCOPE ===");
            console.log("Credentials: Derived from physical Shell");
            console.log("Witness and proving: Mac host memory");
            console.log("Pinned proving artifacts: SHA-256 validated");
            console.log("Private values: Not included in evidence");
            console.log(
              "Memory zeroization: Not guaranteed for JavaScript BigInt",
            );
            console.log("Pool state: Synthetic, not on-chain");
            console.log("Local EVM execution: NOT TESTED");
            console.log("Live contract acceptance: NOT TESTED");
            console.log("RPC calls: NONE");
            console.log("Signed transactions: NONE");
            console.log("Broadcast transactions: NONE");

            console.log(
              "\nPASS: Seven guided checkpoints completed",
            );
            console.log(
              "PASS: Evidence classifications and limitations reported",
            );
            continue;
          }

          console.log(
            "STATUS: NOT RUN — implementation not integrated yet",
          );
        }

        console.log("\nGuided walkthrough complete.");
        console.log(
          withdrawalProof
            ? "Hardware-to-Groth16 proof verified; offline withdrawal calldata validated."
            : depositSecrets
              ? "Hardware deposit stages completed; proving not completed."
              : "No cryptographic stages executed.",
        );
        console.log("No transactions signed or broadcast.");
      } finally {
        depositSecrets = undefined;
        rl?.close();
      }
    });
}
