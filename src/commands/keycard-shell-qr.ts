import { spawnSync } from "node:child_process";
import { readFile, mkdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";

import type { Command } from "commander";
import QRCode from "qrcode";

import {
  createShellQrRequest,
  createShellQrResponseSession,
} from "../utils/keycard-shell-qr-protocol.js";

import { encodeShellQrUr } from "../utils/keycard-shell-qr-transport.js";
import { decodeShellQrImage } from "../utils/keycard-shell-qr-image.js";
import { exchangeShellQr } from "../utils/keycard-shell-qr-exchange.js";
import { createShellQrR3Provider } from "../utils/keycard-shell-qr-r3-provider.js";
import { createShellBatchRequest } from "../utils/keycard-shell-qr-batch.js";
import { decryptShellBatchResponse } from "../utils/keycard-shell-qr-batch-response.js";

type Options = {
  responseImage?: string;
  batchPaths?: string;
  credentialMode?: string;
  entrypoint?: string;
  depositIndex?: string;
  withdrawIndex?: string;
};

function parseIndex(value: string | undefined, name: string): number {
  if (!value || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`Valid ${name} required`);
  }

  const index = Number(value);
  if (!Number.isSafeInteger(index) || index > 0x7fffffff) {
    throw new Error(`Invalid ${name}`);
  }

  return index;
}

export function registerKeycardShellQrCommand(
  program: Command,
  exchange: typeof exchangeShellQr = exchangeShellQr,
): void {
  program
    .command("keycard-shell-qr")
    .description("Keycard Shell Privacy Pools V1 QR receipt")
    .option("--response-image <path>", "PNG containing Shell response QR")
    .option("--batch-paths <paths>", "KKQ3: one or two comma-separated derivation paths")
    .option("--credential-mode <mode>", "SDK operation: deposit, withdrawal or signer")
    .option("--entrypoint <address>", "Sepolia Privacy Pools entrypoint")
    .option("--deposit-index <index>", "Privacy Pools deposit index")
    .option("--withdraw-index <index>", "Privacy Pools withdrawal index")
    .action(async (options: Options) => {
      if (options.credentialMode !== undefined) {
        if (options.batchPaths !== undefined) {
          throw new Error("Choose credential mode or batch paths");
        }

        const mode = options.credentialMode;
        if (!["deposit", "withdrawal", "signer"].includes(mode)) {
          throw new Error("Invalid credential mode");
        }

        if (
          !options.entrypoint ||
          !/^0x[0-9a-fA-F]{40}$/.test(options.entrypoint)
        ) {
          throw new Error("Valid --entrypoint address required");
        }

        const depositIndex = parseIndex(
          options.depositIndex,
          "--deposit-index",
        );

        const coordinates = {
          chainId: 11155111n,
          entrypointAddress: BigInt(options.entrypoint),
          depositIndex,
        };

        const provider = createShellQrR3Provider(
          (request, fingerprint) =>
            exchange(request, fingerprint, options),
        );

        try {
          if (mode === "deposit") {
            await provider.secretManager.getDepositSecrets(
              coordinates,
            );
          } else {
            const withdrawIndex = parseIndex(
              options.withdrawIndex,
              "--withdraw-index",
            );

            const withdrawalCoordinates = {
              ...coordinates,
              withdrawIndex,
            };

            if (mode === "withdrawal") {
              await provider.secretManager.getSecrets(
                withdrawalCoordinates,
              );
            } else {
              await provider.secretManager.deriveEphemeralSigner(
                withdrawalCoordinates,
              );
            }
          }

          console.log(
            `PASS: ${mode} credentials derived via encrypted Shell QR`,
          );
          console.log("No credential values printed.");
        } finally {
          provider.dispose();
        }

        return;
      }

      if (options.batchPaths !== undefined) {
        const paths = options.batchPaths
          .split(",")
          .map((path) => path.trim());

        const session = createShellBatchRequest(paths);
        const response = await exchange(
          session.request,
          session.fingerprint,
          options,
        );

        const credentials = decryptShellBatchResponse(
          session,
          response,
        );

        try {
          console.log(
            `PASS: ${credentials.length} encrypted credential(s) authenticated and decrypted`,
          );
          console.log(
            "Plaintext credentials were not printed or saved.",
          );
        } finally {
          credentials.forEach((credential) => credential.fill(0));
        }
        return;
      }

      const directory = join(
        homedir(),
        "Library/Caches/kohaku-v4-a8",
      );

      await mkdir(directory, { recursive: true });

      const request = createShellQrRequest();
      const session = createShellQrResponseSession(request);
      const requestPath = join(directory, "request.png");

      await QRCode.toFile(
        requestPath,
        encodeShellQrUr(request),
        {
          errorCorrectionLevel: "M",
          margin: 4,
          width: 512,
        },
      );

      console.log(`Request QR: ${requestPath}`);

      if (process.platform === "darwin") {
        spawnSync("open", [requestPath], { stdio: "ignore" });
      }

      console.log(
        "On Shell: Kohaku Key > Privacy Pools V1 > scan > approve.",
      );

      let responsePath = options.responseImage;

      if (!responsePath) {
        if (!process.stdin.isTTY) {
          throw new Error("Interactive terminal required");
        }

        const rl = createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        try {
          const entered = await rl.question(
            "Save the Shell response QR as PNG, then enter its path: ",
          );
          responsePath = entered.trim();
        } finally {
          rl.close();
        }
      }

      if (!responsePath) {
        throw new Error("Response image path required");
      }

      const absolutePath = resolve(responsePath);
      const metadata = await stat(absolutePath);

      if (!metadata.isFile() || metadata.size > 10_000_000) {
        throw new Error("Response must be a PNG under 10 MB");
      }

      const response = decodeShellQrImage(
        await readFile(absolutePath),
      );

      const tag = session.accept(response);

      console.log("PASS: Response version, operation and challenge match");
      console.log(`Receipt tag: 0x${tag.toString("hex")}`);
      console.log(
        "HMAC authenticity is not independently verified by the host.",
      );
    });
}
