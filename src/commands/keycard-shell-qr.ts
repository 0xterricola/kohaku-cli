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

type Options = {
  responseImage?: string;
};

export function registerKeycardShellQrCommand(program: Command): void {
  program
    .command("keycard-shell-qr")
    .description("Keycard Shell Privacy Pools V1 QR receipt")
    .option("--response-image <path>", "PNG containing Shell response QR")
    .action(async (options: Options) => {
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
