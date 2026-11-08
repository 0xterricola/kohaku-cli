import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import QRCode from "qrcode";

import { decodeShellBatchRequest } from "./keycard-shell-qr-batch.js";
import { decodeShellQrImage } from "./keycard-shell-qr-image.js";
import { captureShellQrResponse } from "./keycard-shell-qr-camera.js";
import { encodeShellQrUr } from "./keycard-shell-qr-transport.js";

export async function exchangeShellQr(
  request: Uint8Array,
  fingerprint: string,
  options: { responseImage?: string } = {},
): Promise<Uint8Array> {
  const { paths, hostPublicKey } = decodeShellBatchRequest(request);

  const expectedFingerprint = createHash("sha256")
    .update(hostPublicKey)
    .digest("hex")
    .slice(0, 16);

  if (fingerprint !== expectedFingerprint) {
    throw new Error("Mac fingerprint mismatch");
  }

  const directory = join(
    homedir(),
    "Library/Caches/kohaku-v4-qr-batch",
  );
  await mkdir(directory, { recursive: true });

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
  console.log(`Mac fingerprint: ${fingerprint}`);
  console.log(`Requested paths: ${paths.join(", ")}`);
  console.log(
    "On Shell: Kohaku Key > Privacy Pools V1 > scan.",
  );
  console.log(
    "Verify fingerprint and paths before approving.",
  );

  if (process.platform === "darwin") {
    spawnSync("open", [requestPath], { stdio: "ignore" });
  }

  if (!options.responseImage) {
    return captureShellQrResponse();
  }

  const absolutePath = resolve(options.responseImage);
  const metadata = await stat(absolutePath);

  if (!metadata.isFile() || metadata.size > 10_000_000) {
    throw new Error("Response must be a PNG under 10 MB");
  }

  return decodeShellQrImage(await readFile(absolutePath));
}
