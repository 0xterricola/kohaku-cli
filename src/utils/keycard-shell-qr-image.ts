import jsQR from "jsqr";
import { PNG } from "pngjs";

import { decodeShellQrUr } from "./keycard-shell-qr-transport.js";

export function decodeShellQrImage(image: Uint8Array): Buffer {
  const png = PNG.sync.read(Buffer.from(image));

  if (png.width > 4096 || png.height > 4096) {
    throw new Error("QR image dimensions exceed limit");
  }

  const result = jsQR(
    new Uint8ClampedArray(png.data),
    png.width,
    png.height,
    { inversionAttempts: "attemptBoth" },
  );

  if (!result) {
    throw new Error("No QR code found in image");
  }

  return decodeShellQrUr(result.data);
}
