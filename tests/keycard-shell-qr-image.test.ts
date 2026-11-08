import assert from "node:assert/strict";
import { test } from "node:test";
import QRCode from "qrcode";

import {
  encodeShellQrRequest,
  encodeShellQrResponse,
  createShellQrResponseSession,
} from "../src/utils/keycard-shell-qr-protocol.js";

import {
  encodeShellQrUr,
} from "../src/utils/keycard-shell-qr-transport.js";

import {
  decodeShellQrImage,
} from "../src/utils/keycard-shell-qr-image.js";

test("decode QR PNG and bind response to request", async () => {
  const challenge = Buffer.alloc(16, 0x42);
  const tag = Buffer.alloc(32, 0x7a);

  const request = encodeShellQrRequest(challenge);
  const response = encodeShellQrResponse(challenge, tag);

  const png = await QRCode.toBuffer(
    encodeShellQrUr(response),
    { type: "png", width: 512 },
  );

  const session = createShellQrResponseSession(request);

  assert.deepEqual(
    session.accept(decodeShellQrImage(png)),
    tag,
  );

  assert.throws(
    () => session.accept(decodeShellQrImage(png)),
    /already consumed/,
  );
});

test("reject image without QR", () => {
  const png = Buffer.from(
    "89504e470d0a1a0a",
    "hex",
  );

  assert.throws(() => decodeShellQrImage(png));
});
