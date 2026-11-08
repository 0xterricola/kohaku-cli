import assert from "node:assert/strict";
import { test } from "node:test";
import QRCode from "qrcode";

import {
  encodeShellQrRequest,
  encodeShellQrResponse,
  decodeShellQrRequest,
  decodeShellQrResponse,
} from "../src/utils/keycard-shell-qr-protocol.js";

import {
  encodeShellQrUr,
  decodeShellQrUr,
} from "../src/utils/keycard-shell-qr-transport.js";

const challenge = Buffer.alloc(16, 0x42);
const tag = Buffer.alloc(32, 0x7a);

test("request survives UR:BYTES transport", () => {
  const request = encodeShellQrRequest(challenge);
  const encoded = encodeShellQrUr(request);

  assert.match(encoded, /^ur:bytes\/[a-z]+$/i);
  assert.deepEqual(decodeShellQrUr(encoded), request);
  assert.deepEqual(
    decodeShellQrRequest(decodeShellQrUr(encoded)).challenge,
    challenge,
  );
});

test("response survives UR:BYTES transport", () => {
  const response = encodeShellQrResponse(challenge, tag);
  const encoded = encodeShellQrUr(response);

  assert.deepEqual(decodeShellQrUr(encoded), response);
  assert.deepEqual(
    decodeShellQrResponse(decodeShellQrUr(encoded)).tag,
    tag,
  );
});

test("reject unsupported UR types and multipart input", () => {
  const encoded = encodeShellQrUr(
    encodeShellQrRequest(challenge),
  );

  assert.throws(() =>
    decodeShellQrUr(encoded.replace("ur:bytes/", "ur:seed/")),
  );

  assert.throws(() =>
    decodeShellQrUr("ur:bytes/1-2/invalid"),
  );
});

test("reject corrupted Bytewords checksum", () => {
  const encoded = encodeShellQrUr(
    encodeShellQrRequest(challenge),
  );

  const last = encoded.slice(-1);
  const corrupted = encoded.slice(0, -1) +
    (last === "a" ? "b" : "a");

  assert.throws(() => decodeShellQrUr(corrupted));
});

test("UR request renders as PNG QR", async () => {
  const encoded = encodeShellQrUr(
    encodeShellQrRequest(challenge),
  );

  const png = await QRCode.toBuffer(encoded, {
    type: "png",
    errorCorrectionLevel: "M",
    margin: 4,
  });

  assert.equal(
    png.subarray(0, 8).toString("hex"),
    "89504e470d0a1a0a",
  );
});
