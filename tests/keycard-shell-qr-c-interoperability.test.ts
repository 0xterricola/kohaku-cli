import assert from "node:assert/strict";
import QRCode from "qrcode";
import { encodeShellQrUr } from "../src/utils/keycard-shell-qr-transport.js";
import { decodeShellQrImage } from "../src/utils/keycard-shell-qr-image.js";
import { test } from "node:test";
import { createECDH, createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";

import {
  decodeShellBatchRequest,
} from "../src/utils/keycard-shell-qr-batch.js";
import {
  decryptShellBatchResponse,
} from "../src/utils/keycard-shell-qr-batch-response.js";

const binary = process.env.KOHaku_SHELL_VECTOR_BIN;

test("C firmware KKR3 decrypts to exact V3-R3 credentials", {
  skip: !binary,
}, async () => {
  const output = execFileSync(binary!, ["--vector"], {
    encoding: "utf8",
  });

  function extract(label: string): Buffer {
    const match = output.match(
      new RegExp(`^${label}=([0-9a-f]+)$`, "m"),
    );
    assert.ok(match, `Missing ${label}`);
    return Buffer.from(match[1], "hex");
  }

  const request = extract("KKQ3_REQUEST_HEX");
  const response = extract("KKR3_RESPONSE_HEX");
  const parsed = decodeShellBatchRequest(request);

  assert.equal(parsed.paths.length, 2);
  assert.equal(response.length, 172);

  for (const [label, payload] of [
    ["request", request],
    ["response", response],
  ] as const) {
    const ur = encodeShellQrUr(payload);
    const png = await QRCode.toBuffer(ur, {
      errorCorrectionLevel: "M",
      margin: 4,
      width: 512,
    });

    assert.deepEqual(
      decodeShellQrImage(png),
      payload,
      `${label} QR round-trip`,
    );

    console.log(`PASS: ${label} single-frame QR`);
  }


  // Publicly known synthetic test scalar: 1.
  const hostPrivate = Buffer.alloc(32);
  hostPrivate[31] = 1;

  const host = createECDH("secp256k1");
  host.setPrivateKey(hostPrivate);
  hostPrivate.fill(0);

  assert.deepEqual(
    host.getPublicKey(undefined, "uncompressed"),
    parsed.hostPublicKey,
  );

  let consumed = false;
  const credentials = decryptShellBatchResponse({
    request,
    deriveSharedSecret(shellPublicKey) {
      assert.equal(consumed, false);
      consumed = true;
      return host.computeSecret(shellPublicKey);
    },
  }, response);

  // Same synthetic root used by the firmware native test.
  const root = Buffer.alloc(32, 0x42);

  try {
    assert.equal(credentials.length, 2);

    for (let i = 0; i < parsed.paths.length; i++) {
      const expected = createHmac("sha256", root)
        .update("kohaku-key/v3-r3/privacy-pools-v1/deriveAt")
        .update("\0")
        .update(parsed.paths[i])
        .digest();

      try {
        assert.deepEqual(credentials[i], expected);
      } finally {
        expected.fill(0);
      }
    }

    assert.notDeepEqual(credentials[0], credentials[1]);
  } finally {
    root.fill(0);
    credentials.forEach((credential) => credential.fill(0));
  }
});
