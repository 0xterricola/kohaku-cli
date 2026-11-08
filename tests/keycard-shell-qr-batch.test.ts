import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createShellBatchRequest,
  decodeShellBatchRequest,
} from "../src/utils/keycard-shell-qr-batch.js";
import { encodeShellQrUr } from "../src/utils/keycard-shell-qr-transport.js";

const paths = [
  "m/28784'/1'/0'/0'/17'/0'",
  "m/28784'/1'/0'/1'/17'/0'",
];

test("Two credential paths fit a single request QR", () => {
  const session = createShellBatchRequest(paths);
  const decoded = decodeShellBatchRequest(session.request);

  assert.deepEqual(decoded.paths, paths);
  assert.equal(session.fingerprint.length, 16);
  assert.match(encodeShellQrUr(session.request), /^ur:bytes\//);
});

test("Reject duplicate paths", () => {
  assert.throws(() =>
    createShellBatchRequest([paths[0], paths[0]]),
  );
});

test("Reject malformed batch framing", () => {
  const session = createShellBatchRequest(paths);

  const truncated = session.request.subarray(
    0,
    session.request.length - 1,
  );

  assert.throws(() => decodeShellBatchRequest(truncated));

  const extra = Buffer.concat([
    session.request,
    Buffer.from([0]),
  ]);

  assert.throws(() => decodeShellBatchRequest(extra));
});
