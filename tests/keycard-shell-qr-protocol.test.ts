import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createShellQrRequest,
  createShellQrResponseSession,
  decodeShellQrRequest,
  decodeShellQrResponse,
  encodeShellQrRequest,
  encodeShellQrResponse,
} from "../src/utils/keycard-shell-qr-protocol.js";

const challenge = Buffer.alloc(16, 0x42);
const tag = Buffer.alloc(32, 0x7a);

test("request has fixed binary format", () => {
  const request = encodeShellQrRequest(challenge);

  assert.equal(request.length, 21);
  assert.equal(request.toString("ascii", 0, 4), "KKQ1");
  assert.equal(request[4], 1);
  assert.deepEqual(decodeShellQrRequest(request).challenge, challenge);
});

test("response has fixed binary format", () => {
  const response = encodeShellQrResponse(challenge, tag);

  assert.equal(response.length, 53);
  assert.equal(response.toString("ascii", 0, 4), "KKR1");
  assert.equal(response[4], 1);
  assert.deepEqual(decodeShellQrResponse(response).tag, tag);
});

test("fresh requests use independent challenges", () => {
  const first = createShellQrRequest();
  const second = createShellQrRequest();

  assert.notDeepEqual(first, second);
});

test("reject invalid versions and operations", () => {
  const request = encodeShellQrRequest(challenge);
  const response = encodeShellQrResponse(challenge, tag);

  for (const index of [0, 4]) {
    const badRequest = Buffer.from(request);
    badRequest[index] ^= 0xff;
    assert.throws(() => decodeShellQrRequest(badRequest));

    const badResponse = Buffer.from(response);
    badResponse[index] ^= 0xff;
    assert.throws(() => decodeShellQrResponse(badResponse));
  }
});

test("reject truncation and trailing bytes", () => {
  const request = encodeShellQrRequest(challenge);
  const response = encodeShellQrResponse(challenge, tag);

  for (const bytes of [request, response]) {
    const decode = bytes.length === 21
      ? decodeShellQrRequest
      : decodeShellQrResponse;

    assert.throws(() => decode(bytes.subarray(0, -1)));
    assert.throws(() => decode(Buffer.concat([bytes, Buffer.alloc(1)])));
  }
});

test("bind response to challenge and reject replay", () => {
  const request = encodeShellQrRequest(challenge);
  const response = encodeShellQrResponse(challenge, tag);
  const session = createShellQrResponseSession(request);

  const wrongChallenge = Buffer.alloc(16, 0x43);
  const wrongResponse = encodeShellQrResponse(wrongChallenge, tag);

  assert.throws(
    () => session.accept(wrongResponse),
    /challenge mismatch/,
  );

  assert.deepEqual(session.accept(response), tag);

  assert.throws(
    () => session.accept(response),
    /already consumed/,
  );
});
