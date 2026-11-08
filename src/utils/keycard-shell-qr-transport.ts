import { UR, UREncoder, URDecoder } from "@ngraveio/bc-ur";

export function encodeShellQrUr(payload: Uint8Array): string {
  const encoder = new UREncoder(
    UR.fromBuffer(Buffer.from(payload)),
    200,
  );

  const part = encoder.nextPart();

  if (!/^ur:bytes\/[a-z]+$/i.test(part)) {
    throw new Error("Expected single-part UR:BYTES");
  }

  return part;
}

export function decodeShellQrUr(value: string): Buffer {
  if (!/^ur:bytes\/[a-z]+$/i.test(value)) {
    throw new Error("Expected single-part UR:BYTES");
  }

  const decoder = new URDecoder();
  decoder.receivePart(value.toLowerCase());

  if (!decoder.isComplete() || !decoder.isSuccess()) {
    throw new Error("Invalid UR:BYTES payload");
  }

  return Buffer.from(decoder.resultUR().decodeCBOR());
}
