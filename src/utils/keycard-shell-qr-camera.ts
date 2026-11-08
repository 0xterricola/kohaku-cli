import { spawn } from "node:child_process";
import jsQR from "jsqr";
import { PNG } from "pngjs";

import { decodeShellQrImage } from "./keycard-shell-qr-image.js";

const WIDTH = 960;
const HEIGHT = 960;
const FRAME_SIZE = WIDTH * HEIGHT * 4;

export async function captureShellQrResponse(): Promise<Uint8Array> {
  const device = process.env.KOHAKU_SHELL_CAMERA ?? "0";

  console.log("Camera active. Show the Shell response QR to the Mac webcam.");

  const camera = spawn("ffmpeg", [
    "-hide_banner", "-loglevel", "error",
    "-f", "avfoundation",
    "-framerate", "30",
    "-i", `${device}:none`,
    "-vf", `fps=4,scale=${WIDTH}:${HEIGHT}:force_original_aspect_ratio=decrease,pad=${WIDTH}:${HEIGHT}:(ow-iw)/2:(oh-ih)/2`,
    "-pix_fmt", "rgba",
    "-f", "rawvideo", "pipe:1",
  ], { stdio: ["ignore", "pipe", "pipe"] });

  let error: Error | undefined;
  let stderr = "";
  let timedOut = false;
  let pending = Buffer.alloc(0);
  let framesScanned = 0;
  let qrFrames = 0;
  let shellQrFrames = 0;
  let completed = false;
  const startedAt = Date.now();

  console.log("Scanning automatically — 120-second timeout.");
  console.log("Hold the Shell response QR steady. No Enter key needed.");

  const progress = setInterval(() => {
    const elapsed = Math.min(
      120,
      Math.floor((Date.now() - startedAt) / 1000),
    );
    console.log(
      `SCAN ${elapsed}/120s | Frames: ${framesScanned} | QR detected: ${qrFrames} | Shell QR: ${shellQrFrames}`,
    );
  }, 5_000);

  camera.on("error", (err) => { error = err; });
  camera.on("close", (code, signal) => {
    if (!completed && !timedOut) {
      console.log(
        `Camera stopped before success (exit: ${code ?? "unknown"}, signal: ${signal ?? "none"}).`,
      );
    }
  });
  camera.stderr.setEncoding("utf8");
  camera.stderr.on("data", (chunk: string) => {
    stderr = (stderr + chunk).slice(-2048);
  });

  const timeout = setTimeout(() => {
    timedOut = true;
    console.log("SCAN TIMEOUT: No authenticated Shell response within 120 seconds.");
    camera.kill();
  }, 120_000);

  try {
    for await (const chunk of camera.stdout) {
      pending = Buffer.concat([pending, chunk as Buffer]);

      while (pending.length >= FRAME_SIZE) {
        const frame = pending.subarray(0, FRAME_SIZE);
        pending = pending.subarray(FRAME_SIZE);
        framesScanned++;

        const qr = jsQR(
          new Uint8ClampedArray(frame),
          WIDTH,
          HEIGHT,
        );

        if (qr) {
          qrFrames++;
          if (qrFrames === 1) {
            console.log("QR detected — checking response format.");
          }
        }

        if (!qr || !/^ur:bytes\//i.test(qr.data)) continue;

        shellQrFrames++;
        if (shellQrFrames === 1) {
          console.log("Shell QR detected — authenticating response.");
        }

        try {
          const image = new PNG({
            width: WIDTH,
            height: HEIGHT,
          });
          frame.copy(image.data);
          const png = PNG.sync.write(image);

          const response = decodeShellQrImage(png);
          completed = true;
          console.log("PASS: Shell response QR captured");
          return response;
        } catch {
          // Ignore unreadable frames and continue scanning.
        }
      }
    }

    if (error) throw error;
    throw new Error(
      timedOut
        ? "Camera capture timed out"
        : `Camera stopped without a valid QR: ${stderr.trim()}`,
    );
  } finally {
    clearTimeout(timeout);
    clearInterval(progress);
    camera.kill();
  }
}
