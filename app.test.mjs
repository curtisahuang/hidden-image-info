"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("./app.js", import.meta.url), "utf8");
const sandbox = {
  console,
  crypto: webcrypto,
  DataView,
  TextDecoder,
  TextEncoder,
  Uint8Array,
  Uint8ClampedArray,
};
vm.runInNewContext(
  `${source}\nglobalThis.codec = {
    capacityInBytes,
    embedMessage,
    extractMessage,
    embedTernaryMessage,
    extractTernaryMessage,
    embedSecureMessage,
    extractSecureMessage,
    embedBinaryImage,
    extractBinaryPayload,
    embedTernaryImage,
    extractTernaryPayload,
    embedSecureImage,
    extractSecurePayload,
  };`,
  sandbox,
  { filename: "app.js" },
);
const {
  capacityInBytes,
  embedMessage,
  extractMessage,
  embedTernaryMessage,
  extractTernaryMessage,
  embedSecureMessage,
  extractSecureMessage,
  embedBinaryImage,
  extractBinaryPayload,
  embedTernaryImage,
  extractTernaryPayload,
  embedSecureImage,
  extractSecurePayload,
} = sandbox.codec;

const HEADER_SIZE_IN_PIXELS = 12 * 8;

function pixelData(pixelCount) {
  return new Uint8ClampedArray(pixelCount * 4).fill(255);
}

const pngBytes = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
]);

test("encodes and decodes Unicode text through one channel", () => {
  const pixels = pixelData(512);
  const encoded = embedMessage(pixels, ["blue"], "Secret café");

  assert.equal(extractMessage(encoded, ["blue"]), "Secret café");
  assert.notDeepEqual(encoded, pixels);
});

test("encodes across multiple selected channels", () => {
  const pixels = pixelData(256);
  const channels = ["red", "green", "blue", "alpha"];
  const encoded = embedMessage(pixels, channels, "RGBA");

  assert.equal(extractMessage(encoded, channels), "RGBA");
});

test("rejects decoding with the wrong channel selection", () => {
  const encoded = embedMessage(pixelData(256), ["red"], "hidden");

  assert.throws(
    () => extractMessage(encoded, ["blue"]),
    /No message found/,
  );
});

test("rejects messages larger than the image capacity", () => {
  const pixels = pixelData(104);

  assert.equal(capacityInBytes(pixels, ["blue"]), 1);
  assert.throws(
    () => embedMessage(pixels, ["blue"], "too large"),
    /Payload is too large/,
  );
});

test("detects payload corruption", () => {
  const channels = ["blue"];
  const encoded = embedMessage(pixelData(256), channels, "integrity");
  encoded[HEADER_SIZE_IN_PIXELS * 4 + 2] ^= 1;

  assert.throws(
    () => extractMessage(encoded, channels),
    /integrity check/,
  );
});

test("ternary mode has greater capacity and round-trips Unicode text", () => {
  const pixels = pixelData(512);
  const channels = ["blue"];
  const encoded = embedTernaryMessage(pixels, channels, "Three states △");

  assert.ok(
    capacityInBytes(pixels, channels, "ternary")
      > capacityInBytes(pixels, channels, "binary"),
  );
  assert.equal(extractTernaryMessage(encoded, channels), "Three states △");
});

test("encrypted mode round-trips with the correct password", async () => {
  const pixels = pixelData(2048);
  const encoded = await embedSecureMessage(
    pixels,
    ["red", "blue"],
    "Encrypted café",
    "six-random-words-make-a-strong-password",
  );

  assert.equal(
    await extractSecureMessage(
      encoded,
      ["red", "blue"],
      "six-random-words-make-a-strong-password",
    ),
    "Encrypted café",
  );
});

test("encrypted mode rejects an incorrect password", async () => {
  const encoded = await embedSecureMessage(
    pixelData(2048),
    ["blue"],
    "private",
    "correct-password",
  );

  await assert.rejects(
    () => extractSecureMessage(encoded, ["blue"], "wrong-password"),
    /Incorrect password/,
  );
});

test("binary mode preserves hidden PNG bytes exactly", () => {
  const channels = ["blue"];
  const encoded = embedBinaryImage(pixelData(512), channels, pngBytes);
  const payload = extractBinaryPayload(encoded, channels);

  assert.equal(payload.type, "image");
  assert.deepEqual(Array.from(payload.bytes), Array.from(pngBytes));
});

test("ternary mode preserves hidden PNG bytes exactly", () => {
  const channels = ["green", "blue"];
  const encoded = embedTernaryImage(pixelData(512), channels, pngBytes);
  const payload = extractTernaryPayload(encoded, channels);

  assert.equal(payload.type, "image");
  assert.deepEqual(Array.from(payload.bytes), Array.from(pngBytes));
});

test("encrypted mode preserves hidden PNG bytes exactly", async () => {
  const channels = ["red", "blue"];
  const password = "image-encryption-password";
  const encoded = await embedSecureImage(
    pixelData(2048),
    channels,
    pngBytes,
    password,
  );
  const payload = await extractSecurePayload(encoded, channels, password);

  assert.equal(payload.type, "image");
  assert.deepEqual(Array.from(payload.bytes), Array.from(pngBytes));
});
