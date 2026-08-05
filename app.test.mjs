"use strict";

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("./app.js", import.meta.url), "utf8");
const sandbox = {
  console,
  DataView,
  TextDecoder,
  TextEncoder,
  Uint8Array,
  Uint8ClampedArray,
};
vm.runInNewContext(
  `${source}\nglobalThis.codec = { capacityInBytes, embedMessage, extractMessage };`,
  sandbox,
  { filename: "app.js" },
);
const {
  capacityInBytes,
  embedMessage,
  extractMessage,
} = sandbox.codec;

const HEADER_SIZE_IN_PIXELS = 12 * 8;

function pixelData(pixelCount) {
  return new Uint8ClampedArray(pixelCount * 4).fill(255);
}

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
    /Message is too large/,
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
