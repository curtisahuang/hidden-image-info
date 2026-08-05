"use strict";

const CHANNEL_INDEX = {
  red: 0,
  green: 1,
  blue: 2,
  alpha: 3,
};
const BINARY_MAGIC = new Uint8Array([0x49, 0x53, 0x4d, 0x31]);
const BINARY_IMAGE_MAGIC = new Uint8Array([0x49, 0x53, 0x49, 0x31]);
const TERNARY_MAGIC = new Uint8Array([0x49, 0x53, 0x4d, 0x32]);
const TERNARY_IMAGE_MAGIC = new Uint8Array([0x49, 0x53, 0x49, 0x32]);
const HEADER_SIZE = 12;
const TERNARY_BLOCK_BITS = 19;
const TERNARY_BLOCK_TRITS = 12;
const SECURE_TEXT_VERSION = 1;
const SECURE_IMAGE_VERSION = 2;
const SECURE_SALT_SIZE = 16;
const SECURE_NONCE_SIZE = 12;
const SECURE_HEADER_SIZE = 1 + SECURE_SALT_SIZE + SECURE_NONCE_SIZE + 4;
const AES_GCM_TAG_SIZE = 16;
const KEY_DERIVATION_ITERATIONS = 600000;

function crc32(bytes) {
  let crc = 0xffffffff;

  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }

  return (crc ^ 0xffffffff) >>> 0;
}

function createHeader(magic, payload) {
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);

  header.set(magic, 0);
  view.setUint32(4, payload.length);
  view.setUint32(8, crc32(payload));

  return header;
}

function createPacket(payload, magic) {
  const packet = new Uint8Array(HEADER_SIZE + payload.length);
  packet.set(createHeader(magic, payload));
  packet.set(payload, HEADER_SIZE);
  return packet;
}

function magicMatches(bytes, magic) {
  return magic.every((byte, index) => bytes[index] === byte);
}

function getChannelIndices(channels) {
  if (!channels.length) {
    throw new Error("Select at least one channel.");
  }

  return channels.map((channel) => {
    if (!(channel in CHANNEL_INDEX)) {
      throw new Error(`Unknown channel: ${channel}`);
    }
    return CHANNEL_INDEX[channel];
  });
}

function slotCount(pixelData, channelIndices) {
  return (pixelData.length / 4) * channelIndices.length;
}

function binaryCapacityInBytes(pixelData, channelIndices) {
  return Math.max(0, Math.floor(slotCount(pixelData, channelIndices) / 8) - HEADER_SIZE);
}

function tritsForBitCount(bitCount) {
  if (bitCount === 0) {
    return 0;
  }

  let tritCount = 0;
  let combinations = 1;
  const requiredValues = 2 ** bitCount;
  while (combinations < requiredValues) {
    combinations *= 3;
    tritCount += 1;
  }
  return tritCount;
}

function tritCountForBytes(byteCount) {
  const bitCount = byteCount * 8;
  const fullBlocks = Math.floor(bitCount / TERNARY_BLOCK_BITS);
  return fullBlocks * TERNARY_BLOCK_TRITS
    + tritsForBitCount(bitCount % TERNARY_BLOCK_BITS);
}

function ternaryCapacityInBytes(pixelData, channelIndices) {
  const availableTrits = slotCount(pixelData, channelIndices) - tritCountForBytes(HEADER_SIZE);
  if (availableTrits <= 0) {
    return 0;
  }

  let capacity = Math.floor((availableTrits * Math.log2(3)) / 8);
  while (capacity > 0 && tritCountForBytes(capacity) > availableTrits) {
    capacity -= 1;
  }
  return capacity;
}

function secureCapacityInBytes(pixelData, channelIndices) {
  const availableBits = slotCount(pixelData, channelIndices) - SECURE_HEADER_SIZE * 8;
  return Math.max(0, Math.floor(availableBits / 8) - AES_GCM_TAG_SIZE);
}

function capacityInBytes(pixelData, channels, mode = "binary") {
  const channelIndices = getChannelIndices(channels);
  if (mode === "ternary") {
    return ternaryCapacityInBytes(pixelData, channelIndices);
  }
  if (mode === "secure") {
    return secureCapacityInBytes(pixelData, channelIndices);
  }
  return binaryCapacityInBytes(pixelData, channelIndices);
}

function embedMessage(pixelData, channels, message) {
  return embedBinaryPayload(
    pixelData,
    channels,
    new TextEncoder().encode(message),
    BINARY_MAGIC,
  );
}

function embedBinaryImage(pixelData, channels, imageBytes) {
  return embedBinaryPayload(pixelData, channels, imageBytes, BINARY_IMAGE_MAGIC);
}

function embedBinaryPayload(pixelData, channels, payload, magic) {
  const channelIndices = getChannelIndices(channels);
  const packet = createPacket(payload, magic);
  const availableBits = (pixelData.length / 4) * channelIndices.length;

  if (packet.length * 8 > availableBits) {
    const availableBytes = binaryCapacityInBytes(pixelData, channelIndices);
    throw new Error(`Payload is too large. This image can hold ${availableBytes.toLocaleString()} bytes.`);
  }

  const encodedPixels = new Uint8ClampedArray(pixelData);
  let slot = 0;

  for (const byte of packet) {
    for (let bit = 7; bit >= 0; bit -= 1) {
      const pixelIndex = Math.floor(slot / channelIndices.length);
      const channelIndex = channelIndices[slot % channelIndices.length];
      const dataIndex = pixelIndex * 4 + channelIndex;
      encodedPixels[dataIndex] = (encodedPixels[dataIndex] & 0xfe) | ((byte >>> bit) & 1);
      slot += 1;
    }
  }

  return encodedPixels;
}

function readBytes(pixelData, channelIndices, byteCount, startSlot = 0) {
  const output = new Uint8Array(byteCount);
  let slot = startSlot;

  for (let byteIndex = 0; byteIndex < byteCount; byteIndex += 1) {
    let byte = 0;
    for (let bit = 7; bit >= 0; bit -= 1) {
      const pixelIndex = Math.floor(slot / channelIndices.length);
      const channelIndex = channelIndices[slot % channelIndices.length];
      byte |= (pixelData[pixelIndex * 4 + channelIndex] & 1) << bit;
      slot += 1;
    }
    output[byteIndex] = byte;
  }

  return output;
}

function extractMessage(pixelData, channels) {
  const payload = extractBinaryPayload(pixelData, channels);
  if (payload.type !== "text") {
    throw new Error("The hidden payload is an image, not text.");
  }
  return decodeText(payload.bytes);
}

function extractBinaryPayload(pixelData, channels) {
  const channelIndices = getChannelIndices(channels);
  const totalBytes = Math.floor(((pixelData.length / 4) * channelIndices.length) / 8);

  if (totalBytes < HEADER_SIZE) {
    throw new Error("This image is too small to contain a payload.");
  }

  const header = readBytes(pixelData, channelIndices, HEADER_SIZE);
  const isText = magicMatches(header, BINARY_MAGIC);
  const isImage = magicMatches(header, BINARY_IMAGE_MAGIC);
  if (!isText && !isImage) {
    throw new Error("No message found with the selected channels.");
  }

  const view = new DataView(header.buffer);
  const payloadLength = view.getUint32(4);
  const expectedChecksum = view.getUint32(8);

  if (payloadLength > totalBytes - HEADER_SIZE) {
    throw new Error("The hidden message is incomplete or corrupted.");
  }

  const payload = readBytes(pixelData, channelIndices, payloadLength, HEADER_SIZE * 8);
  if (crc32(payload) !== expectedChecksum) {
    throw new Error("The hidden message failed its integrity check.");
  }

  return {
    type: isImage ? "image" : "text",
    bytes: payload,
  };
}

function bytesToTrits(bytes) {
  const trits = new Uint8Array(tritCountForBytes(bytes.length));
  const totalBits = bytes.length * 8;
  let bitOffset = 0;
  let tritOffset = 0;

  while (bitOffset < totalBits) {
    const blockBits = Math.min(TERNARY_BLOCK_BITS, totalBits - bitOffset);
    let value = 0;
    for (let bit = 0; bit < blockBits; bit += 1) {
      const absoluteBit = bitOffset + bit;
      value = value * 2 + ((bytes[Math.floor(absoluteBit / 8)] >>> (7 - (absoluteBit % 8))) & 1);
    }

    const blockTrits = tritsForBitCount(blockBits);
    for (let trit = blockTrits - 1; trit >= 0; trit -= 1) {
      trits[tritOffset + trit] = value % 3;
      value = Math.floor(value / 3);
    }
    bitOffset += blockBits;
    tritOffset += blockTrits;
  }

  return trits;
}

function tritsToBytes(trits, byteCount) {
  const bytes = new Uint8Array(byteCount);
  const totalBits = byteCount * 8;
  let bitOffset = 0;
  let tritOffset = 0;

  while (bitOffset < totalBits) {
    const blockBits = Math.min(TERNARY_BLOCK_BITS, totalBits - bitOffset);
    const blockTrits = tritsForBitCount(blockBits);
    let value = 0;
    for (let trit = 0; trit < blockTrits; trit += 1) {
      value = value * 3 + trits[tritOffset + trit];
    }
    if (value >= 2 ** blockBits) {
      throw new Error("The hidden ternary data is malformed.");
    }

    for (let bit = blockBits - 1; bit >= 0; bit -= 1) {
      const absoluteBit = bitOffset + bit;
      bytes[Math.floor(absoluteBit / 8)] |= (value & 1) << (7 - (absoluteBit % 8));
      value = Math.floor(value / 2);
    }
    bitOffset += blockBits;
    tritOffset += blockTrits;
  }

  return bytes;
}

function valueForTrit(value, trit) {
  if (value % 3 === trit) {
    return value;
  }

  for (let distance = 1; distance <= 2; distance += 1) {
    if (value - distance >= 0 && (value - distance) % 3 === trit) {
      return value - distance;
    }
    if (value + distance <= 255 && (value + distance) % 3 === trit) {
      return value + distance;
    }
  }
  return value;
}

function writeTrits(pixelData, channelIndices, trits, startSlot = 0) {
  for (let offset = 0; offset < trits.length; offset += 1) {
    const slot = startSlot + offset;
    const pixelIndex = Math.floor(slot / channelIndices.length);
    const channelIndex = channelIndices[slot % channelIndices.length];
    const dataIndex = pixelIndex * 4 + channelIndex;
    pixelData[dataIndex] = valueForTrit(pixelData[dataIndex], trits[offset]);
  }
}

function readTrits(pixelData, channelIndices, tritCount, startSlot = 0) {
  const trits = new Uint8Array(tritCount);
  for (let offset = 0; offset < tritCount; offset += 1) {
    const slot = startSlot + offset;
    const pixelIndex = Math.floor(slot / channelIndices.length);
    const channelIndex = channelIndices[slot % channelIndices.length];
    trits[offset] = pixelData[pixelIndex * 4 + channelIndex] % 3;
  }
  return trits;
}

function embedTernaryMessage(pixelData, channels, message) {
  return embedTernaryPayload(
    pixelData,
    channels,
    new TextEncoder().encode(message),
    TERNARY_MAGIC,
  );
}

function embedTernaryImage(pixelData, channels, imageBytes) {
  return embedTernaryPayload(pixelData, channels, imageBytes, TERNARY_IMAGE_MAGIC);
}

function embedTernaryPayload(pixelData, channels, payload, magic) {
  const channelIndices = getChannelIndices(channels);
  const headerTrits = bytesToTrits(createHeader(magic, payload));
  const payloadTrits = bytesToTrits(payload);

  if (headerTrits.length + payloadTrits.length > slotCount(pixelData, channelIndices)) {
    const availableBytes = ternaryCapacityInBytes(pixelData, channelIndices);
    throw new Error(`Payload is too large. This image can hold ${availableBytes.toLocaleString()} bytes.`);
  }

  const encodedPixels = new Uint8ClampedArray(pixelData);
  writeTrits(encodedPixels, channelIndices, headerTrits);
  writeTrits(encodedPixels, channelIndices, payloadTrits, headerTrits.length);
  return encodedPixels;
}

function extractTernaryMessage(pixelData, channels) {
  const payload = extractTernaryPayload(pixelData, channels);
  if (payload.type !== "text") {
    throw new Error("The hidden payload is an image, not text.");
  }
  return decodeText(payload.bytes);
}

function extractTernaryPayload(pixelData, channels) {
  const channelIndices = getChannelIndices(channels);
  const headerTritCount = tritCountForBytes(HEADER_SIZE);
  if (slotCount(pixelData, channelIndices) < headerTritCount) {
    throw new Error("This image is too small to contain a payload.");
  }

  const header = tritsToBytes(
    readTrits(pixelData, channelIndices, headerTritCount),
    HEADER_SIZE,
  );
  const isText = magicMatches(header, TERNARY_MAGIC);
  const isImage = magicMatches(header, TERNARY_IMAGE_MAGIC);
  if (!isText && !isImage) {
    throw new Error("No ternary message found with the selected channels.");
  }

  const view = new DataView(header.buffer);
  const payloadLength = view.getUint32(4);
  const expectedChecksum = view.getUint32(8);
  const payloadTritCount = tritCountForBytes(payloadLength);
  if (headerTritCount + payloadTritCount > slotCount(pixelData, channelIndices)) {
    throw new Error("The hidden message is incomplete or corrupted.");
  }

  const payload = tritsToBytes(
    readTrits(pixelData, channelIndices, payloadTritCount, headerTritCount),
    payloadLength,
  );
  if (crc32(payload) !== expectedChecksum) {
    throw new Error("The hidden message failed its integrity check.");
  }
  return {
    type: isImage ? "image" : "text",
    bytes: payload,
  };
}

function decodeText(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("The hidden data is not valid UTF-8 text.");
  }
}

function writeBits(pixelData, channelIndices, bytes, slotProvider) {
  let bitOffset = 0;
  for (const byte of bytes) {
    for (let bit = 7; bit >= 0; bit -= 1) {
      const slot = slotProvider(bitOffset);
      const pixelIndex = Math.floor(slot / channelIndices.length);
      const channelIndex = channelIndices[slot % channelIndices.length];
      const dataIndex = pixelIndex * 4 + channelIndex;
      pixelData[dataIndex] = (pixelData[dataIndex] & 0xfe) | ((byte >>> bit) & 1);
      bitOffset += 1;
    }
  }
}

function readBits(pixelData, channelIndices, byteCount, slotProvider) {
  const bytes = new Uint8Array(byteCount);
  let bitOffset = 0;
  for (let byteIndex = 0; byteIndex < byteCount; byteIndex += 1) {
    for (let bit = 7; bit >= 0; bit -= 1) {
      const slot = slotProvider(bitOffset);
      const pixelIndex = Math.floor(slot / channelIndices.length);
      const channelIndex = channelIndices[slot % channelIndices.length];
      bytes[byteIndex] |= (pixelData[pixelIndex * 4 + channelIndex] & 1) << bit;
      bitOffset += 1;
    }
  }
  return bytes;
}

function greatestCommonDivisor(left, right) {
  while (right !== 0) {
    [left, right] = [right, left % right];
  }
  return left;
}

function createKeyedSlotProvider(seed, startSlot, totalSlots) {
  const availableSlots = totalSlots - startSlot;
  if (availableSlots <= 0) {
    throw new Error("This image is too small to contain encrypted data.");
  }

  const view = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
  let step = view.getUint32(0) % availableSlots;
  if (step === 0) {
    step = 1;
  }
  while (greatestCommonDivisor(step, availableSlots) !== 1) {
    step = (step + 1) % availableSlots || 1;
  }
  let position = view.getUint32(4) % availableSlots;

  return () => {
    const slot = startSlot + position;
    position += step;
    if (position >= availableSlots) {
      position -= availableSlots;
    }
    return slot;
  };
}

async function deriveSecureKeys(password, salt) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Password encryption is not available in this browser context.");
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derivedBits = new Uint8Array(await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: KEY_DERIVATION_ITERATIONS,
    },
    keyMaterial,
    512,
  ));
  const encryptionKey = await crypto.subtle.importKey(
    "raw",
    derivedBits.slice(0, 32),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
  return {
    encryptionKey,
    placementSeed: derivedBits.slice(32),
  };
}

function createSecureHeader(version, salt, nonce, ciphertextLength) {
  const header = new Uint8Array(SECURE_HEADER_SIZE);
  header[0] = version;
  header.set(salt, 1);
  header.set(nonce, 1 + SECURE_SALT_SIZE);
  new DataView(header.buffer).setUint32(SECURE_HEADER_SIZE - 4, ciphertextLength);
  return header;
}

async function embedSecureMessage(pixelData, channels, message, password) {
  return embedSecurePayload(
    pixelData,
    channels,
    new TextEncoder().encode(message),
    password,
    SECURE_TEXT_VERSION,
  );
}

async function embedSecureImage(pixelData, channels, imageBytes, password) {
  return embedSecurePayload(
    pixelData,
    channels,
    imageBytes,
    password,
    SECURE_IMAGE_VERSION,
  );
}

async function embedSecurePayload(pixelData, channels, payload, password, version) {
  if (!password) {
    throw new Error("Enter a password for encrypted mode.");
  }

  const channelIndices = getChannelIndices(channels);
  const availableBytes = secureCapacityInBytes(pixelData, channelIndices);
  if (payload.length > availableBytes) {
    throw new Error(`Payload is too large. This image can hold ${availableBytes.toLocaleString()} encrypted bytes.`);
  }

  const salt = crypto.getRandomValues(new Uint8Array(SECURE_SALT_SIZE));
  const nonce = crypto.getRandomValues(new Uint8Array(SECURE_NONCE_SIZE));
  const ciphertextLength = payload.length + AES_GCM_TAG_SIZE;
  const header = createSecureHeader(version, salt, nonce, ciphertextLength);
  const { encryptionKey, placementSeed } = await deriveSecureKeys(password, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: header,
      tagLength: 128,
    },
    encryptionKey,
    payload,
  ));

  const encodedPixels = new Uint8ClampedArray(pixelData);
  writeBits(encodedPixels, channelIndices, header, (offset) => offset);
  const headerBits = SECURE_HEADER_SIZE * 8;
  const keyedSlot = createKeyedSlotProvider(
    placementSeed,
    headerBits,
    slotCount(pixelData, channelIndices),
  );
  writeBits(encodedPixels, channelIndices, ciphertext, keyedSlot);
  return encodedPixels;
}

async function extractSecureMessage(pixelData, channels, password) {
  const payload = await extractSecurePayload(pixelData, channels, password);
  if (payload.type !== "text") {
    throw new Error("The hidden payload is an image, not text.");
  }
  return decodeText(payload.bytes);
}

async function extractSecurePayload(pixelData, channels, password) {
  if (!password) {
    throw new Error("Enter the password used to encode this image.");
  }

  const channelIndices = getChannelIndices(channels);
  const totalSlots = slotCount(pixelData, channelIndices);
  if (totalSlots < SECURE_HEADER_SIZE * 8) {
    throw new Error("This image is too small to contain an encrypted payload.");
  }

  const header = readBits(pixelData, channelIndices, SECURE_HEADER_SIZE, (offset) => offset);
  if (header[0] !== SECURE_TEXT_VERSION && header[0] !== SECURE_IMAGE_VERSION) {
    throw new Error("No encrypted payload found with the selected channels.");
  }

  const salt = header.slice(1, 1 + SECURE_SALT_SIZE);
  const nonce = header.slice(1 + SECURE_SALT_SIZE, SECURE_HEADER_SIZE - 4);
  const ciphertextLength = new DataView(header.buffer).getUint32(SECURE_HEADER_SIZE - 4);
  if (ciphertextLength < AES_GCM_TAG_SIZE
    || ciphertextLength * 8 > totalSlots - SECURE_HEADER_SIZE * 8) {
    throw new Error("The encrypted payload is incomplete or corrupted.");
  }

  const { encryptionKey, placementSeed } = await deriveSecureKeys(password, salt);
  const keyedSlot = createKeyedSlotProvider(
    placementSeed,
    SECURE_HEADER_SIZE * 8,
    totalSlots,
  );
  const ciphertext = readBits(pixelData, channelIndices, ciphertextLength, keyedSlot);

  try {
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: header,
        tagLength: 128,
      },
      encryptionKey,
      ciphertext,
    ));
    return {
      type: header[0] === SECURE_IMAGE_VERSION ? "image" : "text",
      bytes: plaintext,
    };
  } catch {
    throw new Error("Incorrect password or corrupted encrypted payload.");
  }
}

function initialiseApp() {
  const state = {
    encode: null,
    decode: null,
    secretImage: null,
    encodeUrl: null,
    decodeUrl: null,
    secretImageUrl: null,
    decodedImageUrl: null,
  };

  const tabs = [...document.querySelectorAll(".tab")];
  const panels = {
    encode: document.querySelector("#encode-panel"),
    decode: document.querySelector("#decode-panel"),
  };
  const encodeInput = document.querySelector("#encode-image");
  const decodeInput = document.querySelector("#decode-image");
  const secretImageInput = document.querySelector("#secret-image");
  const encodePreview = document.querySelector("#encode-preview");
  const decodePreview = document.querySelector("#decode-preview");
  const secretImagePreview = document.querySelector("#secret-image-preview");
  const encodeDropZone = document.querySelector("#encode-drop-zone");
  const decodeDropZone = document.querySelector("#decode-drop-zone");
  const secretImageDropZone = document.querySelector("#secret-image-drop-zone");
  const encodePlaceholder = document.querySelector("#encode-placeholder");
  const decodePlaceholder = document.querySelector("#decode-placeholder");
  const secretImagePlaceholder = document.querySelector("#secret-image-placeholder");
  const encodeStatus = document.querySelector("#encode-status");
  const decodeStatus = document.querySelector("#decode-status");
  const encodeButton = document.querySelector("#encode-button");
  const decodeButton = document.querySelector("#decode-button");
  const encodeMode = document.querySelector("#encode-mode");
  const decodeMode = document.querySelector("#decode-mode");
  const encodeModeHint = document.querySelector("#encode-mode-hint");
  const decodeModeHint = document.querySelector("#decode-mode-hint");
  const encodePasswordField = document.querySelector("#encode-password-field");
  const decodePasswordField = document.querySelector("#decode-password-field");
  const encodePassword = document.querySelector("#encode-password");
  const decodePassword = document.querySelector("#decode-password");
  const payloadType = document.querySelector("#payload-type");
  const textPayloadField = document.querySelector("#text-payload-field");
  const imagePayloadField = document.querySelector("#image-payload-field");
  const messageInput = document.querySelector("#secret-message");
  const decodedMessage = document.querySelector("#decoded-message");
  const decodedTextResult = document.querySelector("#decoded-text-result");
  const decodedImageResult = document.querySelector("#decoded-image-result");
  const decodedImage = document.querySelector("#decoded-image");
  const downloadHiddenImage = document.querySelector("#download-hidden-image");
  const capacityTotal = document.querySelector("#capacity-total");
  const capacityUsed = document.querySelector("#capacity-used");
  const capacityRemaining = document.querySelector("#capacity-remaining");
  const encodeChannelInputs = [...document.querySelectorAll("#encode-channels input")];
  const decodeChannelInputs = [...document.querySelectorAll("#decode-channels input")];

  function selectedChannels(inputs) {
    return inputs.filter((input) => input.checked).map((input) => input.value);
  }

  function setStatus(element, message, isError = false) {
    element.textContent = message;
    element.classList.toggle("error", isError);
  }

  function formatBytes(bytes) {
    if (bytes < 1024) {
      return `${bytes.toLocaleString()} bytes`;
    }
    return `${(bytes / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} KiB (${bytes.toLocaleString()} bytes)`;
  }

  function isPng(file) {
    return file.type === "image/png" || file.name.toLowerCase().endsWith(".png");
  }

  function loadImage(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const image = new Image();
      image.onload = () => resolve({ image, url });
      image.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error("The selected file could not be read as an image."));
      };
      image.src = url;
    });
  }

  function imageDataFrom(image) {
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(image, 0, 0);
    return {
      canvas,
      context,
      imageData: context.getImageData(0, 0, canvas.width, canvas.height),
    };
  }

  function payloadSize() {
    if (payloadType.value === "image") {
      return state.secretImage?.bytes.length ?? 0;
    }
    return new TextEncoder().encode(messageInput.value).length;
  }

  function refreshCapacity() {
    if (!state.encode) {
      return;
    }

    const channels = selectedChannels(encodeChannelInputs);
    if (!channels.length) {
      capacityTotal.textContent = "—";
      capacityUsed.textContent = formatBytes(payloadSize());
      capacityRemaining.textContent = "—";
      encodeButton.disabled = true;
      setStatus(encodeStatus, "Select at least one channel.", true);
      return;
    }
    if (channels.includes("alpha") && !isPng(state.encode.file)) {
      encodeButton.disabled = true;
      setStatus(encodeStatus, "Alpha encoding requires a PNG source image.", true);
      return;
    }

    const { imageData } = imageDataFrom(state.encode.image);
    const capacity = capacityInBytes(imageData.data, channels, encodeMode.value);
    const usedBytes = payloadSize();
    const remainingBytes = Math.max(0, capacity - usedBytes);
    capacityTotal.textContent = formatBytes(capacity);
    capacityUsed.textContent = formatBytes(usedBytes);
    capacityRemaining.textContent = formatBytes(remainingBytes);
    const passwordMissing = encodeMode.value === "secure" && !encodePassword.value;
    const imageMissing = payloadType.value === "image" && !state.secretImage;
    encodeButton.disabled = usedBytes > capacity || passwordMissing || imageMissing;
    setStatus(
      encodeStatus,
      usedBytes > capacity
        ? `Payload exceeds capacity by ${formatBytes(usedBytes - capacity)}.`
        : imageMissing
          ? "Choose the PNG image to hide."
        : passwordMissing
          ? "Enter a password to use encrypted mode."
          : `Estimated from ${state.encode.image.naturalWidth.toLocaleString()} × ${state.encode.image.naturalHeight.toLocaleString()} pixels and ${channels.length} selected ${channels.length === 1 ? "channel" : "channels"}.`,
      usedBytes > capacity || passwordMissing || imageMissing,
    );
  }

  function updatePayloadControls() {
    const imageSelected = payloadType.value === "image";
    textPayloadField.hidden = imageSelected;
    imagePayloadField.hidden = !imageSelected;
    refreshCapacity();
  }

  function clearDecodedPayload() {
    decodedMessage.value = "";
    decodedTextResult.hidden = false;
    decodedImageResult.hidden = true;
    decodedImage.removeAttribute("src");
    downloadHiddenImage.removeAttribute("href");
    if (state.decodedImageUrl) {
      URL.revokeObjectURL(state.decodedImageUrl);
      state.decodedImageUrl = null;
    }
  }

  function renderDecodedPayload(payload) {
    clearDecodedPayload();
    if (payload.type === "text") {
      decodedMessage.value = decodeText(payload.bytes);
      return;
    }

    const blob = new Blob([payload.bytes], { type: "image/png" });
    state.decodedImageUrl = URL.createObjectURL(blob);
    decodedImage.src = state.decodedImageUrl;
    downloadHiddenImage.href = state.decodedImageUrl;
    decodedTextResult.hidden = true;
    decodedImageResult.hidden = false;
  }

  function refreshDecodeButton() {
    const channelsSelected = selectedChannels(decodeChannelInputs).length > 0;
    const passwordPresent = decodeMode.value !== "secure" || Boolean(decodePassword.value);
    decodeButton.disabled = !state.decode || !channelsSelected || !passwordPresent;
  }

  function updateModeControls() {
    const encodeSecure = encodeMode.value === "secure";
    const decodeSecure = decodeMode.value === "secure";
    encodePasswordField.hidden = !encodeSecure;
    decodePasswordField.hidden = !decodeSecure;

    const encodeHints = {
      binary: "One hidden bit per selected channel value.",
      ternary: "Stores base-3 residues for greater capacity, changing values by at most two.",
      secure: "AES-256-GCM encryption with password-derived, non-sequential pixel placement.",
    };
    encodeModeHint.textContent = encodeHints[encodeMode.value];
    decodeModeHint.textContent = decodeSecure
      ? "Use the same password and channels selected during encoding."
      : "Choose the same technique and channels used during encoding.";
    refreshCapacity();
    refreshDecodeButton();
  }

  async function handleEncodeFile(file) {
    if (file.type && !file.type.startsWith("image/")) {
      setStatus(encodeStatus, "Drop a valid image file.", true);
      return;
    }

    try {
      const loaded = await loadImage(file);
      if (state.encodeUrl) {
        URL.revokeObjectURL(state.encodeUrl);
      }
      state.encode = { file, image: loaded.image };
      state.encodeUrl = loaded.url;
      encodePreview.src = loaded.url;
      encodePreview.hidden = false;
      encodePlaceholder.hidden = true;
      refreshCapacity();
    } catch (error) {
      setStatus(encodeStatus, error.message, true);
    }
  }

  async function handleSecretImageFile(file) {
    if (!isPng(file)) {
      setStatus(encodeStatus, "The hidden image must be a PNG.", true);
      return;
    }

    try {
      const [loaded, bytes] = await Promise.all([
        loadImage(file),
        file.arrayBuffer().then((buffer) => new Uint8Array(buffer)),
      ]);
      if (state.secretImageUrl) {
        URL.revokeObjectURL(state.secretImageUrl);
      }
      state.secretImage = { file, bytes };
      state.secretImageUrl = loaded.url;
      secretImagePreview.src = loaded.url;
      secretImagePreview.hidden = false;
      secretImagePlaceholder.hidden = true;
      refreshCapacity();
    } catch (error) {
      setStatus(encodeStatus, error.message, true);
    }
  }

  async function handleDecodeFile(file) {
    clearDecodedPayload();
    if (!isPng(file)) {
      decodeButton.disabled = true;
      setStatus(decodeStatus, "Drop a PNG image to decode.", true);
      return;
    }

    try {
      const loaded = await loadImage(file);
      if (state.decodeUrl) {
        URL.revokeObjectURL(state.decodeUrl);
      }
      state.decode = { file, image: loaded.image };
      state.decodeUrl = loaded.url;
      decodePreview.src = loaded.url;
      decodePreview.hidden = false;
      decodePlaceholder.hidden = true;
      refreshDecodeButton();
      setStatus(decodeStatus, "Ready to decode.");
    } catch (error) {
      decodeButton.disabled = true;
      setStatus(decodeStatus, error.message, true);
    }
  }

  function containsDraggedFiles(dataTransfer) {
    if (!dataTransfer) {
      return false;
    }

    return Array.from(dataTransfer.types || []).includes("Files")
      || Array.from(dataTransfer.items || []).some((item) => item.kind === "file");
  }

  function firstDroppedFile(dataTransfer) {
    const fileItem = Array.from(dataTransfer?.items || [])
      .find((item) => item.kind === "file");
    return fileItem?.getAsFile() || dataTransfer?.files?.item(0) || null;
  }

  function makeDropZone(zone, input, handleFile) {
    let dragDepth = 0;

    zone.addEventListener("click", () => input.click());
    zone.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        input.click();
      }
    });
    zone.addEventListener("dragenter", (event) => {
      if (!containsDraggedFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      dragDepth += 1;
      zone.classList.add("is-dragging");
    });
    zone.addEventListener("dragover", (event) => {
      if (!containsDraggedFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      event.dataTransfer.dropEffect = "copy";
    });
    zone.addEventListener("dragleave", () => {
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) {
        zone.classList.remove("is-dragging");
      }
    });
    zone.addEventListener("drop", (event) => {
      if (!containsDraggedFiles(event.dataTransfer)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      dragDepth = 0;
      zone.classList.remove("is-dragging");
      const file = firstDroppedFile(event.dataTransfer);
      if (file) {
        handleFile(file);
      }
    });
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => {
      tabs.forEach((item) => {
        const active = item === tab;
        item.classList.toggle("is-active", active);
        item.setAttribute("aria-selected", String(active));
        panels[item.dataset.tab].hidden = !active;
      });
    });

    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {
        return;
      }
      event.preventDefault();
      const direction = event.key === "ArrowRight" ? 1 : -1;
      tabs[(index + direction + tabs.length) % tabs.length].click();
      tabs[(index + direction + tabs.length) % tabs.length].focus();
    });
  });

  window.addEventListener("dragover", (event) => {
    if (containsDraggedFiles(event.dataTransfer)) {
      event.preventDefault();
      event.dataTransfer.dropEffect = "none";
    }
  });

  window.addEventListener("drop", (event) => {
    if (containsDraggedFiles(event.dataTransfer)) {
      event.preventDefault();
    }
  });

  encodeInput.addEventListener("change", () => {
    const file = encodeInput.files.item(0);
    if (file) {
      handleEncodeFile(file);
    }
  });

  decodeInput.addEventListener("change", () => {
    const file = decodeInput.files.item(0);
    if (file) {
      handleDecodeFile(file);
    }
  });

  secretImageInput.addEventListener("change", () => {
    const file = secretImageInput.files.item(0);
    if (file) {
      handleSecretImageFile(file);
    }
  });

  makeDropZone(encodeDropZone, encodeInput, handleEncodeFile);
  makeDropZone(decodeDropZone, decodeInput, handleDecodeFile);
  makeDropZone(secretImageDropZone, secretImageInput, handleSecretImageFile);

  encodeChannelInputs.forEach((input) => input.addEventListener("change", refreshCapacity));
  messageInput.addEventListener("input", refreshCapacity);
  payloadType.addEventListener("change", updatePayloadControls);
  encodeMode.addEventListener("change", updateModeControls);
  decodeMode.addEventListener("change", updateModeControls);
  encodePassword.addEventListener("input", refreshCapacity);
  decodePassword.addEventListener("input", refreshDecodeButton);

  decodeChannelInputs.forEach((input) => {
    input.addEventListener("change", refreshDecodeButton);
  });

  encodeButton.addEventListener("click", async () => {
    const originalLabel = encodeButton.textContent;
    const mode = encodeMode.value;
    const password = encodePassword.value;
    const payloadIsImage = payloadType.value === "image";
    const imageBytes = state.secretImage?.bytes;
    try {
      encodeButton.disabled = true;
      encodeButton.textContent = mode === "secure" ? "Encrypting…" : "Encoding…";
      setStatus(
        encodeStatus,
        mode === "secure"
          ? "Deriving the encryption key…"
          : "Encoding the payload…",
      );
      const channels = selectedChannels(encodeChannelInputs);
      const { canvas, context, imageData } = imageDataFrom(state.encode.image);
      let encodedPixels;
      if (mode === "ternary") {
        encodedPixels = payloadIsImage
          ? embedTernaryImage(imageData.data, channels, imageBytes)
          : embedTernaryMessage(imageData.data, channels, messageInput.value);
      } else if (mode === "secure") {
        encodedPixels = payloadIsImage
          ? await embedSecureImage(imageData.data, channels, imageBytes, password)
          : await embedSecureMessage(
            imageData.data,
            channels,
            messageInput.value,
            password,
          );
      } else {
        encodedPixels = payloadIsImage
          ? embedBinaryImage(imageData.data, channels, imageBytes)
          : embedMessage(imageData.data, channels, messageInput.value);
      }
      imageData.data.set(encodedPixels);
      context.putImageData(imageData, 0, 0);

      const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
      if (!blob) {
        throw new Error("The encoded PNG could not be created.");
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const baseName = state.encode.file.name.replace(/\.[^.]+$/, "") || "image";
      const modeSuffix = mode === "binary" ? "encoded" : mode;
      link.href = url;
      link.download = `${baseName}-${modeSuffix}.png`;
      link.click();
      URL.revokeObjectURL(url);
      setStatus(encodeStatus, "Encoded PNG downloaded.");
    } catch (error) {
      setStatus(encodeStatus, error.message, true);
    } finally {
      encodeButton.textContent = originalLabel;
      const finalStatus = encodeStatus.textContent;
      const hasError = encodeStatus.classList.contains("error");
      refreshCapacity();
      setStatus(encodeStatus, finalStatus, hasError);
    }
  });

  decodeButton.addEventListener("click", async () => {
    const originalLabel = decodeButton.textContent;
    const mode = decodeMode.value;
    const password = decodePassword.value;
    try {
      decodeButton.disabled = true;
      decodeButton.textContent = mode === "secure" ? "Decrypting…" : "Decoding…";
      setStatus(
        decodeStatus,
        mode === "secure"
          ? "Deriving the decryption key…"
          : "Decoding the message…",
      );
      const channels = selectedChannels(decodeChannelInputs);
      const { imageData } = imageDataFrom(state.decode.image);
      let payload;
      if (mode === "ternary") {
        payload = extractTernaryPayload(imageData.data, channels);
      } else if (mode === "secure") {
        payload = await extractSecurePayload(
          imageData.data,
          channels,
          password,
        );
      } else {
        payload = extractBinaryPayload(imageData.data, channels);
      }
      renderDecodedPayload(payload);
      setStatus(
        decodeStatus,
        payload.type === "image"
          ? "Hidden PNG decoded successfully."
          : "Message decoded successfully.",
      );
    } catch (error) {
      clearDecodedPayload();
      setStatus(decodeStatus, error.message, true);
    } finally {
      decodeButton.textContent = originalLabel;
      refreshDecodeButton();
    }
  });

  updateModeControls();
  updatePayloadControls();

  window.addEventListener("beforeunload", () => {
    if (state.encodeUrl) {
      URL.revokeObjectURL(state.encodeUrl);
    }
    if (state.decodeUrl) {
      URL.revokeObjectURL(state.decodeUrl);
    }
    if (state.secretImageUrl) {
      URL.revokeObjectURL(state.secretImageUrl);
    }
    if (state.decodedImageUrl) {
      URL.revokeObjectURL(state.decodedImageUrl);
    }
  });
}

if (typeof document !== "undefined") {
  initialiseApp();
}
