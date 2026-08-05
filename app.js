"use strict";

const CHANNEL_INDEX = {
  red: 0,
  green: 1,
  blue: 2,
  alpha: 3,
};
const MAGIC = new Uint8Array([0x49, 0x53, 0x4d, 0x31]);
const HEADER_SIZE = 12;

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

function createPacket(message) {
  const payload = new TextEncoder().encode(message);
  const packet = new Uint8Array(HEADER_SIZE + payload.length);
  const view = new DataView(packet.buffer);

  packet.set(MAGIC, 0);
  view.setUint32(4, payload.length);
  view.setUint32(8, crc32(payload));
  packet.set(payload, HEADER_SIZE);

  return packet;
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

function capacityInBytes(pixelData, channels) {
  const channelIndices = getChannelIndices(channels);
  const pixelCount = pixelData.length / 4;
  return Math.max(0, Math.floor((pixelCount * channelIndices.length) / 8) - HEADER_SIZE);
}

function embedMessage(pixelData, channels, message) {
  const channelIndices = getChannelIndices(channels);
  const packet = createPacket(message);
  const availableBits = (pixelData.length / 4) * channelIndices.length;

  if (packet.length * 8 > availableBits) {
    const availableBytes = Math.max(0, Math.floor(availableBits / 8) - HEADER_SIZE);
    throw new Error(`Message is too large. This image can hold ${availableBytes.toLocaleString()} bytes.`);
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
  const channelIndices = getChannelIndices(channels);
  const totalBytes = Math.floor(((pixelData.length / 4) * channelIndices.length) / 8);

  if (totalBytes < HEADER_SIZE) {
    throw new Error("This image is too small to contain a message.");
  }

  const header = readBytes(pixelData, channelIndices, HEADER_SIZE);
  if (!MAGIC.every((byte, index) => header[index] === byte)) {
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

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch {
    throw new Error("The hidden data is not valid UTF-8 text.");
  }
}

function initialiseApp() {
  const state = {
    encode: null,
    decode: null,
    encodeUrl: null,
    decodeUrl: null,
  };

  const tabs = [...document.querySelectorAll(".tab")];
  const panels = {
    encode: document.querySelector("#encode-panel"),
    decode: document.querySelector("#decode-panel"),
  };
  const encodeInput = document.querySelector("#encode-image");
  const decodeInput = document.querySelector("#decode-image");
  const encodePreview = document.querySelector("#encode-preview");
  const decodePreview = document.querySelector("#decode-preview");
  const encodeDropZone = document.querySelector("#encode-drop-zone");
  const decodeDropZone = document.querySelector("#decode-drop-zone");
  const encodePlaceholder = document.querySelector("#encode-placeholder");
  const decodePlaceholder = document.querySelector("#decode-placeholder");
  const encodeStatus = document.querySelector("#encode-status");
  const decodeStatus = document.querySelector("#decode-status");
  const encodeButton = document.querySelector("#encode-button");
  const decodeButton = document.querySelector("#decode-button");
  const messageInput = document.querySelector("#secret-message");
  const decodedMessage = document.querySelector("#decoded-message");
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

  function refreshCapacity() {
    if (!state.encode) {
      return;
    }

    const channels = selectedChannels(encodeChannelInputs);
    if (!channels.length) {
      capacityTotal.textContent = "—";
      capacityUsed.textContent = formatBytes(new TextEncoder().encode(messageInput.value).length);
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
    const capacity = capacityInBytes(imageData.data, channels);
    const messageBytes = new TextEncoder().encode(messageInput.value).length;
    const remainingBytes = Math.max(0, capacity - messageBytes);
    capacityTotal.textContent = formatBytes(capacity);
    capacityUsed.textContent = formatBytes(messageBytes);
    capacityRemaining.textContent = formatBytes(remainingBytes);
    encodeButton.disabled = messageBytes > capacity;
    setStatus(
      encodeStatus,
      messageBytes > capacity
        ? `Message exceeds capacity by ${formatBytes(messageBytes - capacity)}.`
        : `Estimated from ${state.encode.image.naturalWidth.toLocaleString()} × ${state.encode.image.naturalHeight.toLocaleString()} pixels and ${channels.length} selected ${channels.length === 1 ? "channel" : "channels"}.`,
      messageBytes > capacity,
    );
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

  async function handleDecodeFile(file) {
    decodedMessage.value = "";
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
      decodeButton.disabled = false;
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

  makeDropZone(encodeDropZone, encodeInput, handleEncodeFile);
  makeDropZone(decodeDropZone, decodeInput, handleDecodeFile);

  encodeChannelInputs.forEach((input) => input.addEventListener("change", refreshCapacity));
  messageInput.addEventListener("input", refreshCapacity);

  decodeChannelInputs.forEach((input) => {
    input.addEventListener("change", () => {
      decodeButton.disabled = !state.decode || selectedChannels(decodeChannelInputs).length === 0;
    });
  });

  encodeButton.addEventListener("click", () => {
    try {
      const channels = selectedChannels(encodeChannelInputs);
      const { canvas, context, imageData } = imageDataFrom(state.encode.image);
      imageData.data.set(embedMessage(imageData.data, channels, messageInput.value));
      context.putImageData(imageData, 0, 0);

      canvas.toBlob((blob) => {
        if (!blob) {
          setStatus(encodeStatus, "The encoded PNG could not be created.", true);
          return;
        }
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        const baseName = state.encode.file.name.replace(/\.[^.]+$/, "") || "image";
        link.href = url;
        link.download = `${baseName}-encoded.png`;
        link.click();
        URL.revokeObjectURL(url);
        setStatus(encodeStatus, "Encoded PNG downloaded.");
      }, "image/png");
    } catch (error) {
      setStatus(encodeStatus, error.message, true);
    }
  });

  decodeButton.addEventListener("click", () => {
    try {
      const channels = selectedChannels(decodeChannelInputs);
      const { imageData } = imageDataFrom(state.decode.image);
      decodedMessage.value = extractMessage(imageData.data, channels);
      setStatus(decodeStatus, "Message decoded successfully.");
    } catch (error) {
      decodedMessage.value = "";
      setStatus(decodeStatus, error.message, true);
    }
  });

  window.addEventListener("beforeunload", () => {
    if (state.encodeUrl) {
      URL.revokeObjectURL(state.encodeUrl);
    }
    if (state.decodeUrl) {
      URL.revokeObjectURL(state.decodeUrl);
    }
  });
}

if (typeof document !== "undefined") {
  initialiseApp();
}
