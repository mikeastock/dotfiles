/**
 * Generate simple placeholder icons for the extension
 * Usage: node scripts/generate-icons.mjs
 */

import { writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Minimal PNG generator (creates simple colored squares)
function createPng(size, r, g, b) {
  // PNG header
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(size, 0); // width
  ihdrData.writeUInt32BE(size, 4); // height
  ihdrData.writeUInt8(8, 8); // bit depth
  ihdrData.writeUInt8(2, 9); // color type (RGB)
  ihdrData.writeUInt8(0, 10); // compression
  ihdrData.writeUInt8(0, 11); // filter
  ihdrData.writeUInt8(0, 12); // interlace

  const ihdr = createChunk("IHDR", ihdrData);

  // IDAT chunk (image data)
  const rawData = [];
  for (let y = 0; y < size; y++) {
    rawData.push(0); // filter byte
    for (let x = 0; x < size; x++) {
      // Create a circle
      const cx = size / 2;
      const cy = size / 2;
      const radius = size / 2 - 1;
      const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);

      if (dist <= radius) {
        // Inside circle - use the color
        rawData.push(r, g, b);
      } else {
        // Outside circle - transparent (white for simplicity)
        rawData.push(255, 255, 255);
      }
    }
  }

  // Use zlib-less compression (store method)
  const compressed = deflateStore(Buffer.from(rawData));
  const idat = createChunk("IDAT", compressed);

  // IEND chunk
  const iend = createChunk("IEND", Buffer.alloc(0));

  return Buffer.concat([signature, ihdr, idat, iend]);
}

function createChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);

  const typeBuffer = Buffer.from(type);
  const crc = crc32(Buffer.concat([typeBuffer, data]));

  const crcBuffer = Buffer.alloc(4);
  crcBuffer.writeUInt32BE(crc >>> 0);

  return Buffer.concat([length, typeBuffer, data, crcBuffer]);
}

// Simple deflate store (no compression)
function deflateStore(data) {
  const blocks = [];
  let offset = 0;

  while (offset < data.length) {
    const remaining = data.length - offset;
    const blockSize = Math.min(65535, remaining);
    const isLast = offset + blockSize >= data.length;

    const header = Buffer.alloc(5);
    header.writeUInt8(isLast ? 1 : 0, 0);
    header.writeUInt16LE(blockSize, 1);
    header.writeUInt16LE(blockSize ^ 0xffff, 3);

    blocks.push(header);
    blocks.push(data.subarray(offset, offset + blockSize));
    offset += blockSize;
  }

  // Zlib header
  const zlibHeader = Buffer.from([0x78, 0x01]);

  // Adler32 checksum
  const adler = adler32(data);
  const adlerBuffer = Buffer.alloc(4);
  adlerBuffer.writeUInt32BE(adler);

  return Buffer.concat([zlibHeader, ...blocks, adlerBuffer]);
}

function adler32(data) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i++) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0; // Ensure unsigned
}

// CRC32 lookup table
const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  crcTable[i] = c;
}

function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = crcTable[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  }
  return crc ^ 0xffffffff;
}

// Generate icons
const sizes = [16, 32, 48, 128];
const colors = {
  black: [26, 26, 26],
  gray: [156, 163, 175],
  green: [34, 197, 94],
};

const iconsDir = join(__dirname, "..", "public", "icons");
mkdirSync(iconsDir, { recursive: true });

for (const [name, [r, g, b]] of Object.entries(colors)) {
  for (const size of sizes) {
    const png = createPng(size, r, g, b);
    const filename = join(iconsDir, `icon-${name}-${size}.png`);
    writeFileSync(filename, png);
    console.log(`Created ${filename}`);
  }
}

console.log("Done!");
