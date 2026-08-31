#!/usr/bin/env node

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const imageDirectory = join(scriptDirectory, '..', 'src', 'images');

const palette = {
  graphite: [17, 19, 24, 255],
  ivory: [244, 241, 233, 255],
  slate: [126, 132, 146, 255],
  signalStart: [82, 100, 232, 255],
  signalEnd: [132, 145, 255, 255],
  template: [0, 0, 0, 255],
};

const clamp = (value, minimum = 0, maximum = 1) =>
  Math.min(maximum, Math.max(minimum, value));

function superellipseDistance(x, y, halfWidth, halfHeight, exponent) {
  const normalizedX = Math.abs(x - 0.5) / halfWidth;
  const normalizedY = Math.abs(y - 0.5) / halfHeight;
  const radius = (normalizedX ** exponent + normalizedY ** exponent) ** (1 / exponent);
  return (radius - 1) * Math.min(halfWidth, halfHeight);
}

function roundedRectangleDistance(x, y, centerX, centerY, halfWidth, halfHeight, radius) {
  const qx = Math.abs(x - centerX) - halfWidth + radius;
  const qy = Math.abs(y - centerY) - halfHeight + radius;
  return (
    Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - radius
  );
}

function segmentDistance(x, y, ax, ay, bx, by) {
  const abx = bx - ax;
  const aby = by - ay;
  const denominator = abx * abx + aby * aby;
  const projection = denominator === 0 ? 0 : clamp(((x - ax) * abx + (y - ay) * aby) / denominator);
  return Math.hypot(x - (ax + projection * abx), y - (ay + projection * aby));
}

function polylineDistance(x, y, points) {
  let distance = Number.POSITIVE_INFINITY;
  for (let index = 0; index < points.length - 1; index += 1) {
    const current = points[index];
    const next = points[index + 1];
    distance = Math.min(
      distance,
      segmentDistance(x, y, current[0], current[1], next[0], next[1])
    );
  }
  return distance;
}

function sampleCubic(points, start, controlA, controlB, end, steps = 14) {
  if (points.length === 0) points.push(start);
  for (let step = 1; step <= steps; step += 1) {
    const t = step / steps;
    const inverse = 1 - t;
    points.push([
      inverse ** 3 * start[0] +
        3 * inverse ** 2 * t * controlA[0] +
        3 * inverse * t ** 2 * controlB[0] +
        t ** 3 * end[0],
      inverse ** 3 * start[1] +
        3 * inverse ** 2 * t * controlA[1] +
        3 * inverse * t ** 2 * controlB[1] +
        t ** 3 * end[1],
    ]);
  }
}

function buildPrimaryFlow() {
  const points = [
    [0.219, 0.35],
    [0.381, 0.35],
  ];
  sampleCubic(points, [0.381, 0.35], [0.453, 0.35], [0.5, 0.397], [0.5, 0.469]);
  points.push([0.5, 0.531]);
  sampleCubic(points, [0.5, 0.531], [0.5, 0.603], [0.547, 0.65], [0.619, 0.65]);
  points.push([0.781, 0.65]);
  return points;
}

const primaryFlow = buildPrimaryFlow();
const secondaryFlow = primaryFlow.map(([x, y]) => [1 - x, y]);

function mix(a, b, amount) {
  return a + (b - a) * amount;
}

function mixColor(start, end, amount) {
  return [
    Math.round(mix(start[0], end[0], amount)),
    Math.round(mix(start[1], end[1], amount)),
    Math.round(mix(start[2], end[2], amount)),
    Math.round(mix(start[3], end[3], amount)),
  ];
}

function overlay(pixel, color, coverage) {
  const sourceAlpha = clamp(coverage) * (color[3] / 255);
  const destinationAlpha = pixel[3] / 255;
  const outputAlpha = sourceAlpha + destinationAlpha * (1 - sourceAlpha);
  if (outputAlpha === 0) return [0, 0, 0, 0];

  return [
    Math.round((color[0] * sourceAlpha + pixel[0] * destinationAlpha * (1 - sourceAlpha)) / outputAlpha),
    Math.round((color[1] * sourceAlpha + pixel[1] * destinationAlpha * (1 - sourceAlpha)) / outputAlpha),
    Math.round((color[2] * sourceAlpha + pixel[2] * destinationAlpha * (1 - sourceAlpha)) / outputAlpha),
    Math.round(outputAlpha * 255),
  ];
}

function erase(pixel, coverage) {
  const remainingAlpha = Math.round(pixel[3] * (1 - clamp(coverage)));
  return remainingAlpha === 0 ? [0, 0, 0, 0] : [pixel[0], pixel[1], pixel[2], remainingAlpha];
}

function lineCoverage(distance, halfWidth, antialias) {
  return clamp((halfWidth + antialias - distance) / (2 * antialias));
}

function circleCoverage(x, y, centerX, centerY, radius, antialias) {
  const distance = Math.hypot(x - centerX, y - centerY);
  return clamp((radius + antialias - distance) / (2 * antialias));
}

function renderIcon(size, { template = false, update = false } = {}) {
  const pixels = Buffer.alloc(size * size * 4);
  const antialias = 1.15 / size;
  const flowHalfWidth = Math.max(template ? 0.045 : 0.038, 0.75 / size);
  const nodeHalfSize = template ? 0.071 : 0.064;
  const nodeRadius = template ? 0.024 : 0.035;

  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      const x = (px + 0.5) / size;
      const y = (py + 0.5) / size;
      let pixel = [0, 0, 0, 0];

      if (!template) {
        const backgroundDistance = superellipseDistance(x, y, 0.455, 0.455, 5);
        const backgroundCoverage = clamp((antialias - backgroundDistance) / (2 * antialias));
        pixel = overlay(pixel, palette.graphite, backgroundCoverage);

        const borderCoverage = lineCoverage(Math.abs(backgroundDistance), 0.0014, antialias);
        pixel = overlay(pixel, [255, 255, 255, 22], borderCoverage * backgroundCoverage);
      }

      if (x >= 0.16 && x <= 0.84 && y >= 0.29 && y <= 0.71) {
        const secondaryCoverage = lineCoverage(
          polylineDistance(x, y, secondaryFlow),
          flowHalfWidth,
          antialias
        );
        pixel = overlay(pixel, template ? palette.template : palette.slate, secondaryCoverage);

        const primaryCoverage = lineCoverage(
          polylineDistance(x, y, primaryFlow),
          flowHalfWidth,
          antialias
        );
        pixel = overlay(pixel, template ? palette.template : palette.ivory, primaryCoverage);

        const nodeDistance = roundedRectangleDistance(
          x,
          y,
          0.5,
          0.5,
          nodeHalfSize,
          nodeHalfSize,
          nodeRadius
        );
        const nodeCoverage = clamp((antialias - nodeDistance) / (2 * antialias));
        const nodeColor = template
          ? palette.template
          : mixColor(palette.signalStart, palette.signalEnd, clamp((x + y - 0.87) / 0.26));
        pixel = overlay(pixel, nodeColor, nodeCoverage);

        if (!template) {
          const nodeBorderCoverage = lineCoverage(Math.abs(nodeDistance), 0.0012, antialias);
          pixel = overlay(pixel, [255, 255, 255, 45], nodeBorderCoverage * nodeCoverage);
        }
      }

      if (template && update) {
        const haloCoverage = circleCoverage(x, y, 0.8, 0.2, 0.164, antialias);
        pixel = erase(pixel, haloCoverage);
        const badgeCoverage = circleCoverage(x, y, 0.8, 0.2, 0.105, antialias);
        pixel = overlay(pixel, palette.template, badgeCoverage);
      }

      if (!template && update) {
        const badgeBorderCoverage = circleCoverage(x, y, 0.8, 0.2, 0.138, antialias);
        pixel = overlay(pixel, palette.ivory, badgeBorderCoverage);
        const badgeCoverage = circleCoverage(x, y, 0.8, 0.2, 0.096, antialias);
        pixel = overlay(pixel, palette.signalStart, badgeCoverage);
      }

      const offset = (py * size + px) * 4;
      pixels[offset] = pixel[0];
      pixels[offset + 1] = pixel[1];
      pixels[offset + 2] = pixel[2];
      pixels[offset + 3] = pixel[3];
    }
  }

  return encodePng(size, size, pixels);
}

const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])));
  return Buffer.concat([length, typeBuffer, data, checksum]);
}

function encodePng(width, height, pixels) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;

  const scanlines = Buffer.alloc((width * 4 + 1) * height);
  for (let row = 0; row < height; row += 1) {
    const outputOffset = row * (width * 4 + 1);
    scanlines[outputOffset] = 0;
    pixels.copy(scanlines, outputOffset + 1, row * width * 4, (row + 1) * width * 4);
  }

  return Buffer.concat([
    Buffer.from('89504e470d0a1a0a', 'hex'),
    pngChunk('IHDR', header),
    pngChunk('IDAT', deflateSync(scanlines, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function encodeIco(images) {
  const directory = Buffer.alloc(6 + images.length * 16);
  directory.writeUInt16LE(0, 0);
  directory.writeUInt16LE(1, 2);
  directory.writeUInt16LE(images.length, 4);

  let offset = directory.length;
  images.forEach(({ size, png }, index) => {
    const entry = 6 + index * 16;
    directory[entry] = size === 256 ? 0 : size;
    directory[entry + 1] = size === 256 ? 0 : size;
    directory[entry + 2] = 0;
    directory[entry + 3] = 0;
    directory.writeUInt16LE(1, entry + 4);
    directory.writeUInt16LE(32, entry + 6);
    directory.writeUInt32LE(png.length, entry + 8);
    directory.writeUInt32LE(offset, entry + 12);
    offset += png.length;
  });

  return Buffer.concat([directory, ...images.map(({ png }) => png)]);
}

function encodeIcns(images) {
  const chunks = images.map(({ type, png }) => {
    const chunkHeader = Buffer.alloc(8);
    chunkHeader.write(type, 0, 4, 'ascii');
    chunkHeader.writeUInt32BE(png.length + 8, 4);
    return Buffer.concat([chunkHeader, png]);
  });
  const header = Buffer.alloc(8);
  header.write('icns', 0, 4, 'ascii');
  header.writeUInt32BE(8 + chunks.reduce((total, chunk) => total + chunk.length, 0), 4);
  return Buffer.concat([header, ...chunks]);
}

const iconSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" role="img" aria-labelledby="title description">
  <title id="title">AccordLock</title>
  <desc id="description">Two open flows meet at a verified transaction junction.</desc>
  <defs>
    <linearGradient id="signal" x1="458" y1="458" x2="566" y2="566" gradientUnits="userSpaceOnUse">
      <stop stop-color="#5264E8"/>
      <stop offset="1" stop-color="#8491FF"/>
    </linearGradient>
  </defs>
  <path d="M365 46h294c177 0 319 142 319 319v294c0 177-142 319-319 319H365C188 978 46 836 46 659V365C46 188 188 46 365 46Z" fill="#111318"/>
  <path d="M365 46h294c177 0 319 142 319 319v294c0 177-142 319-319 319H365C188 978 46 836 46 659V365C46 188 188 46 365 46Z" fill="none" stroke="#FFFFFF" stroke-opacity=".09" stroke-width="3"/>
  <path d="M800 358H634c-74 0-122 48-122 122v64c0 74-48 122-122 122H224" fill="none" stroke="#7E8492" stroke-width="78" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M224 358h166c74 0 122 48 122 122v64c0 74 48 122 122 122h166" fill="none" stroke="#F4F1E9" stroke-width="78" stroke-linecap="round" stroke-linejoin="round"/>
  <rect x="446" y="446" width="132" height="132" rx="36" fill="url(#signal)"/>
  <rect x="447.5" y="447.5" width="129" height="129" rx="34.5" fill="none" stroke="#FFFFFF" stroke-opacity=".18" stroke-width="3"/>
</svg>
`;

const standardSizes = [16, 32, 48, 64, 128, 256, 512, 1024];
const rendered = new Map(standardSizes.map((size) => [size, renderIcon(size)]));
const icon2x = renderIcon(2048);

writeFileSync(join(imageDirectory, 'icon.svg'), iconSvg);
writeFileSync(join(imageDirectory, 'icon.png'), rendered.get(1024));
writeFileSync(join(imageDirectory, 'icon@2x.png'), icon2x);
writeFileSync(join(imageDirectory, 'icon-512.png'), rendered.get(512));
writeFileSync(join(imageDirectory, 'icon-light.png'), rendered.get(1024));
writeFileSync(
  join(imageDirectory, 'icon.ico'),
  encodeIco([16, 32, 48, 64, 128, 256].map((size) => ({ size, png: rendered.get(size) })))
);

const icns = encodeIcns([
  { type: 'ic10', png: rendered.get(1024) },
  { type: 'ic09', png: rendered.get(512) },
  { type: 'ic08', png: rendered.get(256) },
  { type: 'ic07', png: rendered.get(128) },
  { type: 'icp6', png: rendered.get(64) },
  { type: 'icp5', png: rendered.get(32) },
  { type: 'icp4', png: rendered.get(16) },
]);
writeFileSync(join(imageDirectory, 'icon.icns'), icns);
writeFileSync(join(imageDirectory, 'icon-light.icns'), icns);

writeFileSync(join(imageDirectory, 'iconTemplate.png'), renderIcon(18, { template: true }));
writeFileSync(join(imageDirectory, 'iconTemplate@2x.png'), renderIcon(36, { template: true }));
writeFileSync(
  join(imageDirectory, 'iconTemplateUpdate.png'),
  renderIcon(18, { template: true, update: true })
);
writeFileSync(
  join(imageDirectory, 'iconTemplateUpdate@2x.png'),
  renderIcon(36, { template: true, update: true })
);
writeFileSync(join(imageDirectory, 'iconTray.png'), renderIcon(32));
writeFileSync(join(imageDirectory, 'iconTray@2x.png'), renderIcon(64));
writeFileSync(join(imageDirectory, 'iconTrayUpdate.png'), renderIcon(32, { update: true }));
writeFileSync(join(imageDirectory, 'iconTrayUpdate@2x.png'), renderIcon(64, { update: true }));

console.log('Generated AccordLock brand assets from the transaction-junction mark.');
