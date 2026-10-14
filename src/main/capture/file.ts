// Reads a capture file from disk: pcap or pcapng, optionally gzip-compressed
// (tcpdump -w - | gzip, or a .pcap.gz downloaded from a router).

import { createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { createGunzip } from 'node:zlib';
import type { Readable } from 'node:stream';
import { PcapStreamReader, type RawFrame } from './pcap';

export async function readCaptureFile(path: string, onFrame: (f: RawFrame) => void): Promise<void> {
  const fh = await open(path, 'r');
  const head = Buffer.alloc(2);
  await fh.read(head, 0, 2, 0);
  await fh.close();
  const gzipped = head[0] === 0x1f && head[1] === 0x8b;

  const reader = new PcapStreamReader(onFrame);
  let stream: Readable = createReadStream(path, { highWaterMark: 1 << 20 });
  if (gzipped) stream = stream.pipe(createGunzip());
  await new Promise<void>((resolve, reject) => {
    stream.on('data', (chunk: Buffer) => {
      try {
        reader.push(chunk);
      } catch (e) {
        stream.destroy();
        reject(e);
      }
    });
    stream.on('end', () => resolve());
    stream.on('error', reject);
  });
}
