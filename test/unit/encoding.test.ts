
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decompressBody, createDecompressStream } from '../../src/utils/encoding.js';
import * as zlib from 'node:zlib';
import { promisify } from 'node:util';

const gzipAsync = promisify(zlib.gzip);
const brotliCompressAsync = promisify(zlib.brotliCompress);
const deflateAsync = promisify(zlib.deflate);

describe('decompressBody', () => {
  it('returns body unchanged for no encoding', async () => {
    const buf = Buffer.from('hello');
    const result = await decompressBody(buf, undefined);
    assert.deepEqual(result, buf);
  });

  it('returns body unchanged for identity encoding', async () => {
    const buf = Buffer.from('hello');
    const result = await decompressBody(buf, 'identity');
    assert.deepEqual(result, buf);
  });

  it('decompresses gzip', async () => {
    const compressed = await gzipAsync(Buffer.from('hello gzip'));
    const result = await decompressBody(compressed, 'gzip');
    assert.equal(result.toString(), 'hello gzip');
  });

  it('decompresses x-gzip', async () => {
    const compressed = await gzipAsync(Buffer.from('hello x-gzip'));
    const result = await decompressBody(compressed, 'x-gzip');
    assert.equal(result.toString(), 'hello x-gzip');
  });

  it('decompresses brotli', async () => {
    const compressed = await brotliCompressAsync(Buffer.from('hello brotli'));
    const result = await decompressBody(compressed, 'br');
    assert.equal(result.toString(), 'hello brotli');
  });

  it('decompresses deflate', async () => {
    const compressed = await deflateAsync(Buffer.from('hello deflate'));
    const result = await decompressBody(compressed, 'deflate');
    assert.equal(result.toString(), 'hello deflate');
  });

  it('returns body unchanged for unknown encoding', async () => {
    const buf = Buffer.from('raw data');
    const result = await decompressBody(buf, 'unknown-encoding');
    assert.deepEqual(result, buf);
  });

  it('returns body unchanged for empty buffer', async () => {
    const result = await decompressBody(Buffer.alloc(0), 'gzip');
    assert.equal(result.length, 0);
  });
});

describe('createDecompressStream', () => {
  it('returns null for undefined encoding', () => {
    assert.equal(createDecompressStream(undefined), null);
  });

  it('returns null for identity encoding', () => {
    assert.equal(createDecompressStream('identity'), null);
  });

  it('returns null for unknown encoding', () => {
    assert.equal(createDecompressStream('unknown'), null);
  });

  it('returns a transform for gzip', () => {
    const stream = createDecompressStream('gzip');
    assert.ok(stream !== null);
    stream.destroy();
  });

  it('returns a transform for x-gzip', () => {
    const stream = createDecompressStream('x-gzip');
    assert.ok(stream !== null);
    stream.destroy();
  });

  it('returns a transform for br (brotli)', () => {
    const stream = createDecompressStream('br');
    assert.ok(stream !== null);
    stream.destroy();
  });

  it('returns a transform for deflate', () => {
    const stream = createDecompressStream('deflate');
    assert.ok(stream !== null);
    stream.destroy();
  });

  it('gzip stream correctly decompresses piped data', async () => {
    const src = Buffer.from('streaming decompression test');
    const compressed = await gzipAsync(src);

    const stream = createDecompressStream('gzip')!;
    assert.ok(stream !== null);

    const chunks: Buffer[] = [];
    const result = await new Promise<Buffer>((resolve, reject) => {
      stream.on('data', (c: Buffer) => chunks.push(c));
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      stream.on('error', reject);
      stream.end(compressed);
    });

    assert.equal(result.toString(), src.toString());
  });
});
