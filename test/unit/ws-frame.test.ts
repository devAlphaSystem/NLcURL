/**
 * Tests for the WebSocket frame encoder and parser.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeFrame,
  FrameParser,
  Opcode,
  generateWebSocketKey,
  computeAcceptKey,
} from '../../src/ws/frame.js';

describe('WebSocket frame encoding', () => {
  it('encodes a text frame with masking', () => {
    const payload = Buffer.from('Hello', 'utf8');
    const frame = encodeFrame(Opcode.TEXT, payload);
    assert.ok(Buffer.isBuffer(frame));
    // First byte: FIN=1 | opcode=0x01
    assert.equal(frame[0]! & 0x81, 0x81);
    // Second byte has MASK bit set (client -> server)
    assert.ok(frame[1]! & 0x80, 'Mask bit should be set');
  });

  it('encodes a binary frame', () => {
    const payload = Buffer.from([0x01, 0x02, 0x03]);
    const frame = encodeFrame(Opcode.BINARY, payload);
    assert.ok(Buffer.isBuffer(frame));
    assert.equal(frame[0]! & 0x0f, Opcode.BINARY);
  });

  it('encodes a ping frame', () => {
    const frame = encodeFrame(Opcode.PING, Buffer.alloc(0));
    assert.ok(Buffer.isBuffer(frame));
    assert.equal(frame[0]! & 0x0f, Opcode.PING);
  });

  it('encodes a close frame', () => {
    const payload = Buffer.alloc(2);
    payload.writeUInt16BE(1000, 0); // Normal closure
    const frame = encodeFrame(Opcode.CLOSE, payload);
    assert.ok(Buffer.isBuffer(frame));
    assert.equal(frame[0]! & 0x0f, Opcode.CLOSE);
  });
});

describe('WebSocket FrameParser', () => {
  it('parses an unmasked text frame', () => {
    const parser = new FrameParser();
    const payload = Buffer.from('Hello', 'utf8');

    // Build an unmasked frame: FIN=1 opcode=TEXT, length=5
    const frame = Buffer.alloc(2 + payload.length);
    frame[0] = 0x81; // FIN + TEXT
    frame[1] = payload.length; // No mask
    payload.copy(frame, 2);

    parser.push(frame);
    const result = parser.pull();

    assert.ok(result);
    assert.equal(result.opcode, Opcode.TEXT);
    assert.equal(result.fin, true);
    assert.equal(result.payload.toString('utf8'), 'Hello');
  });

  it('parses frame fed in multiple chunks', () => {
    const parser = new FrameParser();
    const payload = Buffer.from('World', 'utf8');

    const frame = Buffer.alloc(2 + payload.length);
    frame[0] = 0x81; // FIN + TEXT
    frame[1] = payload.length;
    payload.copy(frame, 2);

    // Feed in small chunks
    parser.push(frame.subarray(0, 1));
    assert.equal(parser.pull(), null); // Not enough data

    parser.push(frame.subarray(1, 3));
    assert.equal(parser.pull(), null); // Still not enough

    parser.push(frame.subarray(3));
    const result = parser.pull();
    assert.ok(result);
    assert.equal(result.payload.toString('utf8'), 'World');
  });

  it('parses a close frame', () => {
    const parser = new FrameParser();
    const payload = Buffer.alloc(4);
    payload.writeUInt16BE(1000, 0);
    payload.write('OK', 2, 'utf8');

    const frame = Buffer.alloc(2 + payload.length);
    frame[0] = 0x88; // FIN + CLOSE
    frame[1] = payload.length;
    payload.copy(frame, 2);

    parser.push(frame);
    const result = parser.pull();
    assert.ok(result);
    assert.equal(result.opcode, Opcode.CLOSE);
    assert.equal(result.payload.readUInt16BE(0), 1000);
  });

  it('returns null when no complete frame available', () => {
    const parser = new FrameParser();
    parser.push(Buffer.from([0x81])); // Only first byte
    assert.equal(parser.pull(), null);
  });
});

describe('WebSocket key generation', () => {
  it('generates a valid base64 key', () => {
    const key = generateWebSocketKey();
    assert.ok(typeof key === 'string');
    // Should be base64 of 16 bytes = 24 chars
    assert.equal(key.length, 24);
  });

  it('generates unique keys', () => {
    const key1 = generateWebSocketKey();
    const key2 = generateWebSocketKey();
    assert.notEqual(key1, key2);
  });

  it('computes correct accept key', () => {
    // Known test vector from RFC 6455 Section 4.2.2
    const key = 'dGhlIHNhbXBsZSBub25jZQ==';
    const accept = computeAcceptKey(key);
    assert.equal(accept, 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
  });
});
