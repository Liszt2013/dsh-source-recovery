/** Small shared helpers: strict encoding, hashing, redaction, stream limits. */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { homedir } from 'node:os';
import { RecoveryError } from './errors.js';

/** Lowercase hex. @param {Uint8Array} bytes */
export function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Strict hex decode: even length, lowercase or uppercase hex digits only.
 * @param {string} text
 * @param {string} [label]
 */
export function fromHex(text, label = 'hex value') {
  if (typeof text !== 'string' || text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new RecoveryError('E_ARGS', `${label} must be an even-length hexadecimal string`);
  }
  return Buffer.from(text, 'hex');
}

/** Strict standard base64 decode (rejects URLs-safe and whitespace). @param {string} text @param {string} [label] */
export function fromBase64(text, label = 'base64 value') {
  if (typeof text !== 'string' || text.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new RecoveryError('E_ARGS', `${label} must be canonical standard base64`);
  }
  return Buffer.from(text, 'base64');
}

/** @param {Uint8Array} bytes */
export function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

/** SHA-256. @param {Uint8Array|string} data */
export function sha256(data) {
  return createHash('sha256').update(data).digest();
}

/** SHA-512. @param {Uint8Array|string} data */
export function sha512(data) {
  return createHash('sha512').update(data).digest();
}

/**
 * Digest helpers named for what they are: digests, never "encryption".
 * @param {'sha256'|'sha512'} alg
 * @param {Uint8Array|string} data
 */
export function digest(alg, data) {
  if (alg === 'sha256') return sha256(data);
  if (alg === 'sha512') return sha512(data);
  throw new RecoveryError('E_UNSUPPORTED', `unsupported digest algorithm: ${String(alg)}`);
}

/** Cryptographically secure randomness from the Node/OpenSSL CSPRNG. @param {number} bytes */
export function random(bytes) {
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > 1024 * 1024) {
    throw new RecoveryError('E_ARGS', 'random byte count must be an integer between 1 and 1048576');
  }
  return randomBytes(bytes);
}

/** Constant-time equality for equal-length buffers. @param {Uint8Array} a @param {Uint8Array} b */
export function safeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Redact absolute home and workspace paths from human-facing text. Secrets are
 * never included by construction; this only reduces incidental path leakage in
 * diagnostics and error text.
 * @param {string} text
 */
export function redactPaths(text) {
  if (typeof text !== 'string') return '';
  let out = text;
  const home = homedir();
  if (home && home.length > 1) out = out.split(home).join('~');
  return out;
}

/** Convert a bigint-safe nonnegative integer to a number. @param {bigint} value @param {string} label */
export function bigintToSafeNumber(value, label) {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RecoveryError('E_FORMAT_LIMIT', `${label} exceeds the supported range`);
  }
  return Number(value);
}

/**
 * Read a bounded number of bytes from stdin. Used for passphrases and piped
 * plaintext so neither ever appears in argv.
 * @param {NodeJS.ReadableStream} stream
 * @param {number} limit
 * @returns {Promise<Buffer>}
 */
export function readBoundedStdin(stream, limit) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      stream.off('data', onData);
      stream.off('end', onEnd);
      stream.off('error', onError);
      if (error) reject(error);
      else resolve(value);
    };
    const onData = (chunk) => {
      const buf = Buffer.from(chunk);
      total += buf.length;
      if (total > limit) {
        finish(new RecoveryError('E_LIMIT_INPUT', `stdin exceeded the ${limit}-byte limit`));
        return;
      }
      chunks.push(buf);
    };
    const onEnd = () => finish(null, Buffer.concat(chunks, total));
    const onError = (error) => finish(new RecoveryError('E_IO', 'failed to read stdin', { cause: error }));
    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onError);
  });
}

/**
 * Normalize a secret line read from a file or stdin: remove one trailing
 * CRLF/LF, reject NUL bytes, keep interior bytes intact.
 * @param {Buffer} buffer
 * @param {string} label
 */
export function normalizeSecretLine(buffer, label) {
  let end = buffer.length;
  if (end > 0 && buffer[end - 1] === 0x0a) end -= 1;
  if (end > 0 && buffer[end - 1] === 0x0d) end -= 1;
  const value = buffer.subarray(0, end);
  if (value.includes(0)) throw new RecoveryError('E_PASSPHRASE', `${label} must not contain NUL bytes`);
  return value;
}

/** ISO timestamp for reports. */
export function nowIso() {
  return new Date().toISOString();
}
