/**
 * Stable error taxonomy for dsh-polyglot-crypto.
 *
 * Every expected failure carries a machine-readable `code`. Messages never
 * contain passphrases, plaintext or key material; callers may show them.
 */
export class RecoveryError extends Error {
  /**
   * @param {string} code stable machine code (see docs/KNOWN-LIMITATIONS.md and references/troubleshooting.md)
   * @param {string} message short human-readable description without secrets
   * @param {{cause?: unknown, exitCode?: number, details?: Record<string, unknown>}} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'RecoveryError';
    this.code = code;
    this.exitCode = options.exitCode ?? DEFAULT_EXIT_CODES[code] ?? 1;
    this.details = options.details === undefined ? undefined : options.details;
  }
}

/** Default process exit code per error-code family. */
export const DEFAULT_EXIT_CODES = Object.freeze({
  E_USAGE: 2,
  E_ARGS: 2,
  E_FORMAT_MAGIC: 3,
  E_FORMAT_VERSION: 3,
  E_FORMAT_HEADER: 3,
  E_FORMAT_TRUNCATED: 3,
  E_FORMAT_TRAILING: 3,
  E_FORMAT_NONCANONICAL: 3,
  E_FORMAT_LIMIT: 3,
  E_AUTH_FAILED: 3,
  E_PASSPHRASE: 2,
  E_PASSPHRASE_WEAK: 2,
  E_KDF_UNSUPPORTED: 4,
  E_KDF_PARAMS: 3,
  E_KEY_INVALID: 3,
  E_KEY_PERMISSIONS: 5,
  E_SIGNATURE_INVALID: 3,
  E_IO: 5,
  E_PATH_ABSOLUTE: 2,
  E_PATH_OUTSIDE_ROOT: 5,
  E_PATH_SYMLINK: 5,
  E_PATH_SPECIAL: 5,
  E_PATH_EXISTS: 5,
  E_LIMIT_INPUT: 5,
  E_LIMIT_OUTPUT: 5,
  E_TIMEOUT: 5,
  E_UNAVAILABLE: 4,
  E_UNSUPPORTED: 4,
  E_ADAPTER_FAILED: 5,
  E_ADAPTER_PROTOCOL: 5,
  E_AUTHZ_REQUIRED: 2,
  E_ARCHIVE_INVALID: 3,
  E_ARCHIVE_UNSAFE: 3,
  E_ARCHIVE_ENCRYPTED: 3,
  E_ARCHIVE_SYMLINK: 3,
  E_ARCHIVE_INTEGRITY: 3,
  E_ARCHIVE_BOMB: 3,
  E_SOURCEMAP_INVALID: 3,
  E_NO_SOURCEMAP: 3,
  E_BACKEND_UNAVAILABLE: 4,
  E_TARGET_UNSUPPORTED: 4,
  E_LIMIT: 5,
  E_CONFIG: 2,
  E_PATH_UNSAFE: 5,
  E_INTERNAL: 1,
});

/** Build a RecoveryError. @param {string} code @param {string} message @param {object} [options] */
export function recoveryError(code, message, options) {
  return new RecoveryError(code, message, options);
}

/**
 * Convert any thrown value into a safe RecoveryError. Unknown values are reduced
 * to a message without a stack and without argument data.
 * @param {unknown} error
 * @returns {RecoveryError}
 */
export function asRecoveryError(error) {
  if (error instanceof RecoveryError) return error;
  if (error instanceof Error) {
    const code = error.code === 'ENOENT' ? 'E_IO' : 'E_INTERNAL';
    return new RecoveryError(code, error.message.replace(/\s+/g, ' ').slice(0, 300), { cause: error });
  }
  return new RecoveryError('E_INTERNAL', 'unexpected failure');
}

/** The shared stable JSON envelope. @param {Record<string, unknown>} payload */
export function envelope(payload) {
  return {
    ok: true,
    code: 'OK',
    message: '',
    formatVersion: 'source-recovery/1',
    backend: 'node',
    warnings: [],
    ...payload,
  };
}
