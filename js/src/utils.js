import { randomBytes } from 'crypto';

/**
 * Utility functions for PQJWT
 */

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {Buffer} Random bytes
 */
export function generateRandomBytes(length = 32) {
    return randomBytes(length);
}

/**
 * Validate JWT claims
 * @param {Object} payload - JWT payload
 * @param {number} clockSkew - Clock skew in seconds
 * @returns {Object} Validation result { isValid: boolean, error: string|null }
 */
export function validateClaims(payload, clockSkew = 5) {
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && now >= payload.exp) {
        return { isValid: false, error: `Token expired at ${new Date(payload.exp * 1000).toISOString()}` };
    }

    if (payload.nbf && now + clockSkew < payload.nbf) {
        return { isValid: false, error: `Token not valid before ${new Date(payload.nbf * 1000).toISOString()}` };
    }

    if (payload.iat && payload.iat > now) {
        return { isValid: false, error: `Token issued in future: ${new Date(payload.iat * 1000).toISOString()}` };
    }

    return { isValid: true, error: null };
}

/**
 * Convert bytes to hex string
 * @param {Buffer|Uint8Array} bytes - Bytes to convert
 * @returns {string} Hex string
 */
export function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string to convert
 * @returns {Buffer} Bytes
 */
export function hexToBytes(hex) {
    return Buffer.from(hex, 'hex');
}

/**
 * Sleep utility
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise} Promise that resolves after specified time
 */
export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Deep clone object
 * @param {Object} obj - Object to clone
 * @returns {Object} Cloned object
 */
export function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}