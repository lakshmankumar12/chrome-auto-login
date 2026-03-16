/**
 * totp.js — RFC 6238 TOTP implementation using Web Crypto API
 * No external dependencies.
 */

/**
 * Decode a Base32 string to a Uint8Array.
 * Accepts standard Base32 (RFC 4648), ignores spaces/dashes (common in TOTP secrets).
 */
function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const s = base32.toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((s.length * 5) / 8));

  for (let i = 0; i < s.length; i++) {
    const idx = alphabet.indexOf(s[i]);
    if (idx === -1) throw new Error(`Invalid base32 character: ${s[i]}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return output;
}

/**
 * Generate a TOTP code.
 * @param {string} secret  — Base32-encoded shared secret
 * @param {number} digits  — Code length (default 6)
 * @param {number} period  — Time step in seconds (default 30)
 * @returns {Promise<string>} Zero-padded TOTP code
 */
async function generateTOTP(secret, digits = 6, period = 30) {
  const keyBytes = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / period);

  // Counter as big-endian 8-byte buffer
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  // JS numbers are safe up to 2^53; split into hi/lo 32-bit words
  const hi = Math.floor(counter / 0x100000000);
  const lo = counter >>> 0;
  counterView.setUint32(0, hi, false);
  counterView.setUint32(4, lo, false);

  // Import key and compute HMAC-SHA1
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const hmac = new Uint8Array(signature);

  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

/**
 * Returns seconds remaining in the current TOTP period.
 */
function totpSecondsRemaining(period = 30) {
  return period - (Math.floor(Date.now() / 1000) % period);
}
