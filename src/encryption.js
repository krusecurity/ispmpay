// isrdosec-payment/src/encryption.js
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const jose = require("node-jose");

/**
 * AES Encryption - Secure and developer-friendly implementation
 * @param {string} text - The plaintext to encrypt
 * @param {string} secretKey - The encryption key
 * @param {string} algorithm - The encryption algorithm (default: aes-256-cbc)
 * @returns {string} - The encrypted text in hex format
 */
const encrypt = (text, secretKey, algorithm = "aes-256-cbc") => {
  const key = crypto.scryptSync(secretKey, "salt", 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return `${iv.toString("hex")}:${encrypted}`;
};

/**
 * AES Decryption - Secure and developer-friendly implementation
 * @param {string} encryptedText - The encrypted text in hex format
 * @param {string} secretKey - The encryption key
 * @param {string} algorithm - The encryption algorithm (default: aes-256-cbc)
 * @returns {string} - The decrypted plaintext
 */
const decrypt = (encryptedText, secretKey, algorithm = "aes-256-cbc") => {
  const [ivHex, encrypted] = encryptedText.split(":");
  const key = crypto.scryptSync(secretKey, "salt", 32);
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, "hex"));
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};

/**
 * JWT Token Generation - Customizable and developer-friendly
 * @param {object} payload - The data to be encoded in the token
 * @param {string} secretKey - The secret key for signing the token
 * @param {object} options - JWT options (default: { expiresIn: "1h" })
 * @returns {string} - The generated JWT token
 */
const generateJWT = (payload, secretKey, options = { expiresIn: "1h" }) => {
  return jwt.sign(payload, secretKey, options);
};

/**
 * JWT Verification - Secure verification of JWT tokens
 * @param {string} token - The JWT token to verify
 * @param {string} secretKey - The secret key for verification
 * @returns {object|null} - The decoded token payload if valid, otherwise null
 */
const verifyJWT = (token, secretKey) => {
  try {
    return jwt.verify(token, secretKey);
  } catch (error) {
    return null;
  }
};

/**
 * JOSE Key Management - Secure key generation and encryption
 * @param {number} keySize - RSA key size (default: 2048)
 * @param {string} algorithm - Encryption algorithm (default: RSA-OAEP)
 * @returns {Promise<object>} - Generated JOSE key
 */
const generateKey = async (keySize = 2048, algorithm = "RSA-OAEP") => {
  return await jose.JWK.createKey("RSA", keySize, { alg: algorithm, use: "enc" });
};

/**
 * Encrypt Data Using JOSE - Secure encryption with public key
 * @param {string} data - The plaintext data to encrypt
 * @param {object} publicKey - The recipient's public key (JOSE format)
 * @returns {Promise<string>} - The encrypted data in compact format
 */
const encryptWithJOSE = async (data, publicKey) => {
  const key = await jose.JWK.asKey(publicKey);
  const encrypter = await jose.JWE.createEncrypt({ format: "compact" }, key);
  return encrypter.update(data).final();
};

module.exports = {
  encrypt,
  decrypt,
  generateJWT,
  verifyJWT,
  generateKey,
  encryptWithJOSE
};
