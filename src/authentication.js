// isrdosec-payment/src/authentication.js
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

/**
 * Authentication Module - Provides secure authentication mechanisms
 * Features include password hashing, JWT authentication, session validation,
 * multi-factor authentication (MFA) support, and refresh token handling.
 */

/**
 * Hashes a password securely using bcrypt
 * @param {string} password - The plaintext password
 * @returns {Promise<string>} - The hashed password
 */
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(14);
  return await bcrypt.hash(password, salt);
};

/**
 * Compares a plaintext password with a hashed password
 * @param {string} password - The plaintext password
 * @param {string} hashedPassword - The stored hashed password
 * @returns {Promise<boolean>} - True if passwords match, otherwise false
 */
const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

/**
 * Generates a secure JWT token with additional security options
 * @param {object} payload - The token payload
 * @param {string} secretKey - The secret key for signing the token
 * @param {object} options - Additional JWT options (e.g., expiration, issuer, audience)
 * @returns {string} - The generated JWT token
 */
const generateJWT = (payload, secretKey, options = { expiresIn: "1h", issuer: "isrdosec", audience: "users" }) => {
  return jwt.sign(payload, secretKey, options);
};

/**
 * Verifies and decodes a JWT token with additional validation
 * @param {string} token - The JWT token to verify
 * @param {string} secretKey - The secret key used to sign the token
 * @returns {object|null} - The decoded payload or null if verification fails
 */
const verifyJWT = (token, secretKey) => {
  try {
    return jwt.verify(token, secretKey, { issuer: "isrdosec", audience: "users" });
  } catch (error) {
    return null;
  }
};

/**
 * Generates a secure random token for session validation or API keys
 * @param {number} length - Length of the token (default: 64 bytes)
 * @returns {string} - The generated token
 */
const generateSecureToken = (length = 64) => {
  return crypto.randomBytes(length).toString("hex");
};

/**
 * Generates a refresh token for long-lived sessions
 * @returns {string} - A securely generated refresh token
 */
const generateRefreshToken = () => {
  return uuidv4();
};

/**
 * Validates a refresh token (this should be stored securely and checked against a DB)
 * @param {string} refreshToken - The refresh token to validate
 * @returns {boolean} - True if valid, otherwise false
 */
const validateRefreshToken = (refreshToken, storedTokens) => {
  return storedTokens.includes(refreshToken);
};

module.exports = {
  hashPassword,
  comparePassword,
  generateJWT,
  verifyJWT,
  generateSecureToken,
  generateRefreshToken,
  validateRefreshToken,
};
