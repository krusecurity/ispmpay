// isrdosec-payment/src/securityScan.js
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const jose = require("node-jose");
const { promisify } = require("util");

/**
 * Security Scan Module - Performs vulnerability checks on encryption, JWT, and key management mechanisms
 * Provides insights into weak keys, outdated algorithms, and insecure practices
 */

/**
 * Checks if an encryption key is weak
 * @param {string} key - The encryption key
 * @returns {boolean} - True if the key is weak, otherwise false
 */
const isWeakKey = (key) => {
  return key.length < 32 || /^[a-zA-Z0-9]*$/.test(key); // Key should be at least 32 characters and contain symbols
};

/**
 * Checks if a JWT secret key is secure
 * @param {string} secret - The secret key used for signing JWTs
 * @returns {boolean} - True if the secret is weak, otherwise false
 */
const isWeakJWTSecret = (secret) => {
  return secret.length < 64 || !/[!@#$%^&*(),.?":{}|<>]/g.test(secret); // Must be at least 64 characters and contain special chars
};

/**
 * Checks if a cryptographic algorithm is outdated or insecure
 * @param {string} algorithm - The encryption algorithm
 * @returns {boolean} - True if the algorithm is outdated, otherwise false
 */
const isWeakAlgorithm = (algorithm) => {
  const weakAlgorithms = ["des", "rc4", "md5", "sha1", "aes-128-cbc", "aes-192-cbc"];
  return weakAlgorithms.includes(algorithm.toLowerCase());
};

/**
 * Scans a JWT token to ensure it has proper expiration, secure headers, and strong algorithms
 * @param {string} token - The JWT token to analyze
 * @returns {object} - Security scan results
 */
const scanJWT = (token) => {
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return { valid: false, reason: "Invalid JWT structure" };
    const { header, payload } = decoded;
    
    return {
      valid: true,
      algorithm: header.alg,
      isAlgorithmWeak: isWeakAlgorithm(header.alg),
      expiresAt: payload.exp ? new Date(payload.exp * 1000) : "No Expiration Set",
      issuedAt: payload.iat ? new Date(payload.iat * 1000) : "No Issued At Set",
      audience: payload.aud || "Not Defined",
      issuer: payload.iss || "Not Defined",
    };
  } catch (error) {
    return { valid: false, reason: error.message };
  }
};

/**
 * Validates a cryptographic key file and checks for security issues
 * @param {string} filePath - Path to the key file
 * @returns {object} - Validation results
 */
const validateKeyFile = (filePath) => {
  try {
    const keyData = fs.readFileSync(filePath, "utf8");
    if (!keyData.includes("-----BEGIN")) {
      return { valid: false, reason: "Invalid Key Format" };
    }
    return { valid: true, message: "Valid Key File" };
  } catch (error) {
    return { valid: false, reason: "File Read Error" };
  }
};

/**
 * Runs a comprehensive security scan on encryption, JWT, and key management implementations
 * @param {object} config - Configurations containing keys, algorithms, and files
 * @returns {object} - Security scan report
 */
const runSecurityScan = (config) => {
  return {
    encryption: {
      keyWeakness: isWeakKey(config.encryptionKey),
      algorithmWeakness: isWeakAlgorithm(config.encryptionAlgorithm),
    },
    jwt: {
      secretWeakness: isWeakJWTSecret(config.jwtSecret),
      scannedToken: config.testJWT ? scanJWT(config.testJWT) : null,
    },
    keys: config.keyFilePath ? validateKeyFile(config.keyFilePath) : null,
  };
};

module.exports = {
  isWeakKey,
  isWeakJWTSecret,
  isWeakAlgorithm,
  scanJWT,
  validateKeyFile,
  runSecurityScan,
};