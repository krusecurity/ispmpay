// isrdosec-payment/src/session.js
const crypto = require("crypto");
const NodeCache = require("node-cache");

const sessionStore = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

/**
 * Session Management Module - Handles secure session creation, validation, and expiration
 * Features include session token generation, secure storage, and automatic expiration.
 */

/**
 * Generates a secure session ID
 * @returns {string} - The generated session ID
 */
const generateSessionId = () => {
  return crypto.randomBytes(32).toString("hex");
};

/**
 * Creates a new session with optional metadata
 * @param {string} userId - The user ID associated with the session
 * @param {object} [metadata={}] - Additional session metadata (e.g., IP, device info)
 * @returns {string} - The generated session ID
 */
const createSession = (userId, metadata = {}) => {
  const sessionId = generateSessionId();
  const sessionData = { userId, ...metadata, createdAt: Date.now() };
  sessionStore.set(sessionId, sessionData);
  return sessionId;
};

/**
 * Validates an existing session
 * @param {string} sessionId - The session ID to validate
 * @returns {object|null} - The session data if valid, otherwise null
 */
const validateSession = (sessionId) => {
  return sessionStore.get(sessionId) || null;
};

/**
 * Refreshes an existing session by extending its TTL
 * @param {string} sessionId - The session ID to refresh
 * @returns {boolean} - True if the session was successfully refreshed, otherwise false
 */
const refreshSession = (sessionId) => {
  const sessionData = sessionStore.get(sessionId);
  if (sessionData) {
    sessionStore.set(sessionId, sessionData);
    return true;
  }
  return false;
};

/**
 * Destroys an active session
 * @param {string} sessionId - The session ID to destroy
 * @returns {boolean} - True if the session was successfully removed, otherwise false
 */
const destroySession = (sessionId) => {
  return sessionStore.del(sessionId) > 0;
};

/**
 * Clears all active sessions (Admin use only)
 */
const clearAllSessions = () => {
  sessionStore.flushAll();
};

module.exports = {
  generateSessionId,
  createSession,
  validateSession,
  refreshSession,
  destroySession,
  clearAllSessions,
};
