// isrdosec-payment/src/logger.js
const winston = require("winston");
const path = require("path");

/**
 * Advanced Logging Module
 * Supports file-based and console logging with customizable log levels and formats.
 */

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
  winston.format.printf(({ timestamp, level, message, meta }) => {
    return `${timestamp} [${level.toUpperCase()}]: ${message} ${meta ? JSON.stringify(meta) : ""}`;
  })
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: logFormat,
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), logFormat),
    }),
    new winston.transports.File({
      filename: path.join(__dirname, "../logs/error.log"),
      level: "error",
    }),
    new winston.transports.File({
      filename: path.join(__dirname, "../logs/combined.log"),
    }),
  ],
});

/**
 * Logs an info message
 * @param {string} message - Log message
 * @param {object} [meta] - Additional metadata
 */
const logInfo = (message, meta = {}) => {
  logger.info(message, { meta });
};

/**
 * Logs a warning message
 * @param {string} message - Log message
 * @param {object} [meta] - Additional metadata
 */
const logWarning = (message, meta = {}) => {
  logger.warn(message, { meta });
};

/**
 * Logs an error message
 * @param {string} message - Log message
 * @param {object} [meta] - Additional metadata
 */
const logError = (message, meta = {}) => {
  logger.error(message, { meta });
};

module.exports = {
  logInfo,
  logWarning,
  logError,
  logger,
};
