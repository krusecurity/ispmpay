// isrdosec-payment/src/rateLimit.js
const rateLimit = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");
const Redis = require("ioredis");

/**
 * Advanced Rate Limiting Middleware
 * Provides flexible, scalable rate limiting with Redis support.
 */

const redisClient = new Redis({
  host: process.env.REDIS_HOST || "127.0.0.1",
  port: process.env.REDIS_PORT || 6379,
  enableOfflineQueue: false,
});

const rateLimiter = (options = {}) => {
  return rateLimit({
    store: new RedisStore({
      sendCommand: (...args) => redisClient.call(...args),
    }),
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes default window
    max: options.max || 100, // Limit each IP to 100 requests per window
    standardHeaders: options.standardHeaders !== undefined ? options.standardHeaders : true, // Return rate limit info in headers
    legacyHeaders: options.legacyHeaders !== undefined ? options.legacyHeaders : false, // Disable old X-RateLimit headers
    keyGenerator: options.keyGenerator || ((req) => req.ip), // Custom key generator (e.g., per user)
    skip: options.skip || (() => false), // Optional function to skip certain requests
    handler: options.handler || ((req, res) => {
      res.status(429).json({
        error: "Rate limit exceeded. Try again later.",
        retryAfter: Math.ceil(options.windowMs / 1000) + " seconds",
      });
    }),
  });
};

module.exports = rateLimiter;
