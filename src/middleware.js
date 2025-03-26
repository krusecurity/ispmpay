// isrdosec-payment/src/middleware.js
const { logInfo, logError } = require("./logger");
const helmet = require("helmet");
const rateLimiter = require("./rateLimit");

/**
 * Middleware for handling request logging, error handling, and security enhancements.
 */

const requestLogger = (req, res, next) => {
  logInfo("Incoming Request", {
    method: req.method,
    url: req.url,
    ip: req.ip,
    headers: req.headers,
  });
  next();
};

const errorHandler = (err, req, res, next) => {
  logError("Server Error", {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.url,
    ip: req.ip,
  });
  res.status(500).json({ error: "Internal Server Error", details: err.message });
};

const notFoundHandler = (req, res, next) => {
  logError("Not Found", { method: req.method, url: req.url, ip: req.ip });
  res.status(404).json({ error: "Resource Not Found" });
};

const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  frameguard: { action: "deny" },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
});

// Custom Rate Limiter for API Protection
const apiRateLimiter = rateLimiter({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 50, // Limit each IP to 50 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = {
  requestLogger,
  errorHandler,
  notFoundHandler,
  securityHeaders,
  apiRateLimiter,
};