// isrdosec-payment/index.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const { requestLogger, errorHandler, notFoundHandler, securityHeaders, apiRateLimiter } = require("./middleware");
const paymentRoutes = require("./routes/paymentRoutes");
const authRoutes = require("./routes/authRoutes");
const session = require("./session");
const logger = require("./logger");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || "development";

// Global Middleware
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || "*" }));
app.use(helmet());
app.use(compression());
app.use(securityHeaders);
app.use(apiRateLimiter);
app.use(requestLogger);
app.use(session.sessionMiddleware);

// Custom Rate Limiter for Enhanced Protection
const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, please try again later."
});

app.use(globalRateLimiter);

// Routes
app.use("/api/payments", paymentRoutes);
app.use("/api/auth", authRoutes);

// Health Check Endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "OK", uptime: process.uptime(), timestamp: Date.now() });
});

// Default Routes & Error Handling
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
  logger.logInfo("Server Started", { port: PORT, environment: NODE_ENV });
  console.log(`🚀 Server running on port ${PORT} in ${NODE_ENV} mode`);
});
