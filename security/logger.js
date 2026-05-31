/**
 * ================================================================
 *  LOGGER MODULE v2.0 — Winston structured JSON logging
 *  Logs to console + rotating daily files in production
 * ================================================================
 */

"use strict";

const { createLogger, format, transports } = require("winston");
const { combine, timestamp, errors, json, colorize, printf } = format;

const devFormat = printf(({ level, message, timestamp, ...meta }) => {
  const metaStr = Object.keys(meta).length ? `\n${JSON.stringify(meta, null, 2)}` : "";
  return `[${timestamp}] ${level}: ${message}${metaStr}`;
});

const logger = createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: combine(
    timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    errors({ stack: true }),
    json()
  ),
  defaultMeta: {
    service:     "absall-api",
    environment: process.env.NODE_ENV || "development",
  },
  transports: [
    new transports.Console({
      format: process.env.NODE_ENV === "production"
        ? combine(timestamp(), json())
        : combine(colorize(), timestamp(), devFormat),
    }),
  ],
  exitOnError: false,
});

// File logging in production (requires: npm install winston-daily-rotate-file)
if (process.env.NODE_ENV === "production") {
  try {
    const DailyRotateFile = require("winston-daily-rotate-file");
    logger.add(new DailyRotateFile({
      filename:    "logs/security-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxSize:     "20m",
      maxFiles:    "30d",    // Keep 30 days
      level:       "warn",   // Only warn+ goes to file
      zippedArchive: true,
    }));
    logger.add(new DailyRotateFile({
      filename:    "logs/all-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxSize:     "20m",
      maxFiles:    "7d",
      level:       "info",
      zippedArchive: true,
    }));
  } catch {
    // Not installed — Hostinger console logs are still captured
  }
}

module.exports = logger;
