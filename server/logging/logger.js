"use strict";
/**
 * Custom Winston logger configuration for SecCam, focusing on log integrity and alerting.
 * This sets up a logger that writes to both the console and a MongoDB collection via a custom transport.
 * Each log message is sanitized for sensitive info and given an integrity hash (HMAC) before storage.
 * The idea is that every log line stored in the database includes a `| HASH: ...` at the end, which is a SHA-256 HMAC of the log content.
 * This allows detection of log tampering – if someone alters a log message, its hash won’t match.
 * The logger also works in tandem with `logger-helper.js` to watch for suspicious patterns (like too many errors or too many 404s in a short time) and prints console warnings if thresholds are exceeded.
 */


const crypto = require("crypto");
const winston = require("winston");
const {combine, timestamp, printf} = winston.format;

const LogModel = require("../models/log");
const helper = require("./logger-helper");


const MAX_LENGTH = 500;

/**
 * Sanitize a message so log‑injection or sensitive data never reach the sinks.
 * @param {string} txt – raw string coming from application code
 * @returns {string} cleaned up and length‑bounded text
 */
const sanitize = (txt = "") => {
    if (typeof txt !== "string") return "";

    let out = txt
        .replace(/[ \n\r]+/g, " ")  // replace space
        .replace(/\t/g, " ")        // replace tab
        .replace(/%/g, "%25")       // escape %
        .replace(/\|/g, "\\|")      // escape |
        .replace(/[<>]/g, "")       // remove < and >
        .replace(/(password|token|authToken|secret|key|credential)(\s*[:=]\s*)([^\s]+)/gi,
            (_m, k, sep) => `${k}${sep}******`);

    if (out.length > MAX_LENGTH) out = `${out.slice(0, MAX_LENGTH)}... [TRUNCATED]`;
    return out;
};


const makeHash = str =>
    crypto.createHmac("sha256", process.env.ACCESS_TOKEN_SECRET || "dev-secret")
        .update(str)
        .digest("hex");

const safeStringify = obj => {
    const seen = new WeakSet();
    return JSON.stringify(obj, (k, v) => {
        if (typeof v === "object" && v !== null) {
            if (seen.has(v)) return "[Circular]";
            seen.add(v);
        }
        if (typeof v === "function") return `[Function:${v.name || "anon"}]`;
        return v;
    });
};


/**
 * Here we define a custom Winston transport (MongoTransport) that writes logs to the MongoDB through our Mongoose model.
 * Before saving, we call `helper.checkLogEntry(info)` which applies some in-memory rate checks (to detect floods or anomalies) and then construct a Log document.
 * Each log message is formatted with a timestamp, level, and the message itself – plus we append a HMAC hash of the entire line at the end (the hash is computed with a secret key, making it tamper-evident).
 * The formatter replaces any sensitive fields (like passwords or tokens) with placeholders before computing the hash.
 * Finally, the logger is created with this formatter and our custom transport, so that every log saved to the database is integrity-protected and we get immediate alerts on the console if something unusual is happening (like rapid 4xx responses or repeated errors).
 */

class MongoTransport extends winston.Transport {
    log(info, done) {
        setImmediate(() => this.emit("logged", info));

        try {
            helper.checkLogEntry(info);
            const doc = new LogModel({log: info[Symbol.for("message")]});
            doc.save().then(() => done()).catch(done);
        } catch (err) {
            done(err);
        }
    }
}


const formatter = printf(({timestamp, level, message, stack, ...meta}) => {
    const base = `[${timestamp}] ${level.toUpperCase()}: ${sanitize(message)}`;
    let line = base;

    if (Object.keys(meta).length) {
        try {
            line += ` ${safeStringify(meta)}`;
        } catch {
            line += " [meta‑unserialisable]";
        }
    }
    if (stack) line += `\n${stack}`;

    return `${line} | HASH: ${makeHash(line)}`;
});

const logger = winston.createLogger({
    level: "info",
    format: combine(
        timestamp({format: "DD-MM-YYYY HH:mm:ss"}),
        formatter,
    ),
    transports: [
        new MongoTransport(),
        new winston.transports.Console({handleExceptions: true}),
    ],
    exitOnError: false,
});

module.exports = logger;
