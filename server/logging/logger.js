"use strict";

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
        .replace(/[\r\n]+/g, " ")
        .replace(/\t/g, " ")
        .replace(/%/g, "%25")
        .replace(/\|/g, "\\|")
        .replace(/[<>]/g, "")
        .replace(/(password|token|secret|key|credential)(\s*[:=]\s*)([^\s]+)/gi,
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
