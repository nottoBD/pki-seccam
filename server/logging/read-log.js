"use strict";

const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const mongoose = require("mongoose");
const LogModel = require("../models/log");

const DB_URI = process.env.DB_URL || "mongodb://localhost:27017/seccam";
const HMAC_KEY = process.env.ACCESS_TOKEN_SECRET || "dev-secret";
const HASH_RE = /(.*)\|\s*HASH:\s*([a-f0-9]{64})$/;

// CLI commands: $ node read-log.js dump log.txt   |   $ node read-log.js reset
// $ docker compose exec server node logging/read-log.js dump /tmp/log.txt
// $ docker compose cp server:/tmp/log.txt ./log.txt
// $

/**
 * @param {string} line – raw log line from DB
 * @returns {{ ok: true, msg: string } | { ok: false, err: string }}
 */
function verifyLine(line) {
    const m = line.match(HASH_RE);
    if (!m) return {ok: false, err: "No hash trailer"};

    const [, payload, hash] = m;
    const calc = crypto.createHmac("sha256", HMAC_KEY)
        .update(payload.trim())
        .digest("hex");

    if (calc !== hash) return {ok: false, err: "Hash mismatch"};
    return {ok: true, msg: payload.trim()};
}

async function connectMongo() {
    if (mongoose.connection.readyState === 1) return; // already connected
    await mongoose.connect(DB_URI);
}

/**
 * Fetch logs, verify integrity, then print or save.
 * @param {string} [outFile] – if provided, write to that file.
 */
async function readLogs(outFile = "") {
    await connectMongo();

    const docs = await LogModel.find().lean();
    if (!docs.length) {
        console.log("(no logs)");
        return;
    }

    const verified = docs.map(d => verifyLine(d.log))
        .filter(r => r.ok)
        .map(r => r.msg)
        .join("\n");

    if (!verified) {
        console.warn("All logs failed integrity check. Nothing exported.");
        return;
    }

    if (outFile) {
        const full = path.resolve(__dirname, outFile);
        await fs.writeFile(full, verified, "utf8");
        console.log(`Logs written → ${full}`);
    } else {
        console.log(verified);
    }
}

async function resetDB() {
    await connectMongo();
    await LogModel.deleteMany();
    console.log("Log collection emptied.");
}

if (require.main === module) {
    (async () => {
        const [task = "dump", file] = process.argv.slice(2);

        try {
            if (task === "reset") await resetDB();
            else await readLogs(file);
        } catch (err) {
            console.error(err);
            process.exitCode = 1;
        } finally {
            await mongoose.disconnect();
        }
    })();
}

module.exports = {readLogs, resetDB};
