"use strict";

const mongoose = require("mongoose");
const crypto = require("crypto");

const logSchema = new mongoose.Schema({
    log: {
        type: String,
        required: true,
    },

    level: {
        type: String,
        enum: ["debug", "info", "warn", "error", "fatal"],
        default: "info",
        index: true,
    },

    integrityOK: {
        type: Boolean,
        default: false,
        index: true,
    },

    uploadedAt: {
        type: Date,
        default: Date.now,
        index: true,
    },
});

logSchema.index({log: "text"});

logSchema.pre("save", function (next) {
    const line = this.log || "";

    const lvl = line.match(/\]\s+(\w+):/);
    if (lvl) this.level = lvl[1].toLowerCase();

    const m = line.match(/(.*)\|\s*HASH:\s*([a-f0-9]{64})$/);
    if (m) {
        const [, payload, hash] = m;
        const calc = crypto
            .createHmac("sha256", process.env.ACCESS_TOKEN_SECRET || "dev-secret")
            .update(payload.trim())
            .digest("hex");
        this.integrityOK = calc === hash;
    } else {
        this.integrityOK = false;
    }

    next();
});

module.exports = mongoose.model("Log", logSchema);
