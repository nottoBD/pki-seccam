"use strict";


const WINDOW_MS = 60_000;           // size sliding window
const ALERT_CHUNK_DELAY = 100;      // warn delayed chunks
const ALERT_ENDPOINT_4XX = 100;     // warn 400/404
const ALERT_INACTIVITY_EVT = 1_000;  //warn inactivity err
const ALERT_USER_ACTIVITY = 50;     // user flood


class ExpiringMap {
    /**
     * @param {number} ttl – time‑to‑live in ms for each entry
     */
    constructor(ttl) {
        this.ttl = ttl;
        this._m = new Map();
    }

    _now() {
        return Date.now();
    }

    _isFresh(rec) {
        return this._now() - rec.ts < this.ttl;
    }

    #gc(key) {
        const rec = this._m.get(key);
        if (rec && !this._isFresh(rec)) this._m.delete(key);
    }

    set(key, val) {
        this._m.set(key, {val, ts: this._now()});
    }

    get(key) {
        this.#gc(key);
        return this._m.get(key)?.val;
    }

    inc(key, by = 1) {
        const val = (this.get(key) || 0) + by;
        this.set(key, val);
        return val;
    }

    forEach(fn) {
        for (const [k, rec] of this._m) {
            this.#gc(k);
            if (this._m.has(k)) fn(rec.val, k);
        }
    }
}

const alert = msg => console.warn("[ALERT]", msg);

const mem = {
    chunkDelay: new ExpiringMap(WINDOW_MS),
    endpoint4xx: new ExpiringMap(WINDOW_MS),
    inactivity: new ExpiringMap(WINDOW_MS),
    perUser: new ExpiringMap(WINDOW_MS),
};

function checkLogEntry(info) {
    const {level, message = "", timestamp, userID, meta = {}} = info;

    // delayed chunk
    if (level === "warn" && meta.chunk && meta.delay) {
        const c = mem.chunkDelay.inc("sum");
        if (c > ALERT_CHUNK_DELAY) alert(`Delayed chunks > ${ALERT_CHUNK_DELAY}`);
    }

    // endpoint 4xx
    if (level === "info" && /\b404\b/.test(message)) {
        const c = mem.endpoint4xx.inc("sum");
        if (c > ALERT_ENDPOINT_4XX) alert("Excessive 4xx responses detected");
    }

    // inactivity errors
    if (level === "error" && /inactivity/i.test(message)) {
        const c = mem.inactivity.inc("sum");
        if (c > ALERT_INACTIVITY_EVT) alert("High inactivity error rate");
    }

    // per‑user flood protection
    if (userID) {
        const u = mem.perUser.inc(userID);
        if (u > ALERT_USER_ACTIVITY) alert(`User ${userID} performed ${u} actions`);
    }

//return
}

module.exports = {checkLogEntry};
