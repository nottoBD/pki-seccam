// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

/*
   spinning up Next.js on a custom HTTPS server (port 3443) so dev runs over TLS
   we load our TLS key & cert (with optional passphrase) from the /tls volume via env vars
   Next's request handler takes over for routing, but now everything is wrapped in TLS for a realistic dev environment
   in production we might rely on nginx or a different setup, but for local development with self-signed certs, this does the job
*/

const {createServer} = require("https");
const {parse} = require("url");
const next = require("next");
const fs = require("fs");

require("dotenv").config();

const dev = process.env.NODE_ENV !== "production";
const app = next({dev});
const handle = app.getRequestHandler();
const KEY_PATH = process.env.TLS_KEY_PATH || "/tls/server.key";
const CERT_PATH = process.env.TLS_CERT_PATH || "/tls/server.crt";


const httpsOptions = {
    key: fs.readFileSync(KEY_PATH),
    cert: fs.readFileSync(CERT_PATH),
};

if (process.env.TLS_KEY_PASSPHRASE) {
    httpsOptions.passphrase = process.env.TLS_KEY_PASSPHRASE;
}

app.prepare().then(() => {
    createServer(httpsOptions, (req, res) => {
        const parsedUrl = parse(req.url, true);
        handle(req, res, parsedUrl);
    }).listen(3443, (err) => {
        if (err) throw err;
        console.log("Frontend running at https://localhost:3443");
    });
});
