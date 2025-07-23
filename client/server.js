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
