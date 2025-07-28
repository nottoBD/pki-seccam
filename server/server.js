require('dotenv').config();

const fs = require('fs');
const https = require('https');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');

const logger = require('./logging/logger');

const app = express();
const PORT = 8888;
const upload = multer({storage: multer.memoryStorage()});

mongoose.connect(process.env.DB_URL)
    .then(() => logger.info(`Connected to DB → ${process.env.DB_URL}`))
    .catch(err => logger.error('DB connection error', err));

const LOCAL_RE = /^https?:\/\/(?:localhost|127(?:\.\d+){3}|[::1])(?::\d+)?$/;

app.use(cors({
    credentials: true,
    origin: (origin, cb) => cb(null, !origin || LOCAL_RE.test(origin)),
    methods: ['GET', 'POST', 'HEAD', 'OPTIONS'],
    exposedHeaders: ['X-Server-Cert'],
}));

app.use(cookieParser());
app.use(express.json());
app.use(upload.none());//accept multipart fields

//CERT PINNING HEADER GET & HEAD
const serverCertPemBase64 = Buffer
    .from(fs.readFileSync('/tls/server.crt', 'utf8'))
    .toString('base64');

app.use((req, res, next) => {
    res.set('X-Server-Cert', serverCertPemBase64);
    next();
});
app.head('*', (_, res) => res.status(200).end());


// socket
const ssl = {
    key: fs.readFileSync('/tls/server.key'),
    cert: fs.readFileSync('/tls/server.crt'),
};

const server = https.createServer(ssl, app);


app.use('/api/user', require('./routes/user-route'));
app.use('/api/ca', require('./routes/ca-route'));
app.use('/api/video', require('./routes/video-route'));

app.post('/stream', require('./controllers/video-ctrl').uploadChunk);


app.get('/', (_, res) => res.send('HTTPS Backend Healthy!'));


server.listen(PORT, '0.0.0.0', () =>
    logger.info(`Secure server running  ➜  https://0.0.0.0:${PORT}`),
);
