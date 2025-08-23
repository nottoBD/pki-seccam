// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

/*
   main express backend setup (HTTPS on port 8888)
   loads the TLS cert and key from /tls (mounted via Docker) and creates an https server wrapping the Express app
   connects to MongoDB, and mounts Swagger UI at /api-docs for interactive API docs
   global middlewares: CORS locked down to localhost, JSON parser, cookie parser, multer for file uploads, plus sets X-Server-Cert header on responses (for client to pin our server cert)
   also responds to any HEAD request with 200 (simple health check)
   mounts all API routes (user, ca, video, keywrap under /api/*) and finally listens on 0.0.0.0:8888
*/

require('dotenv').config();

const fs = require('fs');
const https = require('https');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const logger = require('./logging/logger');

const app = express();
const PORT = 8888;
const upload = multer({storage: multer.memoryStorage()});


const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'PKI Seccam API',
            version: '1.0.0',
            description: 'Secure backend API for PKI-enabled camera system with certificate management, user authentication, and video streaming.',
            contact: {
                name: 'Your Project Team',
            },
            servers: [
                {
                    url: `https://localhost:${PORT}`,
                    description: 'Local development server',
                },
            ],
        },
        components: {
            securitySchemes: {
                cookieAuth: {
                    type: 'apiKey',
                    in: 'cookie',
                    name: 'authToken',
                },
            },
        },
        security: [{ cookieAuth: [] }],
    },
    apis: ['./routes/*.js', './controllers/*.js', './server.js'],
};

const swaggerSpecs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));


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


const ssl = {
    key: fs.readFileSync('/tls/server.key'),
    cert: fs.readFileSync('/tls/server.crt'),
};

const server = https.createServer(ssl, app);


app.use('/api/user', require('./routes/user-route'));
app.use('/api/ca', require('./routes/ca-route'));
app.use('/api/video', require('./routes/video-route'));
app.use('/api/keywrap',  require('./routes/keywrap-route'));

/**
 * @swagger
 * /:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns a simple message indicating the server is healthy.
 *     security: []  # No auth required
 *     responses:
 *       200:
 *         description: Server is healthy
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: HTTPS Backend Healthy!
 */
app.get('/', (_, res) => res.send('HTTPS Backend Healthy!'));


server.listen(PORT, '0.0.0.0', () =>
    logger.info(`Secure server running  ➜  https://0.0.0.0:${PORT}`),
);
