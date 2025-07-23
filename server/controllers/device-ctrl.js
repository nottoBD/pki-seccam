import 'dotenv/config';
import axios from 'axios';
import fs from 'fs/promises';
import path from 'path';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import TrustedUser from '../models/trusteduser.js';
import logger from '../logging/logger.js';
import socket from '../socket.js';
import {getSerialNumber} from '../utils/x509.js';
import forge from 'node-forge';

const CERT_DIR = '/certs';
const io = socket.get();

const findAccount = async (username) =>
    (await User.findOne({username})) || (await TrustedUser.findOne({username}));


/* 1. POST /api/device/request */
const requestDevice = async (req, res) => {
    try {
        const {username, deviceId, deviceName, csrPem: bodyCsrPem, csr} = req.body;
        const csrPem = bodyCsrPem || csr;

        if (!username || !deviceId || !deviceName || !(bodyCsrPem || csr))
            return res.status(400).json({message: 'Missing required fields'});

        const account = await findAccount(username);
        if (!account) return res.status(404).json({message: 'User not found'});

        const existing = account.devices.find(d => d.deviceId === deviceId);

        if (existing) {
            // refresh metadata
            if (csrPem) existing.csrPem = csrPem;
            existing.name = deviceName;
            existing.lastSeen = new Date();
            existing.status = existing.status || 'pending';
            await account.save();
            return res.status(208).json({message: 'Device already registered (updated)'});
        }

        /* a) FIRST device = auto-sign + mark PRIMARY */
        if (account.devices.length === 0) {
            /* step-ca side-car */
            const {data} = await axios.post(
                'http://cert-signer:3001/sign',
                {csr: csrPem}
            );
            const {certificate} = data;

            console.log('signer keys:', Object.keys(data));
            console.log('PEM preview:', certificate.slice(0, 60));

            const certPath = path.join(
                CERT_DIR,
                `${username}_${deviceId}.crt.pem`
            );
            await fs.writeFile(certPath, certificate, 'utf8');

            const serial = getSerialNumber(certificate);
            console.log('⟹ extracted serial:', serial);

            /* push to db */
            account.devices.push({
                deviceId,
                name: deviceName,
                status: 'primary',
                certPath,
                serialNumber: serial,
                issuedAt: new Date(),
                encrypted_symmetric_key: account.devices[0].encrypted_symmetric_key,
                encrypted_hmac_key: account.devices[0].encrypted_hmac_key,
            });
            await account.save();

            return res.status(201).json({certificate});
        }
        account.devices = account.devices
            .filter(d => !(d.deviceId === deviceId && d.status === 'pending'));

        /* pending device */
        account.devices.push({
            deviceId,
            name: deviceName,
            status: 'pending',
            csrPem: csrPem ?? csr,
            issuedAt: new Date()
        });
        await account.save();
        logger.info('save-pending', {deviceId, hasCSR: !!(csrPem ?? csr)});
        io.to(`${username}-primary`).emit('device-pending', {deviceId, deviceName});
        return res.status(202).json({message: 'Device pending approval'});
    } catch (err) {
        logger.error('Device request failed', err);
        res.status(500).json({message: 'Server error'});
    }
};
/* 2. POST /api/device/:id/approve */
const approveDevice = async (req, res) => {
    const {username} = req.user;
    const {id: deviceId} = req.params;

    const query = {
        username: username,
        'devices.deviceId': deviceId,
        'devices.status': 'pending',
        'devices.csrPem': {$exists: true}
    };
    const account = (await User.findOne(query)) || (await TrustedUser.findOne(query));
    if (!account) return res.status(404).json({message: "No pending device with CSR"});

    const device = account.devices.find(d => d.deviceId === deviceId && d.status === 'pending' && d.csrPem);

    /* sign csr */
    const csrPem = device.csrPem || device.csr;
    if (!csrPem) {
        return res.status(400).json({message: 'CSR missing for device'});
    }

    let certificate;
    try {
        ({data: {certificate}} = await axios.post(
            'http://cert-signer:3001/sign',
            {csr: csrPem}
        ));
    } catch (err) {
        logger.error('CSR signing failed', err);
        return res
            .status(err.response?.status || 500)
            .json({message: err.response?.data?.message || 'CSR signing failed'});
    }

    /* extract SPKI PEM for client side */
    const certParsed = forge.pki.certificateFromPem(certificate);
    const spki = forge.pki.publicKeyToSubjectPublicKeyInfo(certParsed.publicKey);
    const spkiPem = forge.pki.publicKeyInfoToPem(spki);


    const certPath = path.join(CERT_DIR, `${username}_${deviceId}.crt.pem`);
    await fs.writeFile(certPath, certificate, 'utf8');

    Object.assign(device, {
        status: 'active',
        csrPem: undefined,
        certPath,
        serialNumber: getSerialNumber(certificate),
        issuedAt: new Date()
    });

    await account.save();

    /* fresh JWT for new device */
    const token = jwt.sign(
        {user: {username, id: account._id, deviceId, isTrustedUser: account instanceof TrustedUser}},
        process.env.ACCESS_TOKEN_SECRET,
        {expiresIn: '30m'}
    );

    io.to(deviceId).emit('device-approved', {certificate: spkiPem, token});
    io.to(`${username}-primary`).emit('device-approved', {deviceId, certificate: spkiPem});

    return res.status(200).json({certificate: spkiPem});
};

/* 3. POST /api/device/:id/deny */
const denyDevice = async (req, res) => {
    const {username} = req.user;
    const {id: deviceId} = req.params;

    const account = await findAccount(username);
    if (!account) return res.sendStatus(404);

    //pending device by ID
    const idx = account.devices.findIndex(d => d.deviceId === deviceId && d.status === 'pending');
    if (idx === -1) return res.sendStatus(404);

    // rm pending device from array
    account.devices.splice(idx, 1);
    await account.save();

    io.to(deviceId).emit('device-denied');
    return res.sendStatus(204);
};

/* 4. GET /api/device/list */
const listDevices = async (req, res) => {
    const account = await findAccount(req.user.username);
    if (!account) return res.sendStatus(404);

    res.json(account.devices.map((d) => ({
        deviceId: d.deviceId,
        name: d.name,
        status: d.status,
        issuedAt: d.issuedAt,
        lastSeen: d.lastSeen,
        isPrimary: d.status === 'primary',
    })));
};

/* 5. POST /device/:id/keys by PRIMARY after approval */
const uploadKeys = async (req, res) => {
    const {username} = req.user;       // set by auth middleware
    const {id: deviceId} = req.params; // :id URL param

    const FIELDS = [
        'encrypted_symmetric_key',
        'signature_symmetric_key',
        'encrypted_hmac_key',
        'signature_hmac_key',
    ];

    for (const f of FIELDS) {
        if (typeof req.body[f] !== 'string' || req.body[f].length === 0) {
            return res.status(400).json({error: `Missing or invalid field: ${f}`});
        }
    }

    const set = Object.fromEntries(
        FIELDS.map(f => [`devices.$[d].${f}`, req.body[f]])
    );

    const updateDeviceKeys = async (Model) =>
        Model.updateOne(
            {username, 'devices.deviceId': deviceId},
            {$set: set},
            {arrayFilters: [{'d.deviceId': deviceId}]}
        );

    const {modifiedCount: m1 = 0} = await updateDeviceKeys(User);
    const {modifiedCount: m2 = 0} = await updateDeviceKeys(TrustedUser);

    if (m1 + m2 > 0) return res.sendStatus(204);   // updated
    return res.sendStatus(404);                    // no such device
};

export {requestDevice, approveDevice, denyDevice, listDevices, uploadKeys};
