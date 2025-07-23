require("dotenv").config();
const crypto = require("crypto");
const fs = require("fs");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const qrcode = require("qrcode");
const speakeasy = require("speakeasy");
const User = require("../models/user");
const TrustedUser = require("../models/trusteduser");
const Videos = require("../models/videos");
const logger = require("../logging/logger");
const Organization = require('../models/organization');
const io = require("../socket").get();
const {getSerialNumber} = require('../utils/x509');
const {sendVerificationMail} = require('../utils/mailer');


/* CURRENT */
const currentUser = async (req, res) => {
    const user = await User.findOne({username: req.user.username}) || await TrustedUser.findOne({username: req.user.username});
    if (!user) return res.sendStatus(404);

    const device = user.devices.find(d => d.deviceId === req.user.deviceId);
    if (!device) return res.status(403).json({message: "Device not authorized"});

    res.json({
        username: user.username,
        email: user.email,
        encrypted_symmetric_key: device.encrypted_symmetric_key,
        encrypted_hmac_key: device.encrypted_hmac_key,
        email_verified: user.email_verified,
    });
};

function encryptForServer(plain) {
    const key = Buffer.from(process.env.TOTP_KEY || 'default', 'hex');
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return iv.toString('base64') + ':' + enc.toString('base64') + ':' +
        c.getAuthTag().toString('base64');
}

function decryptForServer(blob) {
    const [ivB64, encB64, tagB64] = blob.split(':');
    const key = Buffer.from(process.env.TOTP_KEY, 'hex');   // 32‑byte hex!
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
    dec.setAuthTag(tag);
    const plain = Buffer.concat([dec.update(Buffer.from(encB64, 'base64')), dec.final()]);
    return plain.toString('utf8');
}

/* REGISTER */
const registerUser = async (req, res) => {
    try {
        const body = req.body;
        const {
            username, email, email_raw,
            deviceId, deviceName, deviceCsr,
            encrypted_symmetric_key, encrypted_hmac_key,
            hmac_email
        } = body;

        if (body.isTrustedUser) {
            const needed = ['username', 'hmac_username',
                'email', 'hmac_email',
                'fullname', 'hmac_fullname',
                'organization', 'country',
                'deviceId', 'deviceCsr', 'deviceName',
                'encrypted_symmetric_key', 'encrypted_hmac_key',
                'email_raw',
                'public_key',
                'orgCsr'
            ];
            for (const k of needed) if (!body[k])
                return res.status(400).json({message: `Missing field ${k}`});

            if (await TrustedUser.findOne({username: body.username}))
                return res.status(400).json({message: 'Username already exists'});

            const orgName = body.organization.trim();
            const orgCountry = body.country.trim();

            const orgCertPath = `/certs/org_${orgName}_${orgCountry}.crt.pem`;
            fs.mkdirSync('/certs', {recursive: true});

            let orgCertPem = null;
            let serial = null;


            if (body.orgCsr) {
                const {data: orgCertResp} = await axios.post(
                    'http://cert-signer:3001/sign',
                    {csr: body.orgCsr}
                );
                orgCertPem = orgCertResp.certificate;
                fs.writeFileSync(orgCertPath, orgCertPem, 'utf8');
                serial = getSerialNumber(orgCertPem);
            }

            const org = await Organization.findOneAndUpdate(
                {name: orgName, country: orgCountry},
                {
                    name: orgName,
                    country: orgCountry,
                    certPath: orgCertPath,
                    serialNumber: serial || undefined, // only for fresh cert
                    issuedAt: serial ? new Date() : undefined,
                },
                {new: true, upsert: true, runValidators: true}
            );


            /* TOTP + QR */
            const secret = speakeasy.generateSecret({name: `Seccam (${body.username})`, length: 20});
            const qrcode_image = await qrcode.toDataURL(secret.otpauth_url);

            /* sign device-lvl csr */
            const {data: certResp} = await axios.post(
                "http://cert-signer:3001/sign", {csr: body.deviceCsr});
            const deviceCertPem = certResp.certificate;
            const deviceCertPath = `/certs/${body.username}_${body.deviceId}.crt.pem`;
            fs.writeFileSync(deviceCertPath, deviceCertPem, 'utf8');


            const encryptedSecret = crypto.publicEncrypt(
                body.public_key, Buffer.from(secret.base32)).toString('base64');
            const rawToken = crypto.randomBytes(32).toString('hex');

            /* saving trusted user */
            const trusted = await TrustedUser.create({
                username: body.username,
                hmac_username: body.hmac_username,

                email: body.email,
                hmac_email: body.hmac_email,
                fullname: body.fullname,
                hmac_fullname: body.hmac_fullname,

                organization: org._id,

                encrypted_symmetric_key: body.encrypted_symmetric_key,
                encrypted_hmac_key: body.encrypted_hmac_key,

                public_key: body.public_key,
                secret: encryptForServer(secret.base32),
                verification_token_hash: crypto.createHash('sha256').update(rawToken).digest('hex'),
                verification_token_expires: Date.now() + 24 * 60 * 60 * 1000,

                devices: [{
                    deviceId: body.deviceId,
                    name: body.deviceName,
                    status: 'primary',
                    certPath: deviceCertPath,
                    serialNumber: getSerialNumber(deviceCertPem),
                    issuedAt: new Date(),
                    encrypted_symmetric_key: body.encrypted_symmetric_key,
                    encrypted_hmac_key: body.encrypted_hmac_key,
                    encrypted_secret: encryptedSecret,
                }],
            });

            await sendVerificationMail(body.email_raw, body.username, rawToken);
            await Videos.updateOne({username: body.username}, {username: body.username, videos: []}, {upsert: true});

            return res.status(200).json({
                username: body.username,
                email: body.email_raw,
                qrcode_image,
                encrypted_secret: encryptedSecret,
                deviceCertificate: deviceCertPem,
                organizationCertificate: org.certPath ? fs.readFileSync(org.certPath, 'utf8') : undefined,
                message: 'Registration successful, verify your e‑mail.',
            });
            /* end trusted branch */
        }


        if (!username || !email || !deviceId || !deviceCsr || !encrypted_symmetric_key || !encrypted_hmac_key || !email_raw || !hmac_email)
            return res.status(400).json({message: 'Missing required fields'});

        const existingUser = await User.findOne({username});
        if (existingUser)
            return res.status(400).json({message: 'Username already exists'});

        // Gen TOTP/QR
        const secret = speakeasy.generateSecret({name: `Seccam (${username})`, length: 20});
        const qrcode_image = await qrcode.toDataURL(secret.otpauth_url);

        // Sign device CSR
        const {data: certResp} = await axios.post("http://cert-signer:3001/sign", {csr: deviceCsr});
        const deviceCertPem = certResp.certificate;

        const certPath = `/certs/${username}_${deviceId}.crt.pem`;
        fs.mkdirSync('/certs', {recursive: true});
        fs.writeFileSync(certPath, deviceCertPem, "utf8");

        const encryptedSecret = crypto.publicEncrypt(
            body.public_key,
            Buffer.from(secret.base32)
        ).toString('base64');


         // Gen verif token
        const rawToken = crypto.randomBytes(32).toString("hex");

        const user = new User({
            username,
            email, //encrypted email
            hmac_email,
            email_verified: false,
            secret: encryptForServer(secret.base32),
            verification_token_hash: crypto.createHash("sha256").update(rawToken).digest("hex"),
            verification_token_expires: Date.now() + 24 * 60 * 60 * 1000,
            devices: [{
                deviceId,
                name: deviceName,
                status: "primary",
                certPath,
                serialNumber: getSerialNumber(deviceCertPem),
                issuedAt: new Date(),
                encrypted_symmetric_key,
                encrypted_hmac_key,
                encrypted_secret: encryptedSecret
            }],
        });

        await user.save();

        await sendVerificationMail(email_raw, username, rawToken);

        await Videos.updateOne({username}, {username, videos: []}, {upsert: true});

        return res.status(200).json({
            username,
            email: email_raw,
            qrcode_image,
            encrypted_secret: encryptedSecret,
            deviceCertificate: deviceCertPem,
            message: "Registration successful, verify your email."
        });
    } catch (err) {
        logger.error("Registration failed", err);
        return res.status(500).json({message: "Internal server error"});
    }
};

/* LOGIN */
const login = async (req, res) => {
    const {username, code, deviceId} = req.body;
    let user = await User.findOne({username});
    let trusted = false;
    if (!user) {
        user = await TrustedUser.findOne({username});
        trusted = !!user;
    }
    if (!user) return res.status(404).json({message: 'User not found'});
    if (!user.email_verified) return res.status(403).json({message: "Email not verified"});

    const plainSecret = decryptForServer(user.secret);
    const totpValid = speakeasy.totp.verify({secret: plainSecret, encoding: "base32", token: code});
    if (!totpValid) return res.status(400).json({message: "Invalid OTP"});

    const device = user.devices.find(d => d.deviceId === deviceId && ["primary", "active"].includes(d.status));
    if (!device) return res.status(401).json({message: "Device not recognized or pending"});

    const token = jwt.sign({
        user: {username, deviceId, trusted}
    }, process.env.ACCESS_TOKEN_SECRET, {expiresIn: "30m"});

    return res.json({token, accessToken: token});
};


/* Email Link Verification.. */
const verifyEmail = async (req, res) => {
    const {username, token} = req.query;
    if (!username || !token) return res.status(400).json({message: "Bad link"});

    const account =
        (await User.findOne({username})) ||
        (await TrustedUser.findOne({username}));
    if (!account) return res.status(404).json({message: "User not found"});

    if (account.email_verified)
        return res.json({message: "E-mail already verified"});

    const hash = crypto.createHash("sha256").update(token).digest("hex");
    if (hash !== account.verification_token_hash)
        return res.status(400).json({message: "Invalid / used link"});
    if (account.verification_token_expires < Date.now())
        return res.status(400).json({message: "Link expired – re-register."});

    account.email_verified = true;
    account.verification_token_hash = undefined;
    account.verification_token_expires = undefined;
    await account.save();

    return res.json({message: "E-mail verified – you may log in now."});
};


module.exports = {registerUser, login, currentUser, verifyEmail};
