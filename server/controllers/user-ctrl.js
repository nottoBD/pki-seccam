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
const {getSerialNumber} = require('../utils/x509');
const {sendVerificationMail} = require('../utils/mailer');


const getUserSymmetric = async (req, res) => {
    try {
        const {username} = req.user;
        const account =
            (await User.findOne({username})) ||
            (await TrustedUser.findOne({username}));

        if (!account) return res.sendStatus(404);

        return res.json({
            encryptedSymmetricKey: account.encrypted_symmetric_key,
            username
        });
    } catch (err) {
        logger.error(err);
        res.status(500).json({message: 'Server error'});
    }
};

/* CURRENT */
const currentUser = async (req, res) => {
    let user = await User.findOne({username: req.user.username});
    let isTrustedUser = false;

    if (!user) {
        user = await TrustedUser.findOne({username: req.user.username});
        isTrustedUser = !!user;
    }

    if (!user) return res.sendStatus(404);

    res.json({
        username: user.username,
        email: user.email,
        encrypted_symmetric_key: user.encrypted_symmetric_key,
        encrypted_hmac_key: user.encrypted_hmac_key,
        email_verified: user.email_verified,
        isTrustedUser, // <-- add this line
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
            trustedUserCsr,
            encrypted_symmetric_key, encrypted_hmac_key,
            hmac_email, public_key
        } = body;

        // TRUSTED USER branch
        if (body.isTrustedUser) {
            const needed = [
                'username', 'hmac_username',
                'email', 'hmac_email',
                'fullname', 'hmac_fullname',
                'organization', 'country',
                'trustedUserCsr',
                'encrypted_symmetric_key', 'encrypted_hmac_key',
                'email_raw', 'public_key', 'orgCsr'
            ];
            for (const k of needed) if (!body[k])
                return res.status(400).json({message: `Missing field ${k}`});

            if (await TrustedUser.findOne({username: body.username}))
                return res.status(400).json({message: 'Username already exists'});

            const orgName = body.organization.trim();
            const orgCountry = body.country.trim();

            // ORGANIZATION CSR
            const orgCertPath = `/certs/org_${orgName}_${orgCountry}.crt.pem`;
            fs.mkdirSync('/certs', {recursive: true});
            let orgCertPem = null, serial = null;

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
                    serialNumber: serial || undefined,
                    issuedAt: serial ? new Date() : undefined,
                },
                {new: true, upsert: true, runValidators: true}
            );

            // TOTP + QR
            const secret = speakeasy.generateSecret({name: `Seccam (${body.username})`, length: 20});
            const qrcode_image = await qrcode.toDataURL(secret.otpauth_url);

            // sign user csr
            const {data: certResp} = await axios.post("http://cert-signer:3001/sign", {csr: trustedUserCsr});
            const userCertPem = certResp.certificate;
            const userCertPath = `/certs/${body.username}.crt.pem`;
            fs.writeFileSync(userCertPath, userCertPem, 'utf8');

            const encryptedSecret = crypto.publicEncrypt(
                body.public_key,
                Buffer.from(secret.base32)
            ).toString('base64');
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
            });

            await sendVerificationMail(body.email_raw, body.username, rawToken);
            await Videos.updateOne({username: body.username}, {username: body.username, videos: []}, {upsert: true});

            return res.status(200).json({
                username: body.username,
                email: body.email_raw,
                qrcode_image,
                encrypted_secret: encryptedSecret,
                userCertificate: userCertPem,
                organizationCertificate: org.certPath ? fs.readFileSync(org.certPath, 'utf8') : undefined,
                message: 'Registration successful, verify your e‑mail.',
            });
            /* end trusted branch */
        }

        if (!username || !email || !encrypted_symmetric_key || !encrypted_hmac_key || !email_raw || !hmac_email || !public_key)
            return res.status(400).json({message: 'Missing required fields'});

        if (await User.findOne({username}))
            return res.status(400).json({message: 'Username already exists'});

        // QR code normal users
        const secret = speakeasy.generateSecret({name: `Seccam (${username})`, length: 20});
        const qrcode_image = await qrcode.toDataURL(secret.otpauth_url);

        const encryptedSecret = crypto.publicEncrypt(
            public_key,
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

            encrypted_symmetric_key,
            encrypted_hmac_key,
            public_key,
        });

        await user.save();

        await sendVerificationMail(email_raw, username, rawToken);

        await Videos.updateOne({username}, {username, videos: []}, {upsert: true});

        return res.status(200).json({
            username,
            email: email_raw,
            qrcode_image,
            encrypted_secret: encryptedSecret,
            message: "Registration successful, verify your email."
        });
    } catch (err) {
        logger.error("Registration failed", err);
        return res.status(500).json({message: "Internal server error"});
    }
};

/* LOGIN */
const loginUser = async (req, res) => {
    const {username, code} = req.body;
    let user = await User.findOne({username}) || await TrustedUser.findOne({username});
    const trusted = user instanceof TrustedUser;

    if (!user) return res.status(404).json({message: 'User not found'});
    if (!user.email_verified) return res.status(403).json({message: "Email not verified"});

    const plainSecret = decryptForServer(user.secret);
    const totpValid = speakeasy.totp.verify({
        secret: plainSecret,
        encoding: "base32",
        token: code,
    });

    if (!totpValid) return res.status(400).json({message: "Invalid OTP"});

    const token = jwt.sign({
        user: {username, trusted}
    }, process.env.ACCESS_TOKEN_SECRET, {expiresIn: "30m"});

    return res.json({accessToken: token});
};

/* Email Link Verification.. */
const verifyUserEmail = async (req, res) => {
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


module.exports = {registerUser, loginUser, currentUser, verifyUserEmail, getUserSymmetric};
