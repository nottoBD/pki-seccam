const crypto = require('crypto');

const COOKIE_ENCRYPT_KEY = Buffer.from(process.env.COOKIE_ENCRYPT_KEY, 'hex');

const encryptToken = (token) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', COOKIE_ENCRYPT_KEY, iv);
    let encrypted = cipher.update(token, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
};

const decryptToken = (encToken) => {
    const data = Buffer.from(encToken, 'base64');
    const iv = data.slice(0, 16);
    const authTag = data.slice(16, 32);
    const encrypted = data.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', COOKIE_ENCRYPT_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
};

module.exports = { encryptToken, decryptToken };
