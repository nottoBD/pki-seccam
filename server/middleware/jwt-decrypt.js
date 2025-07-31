const jwt = require('jsonwebtoken');
const { decryptToken } = require('../utils/cookie-util');
const logger = require('../logging/logger');

const jwtDecrypt = (encToken) => {
    try {
        const token = decryptToken(encToken);
        const secretKey = process.env.ACCESS_TOKEN_SECRET;
        const decoded = jwt.verify(token, secretKey);
        return decoded;
    } catch (error) {
        console.error("Failed to decrypt/verify JWT:", error.message);
        logger.error("Failed to decrypt/verify JWT:", error.message);
        return null;
    }
};

module.exports = jwtDecrypt;
