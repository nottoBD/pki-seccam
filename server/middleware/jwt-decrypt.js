const jwt = require("jsonwebtoken");
const logger = require("../logging/logger");


const jwtDecrypt = (token) => {
    try {

        const secretKey = process.env.ACCESS_TOKEN_SECRET;
        const decoded = jwt.verify(token, secretKey);
        return decoded;

    } catch (error) {

        console.error("Failed to decrypt JWT:", error.message);
        logger.error("Failed to decrypt JWT:", error.message);
        return null;

    }
};

module.exports = jwtDecrypt;
