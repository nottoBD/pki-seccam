const jwt = require('jsonwebtoken');
const { decryptToken } = require('../utils/cookie-util');
const logger = require('../logging/logger');

const tokenUser = async (req, res, next) => {
    try {
        const encToken = req.cookies.authToken;
        if (!encToken) {
            logger.info('401: User not authorized or cookie missing');
            return res.status(401).json({ message: 'Authentication required' });
        }

        let token;
        try {
            token = decryptToken(encToken);
        } catch (decErr) {
            logger.info('401: Invalid encrypted cookie');
            return res.status(401).json({ message: 'Invalid authentication' });
        }

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                logger.info('401: User not authorized');
                return res.status(401).json({message: 'Invalid or expired authentication' });
            }

            if (!decoded || !decoded.user) {
                logger.info('401: Invalid token payload');
                return res.status(401).json({message: 'Invalid authentication payload'});
            }

            if (decoded.user.isTrustedUser) {
                logger.info('401: Unauthorized action for trusted users');
                return res.status(401).json({ message: 'Unauthorized – Trusted User authentication not allowed here' });
            }
            req.user = decoded.user;
            next();
        });
    } catch (error) {
        logger.error("500: Server error", error)
        res.status(500).send({message: "Server error"});
    }
};

module.exports = tokenUser;
