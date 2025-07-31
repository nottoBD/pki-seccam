require('dotenv').config();
const jwt = require('jsonwebtoken');
const { decryptToken } = require('../utils/cookie-util');
const logger = require('../logging/logger');

module.exports = async (req, res, next) => {
    try {
        const encToken = req.cookies.authToken;
        if (!encToken) {
            logger.info('401: User not authorized – cookie missing');
            return res.status(401).json({message: 'Authentication required' });
        }

        let token;
        try {
            token = decryptToken(encToken);
        } catch (decErr) {
            logger.info('401: Invalid encrypted cookie');
            return res.status(401).json({ message: 'Invalid authentication' });
        }

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, {clockTolerance: 800}, (err, decoded) => {
            if (err) {
                logger.info('401: User not authorized – bad token');
                return res.status(401).json({message: 'Invalid or expired authentication'});
            }

            if (!decoded?.user) {
                logger.info('401: User not authorized – malformed payload');
                return res.status(401).json({message: 'Malformed authentication payload'});
            }

            req.user = decoded.user;
            return next();
        });
    } catch (err) {
        logger.error('500: Authentication validation failed', err);
        return res.status(500).json({message: 'Server error validating authentication'});
    }
};
