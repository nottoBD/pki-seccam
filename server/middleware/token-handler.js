require('dotenv').config();
const jwt = require('jsonwebtoken');
const logger = require('../logging/logger');


module.exports = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization || req.headers.Authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            logger.info('401: User not authorized – token missing');
            return res.status(401).json({message: 'Token missing'});
        }

        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                logger.info('401: User not authorized – bad token');
                return res.status(401).json({message: 'Invalid or expired token'});
            }

            if (!decoded?.user) {
                logger.info('401: User not authorized – malformed payload');
                return res.status(401).json({message: 'Malformed token payload'});
            }

            req.user = decoded.user;
            return next();
        });

    } catch (err) {
        logger.error('500: Token validation failed', err);
        return res.status(500).json({message: 'Server error validating token'});
    }
};
