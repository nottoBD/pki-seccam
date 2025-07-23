const jwt = require("jsonwebtoken");
const logger = require("../logging/logger");


const tokenUser = async (req, res, next) => {
    try {
        let token;
        let authHeader = req.headers.Authorization || req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer")) {
            logger.info("401: User not authorized or token missing")
            return res.status(401).send({message: "User not authorized or token missing"});
        }

        token = authHeader.split(" ")[1];

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                logger.info("401: User not authorized")
                return res.status(401).send({message: "User not authorized!"});
            }

            if (!decoded || !decoded.user) {
                logger.info("401: Invalid token payload")
                return res.status(401).send({message: "Invalid token payload"});
            }

            if (decoded.user && decoded.user.isTrustedUser) {
                logger.info("401: Unauthorized action for trusted users")

                return res.status(401).json({message: "Unauthorized – Trusted User token not allowed here"});
            }
            req.user = decoded.user;
            next();
        });
    } catch (error) {
        logger.info("500: Server error")
        res.status(500).send({message: "Server error"});
    }
};

module.exports = tokenUser;
