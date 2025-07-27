const axios = require('axios');
const fs = require('fs');
const path = require('path');
const logger = require("../logging/logger")
const router = require('express').Router()
const jwt = require('jsonwebtoken')
const {
    registerUser,
    currentUser,
    login,
    verifyEmail,
    getSymmetric,
} = require("../controllers/user-ctrl");
const User = require('../models/user')
const validateToken = require("../middleware/token-handler")


router.head('/register', (req, res) => res.status(200).end());
router.head('/login', (req, res) => res.status(200).end());
router.head('/verify', (req, res) => res.status(200).end());
router.head('/current', validateToken, (req, res) => res.status(200).end());
router.head('/logout', validateToken, (req, res) => res.status(200).end());
router.head('/trusted/csr', (req, res) => res.status(200).end());
router.head('/getSymmetric', validateToken, (req, res) => res.status(200).end());

router.post('/register', registerUser)
router.post('/login', login);
router.get('/verify', verifyEmail);
router.get('/current', validateToken, currentUser)
router.get('/getSymmetric', validateToken, getSymmetric);

router.post('/logout', validateToken, (req, res) => {
    try {
        res.json({message: 'success'});
    } catch (error) {
        logger.info("500: Server Error")
        res.status(500).send({message: "Server error"})
    }
})


/* trusteduser CSR endpoint */
router.post('/trusted/csr', async (req, res) => {
    try {
        const {username, csrPem} = req.body;

        const signResp = await axios.post('http://cert-signer:3001/sign', {
            csr: csrPem,
        });
        const {certificate} = signResp.data;

        const baseDir = '/certs';
        const crtPath = path.join(baseDir, `${username}.crt.pem`);

        await fs.promises.mkdir(baseDir, {recursive: true});
        fs.writeFileSync(crtPath, certificate, 'utf8');

        res.json({certificate});
    } catch (err) {
        console.error('CSR signing failed:', err.message);
        res.status(500).json({message: 'Certificate signing failed'});
    }
});

module.exports = router;
