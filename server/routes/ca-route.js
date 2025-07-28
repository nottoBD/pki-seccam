const axios = require('axios');
const fs = require('fs');
const router = require('express').Router();

const STEP_ROOT = process.env.NODE_EXTRA_CA_CERTS || '/ca/certs/root_ca.crt';

router.get('/root', (req, res) => {
    try {
        const root = fs.readFileSync(STEP_ROOT, 'utf8');
        res.contentType('text/plain');
        res.send(root);
    } catch (err) {
        console.error('Failed to read root CA:', err);
        res.status(500).json({message: 'Failed to retrieve root CA certificate'});
    }
});

router.post('/verify', async (req, res) => {
    try {
        const { cert } = req.body;
        const verifyResp = await axios.post('http://cert-signer:3001/verify', { cert });
        res.json(verifyResp.data);
    } catch (err) {
        res.status(500).json({ message: 'Verification failed', detail: err.response?.data?.error || err.message });
    }
});

module.exports = router;
