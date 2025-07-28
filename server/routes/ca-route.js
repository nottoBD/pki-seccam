const fs = require('fs');
const router = require('express').Router();
const caCtrl = require('../controllers/ca-ctrl');

const STEP_ROOT = process.env.NODE_EXTRA_CA_CERTS || '/ca/certs/root_ca.crt';

/**
 * @swagger
 * /api/ca/root:
 *   get:
 *     summary: Retrieve the root CA certificate
 *     description: Returns the root CA certificate in PEM format.
 *     security: []  # No auth required
 *     responses:
 *       200:
 *         description: Root CA certificate
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       500:
 *         description: Failed to retrieve root CA
 */
router.get('/root', (req, res) => {
    try {
        const root = fs.readFileSync(STEP_ROOT, 'utf8');
        res.contentType('text/plain');
        res.send(root);
    } catch (err) {
        console.error('Failed to read root CA:', err);
        res.status(500).json({ message: 'Failed to retrieve root CA certificate' });
    }
});

/**
 * @swagger
 * /api/ca/verify:
 *   post:
 *     summary: Verify a certificate
 *     description: Verifies the provided PEM certificate against the CA chain.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - cert
 *             properties:
 *               cert:
 *                 type: string
 *                 description: PEM-encoded certificate
 *     responses:
 *       200:
 *         description: Verification result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 valid:
 *                   type: boolean
 *                 cn:
 *                   type: string
 *       400:
 *         description: Invalid certificate provided
 *       500:
 *         description: Verification failed
 */
router.post('/verify', async (req, res) => {
    try {
        const result = await caCtrl.verifyCertificate(req.body);
        res.json(result);
    } catch (err) {
        res.status(500).json({ message: 'Verification failed', detail: err.message });
    }
});

/**
 * @swagger
 * /api/ca/sign:
 *   post:
 *     summary: Sign a Certificate Signing Request (CSR)
 *     description: Signs the provided CSR and returns the signed certificate.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - csr
 *             properties:
 *               csr:
 *                 type: string
 *                 description: PEM-encoded CSR
 *               notAfter:
 *                 type: string
 *                 description: Optional validity end date
 *               notBefore:
 *                 type: string
 *                 description: Optional validity start date
 *     responses:
 *       200:
 *         description: Signed certificate
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 certificate:
 *                   type: string
 *       400:
 *         description: Invalid CSR provided
 *       500:
 *         description: Signing failed
 */
router.post('/sign', async (req, res) => {
    try {
        const result = await caCtrl.signCertificate(req.body);
        res.json(result);
    } catch (err) {
        res.status(500).json({ message: 'Signing failed', detail: err.message });
    }
});

module.exports = router;
