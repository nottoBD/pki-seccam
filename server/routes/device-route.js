const router = require('express').Router();
const validateToken = require('../middleware/token-handler');
const requirePrimary = require('../middleware/primary-device');
const {
    requestDevice,
    approveDevice, denyDevice, listDevices, uploadKeys
} = require('../controllers/device-ctrl');


// pinning/cert
router.head('/request', (req, res) => res.status(200).end());
router.head('/list', validateToken, requirePrimary, (req, res) => res.status(200).end());
router.head('/:id/approve', validateToken, requirePrimary, (req, res) => res.status(200).end());
router.head('/:id/deny', validateToken, requirePrimary, (req, res) => res.status(200).end());
router.head('/:id/keys', validateToken, requirePrimary, (req, res) => res.status(200).end());

// common routes
router.post('/request', requestDevice);
router.get('/list', validateToken, requirePrimary, listDevices);
router.post('/:id/approve', validateToken, requirePrimary, approveDevice);
router.post('/:id/deny', validateToken, requirePrimary, denyDevice);
router.post('/:id/keys', validateToken, requirePrimary, uploadKeys);

module.exports = router;
