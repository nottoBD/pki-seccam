const fs = require('fs');
const router = require('express').Router();
const Organization = require('../models/organization');
const SharedKeys = require('../models/shared-keys');
const validateTokenRegular = require('../middleware/token-user');


router.head('/list', validateTokenRegular, (req, res) => res.status(200).end());
router.head('/share', validateTokenRegular, (req, res) => res.status(200).end());

/* LIST org not yet shared with */
router.get('/list', validateTokenRegular, async (req, res) => {
    try {
        const orgs = await Organization.find({}, {name: 1, country: 1, certPath: 1});

        const shared = await SharedKeys.find(
            {regular_username: req.user.username},
            {organization: 1}
        );
        const sharedSet = new Set(shared.map(s => String(s.organization)));

        const payload = orgs
            .filter(o => !sharedSet.has(String(o._id)))
            .map(o => ({
                _id: o._id,
                name: o.name,
                country: o.country,
                certificate: fs.readFileSync(o.certPath, 'utf8'),
            }));

        res.json(payload);
    } catch (err) {
        console.error(err);
        res.status(500).json({error: 'internal'});
    }
});


/* SHARE videos with org */
router.post('/share', validateTokenRegular, async (req, res) => {
    const {organization, encrypted_symmetric_key} = req.body;
    if (!organization || !encrypted_symmetric_key) {
        return res.status(400).json({message: 'Missing organisation or key'});
    }

    try {
        await SharedKeys.create({
            organization,
            encrypted_symmetric_key,
            regular_username: req.user.username,
        });
        res.status(200).json({message: 'Videos successfully shared with organisation'});
    } catch (err) {
        if (err.code === 11000) { // duplicates
            return res.status(409).json({message: 'Already shared with that organisation'});
        }
        console.error(err);
        res.status(500).json({error: 'internal'});
    }
});

module.exports = router;
