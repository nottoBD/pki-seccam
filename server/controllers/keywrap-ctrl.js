const decryptJWT = require('../middleware/jwt-decrypt');
const Wrapping = require('../models/keywrap');
const User = require('../models/user');
const TrustedUser = require('../models/usertrusted');
const logger = require('../logging/logger');


function getUsername(req) {
    const auth = req.headers.authorization || req.headers.Authorization || '';
    if (!auth.startsWith('Bearer ')) throw new Error('token missing');
    const token = auth.slice(7);
    const decoded = decryptJWT(token);
    if (!decoded?.user?.username) throw new Error('invalid token');
    return decoded.user.username;
}

// GET /api/keywrap  (untrusted user only)
exports.listKeyWraps = async (req, res) => {
    try {
        const username = getUsername(req);
        const normalUser = await User.findOne({ username });
        if (!normalUser) return res.status(403).json({ message: 'Only normal users can manage trusts.' });

        const wraps = await Wrapping.find({ normal_user_id: normalUser._id })
            .populate('trusted_user_id', 'username certificate');

        const shared = wraps.map(w => ({
            _id: w.trusted_user_id._id,
            username: w.trusted_user_id.username,
            certificate: w.trusted_user_id.certificate,
            isShared: true,
        }));

        const allTrustedUsers = await TrustedUser.find({}, '_id username certificate');
        const sharedSet = new Set(shared.map(x => String(x._id)));
        const available = allTrustedUsers
            .filter(tu => !sharedSet.has(String(tu._id)))
            .map(tu => ({ _id: tu._id, username: tu.username, certificate: tu.certificate, isShared: false }));

        res.json([...shared, ...available]);
    } catch (err) {
        logger.error('Error listing key wraps:', err);
        res.status(500).json({ message: 'Internal server error.' });
    }
};

// GET /api/keywrap/:owner_username/keys  (trusted fetch wrapped keys)
exports.getWrappedKeys = async (req, res) => {
    try {
        const trustedUsername = getUsername(req);
        const ownerUsername = req.params.owner_username;

        const owner = await User.findOne({ username: ownerUsername });
        const trustedUser = await TrustedUser.findOne({ username: trustedUsername });

        if (!owner || !trustedUser) {
            return res.status(404).json({ message: 'User(s) not found' });
        }

        const wrap = await Wrapping.findOne({
            normal_user_id: owner._id,
            trusted_user_id: trustedUser._id,
        });

        if (!wrap) return res.status(403).json({ message: 'Access not permitted' });

        res.json({
            wrapped_symmetric_key: wrap.wrapped_symmetric_key,
            wrapped_hmac_key: wrap.wrapped_hmac_key,
        });
    } catch (err) {
        logger.error('Error getting wrapped keys:', err);
        res.status(500).send('Internal Server Error');
    }
};

// POST /api/keywrap  (normal user shares keys with a trusted user)
exports.createKeyWrap = async (req, res) => {
    try {
        const username = getUsername(req);
        const normalUser = await User.findOne({ username });
        if (!normalUser) return res.status(403).json({ message: 'Only normal users can set trust.' });

        const { trusted_user_id, wrapped_symmetric_key, wrapped_hmac_key } = req.body;
        if (!trusted_user_id || !wrapped_symmetric_key || !wrapped_hmac_key) {
            return res.status(400).json({ message: 'Missing trusted_user_id or wrapped keys.' });
        }

        const trustedUser = await TrustedUser.findById(trusted_user_id);
        if (!trustedUser || !trustedUser.certificate) {
            return res.status(400).json({ message: 'Invalid trusted user or certificate missing.' });
        }

        await Wrapping.findOneAndUpdate(
            {
                normal_user_id: normalUser._id,
                trusted_user_id: trustedUser._id,
            },
            {
                $set: {
                    wrapped_symmetric_key,
                    wrapped_hmac_key,
                },
            },
            { upsert: true, new: true }
        );

        res.status(201).json({ message: 'Trust relationship successfully created.' });
    } catch (err) {
        logger.error('Error creating key wrap:', err);
        // Handle duplicate key errors nicely
        if (err?.code === 11000) {
            return res.status(200).json({ message: 'Trust already existed; keys updated.' });
        }
        res.status(500).json({ message: 'Internal server error.' });
    }
};

// DELETE /api/keywrap/:trustedUserId  (user rm trust)
exports.deleteKeyWrap = async (req, res) => {
    try {
        const username = getUsername(req);
        const normalUser = await User.findOne({ username });
        if (!normalUser) return res.status(403).json({ message: 'Only normal users can remove trust.' });

        const { trustedUserId } = req.params;
        await Wrapping.deleteOne({ normal_user_id: normalUser._id, trusted_user_id: trustedUserId });

        res.json({ message: 'Trust relationship successfully removed.' });
    } catch (err) {
        logger.error('Error deleting key wrap:', err);
        res.status(500).json({ message: 'Internal server error.' });
    }
};
