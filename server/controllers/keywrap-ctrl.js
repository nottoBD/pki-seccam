// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.


// Controls the “trust” relationships and key sharing between normal users and trusted users. This handles listing which trusted users a normal user can share with, actually creating/updating a trust (wrapping keys for sharing), retrieving wrapped keys for a trusted user, and removing trust. The overall idea: a normal user can share their encryption keys (encrypted with a trusted user’s public key) so that the trusted user can decrypt and view their videos. All operations ensure the requesting user has the right role – normal vs trusted – to maintain the security model (normal users initiate sharing, trusted users retrieve keys, and no one else can interfere).

const decryptJWT = require('../middleware/jwt-decrypt');
const Wrapping = require('../models/keywrap');
const User = require('../models/user');
const TrustedUser = require('../models/usertrusted');
const logger = require('../logging/logger');
const { decryptToken } = require('../utils/cookie-util');

function getUsername(req) {
    const encToken = req.cookies.authToken;
    if (!encToken) throw new Error('cookie missing');
    const decoded = decryptJWT(encToken);
    if (!decoded?.user?.username) throw new Error('invalid authentication');
    return decoded.user.username;
}

// GET /api/keywrap  (untrusted user only)
// When a normal user opens their “share” management, this provides the data. We confirm the requester is a normal user (not a trusted user) – if they aren’t found in the User collection, we reject the request. Then we fetch all Wrapping records where this user is the normal_user_id, which gives us the list of trusted users they’ve already shared keys with. We populate each with the trusted user’s username and certificate. Those go into a shared list (with isShared: true). We also fetch all existing trusted users in the system and mark those not already shared with as available (isShared: false). The result sent back is a combined list of trusted user info, letting the frontend show which trusted users the normal user can share with and which they have shared with. This design prevents duplicate sharing and lets the user manage trust relationships easily.

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
// Allows a trusted user to fetch the encrypted keys for a specific normal user’s videos. We verify the requester by looking them up in the TrustedUser collection (and get the owner by username from the User collection). If either doesn’t exist, we return 404 (either the owner username is wrong or the requester isn’t actually a trusted user in our DB). Assuming both exist, we look for a Wrapping entry that matches this normal user and trusted user. If none is found, then even if the requester is a trusted user, they don’t have access to this particular owner’s videos – we return 403 Forbidden. If the wrap exists, we respond with the two wrapped keys (wrapped_symmetric_key and wrapped_hmac_key). These are Base64 strings of the normal user’s keys encrypted with the trusted user’s RSA public key. The expectation is the client (trusted user’s browser) will use their RSA private key to decrypt these, obtaining the actual symmetric and HMAC keys needed to decrypt the normal user’s video data. The server never sees the plaintext keys at any point.

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
// Handles a normal user initiating or updating a trust relationship. We ensure the caller is a normal user (look up their username in the User collection – if not found, they might be a trusted user trying to use this endpoint, so we reject with 403). We then expect the request body to contain a trusted_user_id (the target trusted user’s DB ID) and that user’s symmetric and HMAC keys wrapped in RSA (Base64 strings). If any of those are missing, we return 400 (bad request). Next, we verify the trusted user exists and has a certificate on file (a basic sanity check that the target is a valid trusted user who completed their registration). Finally, we store the wrapped keys: using an upsert, we either create a new Wrapping record or update the existing one for this normal-trusted user pair. On success, the trusted user now officially has access to this normal user’s future video data (since their keys are stored and retrievable). We return a 201 Created on first creation. If the user had already shared before, our unique index prevents duplicate entries; we catch that error and respond gracefully with a 200 OK and a message that the trust already existed (meaning we just updated the keys). This way, re-sharing with the same trusted user just refreshes the keys without creating duplicates.

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
// Normal user removing a trust. We confirm the requester is a normal user (same check via User lookup). Given the :trustedUserId in the URL, we delete the corresponding Wrapping record that links this user to that trusted user. After this, the trusted user will no longer be able to retrieve this user’s keys (and thus won’t be able to decrypt any new content). We simply return a success message. Note that this doesn’t revoke access to already fetched data (since the trusted user might have previously retrieved keys), but it stops any future video sharing unless the normal user shares again. It’s essentially “unsharing” their content moving forward.

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
