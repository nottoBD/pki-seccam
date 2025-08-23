// Copyright (C) 2025 David Botton <david.botton@ulb.be>
// This file is part of PKI Seccam <https://github.com/nottoBD/pki-seccam>.
// Licensed under the WTFPL Version 2. See LICENSE file for details.

// Implements the server-side logic for video upload, storage, and retrieval. This controller ensures that only authorized users can save or access video data. Importantly, all video content is handled as encrypted data – the server never needs to decrypt video chunks. The client encrypts each chunk with their own key before upload, and the server simply stores it and serves it back to authorized viewers. The functions below manage mapping videos to users, saving chunk metadata, and enforcing that only the video owner or a trusted user with a proper key-sharing agreement can retrieve the chunks.

const decryptJWT = require('../middleware/jwt-decrypt');
const VideoChunk = require('../models/videochunk');
const Video = require('../models/video');
const TrustedUser = require('../models/usertrusted');
const logger = require('../logging/logger');
const Wrapping = require('../models/keywrap');
const User = require('../models/user');
const { decryptToken } = require('../utils/cookie-util');


// Utility to extract the username from the auth cookie. We decrypt the inbound authToken cookie (AES-GCM via decryptToken) to get the JWT and verify it. If the JWT is missing or invalid, we throw an error, effectively blocking the request with an auth error. This way, all video operations automatically require a valid session – without needing explicit middleware on these routes – and we also get the user’s details from the token for use in permission checks.

function getUsername(req) {
    const encToken = req.cookies.authToken;
    if (!encToken) throw new Error('cookie missing');
    const decoded = decryptJWT(encToken);
    if (!decoded?.user?.username) throw new Error('invalid authentication');
    return decoded.user.username;
}


// Returns a list of videos that a trusted user can access. We first confirm the requester is indeed a trusted user (they must exist in the TrustedUser collection, or we deny access). Then we gather all normal users who have shared keys with this trusted user (the Wrapping records). For each such normal user, we find their video list and include it. The response is an array of objects like { username: <normal_user>, videos: [ { name: <videoName>, sharedBy: <normal_user> }, ... ] }. In effect, when a trusted user hits their dashboard, this gives them an overview of every normal user who trusted them and the videos available from each. If the trusted user has no wraps (no one shared with them yet), the list will be empty.

exports.trustedList = async (req, res) => {
    try {
        const requestingUsername = getUsername(req);
        const trustedUser = await TrustedUser.findOne({ username: requestingUsername });
        if (!trustedUser) return res.status(403).json({ message: 'Only trusted users can access this endpoint.' });

        const wraps = await Wrapping.find({ trusted_user_id: trustedUser._id })
            .populate('normal_user_id', 'username');

        const results = await Promise.all(
            wraps.map(async (w) => {
                const owner = w.normal_user_id;
                const vidDoc = await Video.findOne({ username: owner.username });
                return {
                    username: owner.username,
                    videos: vidDoc ? vidDoc.videos.map(v => ({ name: v.videoName, sharedBy: owner.username })) : [],
                };
            })
        );

        res.json(results);
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};


// Handles a new video chunk upload from a normal user. The request is expected to include an encryptedChunk (the actual video data encrypted in Base64 JSON form) and some metadata (JSON string with videoId, chunk index, timestamp, etc.). We verify both are present, then determine the uploading username via the auth cookie. We then upsert an entry in the Video model for this user if the videoId is new (so each user has a document listing their video names). Next, we store the chunk itself in the VideoChunk collection, including its metadata (index, size, timestamp). The chunk data we save is still encrypted, the server doesn’t decrypt or even inspect it, just logs that it was saved. We log an info message (for audit) and return 200 OK. Security: Because each chunk is end-to-end encrypted by the client’s symmetric key, the server acts purely as storage; even if these chunks were exposed, they’re ciphertext that only the user (or their trusted partner) can decrypt.

exports.uploadChunk = async (req, res) => {
    try {
        const {encryptedChunk, metadata} = req.body;
        if (!encryptedChunk || !metadata)
            return res.status(400).send('Missing encrypted chunk or metadata');

        const meta = JSON.parse(metadata);
        const chunk = JSON.parse(encryptedChunk);
        const {videoId, chunkIndex, timestamp, chunkSize} = meta;

        const username = getUsername(req);

        // video document exists?
        const vidDoc = await Video.findOneAndUpdate(
            {username, 'videos.videoName': {$ne: videoId}},
            {$push: {videos: {videoName: videoId}}},
            {upsert: true, new: true},
        );

        // save chunk
        await VideoChunk.create({
            videoName: videoId,
            chunk,
            metadata: {chunkIndex, timestamp, chunkSize},
        });

        logger.info(`Chunk ${chunkIndex} of ${videoId} saved for ${username}`);
        res.sendStatus(200);
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};


// Returns the list of video IDs belonging to the authenticated user. We fetch the user’s Video record by username and return the array of video names (or an empty list if none). This is used to populate the user’s video library in the UI. Only the owner can call this (since it’s tied to their cookie token).

exports.listMine = async (req, res) => {
    try {
        const username = getUsername(req);
        const userVideo = await Video.findOne({username});
        if (!userVideo) return res.status(200).json({videos: []});
        res.json({
            username,
            videos: userVideo.videos.map(v => ({name: v.videoName})),
        });
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};


// Deletes a video and all its chunks for the authenticated user. We confirm the requester’s identity, then find their Video entry and look for the video name in their list. If it’s not found, either the video doesn’t exist or isn’t theirs (we treat it as unauthorized). If found, we remove that video from the list and delete all corresponding VideoChunk documents from the DB. This frees storage and effectively revokes access to that video (even if a trusted user had keys, the chunks are gone). Logs an info entry for auditing and returns success. Attempting to delete a video that isn’t yours will result in a 401 Unauthorized response.

exports.deleteVideo = async (req, res) => {
    try {
        const username = getUsername(req);
        const video = req.params.name;

        const userVid = await Video.findOne({username});
        if (!userVid) return res.status(404).send('No videos');
        const idx = userVid.videos.findIndex(v => v.videoName === video);
        if (idx === -1) return res.status(401).send('Not authorised');

        userVid.videos.splice(idx, 1);
        await userVid.save();
        await VideoChunk.deleteMany({videoName: video});

        logger.info(`Video ${video} deleted for ${username}`);
        res.sendStatus(200);
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};


// Retrieves all the encrypted chunks for a given video, provided the requester is allowed to view them. We check the :username path param (the video owner) against the requester (from the auth token). If they match, it’s the owner asking for their own video – allowed. If not, we see if the requester is a trusted user who has a key-sharing (wrapping) record with that owner. If such a trust exists, we allow access; otherwise, we return 403 Forbidden. When authorized, we pull all chunks for the video (sorted by chunk index to maintain correct order) and return them as an array of { chunk, metadata } objects. The chunk here is still encrypted data (likely containing the Base64 ciphertext and IV). The client will use the appropriate symmetric key to decrypt each chunk. This mechanism ensures that even though the server serves the data, it cannot decrypt it – only clients with the shared key (owner or trusted user) can. If no chunks are found for that video, we return 404 so the client knows the video is unavailable.

exports.listChunks = async (req, res) => {
    try {
        const requestingUsername = getUsername(req);
        const { username: ownerUsername, name } = req.params;
        const owner = await User.findOne({ username: ownerUsername });
        if (!owner) return res.status(404).send('Owner user not found');

        const isOwnerRequesting = ownerUsername === requestingUsername;

        let hasAccess = isOwnerRequesting;

        if (!hasAccess) {
            const trustedUser = await TrustedUser.findOne({ username: requestingUsername });
            if (trustedUser) {
                const wrapExists = await Wrapping.exists({
                    normal_user_id: owner._id,
                    trusted_user_id: trustedUser._id
                });
                hasAccess = !!wrapExists;
            }
        }

        if (!hasAccess) return res.status(403).send('Access not permitted');
        const chunks = await VideoChunk.find({videoName: name}).sort({'metadata.chunkIndex': 1});

        if (!chunks.length) return res.status(404).send('No chunks');
        res.json(chunks.map(c => ({chunk: c.chunk, metadata: c.metadata})));
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};
