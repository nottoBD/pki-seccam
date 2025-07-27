const decryptJWT = require('../middleware/jwt-decrypt');
const VideoChunk = require('../models/chunk');
const Video = require('../models/videos');
const TrustedUser = require('../models/trusteduser');
const SharedKeys = require('../models/shared-keys');
const logger = require('../logging/logger');

function getUsername(req) {
    const auth = req.headers.authorization || req.headers.Authorization || '';
    if (!auth.startsWith('Bearer ')) throw new Error('token missing');
    const token = auth.slice(7);
    const decoded = decryptJWT(token);
    if (!decoded?.user?.username) throw new Error('invalid token');
    return decoded.user.username;
}

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

exports.listChunks = async (req, res) => {
    try {
        const {username, name} = req.params;
        const hasAccess = await Video.exists({username, 'videos.videoName': name});
        if (!hasAccess) return res.status(404).send('Video not found');

        const chunks = await VideoChunk.find({videoName: name})
            .sort({'metadata.chunkIndex': 1});

        if (!chunks.length) return res.status(404).send('No chunks');
        res.json(chunks.map(c => ({chunk: c.chunk, metadata: [c.metadata]})));
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};

exports.shareWithTrusted = async (req, res) => {
    try {
        const username = getUsername(req);
        const {trusted_user, encrypted_symmetric_key} = req.body;

        await SharedKeys.create({
            username: trusted_user,
            regular_username: username,
            encrypted_symmetric_key,
        });
        res.json({message: `Videos shared with ${trusted_user}`});
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};

exports.listSharedWithOrganisation = async (req, res) => {
    try {
        const tuUsername = getUsername(req);
        const tu = await TrustedUser.findOne({username: tuUsername});
        if (!tu?.organization) return res.status(404).send('Organisation not found');

        const shared = await SharedKeys.find({organization: tu.organization});
        const payload = [];

        for (const sk of shared) {
            const doc = await Video.findOne({username: sk.regular_username});
            if (!doc) continue;
            payload.push({
                username: sk.regular_username,
                videos: doc.videos.map(v => ({name: v.videoName})),
                encrypted_symmetric_key: sk.encrypted_symmetric_key,
            });
        }

        res.json(payload);
    } catch (err) {
        logger.error(err.message);
        res.status(500).send('Internal Server Error');
    }
};
