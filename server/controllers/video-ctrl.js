const decryptJWT = require('../middleware/jwt-decrypt');
const VideoChunk = require('../models/videochunk');
const Video = require('../models/video');
const TrustedUser = require('../models/usertrusted');
const logger = require('../logging/logger');
const Wrapping = require('../models/keywrap');
const User = require('../models/user');


function getUsername(req) {
    const auth = req.headers.authorization || req.headers.Authorization || '';
    if (!auth.startsWith('Bearer ')) throw new Error('token missing');
    const token = auth.slice(7);
    const decoded = decryptJWT(token);
    if (!decoded?.user?.username) throw new Error('invalid token');
    return decoded.user.username;
}

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
