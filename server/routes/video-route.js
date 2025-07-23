const {Router} = require('express');
const video = require('../controllers/video-ctrl');

const r = Router();

r.get('/list', video.listMine);
r.get('/:name/:username/chunks', video.listChunks);
r.delete('/:name', video.deleteVideo);

r.post('/share', video.shareWithTrusted);
r.get('/trustedList', video.listSharedWithOrganisation);

// NOTE: /stream remains at the top level so legacy uploaders keep working;
// you could move it to r.post('/stream', …) and update the front‑end call.
module.exports = r;
