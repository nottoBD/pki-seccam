// Express routes for video streaming and management endpoints. This sets up the API paths under /api/video for listing videos, retrieving video chunks, uploading new video data, etc., and delegates the heavy lifting to the video controller. We define routes for a trusted user to list videos they have access to (GET /trustedList), for a normal user to list their own videos (GET /list), to fetch the encrypted chunks of a specific video (GET /:name/:username/chunks), to delete a video (DELETE /:name), and to upload new encrypted video chunks (POST /streaming). Each of these calls the appropriate controller function. Note: Authentication isn’t explicitly declared here, but these endpoints expect a valid auth token cookie; the controller will internally verify the token and user type (trusted vs normal) as needed to enforce access control.

const {Router} = require('express');
const video = require('../controllers/video-ctrl');

const r = Router();


r.get('/trustedList', video.trustedList);

/**
 * @swagger
 * /api/video/list:
 *   get:
 *     summary: List user's own videos
 *     description: Retrieves a list of videos belonging to the authenticated user.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of user's videos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *                 videos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       name:
 *                         type: string
 *       500:
 *         description: Internal Server Error
 */
r.get('/list', video.listMine);

/**
 * @swagger
 * /api/video/{name}/{username}/chunks:
 *   get:
 *     summary: List chunks of a specific video
 *     description: Retrieves the chunks for a video if the user has access.
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         schema:
 *           type: string
 *         description: The name of the video
 *       - in: path
 *         name: username
 *         required: true
 *         schema:
 *           type: string
 *         description: The username of the video owner
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of video chunks
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   chunk:
 *                     type: object  # Adjust based on chunk structure
 *                   metadata:
 *                     type: array
 *                     items:
 *                       type: object
 *                       properties:
 *                         chunkIndex:
 *                           type: integer
 *                         timestamp:
 *                           type: string
 *                         chunkSize:
 *                           type: integer
 *       404:
 *         description: Video or chunks not found
 *       500:
 *         description: Internal Server Error
 */
r.get('/:name/:username/chunks', video.listChunks);

/**
 * @swagger
 * /api/video/{name}:
 *   delete:
 *     summary: Delete a video
 *     description: Deletes a specific video and its chunks if the user is authorized.
 *     parameters:
 *       - in: path
 *         name: name
 *         required: true
 *         schema:
 *           type: string
 *         description: The name of the video to delete
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Video deleted successfully
 *       401:
 *         description: Not authorized
 *       404:
 *         description: Video not found
 *       500:
 *         description: Internal Server Error
 */
r.delete('/:name', video.deleteVideo);

/**
 * @swagger
 * /api/video/stream:
 *   post:
 *     summary: Upload a video chunk
 *     description: Handles uploading chunks of video data for streaming/storage.
 *     security:
 *       - cookieAuth: []  # Auth required based on controller code
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - encryptedChunk
 *               - metadata
 *             properties:
 *               encryptedChunk:
 *                 type: string
 *                 description: JSON string representing the encrypted chunk data
 *               metadata:
 *                 type: string
 *                 description: JSON string containing videoId, chunkIndex, timestamp, chunkSize
 *     responses:
 *       200:
 *         description: Chunk uploaded successfully
 *       400:
 *         description: Missing encrypted chunk or metadata
 *       500:
 *         description: Internal Server Error
 */
r.post('/streaming', video.uploadChunk);

module.exports = r;
