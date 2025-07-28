const logger = require("../logging/logger")
const router = require('express').Router()
const validateToken = require("../middleware/token-handler")
const {
    registerUser,
    currentUser,
    loginUser,
    verifyUserEmail,
    getUserSymmetric,
    listTrustedUsers,
} = require("../controllers/user-ctrl");

/**
 * @swagger
 * /api/user/register:
 *   head:
 *     summary: HEAD for user registration (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/register', (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/login:
 *   head:
 *     summary: HEAD for user login (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/login', (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/verify:
 *   head:
 *     summary: HEAD for email verification (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/verify', (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/current:
 *   head:
 *     summary: HEAD for current user (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/current', validateToken, (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/logout:
 *   head:
 *     summary: HEAD for user logout (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/logout', validateToken, (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/trusted/csr:
 *   head:
 *     summary: HEAD for trusted user CSR (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/trusted/csr', (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/getSymmetric:
 *   head:
 *     summary: HEAD for getting user symmetric key (preflight check)
 *     description: Returns 200 for preflight or OPTIONS requests.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: OK
 */
router.head('/getSymmetric', validateToken, (req, res) => res.status(200).end());

/**
 * @swagger
 * /api/user/register:
 *   post:
 *     summary: Register a new user
 *     description: Registers a new regular or trusted user. For trusted users, additional fields like organization, CSR, etc., are required.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - email_raw
 *               - encrypted_symmetric_key
 *               - encrypted_hmac_key
 *               - hmac_email
 *               - public_key
 *             properties:
 *               username:
 *                 type: string
 *               email:
 *                 type: string
 *                 description: Encrypted email
 *               email_raw:
 *                 type: string
 *                 description: Raw (unencrypted) email
 *               encrypted_symmetric_key:
 *                 type: string
 *               encrypted_hmac_key:
 *                 type: string
 *               hmac_email:
 *                 type: string
 *               public_key:
 *                 type: string
 *               isTrustedUser:
 *                 type: boolean
 *                 description: Set to true for trusted user registration
 *               hmac_username:
 *                 type: string
 *                 description: Required for trusted users
 *               fullname:
 *                 type: string
 *                 description: Required for trusted users
 *               hmac_fullname:
 *                 type: string
 *                 description: Required for trusted users
 *               organization:
 *                 type: string
 *                 description: Required for trusted users
 *               country:
 *                 type: string
 *                 description: Required for trusted users
 *               trustedUserCsr:
 *                 type: string
 *                 description: CSR for trusted user (PEM)
 *               orgCsr:
 *                 type: string
 *                 description: Organization CSR (PEM, for trusted users)
 *     responses:
 *       200:
 *         description: Registration successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *                 email:
 *                   type: string
 *                 qrcode_image:
 *                   type: string
 *                 encrypted_secret:
 *                   type: string
 *                 message:
 *                   type: string
 *                 userCertificate:
 *                   type: string
 *                   description: For trusted users
 *                 organizationCertificate:
 *                   type: string
 *                   description: For trusted users
 *       400:
 *         description: Missing fields or user already exists
 *       500:
 *         description: Server error
 */
router.post('/register', registerUser)

/**
 * @swagger
 * /api/user/login:
 *   post:
 *     summary: Login a user
 *     description: Authenticates a user using username and OTP code.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - code
 *             properties:
 *               username:
 *                 type: string
 *               code:
 *                 type: string
 *                 description: OTP code
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *       400:
 *         description: Invalid OTP
 *       403:
 *         description: Email not verified
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.post('/login', loginUser);

/**
 * @swagger
 * /api/user/verify:
 *   get:
 *     summary: Verify user email
 *     description: Verifies the user's email using the provided token.
 *     parameters:
 *       - in: query
 *         name: username
 *         schema:
 *           type: string
 *         required: true
 *       - in: query
 *         name: token
 *         schema:
 *           type: string
 *         required: true
 *     responses:
 *       200:
 *         description: Email verified
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid or expired link
 *       404:
 *         description: User not found
 */
router.get('/verify', verifyUserEmail);

/**
 * @swagger
 * /api/user/current:
 *   get:
 *     summary: Get current user details
 *     description: Retrieves details of the authenticated user.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *                 email:
 *                   type: string
 *                 encrypted_symmetric_key:
 *                   type: string
 *                 encrypted_hmac_key:
 *                   type: string
 *                 email_verified:
 *                   type: boolean
 *                 isTrustedUser:
 *                   type: boolean
 *       404:
 *         description: User not found
 */
router.get('/current', validateToken, currentUser)

/**
 * @swagger
 * /api/user/getSymmetric:
 *   get:
 *     summary: Get user's encrypted symmetric key
 *     description: Retrieves the encrypted symmetric key for the authenticated user.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Symmetric key details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 encryptedSymmetricKey:
 *                   type: string
 *                 username:
 *                   type: string
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.get('/getSymmetric', validateToken, getUserSymmetric);

/**
 * @swagger
 * /api/user/trusted/list:
 *   get:
 *     summary: List trusted users
 *     description: Retrieves a list of trusted users with their IDs, usernames, and certificates.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of trusted users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                   username:
 *                     type: string
 *                   certificate:
 *                     type: string
 *       403:
 *         description: Only for non-trusted users
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.get('/trusted/list', validateToken, listTrustedUsers);

/**
 * @swagger
 * /api/user/logout:
 *   post:
 *     summary: Logout the user
 *     description: Logs out the authenticated user.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       500:
 *         description: Server error
 */
router.post('/logout', validateToken, (req, res) => {
    try {
        res.json({message: 'success'});
    } catch (error) {
        logger.info("500: Server Error")
        res.status(500).send({message: "Server error"})
    }
})

module.exports = router;
