const logger = require("../logging/logger")
const router = require('express').Router()
const validateToken = require("../middleware/token-handler")
const {
    registerUser,
    currentUser,
    loginUser,
    verifyUserEmail,
    getUserSymmetric,
} = require("../controllers/user-ctrl");


router.head('/register', (req, res) => res.status(200).end());
router.head('/login', (req, res) => res.status(200).end());
router.head('/verify', (req, res) => res.status(200).end());
router.head('/current', validateToken, (req, res) => res.status(200).end());
router.head('/logout', validateToken, (req, res) => res.status(200).end());
router.head('/trusted/csr', (req, res) => res.status(200).end());
router.head('/getSymmetric', validateToken, (req, res) => res.status(200).end());

router.post('/register', registerUser)
router.post('/login', loginUser);
router.get('/verify', verifyUserEmail);
router.get('/current', validateToken, currentUser)
router.get('/getSymmetric', validateToken, getUserSymmetric);

router.post('/logout', validateToken, (req, res) => {
    try {
        res.json({message: 'success'});
    } catch (error) {
        logger.info("500: Server Error")
        res.status(500).send({message: "Server error"})
    }
})

module.exports = router;
