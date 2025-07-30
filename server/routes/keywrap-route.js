const express = require('express');
const router = express.Router();
const keyWrapCtrl = require('../controllers/keywrap-ctrl');


router.post('/', keyWrapCtrl.createKeyWrap);
router.delete('/:trustedUserId', keyWrapCtrl.deleteKeyWrap);

router.get('/:owner_username/keys', keyWrapCtrl.getWrappedKeys);
router.get('/', keyWrapCtrl.listKeyWraps);

module.exports = router;
