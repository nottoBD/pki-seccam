const mongoose = require('mongoose');
const deviceSchema = require('./device');

const trustedUserSchema = new mongoose.Schema({
    username: {type: String, unique: true, required: true},
    hmac_username: {type: String, required: true},
    email: {type: String, required: true},
    hmac_email: {type: String, required: true},
    fullname: {type: String, required: true},
    hmac_fullname: {type: String, required: true},
    email_verified: {type: Boolean, default: false},
    verification_token_hash: {type: String},
    verification_token_expires: {type: Date},
    secret: {type: String, required: true},
    encrypted_symmetric_key: {type: String},
    encrypted_hmac_key: {type: String},
    public_key: {type: String},

    devices: [deviceSchema],
    organization: {type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true},
});

module.exports = mongoose.model('TrustedUser', trustedUserSchema);
