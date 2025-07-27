const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {type: String, unique: true, required: true},
    email: {type: String, required: true},
    hmac_email: {type: String},
    public_key: {type: String},
    encrypted_symmetric_key: {type: String},
    encrypted_hmac_key: {type: String},
    email_verified: {type: Boolean, default: false},
    verification_token_hash: {type: String},
    verification_token_expires: {type: Date},
    secret: {type: String, required: true},// TOTP
});

module.exports = mongoose.model('User', userSchema);
