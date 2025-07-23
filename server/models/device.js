const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema(
    {
        deviceId: {type: String, required: true},
        name: {type: String, required: true},
        status: {type: String, enum: ['primary', 'active', 'pending'], required: true},

        csrPem: {type: String},
        certPath: {type: String},
        serialNumber: {type: String},
        issuedAt: {type: Date},

        encrypted_symmetric_key: {type: String},
        encrypted_hmac_key: {type: String},
        encrypted_secret: {type: String},

        lastSeen: {type: Date, default: Date.now},
    },
    {_id: false}
);

module.exports = deviceSchema;
