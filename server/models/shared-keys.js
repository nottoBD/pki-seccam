/*  Organization-wide sharing keys
+ *  – one row per  (regular_username × organization) pair
+ */
const mongoose = require('mongoose');

const sharedKeySchema = new mongoose.Schema({
    username: {type: String, required: false},

    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true,
    },
    encrypted_symmetric_key: {type: String, required: true},

    regular_username: {type: String, required: true},
}, {timestamps: true});

sharedKeySchema.index({organization: 1, regular_username: 1}, {unique: true});

module.exports = mongoose.model('Sharedkey', sharedKeySchema);
