const mongoose = require('mongoose');

const wrappingSchema = new mongoose.Schema({
    normal_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    trusted_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'TrustedUser', required: true },
    wrapped_symmetric_key: { type: String, required: true },
    wrapped_hmac_key: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
});

wrappingSchema.index({ normal_user_id: 1, trusted_user_id: 1 }, { unique: true });

module.exports = mongoose.model('Wrapping', wrappingSchema);
