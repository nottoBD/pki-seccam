const mongoose = require('mongoose');

const wrappingSchema = new mongoose.Schema({
    normal_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    trusted_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    wrapped_symmetric_key: { type: String, required: true },
    wrapped_hmac_key: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
});

const Wrapping = mongoose.model('Wrapping', wrappingSchema);
