const mongoose = require("mongoose");


const videoChunkSchema = new mongoose.Schema({
    videoName: {
        type: String,
        required: true,
    },
    chunk: {
        type: Object,
        required: true,
    },
    metadata: [
        {
            chunkIndex: {type: Number, required: true},
            timestamp: {type: Date, required: true},
            chunkSize: {type: Number, required: true},
        },
    ],
});

module.exports = mongoose.model("VideoChunk", videoChunkSchema);
