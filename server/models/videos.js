const mongoose = require("mongoose");

const videoSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    videos: [
        {
            videoName: {
                type: String,
                required: true,
            },
        },
    ],
});

module.exports = mongoose.model("Video", videoSchema);
