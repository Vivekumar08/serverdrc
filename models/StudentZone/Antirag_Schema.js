const mongoose = require('mongoose');

const Antirag_Schema = mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    link: {
        type: String,
        required: true,
        trim: true
    },
    file_path: {
        type: String,
        required: true
    },
    file_mimetype: {
        type: String,
        required: true
    }
}, {
    timestamps: true
});

const Antirag = mongoose.model('Antirag', Antirag_Schema);

module.exports = Antirag;