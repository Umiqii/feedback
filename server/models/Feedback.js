// server/models/Feedback.js

const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
    },
    phone: {
        type: String,
        required: true,
        trim: true,
    },
    review: {
        type: String,
        required: true,
        trim: true,
    },
    consent: {
        type: Boolean,
        required: true,
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5,
    },
    date: {
        type: Date,
        default: Date.now,
    },
});

const Feedback = mongoose.model('Feedback', feedbackSchema);
module.exports = Feedback;
