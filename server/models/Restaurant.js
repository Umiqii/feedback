const mongoose = require('mongoose');

const restaurantSchema = new mongoose.Schema({
    name: { type: String, required: true },
    logo: { type: String }, // Logo dosyasının URL'sini saklayacağız
    comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Feedback' }]
});

const Restaurant = mongoose.model('Restaurant', restaurantSchema);
module.exports = Restaurant;
