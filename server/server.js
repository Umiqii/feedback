// server/server.js

require('dotenv').config(); // Ortam değişkenlerini yükle
const express = require('express');
const mongoose = require('mongoose');
const userRoutes = require('./routes/users'); // Kullanıcı rotalarını içeren dosya
const feedbackRoutes = require('./routes/feedback'); // Feedback rotasını içeren dosya
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');

const app = express();

// Güvenlik için Helmet kullanımı
app.use(helmet());

// CORS Ayarları
const corsOptions = {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// İstekleri loglamak için Morgan kullanımı
app.use(morgan('combined'));

// Rate Limiting Ayarları
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 100, // 15 dakika içinde maksimum 100 istek
    message: 'Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.'
});
app.use(limiter);

// JSON body parsing
app.use(express.json());

// MongoDB bağlantısı
if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI ortam değişkeni tanımlanmalıdır.');
}

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB bağlantısı başarılı.'))
.catch(err => console.error('MongoDB bağlantı hatası:', err));

// Rotaları ekleme
app.use('/api/users', userRoutes); // Kullanıcı rotaları
app.use('/api/feedback', feedbackRoutes); // Feedback rotaları

// Ana sayfa rotası
app.get('/', (req, res) => {
    res.send('Ana Sayfa - Feedback Uygulaması');
});

// Sunucu dinleme
const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor.`);
});
