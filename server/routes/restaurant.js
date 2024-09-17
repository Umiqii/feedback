const express = require('express');
const multer = require('multer');
const Restaurant = require('../models/Restaurant');
const Feedback = require('../models/Feedback');

const router = express.Router();

// Multer kullanarak logo dosyasını yüklemek için ayarlar
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Yüklenecek dosya dizini
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage: storage });

// Restoran ekleme (logo ile birlikte)
router.post('/add', upload.single('logo'), async (req, res) => {
    try {
        const { name } = req.body;
        const logo = req.file ? req.file.path : null;

        const restaurant = new Restaurant({ name, logo });
        await restaurant.save();
        res.status(201).send('Restoran başarıyla eklendi.');
    } catch (error) {
        console.error('Restoran eklenirken hata oluştu:', error);
        res.status(500).send('Restoran eklenirken bir hata oluştu.');
    }
});

// Yorumları gösterme
router.get('/:restaurantId/comments', async (req, res) => {
    try {
        const restaurant = await Restaurant.findById(req.params.restaurantId).populate('comments');
        res.status(200).json(restaurant.comments);
    } catch (error) {
        console.error('Yorumlar alınırken hata oluştu:', error);
        res.status(500).send('Yorumlar alınırken hata oluştu.');
    }
});

// İyi/Kötü yorum sayısı
router.get('/:restaurantId/stats', async (req, res) => {
    try {
        const restaurant = await Restaurant.findById(req.params.restaurantId).populate('comments');
        const goodComments = restaurant.comments.filter(comment => comment.rating >= 4).length;
        const badComments = restaurant.comments.filter(comment => comment.rating <= 3).length;

        res.status(200).json({ goodComments, badComments });
    } catch (error) {
        console.error('İstatistikler alınırken hata oluştu:', error);
        res.status(500).send('İstatistikler alınırken hata oluştu.');
    }
});

module.exports = router;
