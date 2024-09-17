// server/routes/feedback.js

const express = require('express');
const router = express.Router();
const Feedback = require('../models/Feedback');
const { check, validationResult } = require('express-validator');

// POST /api/feedback
router.post('/', [
    check('name')
        .notEmpty().withMessage('Ad gerekli.')
        .trim().escape(),
    check('email')
        .isEmail().withMessage('Geçerli bir e-posta adresi gerekli.')
        .normalizeEmail(),
    check('phone')
        .notEmpty().withMessage('Telefon gerekli.')
        .trim().escape(),
    check('review')
        .notEmpty().withMessage('Geri bildirim gerekli.')
        .trim().escape(),
    check('consent')
        .isBoolean().withMessage('Kişisel verilerin işlenmesine izin vermelisiniz.'),
    check('rating')
        .isInt({ min: 1, max: 5 }).withMessage('Rating 1 ile 5 arasında olmalıdır.')
], async (req, res) => {
    // Doğrulama sonuçlarını kontrol et
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { name, email, phone, review, consent, rating } = req.body;

        const feedback = new Feedback({
            name,
            email,
            phone,
            review,
            consent,
            rating
        });

        await feedback.save();

        res.status(201).json({ message: 'Geri bildirim kaydedildi.' });
    } catch (error) {
        console.error('Geri bildirim kaydedilirken bir hata oluştu:', error);
        res.status(500).json({ message: 'Geri bildirim kaydedilirken bir hata oluştu.' });
    }
});
// Feedback kaydedildiğinde e-posta gönderimi
router.post('/', async (req, res) => {
    try {
        const feedback = new Feedback(req.body);
        await feedback.save();

        // Geri bildirimi admin'e e-posta olarak gönderelim
        const adminEmail = process.env.ADMIN_EMAIL;
        const message = `
            Yeni geri bildirim alındı:
            - İsim: ${req.body.name}
            - E-posta: ${req.body.email}
            - Yorum: ${req.body.review}
            - Puan: ${req.body.rating}
        `;
        await sendEmail(adminEmail, 'Yeni Geri Bildirim', message);

        res.status(201).send({ message: 'Geri bildirim kaydedildi' });
    } catch (error) {
        console.error('Geri bildirim kaydedilirken hata oluştu:', error);
        res.status(500).send('Geri bildirim kaydedilirken bir hata oluştu.');
    }
});


module.exports = router;
