const express = require('express');
const Admin = require('../models/Admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { check, validationResult } = require('express-validator');

const router = express.Router();
const secretKey = process.env.JWT_SECRET;

// Admin kaydı
router.post('/register', [
    check('username').notEmpty().withMessage('Kullanıcı adı gerekli.'),
    check('email').isEmail().withMessage('Geçerli bir e-posta adresi girin.'),
    check('password').isLength({ min: 6 }).withMessage('Şifre en az 6 karakter olmalıdır.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
        const admin = new Admin({ username, email, password });
        await admin.save();
        res.status(201).send('Admin başarıyla kaydedildi.');
    } catch (error) {
        console.error('Admin kaydedilirken hata oluştu:', error);
        res.status(500).send('Kayıt sırasında bir hata oluştu.');
    }
});

// Admin giriş
router.post('/login', [
    check('email').isEmail().withMessage('Geçerli bir e-posta adresi girin.'),
    check('password').notEmpty().withMessage('Şifre gerekli.')
], async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(400).send('Kullanıcı bulunamadı.');
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).send('Şifre yanlış.');
        }

        const token = jwt.sign({ id: admin._id, role: admin.role }, secretKey, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        console.error('Giriş yapılırken hata:', error);
        res.status(500).send('Giriş sırasında bir hata oluştu.');
    }
});

// Admin çıkış (isteğe bağlı olarak frontend'de token silinir)

module.exports = router;
