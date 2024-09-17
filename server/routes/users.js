// routes/users.js

require('dotenv').config(); // Ortam değişkenlerini yükle
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const router = express.Router();

// JWT için gizli anahtar
if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET ortam değişkeni tanımlanmalıdır.');
}
const secretKey = process.env.JWT_SECRET;

// Hesap kilitleme ayarları
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 saat

// Token doğrulama middleware'i
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (bearerHeader && bearerHeader.startsWith('Bearer ')) {
        const bearerToken = bearerHeader.split(' ')[1];
        jwt.verify(bearerToken, secretKey, (err, decoded) => {
            if (err) {
                return res.status(403).send('Geçerli bir token gerekiyor.');
            } else {
                req.user = decoded; // Kullanıcı bilgilerini istek objesine ekle
                next();
            }
        });
    } else {
        res.status(403).send('Geçerli bir token gerekiyor.');
    }
}

// Giriş rotası için Rate Limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 5, // 15 dakika içinde maksimum 5 istek
    message: 'Çok fazla giriş denemesi. Lütfen 15 dakika sonra tekrar deneyin.'
});

// Kullanıcı kaydı
router.post('/register', [
    check('username')
        .notEmpty().withMessage('Kullanıcı adı gerekli.')
        .isLength({ min: 3 }).withMessage('Kullanıcı adı en az 3 karakter olmalıdır.')
        .trim().escape(),
    check('email')
        .isEmail().withMessage('Geçerli bir e-posta adresi girin.')
        .normalizeEmail(),
    check('password')
        .isStrongPassword({
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        }).withMessage('Şifre en az 8 karakter olmalı ve büyük harf, küçük harf, sayı ve özel karakter içermelidir.')
], async (req, res) => {
    // Doğrulama sonuçlarını kontrol et
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { username, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send('Bu e-posta adresi zaten kullanılıyor.');
        }

        const newUser = new User({
            username,
            email,
            password // Şifre hash'lenmesi User modelindeki pre-save hook'u ile yapılır
        });

        await newUser.save();
        res.status(201).send('Kullanıcı başarıyla kaydedildi.');
    } catch (error) {
        console.error('Kullanıcı kaydedilirken bir hata oluştu:', error);
        res.status(500).send('Kullanıcı kaydedilirken bir hata oluştu.');
    }
});

// Kullanıcı girişi
router.post('/login', loginLimiter, [
    check('email')
        .isEmail().withMessage('Geçerli bir e-posta adresi girin.')
        .normalizeEmail(),
    check('password').notEmpty().withMessage('Şifre gerekli.')
], async (req, res) => {
    // Doğrulama sonuçlarını kontrol et
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).send('Geçersiz kullanıcı adı veya şifre.');
        }

        // Hesap kilitli mi?
        if (user.isLocked) {
            return res.status(403).send('Hesabınız geçici olarak kilitlenmiştir. Lütfen daha sonra tekrar deneyin.');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            // Başarısız giriş denemesini artır
            user.incrementLoginAttempts((err) => {
                if (err) console.error('Login attempt increment error:', err);
            });
            return res.status(401).send('Geçersiz kullanıcı adı veya şifre.');
        }

        // Başarılı giriş, loginAttempts'i sıfırla
        user.loginAttempts = 0;
        user.lockUntil = undefined;
        await user.save();

        const token = jwt.sign({ id: user._id }, secretKey, { expiresIn: '1h' });
        res.status(200).send({ message: 'Başarıyla giriş yapıldı.', token: token });
    } catch (error) {
        console.error('Giriş yapılırken bir hata oluştu:', error);
        res.status(500).send('Giriş yapılırken bir hata oluştu.');
    }
});

// Kullanıcı profilini getirme
router.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).send('Kullanıcı bulunamadı.');
        }
        res.status(200).send({ username: user.username, email: user.email });
    } catch (error) {
        console.error('Kullanıcı bilgileri alınırken bir hata oluştu:', error);
        res.status(500).send('Kullanıcı bilgileri alınırken bir hata oluştu.');
    }
});

// Kullanıcı profilini güncelleme
router.put('/profile', verifyToken, [
    check('username')
        .optional()
        .isLength({ min: 3 }).withMessage('Kullanıcı adı en az 3 karakter olmalıdır.')
        .trim().escape(),
    check('email')
        .optional()
        .isEmail().withMessage('Geçerli bir e-posta adresi girin.')
        .normalizeEmail(),
    check('newPassword')
        .optional()
        .isStrongPassword({
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        }).withMessage('Yeni şifre en az 8 karakter olmalı ve büyük harf, küçük harf, sayı ve özel karakter içermelidir.')
], async (req, res) => {
    const { username, email, oldPassword, newPassword } = req.body;

    // Doğrulama sonuçlarını kontrol et
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).send('Kullanıcı bulunamadı.');
        }

        // E-posta güncelleme
        if (email && email !== user.email) {
            const emailExists = await User.findOne({ email });
            if (emailExists) {
                return res.status(400).send('Bu e-posta adresi zaten kullanılıyor.');
            }
            user.email = email;
        }

        // Kullanıcı adı güncelleme
        if (username && username !== user.username) {
            const usernameExists = await User.findOne({ username });
            if (usernameExists) {
                return res.status(400).send('Bu kullanıcı adı zaten kullanılıyor.');
            }
            user.username = username;
        }

        // Şifre güncelleme
        if (newPassword) {
            if (!oldPassword) {
                return res.status(400).send('Mevcut şifre gerekli.');
            }
            const isMatch = await bcrypt.compare(oldPassword, user.password);
            if (!isMatch) {
                return res.status(400).send('Mevcut şifre yanlış.');
            }
            user.password = newPassword; // Şifre hash'lenmesi pre-save hook ile yapılacak
        }

        await user.save();

        res.status(200).send({ message: 'Profil güncellendi', user: { username: user.username, email: user.email } });
    } catch (error) {
        console.error('Profil güncellenirken bir hata oluştu:', error);
        res.status(500).send('Profil güncellenirken bir hata oluştu.');
    }
});

// Kullanıcı hesabını silme
router.delete('/profile', verifyToken, async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.user.id);
        if (!deletedUser) {
            return res.status(404).send('Kullanıcı bulunamadı.');
        }
        res.status(200).send({ message: 'Hesap başarıyla silindi.' });
    } catch (error) {
        console.error('Hesap silinirken bir hata oluştu:', error);
        res.status(500).send('Hesap silinirken bir hata oluştu.');
    }
});

// Şifre sıfırlama için token oluşturma ve email gönderme
router.post('/forgot-password', [
    check('email')
        .isEmail().withMessage('Geçerli bir e-posta adresi girin.')
        .normalizeEmail()
], async (req, res) => {
    // Doğrulama sonuçlarını kontrol et
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const email = req.body.email;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).send('Kullanıcı bulunamadı.');
        }

        // Token oluşturma
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.resetPasswordToken = resetTokenHash;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 saat geçerli
        await user.save();

        const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
        const message = `Şifrenizi sıfırlamak için buraya tıklayın: ${resetUrl}`;

        await sendEmail(user.email, 'Şifre Sıfırlama Talebi', message);

        res.status(200).send('Şifre sıfırlama e-postası gönderildi.');
    } catch (error) {
        console.error('Şifre sıfırlama talebi sırasında bir hata oluştu:', error);
        res.status(500).send('Şifre sıfırlama talebi sırasında bir hata oluştu.');
    }
});

// Token ile şifre sıfırlama
router.post('/reset-password/:token', [
    check('password')
        .isStrongPassword({
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        }).withMessage('Şifre en az 8 karakter olmalı ve büyük harf, küçük harf, sayı ve özel karakter içermelidir.')
], async (req, res) => {
    // Doğrulama sonuçlarını kontrol et
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const resetTokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user = await User.findOne({
            resetPasswordToken: resetTokenHash,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Şifre sıfırlama token geçersiz veya süresi dolmuş.');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).send('Şifreniz başarıyla güncellendi.');
    } catch (error) {
        console.error('Şifre güncellenirken bir hata oluştu:', error);
        res.status(500).send('Şifre güncellenirken bir hata oluştu.');
    }
});

module.exports = router;
