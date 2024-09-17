// server/utils/sendEmail.js

require('dotenv').config(); // Ortam değişkenlerini yükle
const nodemailer = require('nodemailer');

// E-posta gönderme fonksiyonu
const sendEmail = async (to, subject, text) => {
    // SMTP transport nesnesi oluştur
    const port = Number(process.env.SMTP_PORT);
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: port,
        secure: port === 465, // true ise port 465, false ise port 587 kullanılır
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD
        }
    });

    // E-posta gönderimi için mail seçenekleri
    const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: to, // Dinamik alıcı adresi
        subject: subject,
        text: text
    };

    // E-posta gönderimi
    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.response);
    } catch (error) {
        console.error('Email could not be sent:', error);
        throw new Error('Email gönderilemedi.');
    }
};

module.exports = sendEmail;
