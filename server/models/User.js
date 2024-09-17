// server/models/User.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const saltRounds = 10; // Salting rounds for bcrypt
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 saat

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    loginAttempts: { type: Number, required: true, default: 0 },
    lockUntil: { type: Number }
});

// Hesap kilitleme mekanizması için sanal alan
userSchema.virtual('isLocked').get(function() {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Şifreyi kaydetmeden önce hash'leme
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const hash = await bcrypt.hash(this.password, saltRounds);
        this.password = hash; // Hashlenmiş şifreyi kaydet
        next();
    } catch (err) {
        next(err);
    }
});

// Başarısız giriş denemelerini güncelleme
userSchema.methods.incrementLoginAttempts = function() {
    // Hesap kilitli mi?
    if (this.lockUntil && this.lockUntil < Date.now()) {
        // Kilit süresi dolmuş, sıfırla
        return this.updateOne({
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1 }
        }).exec();
    }
    // Aksi halde loginAttempts'i artır
    const updates = { $inc: { loginAttempts: 1 } };
    // Maksimum deneme sayısına ulaşıldıysa kilitle
    if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
        updates.$set = { lockUntil: Date.now() + LOCK_TIME };
    }
    return this.updateOne(updates).exec();
};

const User = mongoose.model('User', userSchema);
module.exports = User;
