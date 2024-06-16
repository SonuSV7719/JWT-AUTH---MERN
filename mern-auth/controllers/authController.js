// controllers/authController.js
const User = require('../models/User');
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require('../utils/jwt');
const bcrypt = require('bcryptjs');

// Register a new user
const register = async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({ email, password });
        await user.save();

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshToken = refreshToken;
        await user.save();

        res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true });
        res.json({ accessToken });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
};

// Login a user
const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        user.refreshToken = refreshToken;
        await user.save();

        res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: true });
        res.json({ accessToken });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
};

// Refresh the access token
const refreshToken = async (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = verifyRefreshToken(refreshToken);
        const user = await User.findById(decoded.id);
        
        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({ msg: 'Invalid token' });
        }

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        user.refreshToken = newRefreshToken;
        await user.save();

        res.cookie('refreshToken', newRefreshToken, { httpOnly: true, secure: true });
        res.json({ accessToken: newAccessToken });
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// Logout a user
const logout = async (req, res) => {
    const { refreshToken } = req.cookies;

    try {
        const decoded = verifyRefreshToken(refreshToken);
        const user = await User.findById(decoded.id);
        
        if (user) {
            user.refreshToken = '';
            await user.save();
        }

        res.clearCookie('refreshToken', { httpOnly: true, secure: true });
        res.json({ msg: 'Logged out' });
    } catch (err) {
        res.status(500).json({ msg: 'Server error' });
    }
};

module.exports = {
    register,
    login,
    refreshToken,
    logout,
};
