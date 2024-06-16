const express = require('express');
const { register, login, refreshToken, logout } = require('../controllers/authController');
const router = express.Router();
const { verifyToken, verifyTokenAndFetchUser } = require('../middlewares/authMiddleware');

router.post('/register', register);
router.post('/login', login);
router.post('/token', refreshToken);
router.post('/logout', logout);


// Example of a protected route
router.get('/protected', verifyTokenAndFetchUser, (req, res) => {
    res.json({ msg: `Hello, ${req.user.email}` });
});


module.exports = router;
