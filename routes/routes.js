const router = require('express').Router();
const bcrypt = require('bcryptjs');
const userSchema = require('../models/userSchema');
const jwt = require('jsonwebtoken');
const isAdmin = require('../middlewares/isAdmin');
const tokenVerify = require('../middlewares/tokenVerification');

// Signup Route
router.post("/signup", async (req, res) => {
    const existingUser = await userSchema.findOne({ email: req.body.email });
    if (existingUser) {
        return res.status(400).send({
            message: 'Email already exists! Please use a different email.'
        });
    }

    const salt = await bcrypt.genSalt(11);
    const hashPassword = await bcrypt.hash(req.body.password, salt);

    const role = req.body.role || 'user';

    const user = new userSchema({
        name: req.body.name,
        email: req.body.email,
        phone: req.body.phone,
        password: hashPassword,
        role: role
    });

    res.send(await user.save());
});

// Login Route - Send Token in Response
router.post('/login', async (req, res) => {
    const user = await userSchema.findOne({ email: req.body.email });
    if (!user) {
        return res.status(404).send({
            message: 'Email or password is not correct!'
        });
    }
    if (!await bcrypt.compare(req.body.password, user.password)) {
        return res.status(400).send({
            message: 'Email or password is not correct!!'
        });
    }

    const role = req.body.role || 'user';

    const token = jwt.sign({ _id: user.id, role: user.role }, "secret", { expiresIn: '1d' }); // Token expires in 1 day

    res.send({
        message: 'Successfully Login!',
        token: token,  // Send token in the response
        role: role
    });
});

// User Route - Verify Token from Bearer Header
router.get('/user', tokenVerify, async (req, res) => {
    try {
        const user = await userSchema.findOne({ _id: req.user._id });

        const { password, ...data } = await user.toJSON();

        res.send(data);
    } catch (error) {
        return res.status(401).send({
            message: 'Unauthenticated user!'
        });
    }
});

// Admin Users Route
router.get('/users', isAdmin, async (req, res) => {
    try {
        const users = await userSchema.find();
        res.send(users);
    } catch (error) {
        res.status(500).send({
            message: 'Error Fetching Users!',
            error: error.message
        });
    }
});

// Logout Route - Not needed for localStorage, but it's here if you need it
router.post('/logout', (req, res) => {
    res.send({
        message: 'Logout Successfully!'
    });
});

module.exports = router;
