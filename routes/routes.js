const router = require('express').Router()
const bcrypt = require('bcryptjs')
const userSchema = require('../models/userSchema')
const jwt = require('jsonwebtoken')
const isAdmin = require('../middlewares/isAdmin')

router.post("/signup", async (req, res) => {

    const existingUser = await userSchema.findOne({ email: req.body.email });
    if (existingUser) {
        return res.status(400).send({
            message: 'Email already exists! Please use a different email.'
        });
    }

    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash(req.body.password, salt)

    const role = req.body.role || 'user';

    const user = new userSchema({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword,
        role: role
    })

    res.send(await user.save())
});

router.post('/login', async (req, res) => {
    const user = await userSchema.findOne({ email: req.body.email })
    if (!user) {
        return res.status(404).send({
            message: 'Email or password is not correct!'
        })
    }
    if (!await bcrypt.compare(req.body.password, user.password)) {
        return res.status(400).send({
            message: 'Email or password is not correct!!'
        })
    }

    const token = jwt.sign({ _id: user.id, role: user.role }, "secret")
    res.cookie('jwt', token, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 //one day expiration
    })

    res.send({
        message: 'Successfully Login!',
        token: token
    })
})

router.get('/user', async (req, res) => {
    try {
        const cookie = req.cookies['jwt']

        const claims = jwt.verify(cookie, 'secret')

        if (!claims) {
            return res.status(401).send({
                message: 'Unauthenticated user!'
            })
        }

        const user = await userSchema.findOne({ _id: claims._id })

        const { password, ...data } = await user.toJSON()

        res.send(data)
    } catch (error) {
        return res.status(401).send({
            message: 'Unauthenticated user!'
        })
    }

})

router.get('/users', isAdmin, async (req, res) => {
    try {
        const users = await userSchema.find()

        res.send(users)
    } catch (error) {
        res.status(500).send({
            message: 'Error Fetching Users!',
            error: error.message
        })
    }
})

router.post('/logout', (req, res) => {
    res.cookie('jwt', '', { maxAge: '0' })
    res.send({
        message: 'Logout Successfully!'
    })
})

module.exports = router