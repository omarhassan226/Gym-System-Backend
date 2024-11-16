const jwt = require('jsonwebtoken');
const secretKey = 'secret';

const tokenVerify = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) {
        return res.status(401).send({ message: 'No token provided' });
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).send({ message: 'Invalid token' });
        }

        req.user = user;
        next();
    });
};

module.exports = tokenVerify;
