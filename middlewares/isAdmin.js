const jwt = require('jsonwebtoken');

const isAdmin = (req, res, next) => {
    const cookie = req.cookies['jwt'];


    if (!cookie) {
        return res.status(401).send({
            message: 'No token provided | Login first!'
        });
    }

    try {
        const claims = jwt.verify(cookie, 'secret');
        if (claims.role !== 'admin') {
            return res.status(403).send({
                message: 'Access denied. Admins only.'
            });
        }

        next(); // Allow access if the role is admin
    } catch (error) {
        res.status(401).send({
            message: 'Unauthenticated user!'
        });
    }
};

module.exports = isAdmin