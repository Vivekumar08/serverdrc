const jwt = require('jsonwebtoken')
require('cookie-parser')

const verifyToken = (req, res, next) => {
    const token = req.cookies.jwtoken;
    if (token) {
        jwt.verify(token, process.env.SECRET_KEY, (err,user) => {
            if (err) return res.sendStatus(403);
            req.user = user.id
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

module.exports = verifyToken;