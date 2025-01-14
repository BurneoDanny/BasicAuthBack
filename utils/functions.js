var jwt = require("jsonwebtoken");

const generateAccessToken = (user) => {
    const accessToken = jwt.sign(
        {
            id: user.id,
            email: user.email
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || '1h' }
    );
    return accessToken;
}

const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign(
        {
            id: user.id,
            email: user.email
        },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d'}
    );
    return refreshToken;
}


module.exports = {
    generateAccessToken,
    generateRefreshToken,

};  