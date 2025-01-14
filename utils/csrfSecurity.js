const crypto = require('crypto');

const crsfToken = new Map();

function generateCSRFToken(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    crsfToken.set(userId, token);
    return token;
}

function validateCSRFToken(userId, token) {
    const storedToken = crsfToken.get(userId.toString());
    console.log("Token almacenado en el servidor:", storedToken);
    console.log("Token recibido del cliente:", token);
    if(!storedToken || storedToken !== token) {
        return false;
    }
    return true;
}

function clearCSRFToken(userId) {
    crsfToken.delete(userId);
}

module.exports = {
    generateCSRFToken,
    validateCSRFToken,
    clearCSRFToken
}