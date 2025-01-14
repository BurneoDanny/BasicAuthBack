const { validateCSRFToken } = require("./csrfSecurity");


const csrfProtection = (req, res, next) => {
    const csrfToken = req.headers['x-xsrf-token']; 
    const userId = req.user?.id || req.body.user?.id;

    console.log(csrfToken, userId)
    if (!csrfToken || !userId) {
        return res.status(403).json({ message: "Falta el token CSRF o el ID del usuario." });
    }

    const isValid = validateCSRFToken(userId, csrfToken);
    if (!isValid) {
        return res.status(403).json({ message: "Token CSRF inválido." });
    }

    next();
};

module.exports = { csrfProtection };
