var jwt = require("jsonwebtoken");
var bcrypt = require("bcrypt");
const CryptoJS = require("crypto-js");
var UserModel = require("../models").users;
var RefreshTokenModel = require("../models").refresh_tokens;
const { generateAccessToken, generateRefreshToken } = require("../utils/functions");
const { generateCSRFToken, clearCSRFToken } = require("../utils/csrfSecurity");
const { sendVerificationEmail, forgotPasswordTemplate, verifyTemplate } = require("../utils/emailService");

const verifyJwt = function (req, res, next) {
    const authHeader =
        req.body.token ||
        (req.headers.authorization && req.headers.authorization.split(" ")[1]);
    if (authHeader) {
        jwt.verify(authHeader, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json("Token is not valid");
            }
            req.user = user;
            req.body.user = user;
            next();
        });
    } else {
        res.status(401).json("You are not authenticated!");
    }
};

const refreshJwt = async (req, res) => {
    try {
        const refreshToken = req.body.refreshToken;

        if (!refreshToken) return res.status(401).json("¡No estás autenticado!");

        jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET,
            async (err, user) => {
                if (err) {
                    return res.status(403).json("Token is not valid");
                }

                const refreshTokenRecord = await RefreshTokenModel.findOne({ where: { token: refreshToken } });
                if (!refreshTokenRecord) {
                    return res.status(404).json({
                        message: "¡Refresh Token no es válido!",
                    });
                }
                await RefreshTokenModel.destroy({ where: { token: refreshToken } });

                const newAccessToken = generateAccessToken(user);
                const newRefreshToken = generateRefreshToken(user);

                await RefreshTokenModel.create({
                    token: newRefreshToken,
                    email: user.email,
                });

                res.cookie('accessToken', newAccessToken, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'strict',
                    maxAge: process.env.ACCESS_TOKEN_EXPIRES_IN_MILISECONDS,
                });
        
                res.cookie('refreshToken', newRefreshToken, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'strict',
                    maxAge: REFRESH_TOKEN_EXPIRES_IN_MILISECONDS,
                });
        
                return res.status(202).json({
                    message: "Refresco de sesión exitoso",
                });
            }
        );
    } catch (error) {
        return res.status(500).json({
            message: "Error en la función RefreshJwt",
            error: error.message,
        });
    }
};

const login = async function (req, res) {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Correo y contraseña son obligatorios" });
        }

        const user = await UserModel.findOne({ where: { email } });
        if (!user) {
            return res.status(400).json({
                message: "Error, email or password invalid",
            });
        }

        if (!user.isVerified) {
            return res.status(409).json({
                message: "Un correo electrónico se ha enviado a su cuenta. Por favor, verifique.",
            });
        }

        const decryptedPassword = CryptoJS.AES.decrypt(password, "REACT_APP_FRONTEND_SECRET_KEY").toString(CryptoJS.enc.Utf8);
        const isPasswordValid = await bcrypt.compare(decryptedPassword, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({
                message: "Password not valid",
            });
        }

        if (!user.isSignedIn) {
            user.isSignedIn = true;
        } else {
            return res.status(409).json({ message: "El usuario ya ha iniciado sesión" });
        }
        await user.save();

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        const csrfToken = generateCSRFToken(user.id.toString());
        await RefreshTokenModel.create({
            email: user.email,
            token: refreshToken,
        });

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: process.env.ACCESS_TOKEN_EXPIRES_IN_MILISECONDS,
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: process.env.REFRESH_TOKEN_EXPIRES_IN_MILISECONDS,
        });

        res.cookie('csrfToken', csrfToken, {
            httpOnly: false,
            secure: true,
            sameSite: 'strict',
        });

        return res.status(202).json({
            message: "Inicio de sesión exitoso",
            email: user.email,
            id: user.id,
        });
    } catch (err) {
        console.error("Error en /login:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
            error: err.message,
        });
    }
};

const register = async function (req, res) {
    try {
        const { email, username, password } = req.body;
        if (!email || !username || !password) {
            return res.status(400).json({ message: "Todos los campos son obligatorios" });
        }
        const existingUser = await UserModel.findOne({ where: { email } });
        if (existingUser) {
            return res.status(409).json({ message: "El correo electrónico ya está registrado" });
        }

        const encryptedTempPassword = CryptoJS.AES.encrypt(password, process.env.REACT_APP_SECRET_KEY_AES_PASSWORD).toString(); // requerimiento
        const hashedPassword = await bcrypt.hash(password, 10);
        const emailToken = jwt.sign({ email }, process.env.EMAIL_SECRET, { expiresIn: '2h' });
        const newUser = await UserModel.create({
            email,
            username,
            password: hashedPassword,
            tempPassword: encryptedTempPassword,
            emailToken,
            isVerified: false,
            isSignedIn: false,
        });

        const emailVerifyTemplate  = verifyTemplate(emailToken);
        await sendVerificationEmail(email, emailVerifyTemplate );

        return res.status(201).json({
            message: "Usuario registrado exitosamente. Verifique su correo electrónico para verificar su cuenta y poder logearse."
        });
    } catch (err) {
        console.error("Error en /register:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
            error: err.message,
        });
    }
};

const logout = async function (req, res) {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: "El correo es obligatorio para cerrar sesión." });
        }
        const user = await UserModel.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: "Usuario no encontrado." });
        }
        if (!user.isSignedIn) {
            return res.status(400).json({ message: "El usuario ya ha cerrado sesión." });
        }
        user.isSignedIn = false;

        await user.save();
        await RefreshTokenModel.destroy({ where: { email } });

        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        });

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
        });

        res.cookie('csrfToken', '', {
            httpOnly: false,
            secure: true,
            sameSite: 'strict',
            maxAge: 0,
        });

        clearCSRFToken(user.id.toString());
        return res.status(200).json({ message: "Cierre de sesión exitoso." });
    } catch (err) {
        console.error("Error en /logout:", err);
        return res.status(500).json({
            message: "Error interno del servidor.",
            error: err.message,
        });
    }
};

const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
      const oldUser = await UserModel.findOne({ email });
      if (!oldUser) {
        return res.status(404).json({ message: "No existe dicho usuario" });
      }
      //const payload = { email: oldUser.email, id: oldUser._id };
      //const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" }); // se comenta por requerimiento
      const emailforgotPasswordTemplate = forgotPasswordTemplate(oldUser.tempPassword);
      await sendVerificationEmail(oldUser.email, emailforgotPasswordTemplate);
      return res.status(202).json({
        message: "Verifique su correo electrónico."
    });
    } catch (error) {
      console.log("Error when verifying the token.", error);
    }
};

module.exports = {
    verifyJwt,
    refreshJwt,
    login,
    register,
    logout,
    forgotPassword,
};