const nodemailer = require("nodemailer");
var jwt = require("jsonwebtoken");
var UserModel = require("../models").users;

const sendVerificationEmail = async (email, template) => {
    try {
        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST, // Ejemplo: 'smtp.gmail.com'
            port: process.env.SMTP_PORT, // Ejemplo: 587
            secure: false, // true para 465, false para otros puertos
            auth: {
                user: process.env.SMTP_USER, // Correo de tu cuenta
                pass: process.env.SMTP_PASSWORD, // Contraseña de tu cuenta
            },
        });

        const mailOptions = {
            from: `"Tu Aplicación" <${process.env.SMTP_USER}>`,
            to: email,
            subject: "Verificación de correo electrónico",
            html: template
        };


        await transporter.sendMail(mailOptions);
        console.log(`Correo enviado a: ${email}`);
    } catch (err) {
        console.error("Error al enviar el correo:", err.message);
        throw new Error("Error al enviar el correo de verificación");
    }
};

const verifyUserByEmail = async (req, res) => {
    try {
        const { token } = req.params;
        if (!token) {
            return res.status(400).json({ message: "Token no proporcionado" });
        }
        const decoded = jwt.verify(token, process.env.EMAIL_SECRET);
        const user = await UserModel.findOne({ where: { email: decoded.email } });
        if (!user) {
            return res.status(404).json({ message: "Usuario no encontrado" });
        }
        if (user.isVerified) {
            return res.status(400).json({ message: "El usuario ya está verificado" });
        }
        user.isVerified = true;
        user.emailToken = null;
        await user.save();
        return res.redirect(`${process.env.FRONTEND_URL}/accountVerified`);
    }
    catch (err) {
        console.error("Error en /verifyEmail:", err);
        return res.status(500).json({
            message: "Error interno del servidor",
            error: err.message,
        });
    }
};

const verifyTemplate = (token) => {
    return `
        <h1>Verifica tu cuenta</h1>
        <p>Gracias por registrarte. Por favor, haz clic en el enlace de abajo para verificar tu correo electrónico:</p>
        <a href="${process.env.BASE_URL}/system/verifyEmail/${token}" target="_blank">Verificar mi correo</a>
        <p>Si no solicitaste este correo, ignóralo.</p>
    `;
};

const forgotPasswordTemplate = (encryptedTempPassword) => {
    return `
        <h1>Recupera tu contraseña</h1>
        <p>Hemos recibido tu solicitud de recuperación de contraseña. A continuación, encontrarás tu contraseña encriptada:</p>
        <p><strong>${encryptedTempPassword}</strong></p>
        <p>Para desencriptar tu contraseña, ve a la opción <strong>"Desencriptar contraseña"</strong> que se encuentra debajo del enlace "Olvidé mi contraseña" en el formulario de inicio de sesión.</p>
        <a href="${process.env.FRONTEND_URL}/">Desencriptar contraseña</a>
        <p>Usa la contraseña desencriptada para iniciar sesión en tu cuenta.</p>
        <p>Si no solicitaste esta recuperación de contraseña, ignora este correo.</p>
    `;

};


module.exports = { sendVerificationEmail, verifyUserByEmail, verifyTemplate, forgotPasswordTemplate };
