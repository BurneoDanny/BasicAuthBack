var UserModel = require("../models").users;
const bcrypt = require("bcrypt");
const CryptoJS = require("crypto-js");

const updateUser = async (req, res) => {
    try {
      const { id } = req.params;
      const { email, username } = req.body;
      if (!email || !username) {
        return res.status(400).json({ message: "El correo y nombre son obligatorios." });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ message: "El correo no es válido." });
      }
      
      const user = await UserModel.findByPk(id);
      if (!user) {
        return res.status(404).json({ message: "Usuario no encontrado." });
      }

      const encryptedUsername = CryptoJS.AES.encrypt(
        username,
        process.env.REACT_APP_SECRET_KEY_AES_PASSWORD
    ).toString(); // requerimiento
  
      user.email = email;
      user.username = encryptedUsername;
      await user.save();
  
      return res.status(200).json({
        id: user.id,
        email: user.email,
        username: user.username,
      });
    } catch (error) {
      console.error("Error al actualizar usuario:", error);
      return res.status(500).json({ message: "Error interno del servidor." });
    }
  };

  const passwordUpdate = async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const { id } = req.params;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: "Ambas contraseñas son obligatorias." });
        }

        const user = await UserModel.findByPk(id);
        if (!user) {
            return res.status(404).json({ message: "Usuario no encontrado." });
        }

        const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
        if (!isPasswordValid) {
            return res.status(403).json({ message: "La contraseña actual no es válida." });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const encryptedPassword = CryptoJS.AES.encrypt(
            newPassword,
            process.env.REACT_APP_SECRET_KEY_AES_PASSWORD
        ).toString();
        user.password = hashedPassword;
        user.tempPassword = encryptedPassword;
        await user.save();

        return res.status(200).json({ message: "Contraseña actualizada correctamente." });
    } catch (error) {
        console.error("Error al actualizar la contraseña:", error);
        return res.status(500).json({ message: "Error interno del servidor." });
    }
};
  

module.exports = {
    updateUser,
    passwordUpdate
};