var express = require('express');
var router = express.Router();
var SystemsController = require('../controllers/systemController.js');
const { verifyJwt } = require('../controllers/systemController.js');
var EmailService = require('../utils/emailService.js');
const { csrfProtection } = require('../utils/csrfMiddleware.js');

router.post("/login", SystemsController.login);

router.post("/register", SystemsController.register);

router.post("/logout", verifyJwt, csrfProtection,  SystemsController.logout);

router.post("/forgotPassword", SystemsController.forgotPassword);

router.post("/refresh", SystemsController.refreshJwt);

router.get('/verifyEmail/:token', EmailService.verifyUserByEmail);

//router.post("/verifyUser", verifyJwt, SystemsController.verifyUserInDB); 

//router.post("/validate", verifyJwt, SystemsController.verifyCode); // ??????

router.post("/verifytoken", verifyJwt, (req, res) => {
    res.status(200).json(req.body.user);
});  //??????

router.get('/login', function (req, res) {
    res.render('login', { user: req.user });
}); //??????

module.exports = router;