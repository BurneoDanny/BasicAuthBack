var express = require('express');
var router = express.Router();
var UserController = require('../controllers/userController.js');
const { verifyJwt } = require('../controllers/systemController.js');
const { csrfProtection } = require('../utils/csrfMiddleware.js');


router.put("/:id", verifyJwt, csrfProtection, UserController.updateUser);
router.put("/passwordUpdate/:id", verifyJwt, csrfProtection, UserController.passwordUpdate);

module.exports = router;