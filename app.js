//Basics Imports
var express = require('express');
var path = require('path');
var cors = require('cors');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

// dotenv config
const dotenv = require("dotenv");
dotenv.config();

// App basics setup
var app = express();
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true,
}));
app.use(logger("dev"));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes setup
var systemRouter = require('./routes/system.route');
var userRouter = require('./routes/user.route');

app.use('/system', systemRouter);
app.use('/user', userRouter);


// EL inicio del servidor se lo gestiona en wwww.
module.exports = app;
