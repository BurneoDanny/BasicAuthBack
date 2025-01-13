const startCronJob  = require('./cron/subscriptionChecker');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
require('./models/index');
const dotenv = require("dotenv");
dotenv.config();
const bodyParser = require('body-parser');
const csrfProtection = require('./middlewares/csrfMiddleware.js');
var cors = require('cors');
var passport = require('passport');

var systemRouter = require('./routes/systemRoutes');
var userRouter = require('./routes/userRoutes');
var projectRouter = require('./routes/projectRoutes');
var canvasRouter = require('./routes/canvasRoutes');
var authGoogleRouter = require('./authentication/strategies/google');
var paymentRouter = require('./routes/paymentRoutes');
var OpenAIRouter = require('./routes/openAIRoutes');
var barcodeRouter = require('./routes/barcodeRoutes');

var rateLimiter = require('./util/rateLimiter');
var app = express();

app.use(cors());

startCronJob();
app.use(logger('dev'));
function userLoggingMiddleware(req, res, next) {
    req.userDetails = {
      method: req.method,
      requestUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
      protocol: `HTTP/${req.httpVersion}`,
      remoteIP: req.ip,
      remoteIPV4: req.ip.indexOf(':') >= 0 ? req.ip.substring(req.ip.lastIndexOf(':') + 1) : req.ip,
      userAgent: req.get('User-Agent'),
      referrer: req.get('Referrer'),
      requestSize: req.socket.bytesRead
    };
    next();
}

app.use(userLoggingMiddleware);
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    if (req.originalUrl === '/payment/webhook') {
        next();
    } else {
        bodyParser.json({ limit: '50mb' })(req, res, next);
    }
});

app.post('/payment/webhook', 
    express.raw({type: 'application/json'}),
    (req, res, next) => {
        req.rawBody = req.body;
        next();
    }
);

app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

app.use(rateLimiter);
function conditionalCSRFProtection(req, res, next) {
  const exemptedPaths = ['/system/login', '/system/logout', , '/auth/google'];
  if (exemptedPaths.includes(req.path)) {
      return next();
  }
  return csrfProtection(req, res, next);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/system', systemRouter);
app.use('/user', userRouter);
app.use('/project', projectRouter);
app.use('/canvas', canvasRouter);
app.use('/auth', authGoogleRouter);
app.use('/payment', paymentRouter);
app.use('/data', OpenAIRouter);
app.use('/barcode',barcodeRouter);

app.listen(process.env.DEFAULT_PORT);
console.log("Server running on port " + process.env.DEFAULT_PORT);


const User = require('./models/usersModel.js');
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

module.exports = app;
