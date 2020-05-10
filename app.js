const express = require('express');
const app = express();
const db = require('./db');

const cookieParser = require('cookie-parser');

const UserController = require('./modules/controllers/UserController');
const WalletController = require('./modules/controllers/WalletController');


app.use(cookieParser());

app.use('/users', UserController);
app.use('/wallets', WalletController);

module.exports = app;