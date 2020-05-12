const mongoose = require('mongoose');
var User = require('../models/User');

const SignedMessageSchema = new mongoose.Schema({
	                                                user: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},
	                                                sign: String,
	                                                isValid: Boolean,
	                                                message: String,
	                                                signedAddress: String,
	                                                signed_time: Date,
                                                });
mongoose.model('SignedMessage', SignedMessageSchema);

module.exports = mongoose.model('SignedMessage');