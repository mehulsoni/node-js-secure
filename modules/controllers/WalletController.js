const ethUtil = require('ethereumjs-util')

const jwt = require('jsonwebtoken');
const {check, validationResult} = require("express-validator");
const SignedMessage = require('../models/SignedMessage');
var User = require('../models/User');
const config = require('../config/config');

const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');

router.use(bodyParser.urlencoded({extended: true}));
router.use(bodyParser.json());

const hashPersonalMessage = (msg) => {
	const buffer = Buffer.from(msg);
	const result = ethUtil.hashPersonalMessage(buffer);
	return ethUtil.bufferToHex(result);
};

const recoverPublicKey = (sig, hash) => {
	const sigParams = ethUtil.fromRpcSig(sig);
	const hashBuffer = Buffer.from(hash.replace("0x", ""), "hex");
	const result = ethUtil.ecrecover(
		hashBuffer,
		sigParams.v,
		sigParams.r,
		sigParams.s
	);
	return ethUtil.bufferToHex(ethUtil.publicToAddress(result));
}

const authenticateJWT = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		jwt.verify(authHeader, config.secret, (err, user) => {
			if (!user) {
				return res.status(403).json({
					                            auth: false,
					                            message: "Invalid Auth Token"
				                            });
			}
			req.user = user;
			next();
		});
	} else {
		return res.status(401).json({
			                            auth: false,
			                            message: "Auth Token Required"
		                            });
	}
};

router.post("/validate/message",
            [
	            check("owner", "Please enter a valid owner address").exists(),
	            check("sign", "Please enter a valid sign message").exists(),
	            check("message", "Please enter a valid message").exists()
            ],
            async (req, res) => {

	            try {
		            // validate request parameter
		            const errors = validationResult(req);
		            if (!errors.isEmpty()) {
			            return res.status(400).json({
				                                        errors: errors.array()
			                                        });
		            }

		            const {owner, sign, message} = req.body;
		            if (message === '') {
			            return res.status(400).json({
				                                        errors: "Invalid message"
			                                        });
		            }

		            // mehul.soni89@gmail.com 1589070400311 check for old time requests
		            const timestamp = message.split(' ')[1];
		            const curr_time = (new Date()).getTime();
		            if (((curr_time - timestamp) / 1000 / 60) > 1) {
			            return res.status(400).json({
				                                        errors: "Invalid Request"
			                                        });
		            }

		            // check for signature already exist into database or not.
		            let signedMessage = await SignedMessage.findOne({
			                                                            sign
		                                                            });
		            if (signedMessage) {
			            return res.status(400).json({
				                                        message: "Invalid Request"
			                                        });
		            }

		            const signer = recoverPublicKey(sign, hashPersonalMessage(message));
		            const verified = signer.toLowerCase() === owner.toLowerCase()

		            if (!verified) {
			            return res.status(401).json({auth: false, message: signedMessage});
		            }

		            // check for user exist or not. if yes, update counter and last login date. if not then create new
		            // one with
		            let user = await User.findOne({
			                                          owner: owner
		                                          });
		            if (!user) {
			            user = new User({
				                            owner: owner,
				                            login_count: 1,
				                            last_login_time: new Date(),
			                            });
		            }
		            user.login_count += 1;
		            user.last_login_time = new Date();
		            await user.save();

		            let status = true;
		            signedMessage = new SignedMessage({
			                                              user: User,
			                                              sign: sign,
			                                              isValid: status,
			                                              message: message,
			                                              signedAddress: signer,
			                                              signed_time: new Date()
		                                              });
		            await signedMessage.save();

		            const payload = {
			            user: {
				            owner: owner
			            }
		            };

		            jwt.sign(
			            payload,
			            config.secret,
			            {
				            expiresIn: '1h'
			            },
			            (err, token) => {
				            if (err) {
					            throw err;
				            }

				            return res.status(200).json({
					                                        auth: true,
					                                        user: user,
					                                        token: token,
					                                        signed_time: (new Date()).getTime().toString()
				                                        });
			            }
		            );
	            } catch (e) {
		            console.error(e);
		            return res.status(500).json({
			                                        message: "Server Error"
		                                        });
	            }
            }
);

// VERIFY JWT TOKEN IS EXPIRED OR NOT
router.get('/verify', authenticateJWT, function (req, res) {
	res.status(200).send({
		                     auth: true,
		                     message: 'sucess',
		                     date: (new Date()).getTime().toString()
	                     });
});

module.exports = router;
