const ethUtil = require('ethereumjs-util')

const jwt = require('jsonwebtoken');
const {check, validationResult} = require("express-validator");
const SignedMessage = require('../models/SignedMessage');
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

		            let status = true;
		            signedMessage = new SignedMessage({
			                                              owner: owner,
			                                              sign: sign,
			                                              isValid: status,
			                                              message: message,
			                                              signedAddress: signer,
			                                              signed_time: new Date()
		                                              });
		            await signedMessage.save();

		            const payload = {
			            user: {
				            address: owner
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
					                                 addess: owner,
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

// RETURNS ALL THE USERS SIGNED MESSAGES IN THE DATABASE
router.get('/signed-messages/:address', authenticateJWT, function (req, res) {
	SignedMessage.find({owner: req.params.address}, function (err, messages) {
		if (err) {
			return res.status(500).send("There was a problem finding the signed Messages.");
		}
		res.status(200).send(messages);
	});
});

// RETURNS ALL THE USERS TOKEN MESSAGES IN THE DATABASE
router.get('/verify', authenticateJWT, function (req, res) {
	res.status(200).send(messages);
});

module.exports = router;
