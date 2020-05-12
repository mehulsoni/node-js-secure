var mongoose = require('mongoose');
var UserSchema = new mongoose.Schema({
	                                     owner: {type: String, unique: true, required: true},
	                                     login_count: Number,
	                                     last_login_time: Date,
                                     });
mongoose.model('User', UserSchema);

module.exports = mongoose.model('User');