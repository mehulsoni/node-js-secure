var app = require('./app');
var port = 8086;
var cors = require('cors')
app.use(cors())

var server = app.listen(port, function() {
  console.log('Express server listening on port ' + port);
});