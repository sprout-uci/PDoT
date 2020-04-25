var dnsd = require('dnsd')
dnsd.createServer(function(req, res) {
	  res.end('1.2.3.4')
}).listen(53, '127.0.0.54')
console.log('Server running at 127.0.0.54:53')
