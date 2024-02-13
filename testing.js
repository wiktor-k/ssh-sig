

var sshpk = require('sshpk-browser');
var fs = require('fs');
var sig = fs.readFileSync('/home/wiktor/src/meta/ssh-sig/signed-data.txt.sig', 'utf-8')


sig = sshpk.parseSignature(sig, 'rsa', 'x')

console.log(sig)
