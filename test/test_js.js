// Подозрительный JavaScript
const { exec } = require('child_process');
const fs = require('fs');
const net = require('net');

exec('whoami', (err, stdout) => console.log(stdout));

const client = net.connect({ host: 'api.telegram.org', port: 443 });
fs.writeFileSync('/tmp/malware.txt', 'payload');

eval("console.log('dynamic code execution')");
