const readline = require('readline');
const util = require('util');

const protocol = require('@replit/protocol');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});
rl.on('line', (l) => {
  const buf = Buffer.from(l, 'base64');
  const c = protocol.api.Command.decode(buf);
  console.log(util.inspect(c, {depth: null, colors: true}));
});
