const fs = require('fs');
const util = require('util');

const protocol = require('@replit/protocol');

const harJson = fs.readFileSync(process.argv[2], 'utf-8');
const har = JSON.parse(harJson);

const gcmPattern = /^https:\/\/replit\.com\/data\/repls\/[0-9a-f-]+\/get_connection_metadata$/;
const connectionUrls = {};
const connectSids = {};
for (const entry of har.log.entries) {
  if (gcmPattern.test(entry.request.url)) {
    if (entry.response.status === 200) {
      const connectSidCookie = entry.request.cookies.find((c) => c.name === 'connect.sid');
      if (connectSidCookie) {
        connectSids[connectSidCookie.value] = true;
      }
      const metadata = JSON.parse(entry.response.content.text);
      const connectionUrl = `${metadata.gurl}/wsv2/${metadata.token}`;
      connectionUrls[connectionUrl] = true;
    }
  } else if (entry.request.url in connectionUrls) {
    if (entry.response.status === 101) {
      const channelZero = {content: []};
      const channelIds = {0: channelZero};
      const refs = {};
      for (const m of entry._webSocketMessages) {
        if (m.opcode !== 2) {
          console.log(m);
          continue;
        }
        const command = protocol.api.Command.decode(Buffer.from(m.data, 'base64'));
        if (m.type === 'send') {
          const pair = {req: command};
          if (command.ref) {
            refs[command.ref] = pair;
          }
          channelIds[command.channel].content.push(pair);
        } else {
          let pair;
          if (command.ref && command.ref in refs) {
            pair = refs[command.ref];
            delete refs[command.ref];
            pair.res = command;
          } else {
            pair = {res: command};
            channelIds[command.channel].content.push(pair);
          }
          if (command.openChanRes) {
            pair.content = [];
            channelIds[command.openChanRes.id] = pair;
          }
        }
      }
      console.log(util.inspect(channelZero, {depth: null, x_not_colors: true}));
    }
  }
}
for (const connectSid in connectSids) {
  console.log('connect.sid', connectSid);
}
