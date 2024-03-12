const fs = require('fs');
const https = require('https');
const path = require('path');
const util = require('util');

const express = require('express');
const protocol = require('@replit/protocol');
const ws = require('ws');

// last 64 bits of SHA-256 of an excerpt from
// https://blog.replit.com/glitch
const DESC_OPT_IN = '4118d46a7203cf1b';
const REPLIT_FIREBASE_API_KEY = 'AIzaSyARAzVTWc_KOBojIholLo2wzwNOQ6VKcB8';
const ID_TOKEN_EXP_MARGIN = 30 * 1000;
const SID_EXP_MARGIN = 30 * 1000;
const PINGER_CONNECT_DELAY = 1000;
const PING_DELAY = 1000;
const OUTPUT_RESPAWN_DELAY = 1000;

const verboseRepls = {};
for (const replId of process.env.VERBOSE_REPLS.split(',')) {
  verboseRepls[replId] = true;
}

let state = null;
let username = '';
let repls = {};

async function saveQueueClearTemp(dir) {
  for (const name in await fs.promises.readdir(dir)) {
    if (name.endsWith('.tmp')) {
      const filename = `${dir}/${name}`;
      console.error('save queue unlinking temporary file', filename);
      try {
        await fs.promises.unlink(filename)
      } catch (e) {
        console.error(e);
      }
    }
  }
}

async function saveQueueCreate(filename) {
  let json = '';
  let read = false;
  try {
    json = await fs.promises.readFile(filename, {encoding: 'utf8'});
    read = true;
  } catch (e) {
    console.error(e);
  }
  let value;
  if (read) {
    value = JSON.parse(json);
  } else {
    value = {};
  }
  return {
    filename,
    value,
    writing: Promise.resolve(),
    snapshotted: true,
  };
}

async function saveQueueWriteNow(sq) {
  const valueSnapshot = JSON.stringify(sq.value);
  await fs.promises.writeFile(`${sq.filename}.tmp`, valueSnapshot, {mode: 0o600});
  await fs.promises.rename(`${sq.filename}.tmp`, sq.filename);
}

function saveQueueWrite(sq) {
  if (!sq.snapshotted) return sq.writing;
  sq.snapshotted = false;
  return sq.writing = sq.writing.catch((reason) => { }).then(() => {
    sq.snapshotted = true;
    return saveQueueWriteNow(sq);
  });
}

function requestFull(method, url, headers, bodyBuf) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method,
      headers: {
        'Content-Length': bodyBuf.length,
        ...headers,
      },
    });
    req.on('error', (e) => {
      reject(e);
    });
    req.on('response', (res) => {
      const chunks = [];
      res.on('error', (e) => {
        reject(e);
      });
      res.on('data', (chunk) => {
        chunks.push(chunk);
      });
      res.on('end', () => {
        const resBodyBuf = Buffer.concat(chunks);
        resolve({res, bodyBuf: resBodyBuf});
      });
    });
    req.end(bodyBuf);
  });
}

function jwtDecode(jwt) {
  const jwtParts = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(jwtParts[0], 'base64url').toString()),
    payload: JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString()),
  };
}

let idTokenUseUntil = null;
let idTokenPromised = null;

function idTokenGet() {
  if (idTokenPromised) return idTokenPromised;
  if (state.value.idToken) {
    if (idTokenUseUntil === null) {
      idTokenUseUntil = jwtDecode(state.value.idToken).payload.exp * 1000 - ID_TOKEN_EXP_MARGIN;
    }
    if (Date.now() < idTokenUseUntil) {
      return Promise.resolve(state.value.idToken);
    }
  }
  console.error('id token refreshing');
  idTokenUseUntil = null;
  return idTokenPromised = (async () => {
    // https://firebase.google.com/docs/reference/rest/auth#section-refresh-token
    const tokenResult = await requestFull(
      'POST',
      `https://securetoken.googleapis.com/v1/token?key=${encodeURIComponent(REPLIT_FIREBASE_API_KEY)}`,
      {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      Buffer.from(`grant_type=refresh_token&refresh_token=${encodeURIComponent(process.env.REFRESH_TOKEN)}`),
    );
    if (tokenResult.res.statusCode !== 200) throw new Error(`Firebase token response ${tokenResult.res.statusCode} not ok, body ${tokenResult.bodyBuf.toString()}`);
    const idToken = JSON.parse(tokenResult.bodyBuf.toString()).id_token;
    state.value.idToken = idToken;
    saveQueueWrite(state).catch((e) => {
      console.error(e);
    });
    idTokenPromised = null;
    return idToken;
  })();
}

let sidUseUntil = null;
let sidPromised = null;

function sidGet() {
  if (sidPromised) return sidPromised;
  if (state.value.sid) {
    if (sidUseUntil === null) {
      sidUseUntil = jwtDecode(state.value.sid).payload.exp * 1000 - SID_EXP_MARGIN;
    }
    if (Date.now() < sidUseUntil) {
      return Promise.resolve(state.value.sid);
    }
  }
  console.error('sid refreshing');
  sidUseUntil = null;
  return sidPromised = (async () => {
    const authResult = await requestFull(
      'POST',
      'https://replit.com/api/v1/auth',
      {
        'Authorization': `Bearer ${await idTokenGet()}`,
        'Content-Type': 'application/json',
        'Origin': 'https://replit.com',
        'X-Requested-With': 'XMLHttpRequest',
      },
      Buffer.from(JSON.stringify({})),
    );
    if (authResult.res.statusCode !== 200) throw new Error(`Replit auth response ${authResult.res.statusCode} not ok, body ${authResult.bodyBuf.toString()}`);
    let sid = null;
    if (authResult.res.headers['set-cookie']) {
      for (const setCookieStr of authResult.res.headers['set-cookie']) {
        const m = /^([^\s=]+)=([^\s;]+)/.exec(setCookieStr);
        if (!m) continue;
        if (m[1] === 'connect.sid') {
          sid = m[2];
          break;
        }
      }
    }
    if (!sid) throw new Error(`Replit auth response did not set connect.sid cookie, body ${authResult.bodyBuf.toString()}`);
    state.value.sid = sid;
    saveQueueWrite(state).catch((e) => {
      console.error(e);
    });
    sidPromised = null;
    return sid;
  })();
}

function tokenDecode(token) {
  const parts = token.split('.');
  const payload = Buffer.from(parts[2], 'base64url');
  const sigLen = 64;
  return {
    version: parts[0],
    purpose: parts[1],
    token: protocol.api.ReplToken.decode(Buffer.from(payload.subarray(0, -sigLen).toString(), 'base64')),
    authority: protocol.api.GovalSigningAuthority.decode(Buffer.from(Buffer.from(parts[3], 'base64url').toString(), 'base64')),
  }
}

function pingerCreate(id) {
  const pinger = {
    id,
    socket: null,
    reconnectTimeout: null,
    info: {
      wantReconnect: true,
      lastError: '(none)',
      socketCloseReason: null,
      socketCloseCode: null,
      dotdevHostname: null,
      lastOpenTime: null,
      lastCloseTime: null,
      lastPingTime: null,
      lastPongTime: null,
      lastRunTime: null,
      lastStopTime: null,
    },
  };
  return pinger;
}

function pingerConnect(pinger) {
  if (pinger.socket && pinger.socket.readyState !== ws.WebSocket.CLOSED) return;
  if (pinger.reconnectTimeout) {
    clearTimeout(pinger.reconnectTimeout);
    pinger.reconnectTimeout = null;
  }

  pinger.socket = null;

  (async () => {
    try {
      const metadataResult = await requestFull(
        'POST',
        `https://replit.com/data/repls/${pinger.id}/get_connection_metadata`,
        {
          'Content-Type': 'application/json',
          'Cookie': `connect.sid=${await sidGet()}`,
          'Origin': 'https://replit.com',
          'X-Requested-With': 'XMLHttpRequest',
        },
        Buffer.from(JSON.stringify({})),
      );
      if (metadataResult.res.statusCode !== 200) throw new Error(`Replit get connection metadata response ${metadataResult.res.statusCode} not ok, body ${metadataResult.bodyBuf.toString()}`);
      const metadata = JSON.parse(metadataResult.bodyBuf.toString());
      const tokenDecoded = tokenDecode(metadata.token);
      if (tokenDecoded.token.repl.id !== pinger.id) throw new Error(`received token for other repl, must invite @${username}`);
      pinger.info.dotdevHostname = metadata.dotdevHostname;

      // client
      let nextRefNum = 0;
      const refHandlers = {};
      const channelHandlers = {};

      function socketSend(o) {
        const command = protocol.api.Command.create(o);
        if (verboseRepls[pinger.id] && !command.ping) {
          console.error('pinger', pinger.id, '>', util.inspect(command, {depth: null}));
        }
        pinger.socket.send(protocol.api.Command.encode(command).finish());
      }

      function socketRequest(o, refHandler) {
        const ref = `r${nextRefNum++}`;
        refHandlers[ref] = refHandler;
        socketSend({...o, ref});
      }

      function socketRequestChan(openChan, openChanResHandler, channelHandler) {
        socketRequest({openChan}, (c) => {
          channelHandlers[c.openChanRes.id] = channelHandler;
          openChanResHandler(c.openChanRes);
        });
      }

      // ping
      let pingTimeout = null;

      function ping() {
        pinger.info.lastPingTime = Date.now();
        socketRequest({ping: {}}, (c) => {
          pinger.info.lastPongTime = Date.now();
          pingTimeout = setTimeout(() => {
            pingTimeout = null;
            ping();
          }, PING_DELAY);
        });
      }

      function pingStart() {
        ping();
      }

      function pingStop() {
        if (pingTimeout) {
          clearTimeout(pingTimeout);
          pingTimeout = null;
        }
      }

      // output
      let outputChanId = null;
      let outputRunTimeout = null;

      function outputWatch() {
        socketRequestChan({
          service: 'output',
          name: 'output',
          action: 'ATTACH_OR_CREATE',
        }, (openChanRes) => {
          outputChanId = openChanRes.id;
          console.error('pinger', pinger.id, 'output channel', outputChanId, 'open');
        }, (c) => {
          if (c.state === protocol.api.State.Stopped) {
            console.error('pinger', pinger.id, 'output stopped');
            pinger.info.lastStopTime = Date.now();
            outputRunTimeout = setTimeout(() => {
              outputRunTimeout = null;
              socketSend({channel: outputChanId, runMain: {}});
            }, OUTPUT_RESPAWN_DELAY);
          } else if (c.state === protocol.api.State.Running) {
            console.error('pinger', pinger.id, 'output running');
            pinger.info.lastRunTime = Date.now();
          } else if (c.error) {
            pinger.info.lastError = `output: ${c.error}`;
          }
        });
      }

      function outputStart() {
        outputWatch();
      }

      function outputStop() {
        if (outputRunTimeout) {
          clearTimeout(outputRunTimeout);
          outputRunTimeout = null;
        }
      }

      // socket
      pinger.socket = new ws.WebSocket(`${metadata.gurl}/wsv2/${metadata.token}`);
      pinger.socket.on('open', () => {
        console.error('pinger', pinger.id, 'open');
        pinger.info.lastOpenTime = Date.now();
        pingStart();
        outputStart();
      });
      pinger.socket.on('close', (code, reason) => {
        console.error('pinger', pinger.id, 'close', code, reason);
        pinger.info.socketCloseCode = code;
        pinger.info.socketCloseReason = reason.toString();
        pinger.info.lastCloseTime = Date.now();
        if (verboseRepls[pinger.id]) {
          console.error('pinger', pinger.id, 'info', pinger.info);
        }
        pingStop();
        outputStop();
        if (pinger.info.wantReconnect) {
          pinger.reconnectTimeout = setTimeout(() => {
            pinger.reconnectTimeout = null;
            pingerConnect(pinger);
          }, PINGER_CONNECT_DELAY);
        }
      });
      pinger.socket.on('error', (e) => {
        pinger.info.lastError = `socket event: ${e}`;
      });
      pinger.socket.on('message', (data, isBinary) => {
        const command = protocol.api.Command.decode(data);
        if (verboseRepls[pinger.id] && !command.pong) {
          console.error('pinger', pinger.id, '<', util.inspect(command, {depth: null}));
        }
        if (command.ref && command.ref in refHandlers) {
          const handler = refHandlers[command.ref];
          delete refHandlers[command.ref];
          handler(command);
        } else if (command.channel in channelHandlers) {
          channelHandlers[command.channel](command);
        }
      });
    } catch (e) {
      pinger.info.lastError = `connect: ${e}`;
    }
  })();
}

function pingerStop(pinger) {
  pinger.info.wantReconnect = false;
  if (pinger.reconnectTimeout) {
    clearTimeout(pinger.reconnectTimeout);
    pinger.reconnectTimeout = null;
  }
  if (pinger.socket) {
    pinger.socket.close();
  }
}

const startup = (async () => {
  // ensure state dir exists
  try {
    await fs.promises.mkdir('.data', {recursive: true, mode: 0o700});
  } catch (e) {
    console.error(e);
  }

  // clean up temporary files
  await saveQueueClearTemp('.data');

  // load saved state
  state = await saveQueueCreate('.data/state.json');

  // get username
  // https://replit.com/@masfrost/replit-gql-schema#schema.graphql
  const currentUserResult = await requestFull(
    'POST',
    'https://replit.com/graphql',
    {
      'Content-Type': 'application/json',
      'Cookie': `connect.sid=${encodeURIComponent(await sidGet())}`,
      'Origin': 'https://replit.com',
      'X-Requested-With': 'XMLHttpRequest',
    },
    Buffer.from(JSON.stringify({
      query: '{ currentUser { username } }',
    })),
  );
  if (currentUserResult.res.statusCode !== 200) throw new Error(`Replit graphql response ${currentUserResult.res.statusCode} not ok, body ${currentUserResult.bodyBuf.toString()}`);
  const currentUserRes = JSON.parse(currentUserResult.bodyBuf.toString());
  if (!currentUserRes.data) throw new Error(`Replit graphql no data, response was ${JSON.stringify(currentUserRes)}`);
  const currentUser = currentUserRes.data.currentUser;
  if (!currentUser) throw new Error(`Replit graphql no current user, response was ${JSON.stringify(currentUserRes)}`);
  username = currentUser.username;

  // initialize repls
  if (!state.value.repls) {
    state.value.repls = {};
  }

  for (const id in state.value.repls) {
    console.error('restoring repl', id);
    repls[id] = pingerCreate(id);
    pingerConnect(repls[id]);
  }
})();

startup.catch((e) => {
  console.error(e);
});

const saneForm = express.urlencoded({extended: false});
const app = express();
app.use(express.static('public'));
app.use((req, res, next) => {
  startup.then(() => {
    next();
  }, (e) => {
    next(e);
  })
});
app.get('/repls', (req, res) => {
  const result = {};
  for (const id in repls) {
    result[id] = {
      socketReadyState: repls[id].socket ? repls[id].socket.readyState : '(no socket)',
      info: repls[id].info,
    };
  }
  res.json(result);
});
app.post('/repls/add', saneForm, (req, res, next) => {
  const url = '' + req.body.url;
  (async () => {
    try {
      const replResult = await requestFull(
        'POST',
        'https://replit.com/graphql',
        {
          'Content-Type': 'application/json',
          'Cookie': `connect.sid=${encodeURIComponent(await sidGet())}`,
          'Origin': 'https://replit.com',
          'X-Requested-With': 'XMLHttpRequest',
        },
        Buffer.from(JSON.stringify({
          query: 'query ($url: String!) { repl(url: $url) { ... on Repl { id description } } }',
          variables: {url},
        })),
      );
      if (replResult.res.statusCode !== 200) throw new Error(`Replit graphql response ${replResult.res.statusCode} not ok, body ${replResult.bodyBuf.toString()}`);
      const replRes = JSON.parse(replResult.bodyBuf.toString());
      if (!replRes.data) throw new Error(`Replit graphql no data, response was ${JSON.stringify(replRes)}`);
      const repl = replRes.data.repl;
      if (!repl.description.includes(DESC_OPT_IN)) {
        res.status(403);
        res.end(`must add opt-in string ${DESC_OPT_IN} in description`);
        return;
      }
      if (state.value.repls[repl.id]) {
        pingerConnect(repls[repl.id]);
        res.redirect('/repls');
        return;
      }
      state.value.repls[repl.id] = true;
      repls[repl.id] = pingerCreate(repl.id);
      pingerConnect(repls[repl.id]);
      await saveQueueWrite(state);
      res.redirect('/repls');
    } catch (e) {
      next(e);
    }
  })();
});
app.post('/repls/remove', saneForm, (req, res, next) => {
  const url = '' + req.body.url;
  (async () => {
    try {
      const replResult = await requestFull(
        'POST',
        'https://replit.com/graphql',
        {
          'Content-Type': 'application/json',
          'Cookie': `connect.sid=${encodeURIComponent(await sidGet())}`,
          'Origin': 'https://replit.com',
          'X-Requested-With': 'XMLHttpRequest',
        },
        Buffer.from(JSON.stringify({
          query: 'query ($url: String!) { repl(url: $url) { ... on Repl { id description } } }',
          variables: {url},
        })),
      );
      if (replResult.res.statusCode !== 200) throw new Error(`Replit graphql response ${replResult.res.statusCode} not ok, body ${replResult.bodyBuf.toString()}`);
      const replRes = JSON.parse(replResult.bodyBuf.toString());
      if (!replRes.data) throw new Error(`Replit graphql no data, response was ${JSON.stringify(replRes)}`);
      const repl = replRes.data.repl;
      if (!state.value.repls[repl.id]) {
        res.redirect('/repls');
        return;
      }
      if (repl.description.includes(DESC_OPT_IN)) {
        res.status(403);
        res.end(`must remove opt-in string ${DESC_OPT_IN} from description`);
        return;
      }
      delete state.value.repls[repl.id];
      const pinger = repls[repl.id];
      delete repls[repl.id];
      pingerStop(pinger);
      await saveQueueWrite(state);
      res.redirect('/repls');
    } catch (e) {
      next(e);
    }
  })();
});
app.post('/repls/remove_deleted', saneForm, (req, res, next) => {
  const id = '' + req.body.id;
  if (!id.includes('-') || id.includes('/')) throw new Error('ID malformed');
  (async () => {
    try {
      if (!state.value.repls[id]) {
        res.redirect('/repls');
        return;
      }
      const replResult = await requestFull(
        'POST',
        'https://replit.com/graphql',
        {
          'Content-Type': 'application/json',
          'Cookie': `connect.sid=${encodeURIComponent(await sidGet())}`,
          'Origin': 'https://replit.com',
          'X-Requested-With': 'XMLHttpRequest',
        },
        Buffer.from(JSON.stringify({
          query: 'query ($id: String!) { repl(id: $id) { ... on Repl { id } } }',
          variables: {id},
        })),
      );
      if (replResult.res.statusCode !== 200) throw new Error(`Replit graphql response ${replResult.res.statusCode} not ok, body ${replResult.bodyBuf.toString()}`);
      const replRes = JSON.parse(replResult.bodyBuf.toString());
      if (replRes.data) throw new Error(`repl still exists`);
      delete state.value.repls[id];
      const pinger = repls[id];
      delete repls[id];
      pingerStop(pinger);
      await saveQueueWrite(state);
      res.redirect('/repls');
    } catch (e) {
      next(e);
    }
  })();
});
app.listen(process.env.PORT, () => {
  console.error('listening');
});
