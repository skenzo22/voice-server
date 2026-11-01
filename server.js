// Voice relay server - no external libraries.
// - GET /                  -> "voice relay ok" (also used by the app to wake the server)
// - WebSocket /?room=X&name=Y&v=2
//     v=3 clients get:   [0x01][senderId][audio...]   and   [0x03][count]{[id][flags][len][name]}...
//                        flags: bit0 = that person closed his mic, bit1 = this entry is you
//                        and may send the text frame "m1" / "m0" to tell the room his mic is closed / open
//                        and "b<id>" / "u<id>" to stop / allow sending his voice to the person with that id
//     v=2 clients get:   [0x01][senderId][audio...]   and   [0x02][count]{[id][len][name]}...
//     older clients get: the raw audio bytes, nothing else.
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_ROOM_USERS = 16;
const MAX_PAYLOAD = 4096;       // audio frames are ~320 bytes
const MAX_BACKLOG = 64 * 1024;  // skip audio for clients that cannot keep up
const rooms = new Map();        // room -> Map(id -> client)

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('voice relay ok');
});

function cleanName(raw) {
  let n = String(raw || '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  n = Array.from(n).slice(0, 16).join('');
  return n || 'Player';
}

function frame(opcode, payload) {
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.from([0x80 | opcode, len]);
  } else {
    head = Buffer.from([0x80 | opcode, 126, len >> 8, len & 255]);
  }
  return Buffer.concat([head, payload]);
}

function send(client, opcode, payload) {
  const s = client.socket;
  if (s.destroyed || !s.writable) return;
  if (opcode === 2 && s.writableLength > MAX_BACKLOG) return; // drop audio, never queue it forever
  s.write(frame(opcode, payload));
}

function broadcastRoster(room) {
  const members = rooms.get(room);
  if (!members) return;
  // v2 list (id, name)
  const parts2 = [Buffer.from([2, members.size])];
  for (const [id, c] of members) {
    const nb = Buffer.from(c.name, 'utf8');
    parts2.push(Buffer.from([id, nb.length]), nb);
  }
  const msg2 = Buffer.concat(parts2);
  for (const c of members.values()) {
    if (c.ver === 2) {
      send(c, 2, msg2);
    } else if (c.ver >= 3) {
      // v3 list: every person gets his own copy, with "this is you" marked
      const parts3 = [Buffer.from([3, members.size])];
      for (const [id, m] of members) {
        const nb = Buffer.from(m.name, 'utf8');
        const flags = (m.micMuted ? 1 : 0) | (m === c ? 2 : 0);
        parts3.push(Buffer.from([id, flags, nb.length]), nb);
      }
      send(c, 2, Buffer.concat(parts3));
    }
  }
}

function removeClient(client) {
  if (client.removed) return;
  client.removed = true;
  const members = rooms.get(client.room);
  if (members) {
    members.delete(client.id);
    for (const m of members.values()) m.blocked.delete(client.id);
    if (members.size === 0) rooms.delete(client.room);
    else broadcastRoster(client.room);
  }
  client.socket.destroy();
}

function handleMessage(client, opcode, payload) {
  client.alive = true;
  if (opcode === 2) { // audio
    if (payload.length === 0 || payload.length > MAX_PAYLOAD) return;
    const members = rooms.get(client.room);
    if (!members) return;
    const wrapped = Buffer.concat([Buffer.from([1, client.id]), payload]);
    for (const c of members.values()) {
      if (c === client) continue;
      if (client.blocked.size && client.blocked.has(c.id)) continue; // he asked not to be heard by this person
      send(c, 2, c.ver >= 2 ? wrapped : payload);
    }
  } else if (opcode === 1) { // text: "m1" = my mic is closed, "m0" = my mic is open
    const t = payload.toString('utf8');
    if ((t[0] === 'b' || t[0] === 'u') && /^\d{1,3}$/.test(t.slice(1))) {
      const rid = parseInt(t.slice(1), 10);
      if (t[0] === 'b') {
        if (client.blocked.size < 64) client.blocked.add(rid);
      } else {
        client.blocked.delete(rid);
      }
    } else if (t === 'm1' || t === 'm0') {
      const closed = t === 'm1';
      if (client.micMuted !== closed) {
        client.micMuted = closed;
        broadcastRoster(client.room);
      }
    }
  } else if (opcode === 9) { // ping
    send(client, 10, payload);
  } else if (opcode === 8) { // close
    send(client, 8, Buffer.alloc(0));
    removeClient(client);
  }
  // text frames and pongs only count as "alive"
}

function attachParser(client) {
  let buf = Buffer.alloc(0);
  client.socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const b0 = buf[0], b1 = buf[1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        removeClient(client); // far too big for this service
        return;
      }
      if (len > MAX_PAYLOAD) { removeClient(client); return; }
      const need = off + (masked ? 4 : 0) + len;
      if (buf.length < need) return;
      let payload = buf.slice(off + (masked ? 4 : 0), need);
      if (masked) {
        const mask = buf.slice(off, off + 4);
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      }
      buf = buf.slice(need);
      handleMessage(client, opcode, payload);
      if (client.removed) return;
    }
  });
}

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch (e) {
    socket.destroy();
    return;
  }
  const room = (url.searchParams.get('room') || '').slice(0, 64);
  if (!key || !room) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }
  let members = rooms.get(room);
  if (members && members.size >= MAX_ROOM_USERS) {
    socket.end('HTTP/1.1 503 Room Full\r\n\r\n');
    return;
  }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);

  if (!members) {
    members = new Map();
    rooms.set(room, members);
  }
  let id = 1;
  while (members.has(id)) id++;
  const client = {
    socket, room, id,
    name: cleanName(url.searchParams.get('name')),
    ver: parseInt(url.searchParams.get('v') || '1', 10) || 1,
    micMuted: false,
    blocked: new Set(),
    alive: true, removed: false,
  };
  members.set(id, client);
  socket.on('close', () => removeClient(client));
  socket.on('error', () => removeClient(client));
  attachParser(client);
  broadcastRoster(room);
});

// Drop connections that went silent (phone lost signal, app killed...).
setInterval(() => {
  for (const members of rooms.values()) {
    for (const c of Array.from(members.values())) {
      if (!c.alive) { removeClient(c); continue; }
      c.alive = false;
      send(c, 9, Buffer.alloc(0));
    }
  }
}, 25000);

server.listen(PORT, () => console.log('voice relay listening on ' + PORT));
