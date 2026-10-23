// Minimal voice relay: no dependencies.
// Client connects to ws(s)://HOST/?room=CODE  and every binary message it sends
// is forwarded to the other clients in the same room.
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const MAX_FRAME = 64 * 1024;       // reject frames larger than this
const MAX_PER_ROOM = 16;
const rooms = new Map();           // room -> Set<socket>

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('voice relay ok\n');
});

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x');
  const room = (url.searchParams.get('room') || '').slice(0, 32);
  const key = req.headers['sec-websocket-key'];
  if (!room || !key) { socket.destroy(); return; }

  const set = rooms.get(room) || new Set();
  if (set.size >= MAX_PER_ROOM) { socket.destroy(); return; }

  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);

  set.add(socket);
  rooms.set(room, set);
  let buf = Buffer.alloc(0);

  const cleanup = () => {
    set.delete(socket);
    if (set.size === 0) rooms.delete(room);
  };
  socket.on('close', cleanup);
  socket.on('error', () => { cleanup(); socket.destroy(); });

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      if (buf.length < 2) return;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (len > MAX_FRAME) { socket.destroy(); return; }
      const need = off + (masked ? 4 : 0) + len;
      if (buf.length < need) return;
      let payload = buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) {
        const mask = buf.subarray(off, off + 4);
        const out = Buffer.alloc(len);
        for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
        payload = out;
      }
      buf = buf.subarray(need);

      if (opcode === 0x8) { socket.end(); return; }                 // close
      if (opcode === 0x9) { socket.write(frame(0xA, payload)); continue; } // ping -> pong
      if (opcode === 0x2) {                                          // binary audio
        const f = frame(0x2, payload);
        for (const peer of set) if (peer !== socket && !peer.destroyed) peer.write(f);
      }
    }
  });
});

function frame(opcode, payload) {
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([head, payload]);
}

server.listen(PORT, () => console.log('voice relay listening on ' + PORT));
