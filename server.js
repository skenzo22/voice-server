// Voice relay server - no external libraries.
// - GET /                  -> "voice relay ok" (also used by the app to wake the server)
// - GET /admin             -> admin panel (needs the ADMIN_PASSWORD environment variable on Render)
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
const MAX_CLIENTS = 400;        // whole server
const MAX_FRAMES_PER_SEC = 150; // a normal speaker sends 50; more than this is abuse and is dropped
const BAN_MS = 10 * 60 * 1000;  // a person removed by the admin cannot come back for 10 minutes
let totalClients = 0;
const byCid = new Map();       // client id -> connection (one live connection per phone)
const rooms = new Map();        // room -> Map(id -> client)
const bans = new Map();         // "c:<cid>" or "i:<ip>" -> time when the ban ends

// ---------------------------------------------------------------- admin panel
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const adminHash = ADMIN_PASSWORD ? sha(ADMIN_PASSWORD) : null;
// A key derived from the password (not the password itself). The admin apps put it in the connection address,
// so the server knows this connection is the real admin and shows it as the verified "Admin".
const ADMIN_WS_TOKEN = ADMIN_PASSWORD
  ? crypto.createHmac('sha256', ADMIN_PASSWORD).update('voice-admin-ws').digest('hex') : '';

// Nobody else may use a name that looks like the admin's (the server renames them to "Player").
function isReserved(n) {
  const a = String(n).normalize('NFKC').toLowerCase();
  const latin = a.replace(/[^a-z]/g, '');
  const ar = a.replace(/[أإآٱ]/g, 'ا').replace(/[ً-ٟـ]/g, '').replace(/[^ء-ي]/g, '');
  return latin.includes('admin') || ar.includes('ادمن') || ar.includes('مشرف');
}

// ---------------------------------------------------------------- health numbers (shown in the admin app)
const stats = { start: Date.now(), peak: 0, joins: 0, rejected: 0, framesIn: 0, framesOut: 0, bytesOut: 0, dropped: 0, rateLimited: 0 };
const rates = { framesIn: 0, framesOut: 0, kbpsOut: 0, dropped: 0, cpuPct: 0, lagMs: 0 };
let lagMax = 0, lastTick = Date.now();
setInterval(() => { // how late the server's own timer runs: the best sign that it is overloaded
  const n = Date.now();
  lagMax = Math.max(lagMax, n - lastTick - 500);
  lastTick = n;
}, 500);
let prev = { t: Date.now(), fi: 0, fo: 0, bo: 0, dr: 0, cpu: process.cpuUsage() };
setInterval(() => {
  const n = Date.now();
  const sec = Math.max(1, (n - prev.t) / 1000);
  const cpu = process.cpuUsage(prev.cpu);
  rates.framesIn = Math.round((stats.framesIn - prev.fi) / sec);
  rates.framesOut = Math.round((stats.framesOut - prev.fo) / sec);
  rates.kbpsOut = Math.round((stats.bytesOut - prev.bo) * 8 / 1000 / sec);
  rates.dropped = Math.round(((stats.dropped - prev.dr) / sec) * 10) / 10;
  rates.cpuPct = Math.round((cpu.user + cpu.system) / 1000 / (sec * 1000) * 1000) / 10;
  rates.lagMs = lagMax;
  lagMax = 0;
  prev = { t: n, fi: stats.framesIn, fo: stats.framesOut, bo: stats.bytesOut, dr: stats.dropped, cpu: process.cpuUsage() };
}, 5000);
const failedLogins = new Map(); // ip -> { n, first }
const MAX_FAILS = 10;
const FAIL_WINDOW = 10 * 60 * 1000;

function clientIp(req) {
  const x = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return x || req.socket.remoteAddress || '';
}

function reply(res, code, type, body, extra) {
  res.writeHead(code, Object.assign({ 'Content-Type': type, 'Cache-Control': 'no-store' }, extra || {}));
  res.end(body);
}

// returns true when the request carries the right password; otherwise it answers the request itself
function adminAuthed(req, res) {
  if (!adminHash) { reply(res, 404, 'text/plain', 'Not found'); return false; }
  const ip = clientIp(req);
  const now = Date.now();
  let f = failedLogins.get(ip);
  if (f && now - f.first > FAIL_WINDOW) { failedLogins.delete(ip); f = null; }
  if (f && f.n >= MAX_FAILS) { reply(res, 429, 'application/json', '{"error":"too many attempts"}'); return false; }
  const given = sha(req.headers['x-admin-key'] || '');
  if (!crypto.timingSafeEqual(given, adminHash)) {
    if (failedLogins.size > 5000) failedLogins.clear();
    if (!f) { f = { n: 0, first: now }; failedLogins.set(ip, f); }
    f.n++;
    reply(res, 401, 'application/json', '{"error":"unauthorized"}');
    return false;
  }
  failedLogins.delete(ip);
  return true;
}

function roomsSnapshot() {
  const now = Date.now();
  const list = [];
  for (const [room, members] of rooms) {
    list.push({
      room,
      count: members.size,
      members: Array.from(members.values()).map((c) => ({
        id: c.id, name: c.name, ver: c.ver,
        muted: !!c.micMuted, admin: !!c.admin,
        speaking: now - c.lastAudio < 500,
      })),
    });
  }
  list.sort((a, b) => b.count - a.count || (a.room < b.room ? -1 : 1));
  return { total: totalClients, rooms: list };
}

function healthSnapshot() {
  const now = Date.now();
  let speaking = 0;
  for (const members of rooms.values()) for (const c of members.values()) if (now - c.lastAudio < 500) speaking++;
  const mem = process.memoryUsage();
  let level = 'ok';
  if (rates.lagMs > 80 || totalClients > MAX_CLIENTS * 0.7 || mem.rss > 400 * 1048576 || rates.dropped > 1) level = 'busy';
  if (rates.lagMs > 250 || totalClients >= MAX_CLIENTS || rates.dropped > 10) level = 'overload';
  return {
    level,
    uptime: Math.round((now - stats.start) / 1000),
    clients: totalClients, peak: stats.peak, maxClients: MAX_CLIENTS,
    rooms: rooms.size, speaking,
    memMb: Math.round(mem.rss / 1048576), cpuPct: rates.cpuPct, lagMs: rates.lagMs,
    framesIn: rates.framesIn, framesOut: rates.framesOut, kbpsOut: rates.kbpsOut, dropPerSec: rates.dropped,
    droppedTotal: stats.dropped, rateLimited: stats.rateLimited,
    joins: stats.joins, rejected: stats.rejected,
  };
}

function kickClient(room, id) {
  const members = rooms.get(room);
  const c = members && members.get(id);
  if (!c || c.admin) return false;
  bans.set(c.cid ? 'c:' + c.cid : 'i:' + c.ip, Date.now() + BAN_MS);
  send(c, 8, Buffer.alloc(0));
  removeClient(c);
  return true;
}

const ADMIN_HTML = String.raw`<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>لوحة التحكم - الدردشة الصوتية</title>
<style>
:root{--bg:#0a0a0a;--card:#151515;--line:#2a2a2a;--red:#e0242b;--text:#f2f2f2;--dim:#9a9a9a;--ok:#2fbf71}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;padding:16px 16px 110px}
h1{font-size:20px;margin:0}
header{display:flex;align-items:center;gap:12px;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap}
.stat{color:var(--dim);font-size:14px}
button{font:inherit;color:var(--text);background:#1f1f1f;border:1px solid var(--line);border-radius:10px;padding:8px 14px;cursor:pointer}
button.red{background:var(--red);border-color:var(--red);font-weight:600}
button:disabled{opacity:.5}
input[type=password]{font:inherit;color:var(--text);background:#101010;border:1px solid var(--line);border-radius:10px;padding:10px 12px;width:100%}
#login{max-width:320px;margin:20vh auto 0;display:flex;flex-direction:column;gap:10px}
#err{color:var(--red);min-height:1.2em;font-size:14px}
#app{display:none}
#rooms{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.room{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px}
.room.me{border-color:var(--red)}
.room h2{font-size:16px;margin:0 0 8px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.room h2 span{color:var(--dim);font-weight:400;font-size:13px}
.p{display:flex;align-items:center;gap:8px;padding:6px 0;border-top:1px solid var(--line);font-size:14px}
.p .n{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dot{width:10px;height:10px;border-radius:50%;background:#444;flex:none}
.dot.talk{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.m{color:var(--dim);font-size:12px}
.k{padding:3px 8px;font-size:12px;color:var(--red)}
.empty{color:var(--dim);text-align:center;padding:40px 0}
details{margin-bottom:14px;color:var(--dim);font-size:13px}
details label{margin-inline-end:14px}
select{font:inherit;background:#101010;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:3px 6px}
#bar{display:none;position:fixed;inset-inline:0;bottom:0;background:#111;border-top:1px solid var(--red);padding:12px 16px;align-items:center;gap:12px;justify-content:space-between;flex-wrap:wrap}
.opts{display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--dim);flex:1;min-width:220px}
.opts input[type=range]{width:140px;vertical-align:middle}
#lvl{height:8px;background:#222;border-radius:4px;overflow:hidden}
#lvl i{display:block;height:100%;width:0;background:var(--ok)}
#bar .t{font-size:14px}
#talk{min-width:150px;padding:14px 18px;touch-action:none;user-select:none;-webkit-user-select:none}
#talk.on{background:var(--ok);border-color:var(--ok);color:#000}
#msg{color:var(--dim);font-size:13px;margin-bottom:10px;min-height:1.2em}
</style>
</head>
<body>
<div id="login">
  <h1>لوحة التحكم</h1>
  <input id="pw" type="password" placeholder="كلمة السر" autocomplete="current-password">
  <button class="red" id="go">دخول</button>
  <div id="err"></div>
</div>
<div id="app">
  <header>
    <h1>الغرف المفتوحة</h1>
    <div><span class="stat" id="stat"></span> <button id="out">خروج</button></div>
  </header>
  <div id="msg"></div>
  <div id="rooms"></div>
</div>
<div id="bar">
  <div class="t">أنت في الغرفة <b id="cur"></b> باسم Admin، ويراك الجميع في القائمة</div>
  <div class="opts">
    <label>قوة المايك <input type="range" id="gain" min="50" max="800" value="300"> <span id="gv">300%</span></label>
    <label><input type="checkbox" id="nsup"> تنقية المتصفح (أوقفها مع السماعة)</label>
    <div id="lvl"><i></i></div>
  </div>
  <div><button id="talk">اضغط للكلام</button> <button id="leave">خروج من الغرفة</button></div>
</div>
<script>
(function(){
var key='';try{key=sessionStorage.getItem('k')||''}catch(e){}
var $=function(id){return document.getElementById(id)};
var ws=null,joined=null,ctx=null,nextT=0,mic=null,proc=null,talking=false,want=false,timer=null,lvlPeak=0,wst='';
var cid='adm'+Math.random().toString(36).slice(2,12)+Date.now().toString(36);

function api(path,method){
  return fetch(path,{method:method||'GET',headers:{'x-admin-key':key},cache:'no-store'}).then(function(r){
    if(r.status===401||r.status===429){var s=r.status;logout(s===429?'محاولات كثيرة، انتظر قليلاً':'كلمة السر خاطئة');throw new Error('auth')}
    return r.json();
  });
}
function showApp(on){$('login').style.display=on?'none':'flex';$('app').style.display=on?'block':'none'}
function logout(msg){
  key='';try{sessionStorage.removeItem('k')}catch(e){}
  leave();clearTimeout(timer);showApp(false);$('err').textContent=msg||'';
}
function login(){
  key=$('pw').value;$('err').textContent='';
  api('/admin/api/rooms').then(function(d){
    try{sessionStorage.setItem('k',key)}catch(e){}
    showApp(true);render(d);poll();
  }).catch(function(e){if(e&&e.message!=='auth')$('err').textContent='تعذر الاتصال بالسيرفر'});
}
function poll(){
  clearTimeout(timer);
  api('/admin/api/rooms').then(render).catch(function(){}).then(function(){
    if(key)timer=setTimeout(poll,2000);
  });
}
function render(d){
  wst=d.wst||wst;
  $('stat').textContent='المتصلون: '+d.total+' | الغرف: '+d.rooms.length;
  var box=$('rooms');box.textContent='';
  if(!d.rooms.length){var e=document.createElement('div');e.className='empty';e.textContent='لا توجد غرف الآن';box.appendChild(e);return}
  d.rooms.forEach(function(r){
    var c=document.createElement('div');c.className='room'+(r.room===joined?' me':'');
    var h=document.createElement('h2');
    var t=document.createElement('div');t.textContent='غرفة '+r.room;
    var s=document.createElement('span');s.textContent=r.count+' / 16';t.appendChild(document.createTextNode(' '));t.appendChild(s);
    var j=document.createElement('button');j.textContent=r.room===joined?'داخل الغرفة':'دخول';j.disabled=r.room===joined;
    j.onclick=function(){join(r.room)};
    h.appendChild(t);h.appendChild(j);c.appendChild(h);
    r.members.forEach(function(m){
      var p=document.createElement('div');p.className='p';
      var d1=document.createElement('span');d1.className='dot'+(m.speaking?' talk':'');
      var n=document.createElement('span');n.className='n';n.textContent=m.name;
      var st=document.createElement('span');st.className='m';st.textContent=m.muted?'مايك مغلق':'';
      var k=document.createElement('button');k.className='k';k.textContent='إخراج';
      k.onclick=function(){if(confirm('إخراج '+m.name+' من الغرفة ومنعه 10 دقائق؟'))
        api('/admin/api/kick?room='+encodeURIComponent(r.room)+'&id='+m.id,'POST').then(poll)};
      p.appendChild(d1);p.appendChild(n);p.appendChild(st);p.appendChild(k);c.appendChild(p);
    });
    box.appendChild(c);
  });
}

function join(room){
  leave();
  var AC=window.AudioContext||window.webkitAudioContext;
  if(!ctx)ctx=new AC();
  if(ctx.resume)ctx.resume();
  var proto=location.protocol==='https:'?'wss://':'ws://';
  var w=new WebSocket(proto+location.host+'/?room='+encodeURIComponent(room)+'&name=Admin&v=3&cid='+cid+'&ak='+wst);
  w.binaryType='arraybuffer';
  var opened=false;
  ws=w;
  w.onopen=function(){opened=true;joined=room;nextT=0;$('cur').textContent=room;$('bar').style.display='flex';$('msg').textContent='';w.send('m1');poll()};
  w.onmessage=function(e){
    if(typeof e.data==='string')return;
    var u=new Uint8Array(e.data);
    if(u.length>2&&u[0]===1)play(u.subarray(2));
  };
  w.onclose=function(){
    if(ws!==w)return;
    ws=null;joined=null;stopMic();$('bar').style.display='none';
    $('msg').textContent=opened?'انقطع الاتصال بالغرفة':'تعذر الدخول (الغرفة ممتلئة أو محظور مؤقتاً)';
    poll();
  };
}
function leave(){
  want=false;talking=false;
  var w=ws;ws=null;joined=null;
  if(w){try{w.close()}catch(e){}}
  stopMic();$('bar').style.display='none';$('talk').classList.remove('on');
}
function stopMic(){
  if(proc){try{proc.disconnect()}catch(e){}proc.onaudioprocess=null;proc=null}
  if(mic){mic.getTracks().forEach(function(t){t.stop()});mic=null}
}

// The app sends 16 kHz mono, G.711 mu-law, 8 bit, 320 samples (20 ms) per frame.
var RATE=16000,FRAME=320;
function mu2lin(b){var u=~b&255,sg=u&128,ex=(u>>4)&7,mt=u&15,s=((mt<<3)+132)<<ex;s-=132;return sg?-s:s}
function lin2mu(x){var s=x,sg=(s>>8)&128;if(sg)s=-s;if(s>32635)s=32635;s+=132;var ex=7;for(var m=16384;(s&m)===0&&ex>0;m>>=1)ex--;var mt=(s>>(ex+3))&15;return (~(sg|(ex<<4)|mt))&255}
var MU=new Float32Array(256);for(var k=0;k<256;k++)MU[k]=mu2lin(k)/32768;

function play(u8){
  if(!ctx)return;
  var n=u8.length;if(n<1)return;
  var rate=RATE;
  var buf=ctx.createBuffer(1,n,rate),ch=buf.getChannelData(0);
  for(var i=0;i<n;i++)ch[i]=MU[u8[i]];
  var s=ctx.createBufferSource();s.buffer=buf;s.connect(ctx.destination);
  var t=ctx.currentTime;
  if(nextT<t+0.02||nextT>t+0.6)nextT=t+0.08;
  s.start(nextT);nextT+=n/rate;
}

function ensureMic(){
  if(mic)return Promise.resolve();
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia)return Promise.reject(new Error('nomic'));
  var clean=$('nsup').checked;
  return navigator.mediaDevices.getUserMedia({audio:{echoCancellation:clean,noiseSuppression:clean,autoGainControl:true}}).then(function(s){
    mic=s;
    var src=ctx.createMediaStreamSource(s);
    proc=ctx.createScriptProcessor(2048,1,1);
    var ratio=ctx.sampleRate/RATE,acc=0,cnt=0,pos=0,q=[];
    proc.onaudioprocess=function(e){
      if(!talking||!ws||ws.readyState!==1)return;
      var d=e.inputBuffer.getChannelData(0),g=(+$('gain').value)/100,peak=0;
      for(var i=0;i<d.length;i++){
        acc+=d[i];cnt++;pos+=1;
        if(pos>=ratio){
          pos-=ratio;
          var v=Math.max(-1,Math.min(1,acc/cnt*g));acc=0;cnt=0;
          if(Math.abs(v)>peak)peak=Math.abs(v);
          q.push(Math.round(v*32767));
        }
      }
      lvlPeak=Math.max(peak,lvlPeak*0.85); // holds the peak briefly so the meter is readable
      $('lvl').firstChild.style.width=Math.round(lvlPeak*100)+'%';
      while(q.length>=FRAME){
        var f=q.splice(0,FRAME),b=new Uint8Array(FRAME);
        for(var j=0;j<FRAME;j++)b[j]=lin2mu(f[j]);
        if(ws.bufferedAmount<65536)ws.send(b);
      }
    };
    var z=ctx.createGain();z.gain.value=0;
    src.connect(proc);proc.connect(z);z.connect(ctx.destination);
  });
}
function down(){
  if(!ws||want)return;
  want=true;
  ensureMic().then(function(){
    if(!want||!ws)return;
    talking=true;$('talk').classList.add('on');$('talk').textContent='تتكلم الآن';
    ws.send('m0');
  }).catch(function(){want=false;$('msg').textContent='تعذر فتح المايك. اسمح للموقع باستخدام المايك، ويحتاج اتصالاً آمناً https'});
}
function up(){
  want=false;
  if(talking){talking=false;try{if(ws)ws.send('m1')}catch(e){}}
  $('talk').classList.remove('on');$('talk').textContent='اضغط للكلام';
}

var tb=$('talk');
tb.addEventListener('pointerdown',function(e){e.preventDefault();try{tb.setPointerCapture(e.pointerId)}catch(x){}down()});
tb.addEventListener('pointerup',up);
tb.addEventListener('pointercancel',up);
tb.addEventListener('contextmenu',function(e){e.preventDefault()});
document.addEventListener('keydown',function(e){
  if(e.code==='Space'&&!e.repeat&&ws&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){e.preventDefault();down()}
});
document.addEventListener('keyup',function(e){if(e.code==='Space')up()});
$('gain').oninput=function(){$('gv').textContent=this.value+'%'};
$('nsup').onchange=function(){stopMic()}; // the new setting is used the next time the mic opens
$('go').onclick=login;
$('pw').addEventListener('keydown',function(e){if(e.key==='Enter')login()});
$('out').onclick=function(){logout('')};
$('leave').onclick=function(){leave();poll()};
window.addEventListener('beforeunload',function(){leave()});
if(key){
  api('/admin/api/rooms').then(function(d){showApp(true);render(d);poll()}).catch(function(){});
}
})();
</script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  const path = (req.url || '/').split('?')[0];
  if (path === '/admin' || path === '/admin/') {
    if (!adminHash) return reply(res, 404, 'text/plain', 'Not found');
    return reply(res, 200, 'text/html; charset=utf-8', ADMIN_HTML, {
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ws: wss:",
    });
  }
  if (path === '/admin/api/rooms' && req.method === 'GET') {
    if (!adminAuthed(req, res)) return;
    return reply(res, 200, 'application/json', JSON.stringify(Object.assign(roomsSnapshot(), { wst: ADMIN_WS_TOKEN })));
  }
  if (path === '/admin/api/health' && req.method === 'GET') {
    if (!adminAuthed(req, res)) return;
    return reply(res, 200, 'application/json', JSON.stringify(healthSnapshot()));
  }
  if (path === '/admin/api/kick' && req.method === 'POST') {
    if (!adminAuthed(req, res)) return;
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch (e) { return reply(res, 400, 'application/json', '{"error":"bad"}'); }
    const ok = kickClient(url.searchParams.get('room') || '', parseInt(url.searchParams.get('id'), 10));
    return reply(res, 200, 'application/json', JSON.stringify({ ok }));
  }
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

function writeFrame(client, buf, droppable) {
  const s = client.socket;
  if (s.destroyed || !s.writable) return;
  if (droppable && s.writableLength > MAX_BACKLOG) { stats.dropped++; return; } // drop audio, never queue it forever
  stats.framesOut++;
  stats.bytesOut += buf.length;
  s.write(buf);
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
        const flags = (m.micMuted ? 1 : 0) | (m === c ? 2 : 0) | (m.admin ? 4 : 0); // 4 = verified admin
        parts3.push(Buffer.from([id, flags, nb.length]), nb);
      }
      send(c, 2, Buffer.concat(parts3));
    }
  }
}

function removeClient(client) {
  if (client.removed) return;
  client.removed = true;
  totalClients--;
  if (client.cid && byCid.get(client.cid) === client) byCid.delete(client.cid);
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
    // a speaker cannot send more than a normal number of frames per second
    const now = Date.now();
    if (now - client.winStart >= 1000) { client.winStart = now; client.winFrames = 0; }
    if (++client.winFrames > MAX_FRAMES_PER_SEC) { stats.rateLimited++; return; }
    stats.framesIn++;
    client.lastAudio = now; // lets the admin panel show who is speaking
    // build each kind of frame ONCE and give the same bytes to every listener
    let frameV2 = null, frameRaw = null;
    for (const c of members.values()) {
      if (c === client) continue;
      if (client.blocked.size && client.blocked.has(c.id)) continue; // he asked not to be heard by this person
      if (c.ver >= 2) {
        if (!frameV2) frameV2 = frame(2, Buffer.concat([Buffer.from([1, client.id]), payload]));
        writeFrame(c, frameV2, true);
      } else {
        if (!frameRaw) frameRaw = frame(2, payload);
        writeFrame(c, frameRaw, true);
      }
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
  // the verified admin: the connection carries the key derived from the admin password
  const ak = url.searchParams.get('ak') || '';
  const isAdmin = !!ADMIN_WS_TOKEN && ak.length === ADMIN_WS_TOKEN.length &&
    crypto.timingSafeEqual(Buffer.from(ak), Buffer.from(ADMIN_WS_TOKEN));
  let displayName = isAdmin ? 'Admin' : cleanName(url.searchParams.get('name'));
  if (!isAdmin && isReserved(displayName)) displayName = 'Player';
  if (totalClients >= MAX_CLIENTS && !isAdmin) {
    stats.rejected++;
    socket.end('HTTP/1.1 503 Server Full\r\n\r\n');
    return;
  }
  const cid =(url.searchParams.get('cid') || '').replace(/[^0-9a-zA-Z]/g, '').slice(0, 40);
  const ip = clientIp(req);
  const banKey = cid.length >= 8 ? 'c:' + cid : 'i:' + ip;
  if (!isAdmin && (bans.get(banKey) || 0) > Date.now()) {
    stats.rejected++;
    socket.end('HTTP/1.1 403 Removed By Admin\r\n\r\n');
    return;
  }
  let members = rooms.get(room);
  if (members && members.size >= MAX_ROOM_USERS && !isAdmin) {
    stats.rejected++;
    socket.end('HTTP/1.1 503 Room Full\r\n\r\n');
    return;
  }
  // the same phone connecting again (toggle, network change, app restart): drop its older connection first
  if (cid.length >= 8 && byCid.has(cid)) removeClient(byCid.get(cid));
  members = rooms.get(room);
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
    socket, room, id, ip, admin: isAdmin,
    name: displayName,
    ver: parseInt(url.searchParams.get('v') || '1', 10) || 1,
    cid: cid.length >= 8 ? cid : '',
    micMuted: false,
    blocked: new Set(),
    winStart: 0, winFrames: 0, lastAudio: 0,
    alive: true, removed: false,
  };
  members.set(id, client);
  totalClients++;
  stats.joins++;
  if (totalClients > stats.peak) stats.peak = totalClients;
  if (client.cid) byCid.set(client.cid, client);
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
  const now = Date.now();
  for (const [k, until] of bans) if (until <= now) bans.delete(k);
}, 25000);

server.listen(PORT, () => console.log('voice relay listening on ' + PORT + (adminHash ? ' (admin panel on /admin)' : ' (admin panel off: set ADMIN_PASSWORD)')));
