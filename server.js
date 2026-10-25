const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { exec, execFile, spawn, spawnSync } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);
// reloadFrankenPHP is a function declaration further down (hoisted), safe to wrap here.
const reloadFrankenPHPAsync = promisify(reloadFrankenPHP);
const si = require('systeminformation');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const crypto = require('crypto');
const Redis = require('ioredis');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PANEL_PORT || 8765;
const CREDS_FILE = '/root/.pspanel_credentials';
const AUTH_FILE  = process.env.PANEL_AUTH_FILE || '/root/.pspanel_auth';

// ── Self-update config ──
const https = require('https');
const PANEL_DIR = __dirname;
// Raw GitHub base used to check for / download new panel versions.
const GITHUB_RAW = process.env.PANEL_UPDATE_URL || 'https://raw.githubusercontent.com/setiawansopan/PS-Panel/main';

app.use(express.json({ limit: '100mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
// GitHub webhooks can also be configured with content type
// application/x-www-form-urlencoded (body: payload=<json>); the HMAC signature
// covers that raw form body, so keep it too.
app.use(express.urlencoded({ extended: false, limit: '25mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Credentials ──
function getCreds() {
  const c = {};
  if (fs.existsSync(CREDS_FILE))
    fs.readFileSync(CREDS_FILE,'utf8').split('\n').forEach(l => {
      const i = l.indexOf('='); if (i <= 0) return;   // split on the FIRST '=' only: a password may contain '='
      const k = l.slice(0, i).trim(), v = l.slice(i + 1).replace(/\r$/, ''); if (k && v) c[k] = v;
    });
  return c;
}

// ── Auth ──
// Persistent auth state lives in AUTH_FILE (mode 600): { user, hash, secret, tv }.
//  - user   admin username (lowercase). Installs from before usernames existed get 'admin'.
//  - hash   bcrypt hash of the admin password. Once the file exists it is the source of
//           truth; PANEL_PASS (creds file / env) is only the initial password and is ignored
//           afterwards, so a password changed from the panel survives restarts.
//  - secret JWT signing secret, persisted so sessions survive restarts (PANEL_SECRET env wins).
//  - tv     token version, bumped on password change to invalidate every existing token.
function loadAuthState() {
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')); } catch { return {}; }
}
function saveAuthState(st) {
  const tmp = AUTH_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
  fs.renameSync(tmp, AUTH_FILE);
}
const USER_RE = /^[a-z0-9._-]{3,32}$/;
const normUser = u => String(u || '').trim().toLowerCase();
const authState = loadAuthState();
let dirty = false;
if (!USER_RE.test(authState.user || '')) {
  const u = normUser(getCreds().PANEL_USER || process.env.PANEL_USER);
  authState.user = USER_RE.test(u) ? u : 'admin';
  dirty = true;
}
if (!authState.hash) {
  authState.hash = bcrypt.hashSync(getCreds().PANEL_PASS || process.env.PANEL_PASS || 'admin123', 10);
  dirty = true;
}
if (!authState.secret) { authState.secret = crypto.randomBytes(32).toString('hex'); dirty = true; }
if (!Number.isInteger(authState.tv)) { authState.tv = 0; dirty = true; }
if (dirty) { try { saveAuthState(authState); } catch (e) { console.warn('[auth] cannot persist', AUTH_FILE, e.message); } }

const SECRET = process.env.PANEL_SECRET || authState.secret;
const MIN_PASS_LEN = 8;
function signToken() { return jwt.sign({ role: 'admin', tv: authState.tv }, SECRET, { expiresIn: '8h' }); }
function verifyToken(t) {
  const p = jwt.verify(t, SECRET);
  if ((p.tv || 0) !== authState.tv) throw new Error('token revoked');
  return p;
}
function setPassword(newPass) {
  authState.hash = bcrypt.hashSync(newPass, 10);
  authState.tv += 1;
  saveAuthState(authState);
}

// CLI: node server.js --init-credentials   (used by install.sh; reads PANEL_INIT_USER / PANEL_INIT_PASS
// from the environment so the password never appears in the process list)
if (process.argv.includes('--init-credentials')) {
  const u = normUser(process.env.PANEL_INIT_USER || 'admin'), pw = process.env.PANEL_INIT_PASS || '';
  if (!USER_RE.test(u)) { console.error('Username harus 3-32 karakter: huruf kecil, angka, titik, minus, garis bawah.'); process.exit(1); }
  if (pw.length < MIN_PASS_LEN) { console.error(`Password minimal ${MIN_PASS_LEN} karakter.`); process.exit(1); }
  authState.user = u; setPassword(pw);
  console.log(`Kredensial panel disetel (username: ${u}).`);
  process.exit(0);
}
// CLI: node server.js --set-username <name>
if (process.argv.includes('--set-username')) {
  const u = normUser(process.argv[process.argv.indexOf('--set-username') + 1]);
  if (!USER_RE.test(u)) { console.error('Username harus 3-32 karakter: huruf kecil, angka, titik, minus, garis bawah.'); process.exit(1); }
  authState.user = u; authState.tv += 1; saveAuthState(authState);
  console.log(`Username panel diganti menjadi: ${u}`);
  console.log('Semua sesi login lama dibatalkan. Jika panel sedang berjalan: pm2 restart ps-panel');
  process.exit(0);
}
// CLI: node server.js --reset-password [newpassword]
if (process.argv.includes('--reset-password')) {
  const i = process.argv.indexOf('--reset-password');
  const pw = process.argv[i + 1] && !process.argv[i + 1].startsWith('--')
    ? process.argv[i + 1]
    : crypto.randomBytes(9).toString('base64url');
  if (pw.length < MIN_PASS_LEN) { console.error(`Password minimal ${MIN_PASS_LEN} karakter.`); process.exit(1); }
  setPassword(pw);
  console.log(`Password panel direset. Username: ${authState.user}  Password baru: ${pw}`);
  console.log('Semua sesi login lama dibatalkan. Jika panel sedang berjalan: pm2 restart ps-panel');
  process.exit(0);
}

function auth(req,res,next){
  const t = req.headers.authorization?.split(' ')[1];
  if(!t) return res.status(401).json({error:'Unauthorized'});
  try { req.user = verifyToken(t); next(); }
  catch { res.status(401).json({error:'Invalid token'}); }
}

// ── Rate limiting (login) ──
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const WINDOW = 15 * 60 * 1000;
  const e = loginAttempts.get(ip) || { count: 0, resetAt: now + WINDOW };
  if (now > e.resetAt) { e.count = 0; e.resetAt = now + WINDOW; }
  e.count++;
  loginAttempts.set(ip, e);
  return e.count > 5;
}

app.post('/api/login',(req,res)=>{
  const ip = req.ip || req.socket.remoteAddress;
  if (checkRateLimit(ip)) return res.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
  const { username, password } = req.body || {};
  // bcrypt always runs so a wrong username takes as long as a wrong password
  const passOk = typeof password === 'string' && bcrypt.compareSync(password, authState.hash);
  if (passOk && normUser(username) === authState.user) { loginAttempts.delete(ip); res.json({ token: signToken(), username: authState.user }); }
  else res.status(401).json({ error: 'Username atau password salah' });
});

app.get('/api/account', auth, (req, res) => res.json({ ok: true, username: authState.user, version: (localVersion() || {}).version || null }));

// Re-check the password for the current session (used to unlock edit forms; not a login).
app.post('/api/verify-password', auth, (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (checkRateLimit('pw:' + ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { password } = req.body || {};
  if (typeof password === 'string' && bcrypt.compareSync(password, authState.hash)) { loginAttempts.delete('pw:' + ip); return res.json({ ok: true }); }
  res.status(403).json({ error: 'Wrong password' });
});

app.post('/api/username', auth, (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (checkRateLimit('pw:' + ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { password, newUsername } = req.body || {};
  if (typeof password !== 'string' || !bcrypt.compareSync(password, authState.hash)) return res.status(403).json({ error: 'Password salah' });
  const u = normUser(newUsername);
  if (!USER_RE.test(u)) return res.status(400).json({ error: 'Username harus 3-32 karakter: huruf kecil, angka, titik, minus, garis bawah' });
  if (u === authState.user) return res.status(400).json({ error: 'Username baru sama dengan yang sekarang' });
  try { authState.user = u; authState.tv += 1; saveAuthState(authState); }   // old sessions must log in with the new name
  catch (e) { return res.status(500).json({ error: 'Gagal menyimpan: ' + e.message }); }
  loginAttempts.delete('pw:' + ip);
  res.json({ ok: true, username: u });
});

app.post('/api/password', auth, (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (checkRateLimit('pw:' + ip)) return res.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
  const { oldPassword, newPassword } = req.body || {};
  if (typeof oldPassword !== 'string' || typeof newPassword !== 'string')
    return res.status(400).json({error:'Password lama dan baru wajib diisi'});
  if (!bcrypt.compareSync(oldPassword, authState.hash))
    return res.status(403).json({error:'Password lama salah'});
  if (newPassword.length < MIN_PASS_LEN)
    return res.status(400).json({error:`Password baru minimal ${MIN_PASS_LEN} karakter`});
  if (newPassword === oldPassword)
    return res.status(400).json({error:'Password baru tidak boleh sama dengan yang lama'});
  try { setPassword(newPassword); }
  catch (e) { return res.status(500).json({error:'Gagal menyimpan: ' + e.message}); }
  loginAttempts.delete('pw:' + ip);
  res.json({ok:true});
});

// ── Services ──
const SERVICES = {
  frankenphp: {name:'FrankenPHP', unit:'frankenphp'},
  postgresql: {name:'PostgreSQL', unit:'postgresql'},
  redis:      {name:'Redis',      unit:'redis-server'},
  node:       {name:'Node.js',    unit:null},
};
async function svcStatus(unit){
  if(!unit) return 'unknown';
  return new Promise(r=>exec(`systemctl is-active ${unit}`,(e,o)=>r(o.trim())));
}
app.get('/api/services', auth, async(req,res)=>{
  const out={};
  for(const[k,s] of Object.entries(SERVICES))
    out[k]={...s, status: await svcStatus(s.unit)};
  res.json(out);
});
app.post('/api/services/:name/:action', auth,(req,res)=>{
  const {name,action}=req.params;
  const s=SERVICES[name];
  if(!s||!s.unit) return res.status(404).json({error:'Not found'});
  if(!['start','stop','restart'].includes(action)) return res.status(400).json({error:'Bad action'});
  exec(`systemctl ${action} ${s.unit}`,(err,_,se)=>{
    if(err) return res.status(500).json({error:se});
    res.json({ok:true});
  });
});

// ── System metrics ──
app.get('/api/metrics', auth, async(req,res)=>{
  try {
    // Individual catches so one failing call doesn't kill the entire response
    const [cpu, mem, disk, net, procs, temp] = await Promise.all([
      si.currentLoad().catch(()=>({currentLoad:0,cpus:[],avgLoad1:0,avgLoad5:0,avgLoad15:0})),
      si.mem().catch(()=>({used:0,total:1,free:0,cached:0})),
      si.fsSize().catch(()=>[]),
      si.networkStats().catch(()=>[]),
      si.processes().catch(()=>({list:[]})),
      si.cpuTemperature().catch(()=>null),
    ]);

    const topProcs = (procs.list||[])
      .sort((a,b)=>(b.pcpu||0)-(a.pcpu||0))
      .slice(0,5)
      .map(p=>({name:p.name, pid:p.pid, cpu:(p.pcpu||0).toFixed(1), mem:(p.pmem||0).toFixed(1), memVsz: p.mem_vsz||0}));

    const netIface = (net||[]).find(n=>n.iface!=='lo') || (net||[])[0] || {};

    // avgLoad1/5/15 exist in systeminformation v5+; older versions only have avgLoad
    const loadAvg = cpu.avgLoad1 != null
      ? [cpu.avgLoad1, cpu.avgLoad5, cpu.avgLoad15]
      : [cpu.avgLoad, cpu.avgLoad, cpu.avgLoad];

    res.json({
      cpu: { pct: Math.round(cpu.currentLoad||0), cores: cpu.cpus?.length||1, speed: (cpu.currentLoad||0).toFixed(1) },
      mem: { used:mem.used||0, total:mem.total||1, free:mem.free||0, pct:Math.round(((mem.used||0)/(mem.total||1))*100), cached:mem.cached||0 },
      disk: disk[0] ? {used:disk[0].used, size:disk[0].size, pct:Math.round(disk[0].use||0), fs:disk[0].fs} : null,
      load: loadAvg.map(v=>(v||0).toFixed(2)),
      net: { rx: netIface.rx_bytes||0, tx: netIface.tx_bytes||0, rxSec: netIface.rx_sec||0, txSec: netIface.tx_sec||0, iface: netIface.iface||'eth0' },
      procs: topProcs,
      temp: temp?.main || null,
    });
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Redis stats ──
app.get('/api/redis', auth, async(req,res)=>{
  try {
    const redis = new Redis({ host:'127.0.0.1', port:6379, connectTimeout:3000, lazyConnect:true });
    await redis.connect();
    const info = await redis.info();
    let cfg = null; try { cfg = await redisConfigGet(redis); } catch {}
    await redis.quit();
    const parse = (key) => { const m=info.match(new RegExp(key+':(.+)')); return m?m[1].trim():null; };
    res.json({
      ok: true,
      version:       parse('redis_version'),
      uptime:        parse('uptime_in_seconds'),
      clients:       parse('connected_clients'),
      memUsed:       parse('used_memory'),
      memPeak:       parse('used_memory_peak'),
      memTotal:      parse('total_system_memory'),
      hitRate:       (() => {
        const hits   = parseInt(parse('keyspace_hits')||0);
        const misses = parseInt(parse('keyspace_misses')||0);
        const total  = hits+misses;
        return total>0 ? ((hits/total)*100).toFixed(1) : '0.0';
      })(),
      hits:          parse('keyspace_hits'),
      misses:        parse('keyspace_misses'),
      totalCmds:     parse('total_commands_processed'),
      totalConns:    parse('total_connections_received'),
      keyspaceHits:  parse('keyspace_hits'),
      evictions:     parse('evicted_keys'),
      opsPerSec:     parse('instantaneous_ops_per_sec'),
      role:          parse('role'),
      mode:          parse('redis_mode'),
      keyspace:      redisKeyspace(info),
      config:        cfg,
      recommended:   REDIS_RECOMMENDED,
      configFile:    parse('config_file') || '',
    });
  } catch(e){ res.json({ok:false, error:e.message}); }
});

// ── Redis config (CONFIG SET + CONFIG REWRITE) ──
const REDIS_RECOMMENDED = { maxmemory: '1gb', policy: 'volatile-lru', appendonly: 'yes', appendfsync: 'everysec' };
const REDIS_POLICIES = ['noeviction', 'allkeys-lru', 'volatile-lru', 'allkeys-lfu', 'volatile-lfu', 'allkeys-random', 'volatile-random', 'volatile-ttl'];
const REDIS_FSYNC = ['always', 'everysec', 'no'];
const redisClient = () => new Redis({ host: '127.0.0.1', port: 6379, connectTimeout: 3000, lazyConnect: true, maxRetriesPerRequest: 1 });
function redisKeyspace(info) {
  const out = [];
  for (const m of info.matchAll(/^(db\d+):keys=(\d+),expires=(\d+)(?:,avg_ttl=(\d+))?/gm)) out.push({ db: m[1], keys: +m[2], expires: +m[3], avgTtlMs: m[4] ? +m[4] : 0 });
  return out;
}
async function redisConfigGet(r) {
  const get = async k => { const a = await r.config('GET', k); return a && a[1] != null ? String(a[1]) : ''; };
  return { maxmemory: await get('maxmemory'), policy: await get('maxmemory-policy'), appendonly: await get('appendonly'), appendfsync: await get('appendfsync') };
}
// "512mb" / "1gb" / "0" → bytes (null when invalid)
function parseRedisMem(v) {
  const m = String(v).trim().toLowerCase().match(/^(\d+)(kb|mb|gb)?$/);
  if (!m) return null;
  return parseInt(m[1], 10) * ({ kb: 1024, mb: 1048576, gb: 1073741824 }[m[2]] || 1);
}
app.post('/api/redis/config', auth, async (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  const b = req.body || {}, want = {};
  if (b.maxmemory != null) {
    const bytes = parseRedisMem(b.maxmemory);
    if (bytes == null) return res.status(400).json({ ok: false, error: 'maxmemory tidak valid (contoh: 1gb, 512mb, atau 0 = tanpa batas)' });
    if (bytes !== 0 && bytes < 16 * 1048576) return res.status(400).json({ ok: false, error: 'maxmemory minimal 16mb' });
    if (bytes > os.totalmem()) return res.status(400).json({ ok: false, error: `maxmemory melebihi RAM server (${Math.round(os.totalmem() / 1048576)} MB)` });
    want.maxmemory = String(bytes);
  }
  if (b.policy != null) { if (!REDIS_POLICIES.includes(b.policy)) return res.status(400).json({ ok: false, error: 'maxmemory-policy tidak dikenal' }); want['maxmemory-policy'] = b.policy; }
  if (b.appendonly != null) { if (!['yes', 'no'].includes(b.appendonly)) return res.status(400).json({ ok: false, error: 'appendonly harus yes atau no' }); want.appendonly = b.appendonly; }
  if (b.appendfsync != null) { if (!REDIS_FSYNC.includes(b.appendfsync)) return res.status(400).json({ ok: false, error: 'appendfsync harus always, everysec, atau no' }); want.appendfsync = b.appendfsync; }
  if (!Object.keys(want).length) return res.status(400).json({ ok: false, error: 'tidak ada perubahan' });
  const r = redisClient();
  try {
    await r.connect();
    const info = await r.info('server');
    const cfgFile = (info.match(/config_file:(.*)/) || [])[1]?.trim() || '';
    const before = { maxmemory: (await r.config('GET', 'maxmemory'))[1], 'maxmemory-policy': (await r.config('GET', 'maxmemory-policy'))[1], appendonly: (await r.config('GET', 'appendonly'))[1], appendfsync: (await r.config('GET', 'appendfsync'))[1] };
    const done = [];
    try { for (const [k, v] of Object.entries(want)) { await r.config('SET', k, v); done.push(k); } }
    catch (e) {   // roll back whatever was already applied
      for (const k of done) { try { await r.config('SET', k, before[k]); } catch {} }
      return res.json({ ok: false, error: 'CONFIG SET gagal, dikembalikan: ' + e.message });
    }
    let backup = null, rewritten = false, rewriteError = null;
    if (!cfgFile) rewriteError = 'Redis berjalan tanpa berkas konfigurasi; perubahan aktif tetapi hilang saat Redis restart';
    else {
      try { backup = `${cfgFile}.bak.${Date.now()}`; fs.copyFileSync(cfgFile, backup); } catch { backup = null; }
      try { await r.config('REWRITE'); rewritten = true; }
      catch (e) { rewriteError = 'CONFIG REWRITE gagal (' + e.message + '); perubahan aktif tetapi belum permanen'; if (backup) { try { fs.copyFileSync(backup, cfgFile); } catch {} } }
    }
    autotuneLog(`EVENT redis config: ${JSON.stringify(want)} rewrite=${rewritten}`);
    res.json({ ok: true, rewritten, rewriteError, backup, config: await redisConfigGet(r) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
  finally { try { r.disconnect(); } catch {} }
});

// ── PostgreSQL stats ──
app.get('/api/postgres', auth, async(req,res)=>{
  try {
    const creds = getCreds();
    const pool = new Pool({
      host:'localhost', user:'postgres',
      password: creds.PG_PASSWORD||'', database:'postgres',
      connectionTimeoutMillis:3000,
    });
    const [conns, dbSizes, activity, locks] = await Promise.all([
      pool.query(`SELECT count(*) FROM pg_stat_activity`),
      pool.query(`SELECT datname, pg_database_size(datname) as size FROM pg_database WHERE datistemplate=false ORDER BY size DESC`),
      pool.query(`SELECT state, count(*) FROM pg_stat_activity GROUP BY state`),
      pool.query(`SELECT count(*) FROM pg_locks`),
    ]);
    await pool.end();
    res.json({
      ok: true,
      totalConnections: parseInt(conns.rows[0].count),
      databases: dbSizes.rows.map(r=>({name:r.datname, size:parseInt(r.size)})),
      activity: activity.rows,
      locks: parseInt(locks.rows[0].count),
    });
  } catch(e){ res.json({ok:false, error:e.message}); }
});

// ── FrankenPHP stats ──
app.get('/api/frankenphp', auth, async (req, res) => {
  try {
    const execP = (cmd) => new Promise(resolve =>
      exec(cmd, (_, out) => resolve((out || '').trim())));

    const showOut = await execP(
      'systemctl show frankenphp --no-pager ' +
      '--property=ActiveState,MainPID,MemoryCurrent,NRestarts,ActiveEnterTimestamp 2>/dev/null'
    );

    const parseShow = (key) => {
      const m = showOut.match(new RegExp(`^${key}=(.+)$`, 'm'));
      return m ? m[1].trim() : '';
    };

    const activeState = parseShow('ActiveState') || 'unknown';
    const pid         = parseInt(parseShow('MainPID'))  || 0;
    const memRaw      = parseShow('MemoryCurrent');
    const memBytes    = (memRaw && memRaw !== '[not set]' && parseInt(memRaw) < 1e15)
                          ? parseInt(memRaw) : null;
    const restarts    = parseInt(parseShow('NRestarts')) || 0;
    const enterTs     = parseShow('ActiveEnterTimestamp');

    let uptimeSec = null;
    if (enterTs) {
      const t = new Date(enterTs).getTime();
      if (!isNaN(t) && t > 0) uptimeSec = Math.floor((Date.now() - t) / 1000);
    }

    let vhostCount = 0;
    try {
      if (fs.existsSync('/etc/frankenphp/sites'))
        vhostCount = fs.readdirSync('/etc/frankenphp/sites')
          .filter(f => f.endsWith('.conf')).length;
    } catch {}

    const [workersOut, cpuOut, versionOut, logsOut] = await Promise.all([
      pid > 0 ? execP(`ps --ppid ${pid} -o pid= 2>/dev/null | wc -l`) : Promise.resolve('0'),
      pid > 0 ? execP(`ps -p ${pid} -o %cpu= 2>/dev/null`)            : Promise.resolve('0'),
      execP('frankenphp version 2>/dev/null || frankenphp --version 2>/dev/null'),
      execP('journalctl -u frankenphp --no-pager -n 20 --output=short-iso 2>/dev/null'),
    ]);

    const workers  = Math.max(0, parseInt(workersOut) || 0);
    const cpuPct   = parseFloat(cpuOut) || 0;
    const verMatch = versionOut.match(/v?\d+\.\d+\.\d+/);
    const version  = verMatch ? verMatch[0] : '—';
    const logs     = logsOut.split('\n').filter(l => l);

    res.json({ ok: activeState === 'active', status: activeState, version,
      pid: pid || null, uptimeSec, memBytes, cpuPct, restarts, workers, vhostCount, logs });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ── Virtual Hosts ──
const VHOSTS_DIR = '/etc/frankenphp/sites';
fs.mkdirSync(VHOSTS_DIR,{recursive:true});
const CADDYFILE_PATH = process.env.PANEL_CADDYFILE || '/etc/frankenphp/Caddyfile';

// CRITICAL self-heal: FrankenPHP's PHP app is only provisioned if the Caddyfile's
// global options block (the very first block, before any site) declares
// `frankenphp`. Without it, `php_server` directives still show up in the routing
// table, but every request that hits one hangs forever — no error, no log entry,
// nothing — because the PHP runtime behind it was never started. Older installs
// (before this was added to install.sh) shipped without this block by default,
// and it only ever got added as an accidental side effect of changing the
// num_threads setting. Check for it on every reload and repair it if missing.
// `frankenphp fmt --overwrite` after the panel writes the main Caddyfile: removes the
// "Caddyfile input is not formatted" warning (best effort; whitespace-only change).
function fmtCaddyfile() {
  try {
    if (!fs.existsSync(FRANKENPHP_BIN) || !fs.existsSync(CADDYFILE_PATH)) return false;
    return spawnSync(FRANKENPHP_BIN, ['fmt', '--overwrite', CADDYFILE_PATH], { timeout: 15000 }).status === 0;
  } catch { return false; }
}
function ensureFrankenPHPGlobalBlock() {
  if (!fs.existsSync(CADDYFILE_PATH)) return false;
  const content = fs.readFileSync(CADDYFILE_PATH, 'utf8');
  // Older panel versions prepended a SECOND global block when saving num_threads; Caddy
  // refuses to start with two. Merge them into one.
  if (content.includes('# PS-PANEL-MANAGED-START') && (content.match(/^\{[ \t]*$/gm) || []).length > 1) {
    const t = parseInt((content.match(/num_threads\s+(\d+)/) || [])[1], 10);
    fs.copyFileSync(CADDYFILE_PATH, CADDYFILE_PATH + '.bak.' + Date.now());
    fs.writeFileSync(CADDYFILE_PATH, tuneCaddyContent(content, Number.isInteger(t) ? t : null));
    fmtCaddyfile();
    return true;
  }
  const stripped = content.split('\n').filter(l => !l.trim().startsWith('#')).join('\n').trim();
  if (stripped.startsWith('{')) {
    const firstBlock = stripped.match(/^\{([\s\S]*?)\n\}/);
    if (firstBlock && /frankenphp/.test(firstBlock[1])) return false; // already present
  }
  fs.copyFileSync(CADDYFILE_PATH, CADDYFILE_PATH + '.bak.' + Date.now());
  fs.writeFileSync(CADDYFILE_PATH, '{\n\tfrankenphp\n}\n\n' + content);
  fmtCaddyfile();
  return true; // a fix was applied — caller should reload FrankenPHP
}

// Writing a site .conf file alone does NOT make FrankenPHP (Caddy) pick it up —
// the running process needs to reload its config, or the domain keeps serving
// whatever the default/catch-all site was until someone reloads it manually.
// Try a clean reload first (no downtime for other sites); fall back to a full
// restart for older installs whose systemd unit has no ExecReload defined.
function reloadFrankenPHP(cb) {
  try { ensureFrankenPHPGlobalBlock(); } catch {}
  exec('systemctl reload frankenphp', (err) => {
    if (!err) return cb(null);
    exec('systemctl restart frankenphp', (err2) => cb(err2));
  });
}
// ── PHP runtimes: FrankenPHP's embedded PHP (`php_server`) or PHP-FPM (`php_fastcgi`) ──
// FrankenPHP stays the web server either way. With FPM the PHP version is whatever php<ver>-fpm
// packages are installed (PHP 8.5 is the target: PREFERRED_PHP), so PHP security updates arrive
// through apt instead of a new FrankenPHP binary, and the (v1.3.2) embedded OpenSSL is bypassed.
const PHP_ETC        = process.env.PANEL_PHP_ETC  || '/etc/php';
const PHP_SBIN       = process.env.PANEL_PHP_SBIN || '/usr/sbin';
const FPM_RUN        = process.env.PANEL_FPM_RUN  || '/run/php';
const FRANKENPHP_BIN = process.env.PANEL_FRANKENPHP_BIN || '/usr/local/bin/frankenphp';
const PREFERRED_PHP  = process.env.PANEL_PHP_VERSION || '8.5';

const cmpPhpVerDesc = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); return (y[0] - x[0]) || (y[1] - x[1]); };

// Installed php<ver>-fpm packages, newest first.
function fpmRuntimes() {
  let dirs = [];
  try { dirs = fs.readdirSync(PHP_ETC); } catch {}
  return dirs.filter(d => /^\d+\.\d+$/.test(d)).sort(cmpPhpVerDesc).map(v => ({
    version: v,
    bin: path.join(PHP_SBIN, `php-fpm${v}`),
    service: `php${v}-fpm`,
    socket: path.join(FPM_RUN, `php${v}-fpm.sock`),
    confD: path.join(PHP_ETC, v, 'fpm', 'conf.d'),
  })).filter(r => fs.existsSync(r.bin));
}
// Requested version, else the preferred one (8.5), else the newest installed. null = no FPM at all.
function pickFpm(version) {
  const all = fpmRuntimes();
  if (version) return all.find(r => r.version === version) || null;
  return all.find(r => r.version === PREFERRED_PHP) || all[0] || null;
}
async function fpmActive(rt) {
  return new Promise(r => exec(`systemctl is-active ${rt.service}`, (e, o) => r(!e && o.trim() === 'active')));
}

// Which runtime does a Caddy site block use? (comment lines are ignored)
function parseRuntime(content) {
  const text = content.split('\n').filter(l => !l.trim().startsWith('#')).join('\n');
  if (/^\s*php_server\b/m.test(text)) return { runtime: 'frankenphp', version: null };
  const m = text.match(/^\s*php_fastcgi\s+unix\/\/\S*php(\d+\.\d+)-fpm\.sock/m);
  if (m) return { runtime: 'fpm', version: m[1] };
  if (/^\s*php_fastcgi\b/m.test(text)) return { runtime: 'fpm', version: null };   // custom socket / TCP
  return { runtime: null, version: null };
}

// Directive lines for a new PHP site block.
function runtimeLines(runtime, rt, indent = '\t') {
  if (runtime === 'frankenphp') return [`${indent}php_server`];
  return [`${indent}encode zstd gzip`, `${indent}php_fastcgi unix/${rt.socket}`, `${indent}file_server`];
}

// Rewrites the runtime directives inside ONE block body, keeping everything else
// (headers, redirects, extra directives). Returns null when the block has no PHP directive.
function switchRuntimeInBody(body, runtime, rt) {
  const lines = body.split('\n');
  const indent = ((lines.find(l => /^[ \t]+\S/.test(l)) || '').match(/^[ \t]*/) || ['\t'])[0] || '\t';
  const hasEncode = lines.some(l => /^\s*encode\b/.test(l));
  const out = []; let placed = false;
  for (const l of lines) {
    const t = l.trim();
    if (/^php_server\b/.test(t) || /^php_fastcgi\b/.test(t)) {
      if (!placed) {
        placed = true;
        for (const x of runtimeLines(runtime, rt, indent)) if (!(hasEncode && /^\s*encode\b/.test(x))) out.push(x);
      }
    } else if (/^file_server\b/.test(t)) { /* re-added (FPM) or implied by php_server */ }
    else out.push(l);
  }
  return placed ? out.join('\n') : null;
}

const DEFAULT_SITE_RE = /(^http:\/\/:80[ \t]*\{[ \t]*\n)([\s\S]*?)(\n\}[ \t]*(?=\n|$))/m;
const SITE_BLOCK_RE   = /^([^\n{]*\{[ \t]*\n)([\s\S]*?)(\n\}[ \t]*(?=\n|$))/m;

function readDefaultSite() {
  try {
    const m = fs.readFileSync(CADDYFILE_PATH, 'utf8').match(DEFAULT_SITE_RE);
    if (!m) return null;
    const rm = m[2].match(/root\s+\*\s+(\S+)/);
    return { body: m[2], docroot: rm ? rm[1] : null, ...parseRuntime(m[2]) };
  } catch { return null; }
}

// `frankenphp validate`: catches a broken Caddyfile BEFORE the running server sees it.
// Resolves to null when valid (or when there is no binary to check with), else the error text.
async function validateCaddy() {
  if (!fs.existsSync(FRANKENPHP_BIN)) return null;
  try { await execFileAsync(FRANKENPHP_BIN, ['validate', '--config', CADDYFILE_PATH, '--adapter', 'caddyfile'], { timeout: 30000 }); return null; }
  catch (e) { return String((e.stderr || e.message || 'validation failed')).split('\n').filter(Boolean).slice(-3).join(' | '); }
}

// Switches a site (domain, or 'default' for the http://:80 block) to another runtime.
// Backup → write → validate → on failure restore. Returns { file, error } (error = null on success).
async function convertRuntime(target, runtime, version) {
  let rt = null;
  if (runtime === 'fpm') {
    rt = pickFpm(version || null);
    if (!rt) return { error: version ? `php${version}-fpm tidak terpasang` : 'PHP-FPM belum terpasang' };
    if (!(await fpmActive(rt))) return { error: `${rt.service} tidak aktif (systemctl start ${rt.service})` };
  } else if (runtime !== 'frankenphp') return { error: 'runtime harus frankenphp atau fpm' };

  let file, re;
  if (target === 'default') { file = CADDYFILE_PATH; re = DEFAULT_SITE_RE; }
  else {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(target)) return { error: 'domain tidak valid' };
    file = path.join(VHOSTS_DIR, `${target}.conf`); re = SITE_BLOCK_RE;
    if (!fs.existsSync(file)) return { error: 'virtual host tidak ditemukan' };
  }
  let orig;
  try { orig = fs.readFileSync(file, 'utf8'); } catch (e) { return { error: e.message }; }
  const m = orig.match(re);
  if (!m) return { error: 'blok situs tidak ditemukan / format tidak dikenali' };
  const body = switchRuntimeInBody(m[2], runtime, rt);
  if (body == null) return { error: 'situs ini bukan situs PHP (tidak ada php_server / php_fastcgi)' };
  const next = orig.slice(0, m.index) + m[1] + body + m[3] + orig.slice(m.index + m[0].length);
  if (next === orig) return { file, error: null, unchanged: true };

  const backup = file + '.bak.' + Date.now();      // *.conf.bak.* is not matched by `import sites/*.conf`
  fs.copyFileSync(file, backup);
  fs.writeFileSync(file, next);
  const bad = await validateCaddy();
  if (bad) { fs.writeFileSync(file, orig); return { file, error: 'validasi Caddyfile gagal, dikembalikan: ' + bad }; }
  if (file === CADDYFILE_PATH) fmtCaddyfile();
  return { file, backup, error: null };
}

// Runtimes actually referenced by the Caddyfile default site and all site files.
function runtimesInUse() {
  const use = { frankenphp: false, fpm: new Set() };
  const add = r => { if (r.runtime === 'frankenphp') use.frankenphp = true; else if (r.runtime === 'fpm') use.fpm.add(r.version || (pickFpm() || {}).version); };
  const d = readDefaultSite(); if (d) add(d);
  try { for (const f of fs.readdirSync(VHOSTS_DIR).filter(f => f.endsWith('.conf'))) add(parseRuntime(fs.readFileSync(path.join(VHOSTS_DIR, f), 'utf8'))); } catch {}
  use.fpm.delete(undefined);
  return use;
}

app.get('/api/php/runtimes', auth, async (req, res) => {
  const fpm = await Promise.all(fpmRuntimes().map(async rt => {
    let phpVersion = null;
    try { phpVersion = ((await execFileAsync(rt.bin, ['-v'], { timeout: 8000 })).stdout.match(/^PHP (\S+)/) || [])[1] || null; } catch {}
    return { version: rt.version, service: rt.service, socket: rt.socket, active: await fpmActive(rt), phpVersion };
  }));
  const def = readDefaultSite();
  res.json({ ok: true, preferred: PREFERRED_PHP, fpm,
             frankenphp: { installed: fs.existsSync(FRANKENPHP_BIN) },
             defaultSite: def ? { runtime: def.runtime, version: def.version } : null });
});

app.get('/api/vhosts', auth,(req,res)=>{
  const files = (fs.existsSync(VHOSTS_DIR)?fs.readdirSync(VHOSTS_DIR):[]).filter(f=>f.endsWith('.conf'));
  res.json(files.map(f=>{
    const fpath=path.join(VHOSTS_DIR,f);
    const content=fs.readFileSync(fpath,'utf8');
    const stats=fs.statSync(fpath);
    const domain=f.replace('.conf','');
    // Parse document root
    const m=content.match(/root\s+\*\s+(.+?)(?:\n|$)/);
    const docroot=m?m[1].trim():'/var/www/'+domain;
    // Which PHP runtime (if any) serves this site
    const rtm=parseRuntime(content);
    const phpEnabled=rtm.runtime!==null;
    // Check if SSL enabled
    const sslEnabled=!content.match(/^http:\/\//m);
    return {
      file:f,
      domain,
      content,
      docroot,
      phpEnabled,
      runtime:rtm.runtime,
      phpVersion:rtm.version,
      ssl:sslEnabled?'HTTPS':'HTTP',
      created:new Date(stats.mtime).toLocaleDateString('id-ID',{year:'numeric',month:'short',day:'numeric'}),
      size:Math.round(stats.size/1024)+'KB'
    };
  }));
});
app.post('/api/vhosts', auth, async (req,res)=>{
  const {domain,root,php,ssl,laravel,runtime,phpVersion}=req.body||{};
  if(!domain) return res.status(400).json({error:'Domain required'});
  if(!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(domain)) return res.status(400).json({error:'Invalid domain name'});
  const projectRoot = root||`/var/www/${domain}`;
  if(!path.isAbsolute(projectRoot)) return res.status(400).json({error:'Document root must be an absolute path'});
  // The path is written into the Caddyfile: refuse anything that could break out of the directive.
  if(!/^\/[\w.\-\/@+]+$/.test(projectRoot)) return res.status(400).json({error:'Document root hanya boleh berisi huruf, angka dan . _ - / @ +'});
  // PHP runtime: explicit, or FPM when installed (preferred), else FrankenPHP's embedded PHP.
  let rtName=null, rt=null;
  if(php){
    rtName = runtime || (pickFpm(phpVersion||null) ? 'fpm' : 'frankenphp');
    if(rtName==='fpm'){
      rt = pickFpm(phpVersion||null);
      if(!rt) return res.status(400).json({error: phpVersion ? `php${phpVersion}-fpm tidak terpasang` : 'PHP-FPM belum terpasang'});
      if(!(await fpmActive(rt))) return res.status(400).json({error:`${rt.service} tidak aktif (systemctl start ${rt.service})`});
    } else if(rtName!=='frankenphp') return res.status(400).json({error:'runtime harus frankenphp atau fpm'});
  }
  fs.mkdirSync(projectRoot,{recursive:true});
  // Laravel's index.php lives in <project>/public, not the project root — pointing
  // Caddy at the project root means every request 404s straight from Caddy before
  // the app ever runs, which looks like "the server can't find anything" even
  // though the deployed app itself is perfectly fine.
  const docroot = laravel ? path.join(projectRoot,'public') : projectRoot;
  const host = ssl ? domain : `http://${domain}`;
  const lines = rtName ? runtimeLines(rtName, rt) : ['\tfile_server'];
  const config = `${host} {\n\troot * ${docroot}\n${lines.join('\n')}\n}\n`;
  const file = path.join(VHOSTS_DIR,`${domain}.conf`);
  const prev = fs.existsSync(file) ? fs.readFileSync(file,'utf8') : null;
  fs.writeFileSync(file,config);
  const bad = await validateCaddy();
  if(bad){ // never leave a config on disk that the server would refuse
    if(prev===null) fs.rmSync(file,{force:true}); else fs.writeFileSync(file,prev);
    return res.status(400).json({error:'Validasi Caddyfile gagal, dibatalkan: '+bad});
  }
  if(rt) { try { await syncFpmIni([rt.version]); } catch {} }
  reloadFrankenPHP((err)=>{
    res.json({ok:true, runtime:rtName, phpVersion:rt?rt.version:null, reloaded:!err, reloadError: err ? String(err.message||err) : null});
    if(rtName) setImmediate(()=>autotuneTick('runtime situs berubah (vhost baru '+domain+')').catch(()=>{}));
    if(laravel) setImmediate(()=>schedulerEnable(domain, projectRoot, false).catch(()=>{}));
  });
});

// Move a site (or the http://:80 default site) between FrankenPHP's PHP and PHP-FPM.
app.post('/api/runtime/convert', auth, async (req,res)=>{
  const {password,target,runtime,phpVersion}=req.body||{};
  if(typeof password!=='string' || !bcrypt.compareSync(password, authState.hash)) return res.status(403).json({error:'Wrong password'});
  if(!target) return res.status(400).json({error:'target wajib diisi'});
  const r = await convertRuntime(target, runtime, phpVersion||null);
  if(r.error) return res.status(400).json({ok:false, error:r.error});
  let fpmIni = null;
  if(runtime==='fpm'){ try { fpmIni = await syncFpmIni([pickFpm(phpVersion||null).version]); } catch(e){ fpmIni=[{error:e.message}]; } }
  if(r.unchanged) return res.json({ok:true, unchanged:true, fpmIni});
  reloadFrankenPHP((err)=>{
    res.json({ok:true, backup:r.backup, reloaded:!err, reloadError: err ? String(err.message||err) : null, fpmIni});
    setImmediate(()=>autotuneTick('runtime situs berubah ('+(target==='default'?'situs default':target)+' → '+(runtime==='fpm'?'PHP-FPM '+(phpVersion||''):'FrankenPHP')+')').catch(()=>{}));
  });
});
app.delete('/api/vhosts/:domain', auth,(req,res)=>{
  const f=path.join(VHOSTS_DIR,`${req.params.domain}.conf`);
  if(fs.existsSync(f)) fs.unlinkSync(f);
  reloadFrankenPHP((err)=>{
    res.json({ok:true, reloaded:!err, reloadError: err ? String(err.message||err) : null});
  });
});

// ── Vhost Repository Mapping ──
const VHOST_REPO_FILE = '/opt/ps-panel/vhost-repos.json';
function loadVhostRepos(){
  if(fs.existsSync(VHOST_REPO_FILE)){
    try{return JSON.parse(fs.readFileSync(VHOST_REPO_FILE,'utf8'));}catch{}
  }
  return {};
}
function saveVhostRepos(data){
  fs.mkdirSync(path.dirname(VHOST_REPO_FILE),{recursive:true});
  fs.writeFileSync(VHOST_REPO_FILE,JSON.stringify(data,null,2));
}

app.get('/api/vhost-repo/:domain', auth,(req,res)=>{
  const repos=loadVhostRepos();
  const repoUrl=repos[req.params.domain]||null;
  res.json({repoUrl});
});

app.post('/api/vhost-repo/:domain', auth,(req,res)=>{
  const {repoUrl}=req.body;
  if(!repoUrl||repoUrl.length<5) return res.status(400).json({error:'Invalid repo URL'});
  const repos=loadVhostRepos();
  repos[req.params.domain]=repoUrl;
  saveVhostRepos(repos);
  res.json({ok:true});
});

// ── Vhost .env Editor ──
function getVhostEnvPath(domain){
  if(!/^[a-zA-Z0-9.\-_]+$/.test(domain)) return null;
  return `/var/www/${domain}/.env`;
}

app.get('/api/vhost-env/:domain', auth,(req,res)=>{
  const envPath = getVhostEnvPath(req.params.domain);
  if(!envPath) return res.status(400).json({error:'Invalid domain'});
  if(!fs.existsSync(envPath)) return res.json({exists:false, content:'', path:envPath});
  try{
    const content = fs.readFileSync(envPath, 'utf8');
    res.json({exists:true, content, path:envPath});
  }catch(e){
    res.status(500).json({error:'Cannot read .env: '+e.message});
  }
});

app.post('/api/vhost-env/:domain', auth,(req,res)=>{
  const envPath = getVhostEnvPath(req.params.domain);
  if(!envPath) return res.status(400).json({error:'Invalid domain'});
  const {content}=req.body;
  if(typeof content!=='string') return res.status(400).json({error:'Content must be a string'});
  if(content.length>1000000) return res.status(400).json({error:'Content too large'});

  // Validate parent dir exists
  const parentDir = path.dirname(envPath);
  if(!fs.existsSync(parentDir)) return res.status(400).json({error:'Vhost directory not found: '+parentDir});

  try{
    // Backup existing .env
    if(fs.existsSync(envPath)){
      const backupPath = envPath + '.bak';
      fs.copyFileSync(envPath, backupPath);
    }
    fs.writeFileSync(envPath, content);
    // Set proper permissions (readable by web user)
    try{fs.chmodSync(envPath, 0o644);}catch{}
    restartQueueForDomain(req.params.domain).then(restarted=>res.json({ok:true, queueRestarted:restarted})).catch(()=>res.json({ok:true}));
  }catch(e){
    res.status(500).json({error:'Cannot save .env: '+e.message});
  }
});

// Clear Laravel config cache after env change
app.post('/api/vhost-env/:domain/clear-cache', auth,(req,res)=>{
  const domain = req.params.domain;
  if(!/^[a-zA-Z0-9.\-_]+$/.test(domain)) return res.status(400).json({error:'Invalid domain'});
  const appPath = `/var/www/${domain}`;
  if(!fs.existsSync(appPath)) return res.status(400).json({error:'Vhost directory not found'});

  // Commands ordered safest first.
  // - config:clear is safe (file-based)
  // - view:clear & route:clear are file-based
  // - cache:clear may fail if DB-backed cache table doesn't exist (non-fatal)
  // - Manually clear bootstrap/cache/*.php as fallback
  const commands = [
    { cmd: 'php artisan config:clear',           fatal: true  },
    { cmd: 'php artisan view:clear',             fatal: false },
    { cmd: 'php artisan route:clear',            fatal: false },
    { cmd: 'php artisan cache:clear',            fatal: false }, // may fail if cache table missing
    { cmd: `rm -f ${appPath}/bootstrap/cache/config.php ${appPath}/bootstrap/cache/routes-v7.php ${appPath}/bootstrap/cache/services.php`, fatal: false },
  ];
  let output='', i=0;
  function runNext(){
    if(i>=commands.length) return res.json({ok:true, output: output+'\n✓ Done. Run Deploy or migrations to populate DB tables.'});
    const {cmd, fatal} = commands[i++];
    output += `$ ${cmd}\n`;
    exec(cmd, {cwd: appPath, timeout: 30000}, (err, stdout, stderr)=>{
      output += stdout || stderr || '';
      if(err){
        if(fatal){
          output += '\n[FAILED]\n';
          return res.json({ok:false, output});
        }
        output += '[skipped - non-fatal]\n';
      }
      output += '\n';
      runNext();
    });
  }
  runNext();
});

// ── Databases ──
app.get('/api/databases', auth,(req,res)=>{
  exec(`sudo -u postgres psql -c "\\l" --csv 2>/dev/null`,(err,stdout)=>{
    if(err) return res.json({databases:[],error:'Cannot connect'});
    const dbs=stdout.trim().split('\n').slice(1)
      .map(l=>l.split(',')[0])
      .filter(n=>n&&!['template0','template1'].includes(n));
    res.json({databases:dbs});
  });
});
app.post('/api/databases', auth,(req,res)=>{
  const {name}=req.body;
  if(!name||!/^[a-z0-9_]+$/.test(name)) return res.status(400).json({error:'Invalid name'});
  exec(`sudo -u postgres createdb ${name} 2>&1`,(err,_,se)=>{
    if(err) return res.status(500).json({error:se});
    res.json({ok:true});
  });
});

// ── Database Users ──
app.get('/api/db-users', auth, async(req,res)=>{
  try {
    const creds = getCreds();
    const pool = new Pool({
      host:'localhost', user:'postgres',
      password: creds.PG_PASSWORD||'', database:'postgres',
      connectionTimeoutMillis:3000,
    });
    const result = await pool.query(
      `SELECT rolname, rolcanlogin, rolcreatedb FROM pg_roles WHERE rolname NOT IN ('pg_database_owner','postgres') AND NOT rolname LIKE 'pg_%' ORDER BY rolname`
    );
    await pool.end();
    const users = result.rows.map(r=>({
      usename:r.rolname,
      canlogin:r.rolcanlogin,
      cancreatdb:r.rolcreatedb
    }));
    res.json({users});
  } catch(e){ res.json({users:[],error:e.message}); }
});

app.post('/api/db-users', auth, async(req,res)=>{
  const {username,password,cancreatdb}=req.body;
  if(!username||!/^[a-z0-9_]+$/.test(username)) return res.status(400).json({error:'Invalid username'});
  if(!password||password.length<1) return res.status(400).json({error:'Password required'});
  try {
    const creds = getCreds();
    const pool = new Pool({
      host:'localhost', user:'postgres',
      password: creds.PG_PASSWORD||'', database:'postgres',
      connectionTimeoutMillis:3000,
    });
    const escapedPwd = password.replace(/'/g, "''");
    const sql = `CREATE USER "${username}" WITH PASSWORD '${escapedPwd}' LOGIN ${cancreatdb?'CREATEDB':'NOCREATEDB'}`;
    await pool.query(sql);
    await pool.end();
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/db-users/:username', auth, async(req,res)=>{
  const {username}=req.params;
  if(!/^[a-z0-9_]+$/.test(username)) return res.status(400).json({error:'Invalid username'});
  if(['postgres','pg_database_owner'].includes(username)) return res.status(400).json({error:'Cannot delete system user'});
  try {
    const creds = getCreds();
    const pool = new Pool({
      host:'localhost', user:'postgres',
      password: creds.PG_PASSWORD||'', database:'postgres',
      connectionTimeoutMillis:3000,
    });
    await pool.query(`DROP USER IF EXISTS "${username}"`);
    await pool.end();
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/db-users/:username/grant', auth, async(req,res)=>{
  const {username}=req.params;
  const {database,privileges,makeOwner}=req.body;
  if(!/^[a-z0-9_]+$/.test(username)) return res.status(400).json({error:'Invalid username'});
  if(!/^[a-z0-9_]+$/.test(database)) return res.status(400).json({error:'Invalid database'});

  const creds = getCreds();
  const adminPool = new Pool({
    host:'localhost', user:'postgres',
    password: creds.PG_PASSWORD||'', database:'postgres',
    connectionTimeoutMillis:3000,
  });

  // Pool ke target database untuk grant schema-level privileges (PG15+ requirement)
  const targetPool = new Pool({
    host:'localhost', user:'postgres',
    password: creds.PG_PASSWORD||'', database: database,
    connectionTimeoutMillis:3000,
  });

  try {
    const hasAll = privileges?.includes('ALL');

    // Optional: Make user the owner of database (gives full access including schema)
    if(makeOwner){
      await adminPool.query(`ALTER DATABASE "${database}" OWNER TO "${username}"`);
    }

    // 1. Database-level privileges
    const dbPrivs = ['CONNECT','TEMP'].filter(p=>privileges?.includes(p));
    if(hasAll) {
      await adminPool.query(`GRANT ALL PRIVILEGES ON DATABASE "${database}" TO "${username}"`);
    } else if(dbPrivs.length) {
      await adminPool.query(`GRANT ${dbPrivs.join(',')} ON DATABASE "${database}" TO "${username}"`);
    }

    // 2. Schema-level privileges (PG15+ requirement - new users have NO access to public schema by default)
    if(hasAll) {
      await targetPool.query(`GRANT ALL ON SCHEMA public TO "${username}"`);
    } else {
      // For granular grants, still need USAGE + CREATE on schema for table operations
      await targetPool.query(`GRANT USAGE, CREATE ON SCHEMA public TO "${username}"`);
    }

    // 3. Table & sequence privileges
    const tablePrivs = ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'].filter(p=>privileges?.includes(p));
    if(hasAll) {
      await targetPool.query(`GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "${username}"`);
      await targetPool.query(`GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "${username}"`);
      // Default privileges for FUTURE tables/sequences
      await targetPool.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "${username}"`);
      await targetPool.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "${username}"`);
    } else if(tablePrivs.length) {
      const privStr = tablePrivs.join(',');
      await targetPool.query(`GRANT ${privStr} ON ALL TABLES IN SCHEMA public TO "${username}"`);
      await targetPool.query(`GRANT ${privStr} ON ALL SEQUENCES IN SCHEMA public TO "${username}"`);
      await targetPool.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ${privStr} ON TABLES TO "${username}"`);
      await targetPool.query(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ${privStr} ON SEQUENCES TO "${username}"`);
    }

    await adminPool.end();
    await targetPool.end();
    res.json({ok:true});
  } catch(e){
    try{await adminPool.end();}catch{}
    try{await targetPool.end();}catch{}
    res.status(500).json({error:e.message});
  }
});

// ── Settings (PHP.ini + FrankenPHP) ──
// CADDYFILE_PATH is declared earlier (Virtual Hosts section) since it's needed there too.
//
// FrankenPHP is a static binary with its own embedded PHP: it does NOT read the apt PHP's
// /etc/php/8.3/*/php.ini, and (v1.3.2, verified) it does not look in /etc/frankenphp by itself
// either, nor does the Caddyfile `php_ini` directive take effect. What does work is PHPRC: when
// the service has PHPRC=/etc/frankenphp, FrankenPHP loads /etc/frankenphp/php.ini. So the panel
// writes that file, makes sure the unit carries PHPRC (systemd drop-in), and then verifies the
// EFFECTIVE values through the running web process (probe) instead of trusting the file.
const FRANKENPHP_DIR   = process.env.PANEL_FRANKENPHP_DIR || '/etc/frankenphp';
const PHP_INI_FILE     = path.join(FRANKENPHP_DIR, 'php.ini');
const PHPRC_DROPIN_DIR = process.env.PANEL_PHPRC_DROPIN_DIR || '/etc/systemd/system/frankenphp.service.d';
const PHPRC_DROPIN     = path.join(PHPRC_DROPIN_DIR, '10-ps-panel-php.conf');
const PROBE_HTTP_PORT  = parseInt(process.env.PANEL_PROBE_HTTP_PORT, 10) || 80;
const PROBE_HTTPS_PORT = parseInt(process.env.PANEL_PROBE_HTTPS_PORT, 10) || 443;

const PHP_KEYS = [
  'upload_max_filesize',
  'post_max_size',
  'memory_limit',
  'max_execution_time',
  'max_input_vars',
  'max_input_time',
  'opcache.memory_consumption',
  'opcache.max_accelerated_files',
];
// PHP's built-in defaults, used only for the upload ≤ post comparison when a key is unset.
const PHP_DEFAULTS = { upload_max_filesize: '2M', post_max_size: '8M' };

// Validate PHP ini value format
// Size:    -?\d+[KMG]?     (e.g. 128M, 1G, -1)
// Integer: -?\d+           (e.g. 30, 0, -1)
const SIZE_RE = /^-?\d+[KMG]?$/i;
const INT_RE  = /^-?\d+$/;
const PHP_VALIDATORS = {
  upload_max_filesize: SIZE_RE,
  post_max_size:       SIZE_RE,
  memory_limit:        SIZE_RE,
  max_execution_time:  INT_RE,
  max_input_vars:      INT_RE,
  max_input_time:      INT_RE,
  'opcache.memory_consumption':   INT_RE,
  'opcache.max_accelerated_files': INT_RE,
};
const reEsc = k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// "20M" → bytes (NaN when not a size). Used for validation and for comparing saved vs effective.
function sizeToBytes(v) {
  const m = String(v).trim().match(/^(-?\d+)([KMG])?$/i);
  if (!m) return NaN;
  return parseInt(m[1], 10) * ({ K: 1024, M: 1048576, G: 1073741824 }[(m[2] || '').toUpperCase()] || 1);
}
function sameIniValue(a, b) {
  if (a == null || b == null) return false;
  const x = sizeToBytes(a), y = sizeToBytes(b);
  return Number.isNaN(x) || Number.isNaN(y) ? String(a).trim().toLowerCase() === String(b).trim().toLowerCase() : x === y;
}

function readPhpIni() {
  const settings = {};
  for (const k of PHP_KEYS) settings[k] = null;
  try {
    const content = fs.readFileSync(PHP_INI_FILE, 'utf8');
    for (const k of PHP_KEYS) {
      const m = content.match(new RegExp(`^\\s*${reEsc(k)}\\s*=\\s*(.+?)\\s*$`, 'm'));
      if (m) settings[k] = m[1].trim();
    }
  } catch {}
  return { path: PHP_INI_FILE, exists: fs.existsSync(PHP_INI_FILE), settings };
}

function updatePhpIni(updates) {
  // Validate each value
  for (const [k, v] of Object.entries(updates)) {
    if (!PHP_KEYS.includes(k)) throw new Error(`Unknown key: ${k}`);
    if (!PHP_VALIDATORS[k].test(String(v))) throw new Error(`Invalid value for ${k}: ${v}`);
  }
  // upload_max_filesize must not exceed post_max_size (checked on the merged result)
  const cur = readPhpIni().settings;
  const up   = updates.upload_max_filesize ?? cur.upload_max_filesize ?? PHP_DEFAULTS.upload_max_filesize;
  const post = updates.post_max_size       ?? cur.post_max_size       ?? PHP_DEFAULTS.post_max_size;
  const upB = sizeToBytes(up), postB = sizeToBytes(post);
  if (upB > 0 && postB > 0 && upB > postB)
    throw new Error(`upload_max_filesize (${up}) tidak boleh lebih besar dari post_max_size (${post})`);

  fs.mkdirSync(FRANKENPHP_DIR, { recursive: true });
  let content;
  if (fs.existsSync(PHP_INI_FILE)) {
    fs.copyFileSync(PHP_INI_FILE, PHP_INI_FILE + '.bak.' + Date.now());
    content = fs.readFileSync(PHP_INI_FILE, 'utf8');
  } else {
    content = '; Managed by PS Panel (Settings > PHP Configuration). FrankenPHP loads this file through\n' +
              `; PHPRC=${FRANKENPHP_DIR}. Only the keys below are set; everything else keeps PHP's defaults.\n`;
  }
  for (const [k, v] of Object.entries(updates)) {
    const re = new RegExp(`^(\\s*;?\\s*)${reEsc(k)}(\\s*=\\s*).+$`, 'm');
    if (re.test(content)) {
      content = content.replace(re, `${k}$2${v}`);
    } else {
      content += `${content.endsWith('\n') ? '' : '\n'}${k} = ${v}\n`;
    }
  }
  const tmp = PHP_INI_FILE + '.tmp';
  fs.writeFileSync(tmp, content, { mode: 0o644 });
  fs.renameSync(tmp, PHP_INI_FILE);
  return PHP_INI_FILE;
}

// Caddy autosaves its config under XDG_CONFIG_HOME; as www-data with HOME=/var/www it logs
// "unable to create folder for config autosave ... mkdir /var/www/.config: permission denied" on
// every start. Point only XDG_CONFIG_HOME at a directory www-data owns. XDG_DATA_HOME is left
// alone on purpose: TLS certificates live in /var/www/.local/share/caddy and moving that
// directory would make Caddy request new certificates.
const CADDY_CONFIG_DIR = process.env.PANEL_CADDY_CONFIG_DIR || '/var/lib/caddy/config';
async function ensureCaddyConfigDir() {
  try {
    fs.mkdirSync(CADDY_CONFIG_DIR, { recursive: true });
    for (const d of [path.dirname(CADDY_CONFIG_DIR), CADDY_CONFIG_DIR]) { try { await execFileAsync('chown', ['www-data:www-data', d], { timeout: 8000 }); } catch {} }
    const file = path.join(PHPRC_DROPIN_DIR, '20-ps-panel-caddy.conf');
    const want = `[Service]\nEnvironment=XDG_CONFIG_HOME=${CADDY_CONFIG_DIR}\n`;
    let cur = null; try { cur = fs.readFileSync(file, 'utf8'); } catch {}
    if (cur !== want) {
      fs.mkdirSync(PHPRC_DROPIN_DIR, { recursive: true });
      fs.writeFileSync(file, want);
      await execFileAsync('systemctl', ['daemon-reload'], { timeout: 20000 });   // takes effect at the next FrankenPHP restart
      autotuneLog('EVENT drop-in XDG_CONFIG_HOME untuk frankenphp dipasang (berlaku setelah restart berikutnya)');
    }
  } catch (e) { console.warn('[startup] XDG_CONFIG_HOME drop-in:', e.message); }
}

// pm2 shows package.json's version; keep it equal to version.json (the panel's real version).
function syncPackageVersion() {
  try {
    const v = localVersion().version, p = path.join(PANEL_DIR, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (v && pkg.version !== v) { pkg.version = v; fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + '\n'); return true; }
  } catch {}
  return false;
}

// Make sure the frankenphp service runs with PHPRC=/etc/frankenphp (systemd drop-in, so the
// installer's unit file is left alone). Idempotent; returns { changed }.
async function ensurePhprc() {
  let env = '';
  try { env = (await execFileAsync('systemctl', ['show', 'frankenphp', '-p', 'Environment', '--value'], { timeout: 10000 })).stdout; } catch {}
  if (env.split(/\s+/).includes('PHPRC=' + FRANKENPHP_DIR)) return { changed: false };
  fs.mkdirSync(PHPRC_DROPIN_DIR, { recursive: true });
  fs.writeFileSync(PHPRC_DROPIN, `[Service]\nEnvironment=PHPRC=${FRANKENPHP_DIR}\n`);
  await execFileAsync('systemctl', ['daemon-reload'], { timeout: 20000 });
  return { changed: true };
}

// Mirrors the managed PHP settings (/etc/frankenphp/php.ini) into PHP-FPM's conf.d, then RELOADS
// the pool (reload lets running requests finish; restart would cut them). `php-fpm -t` validates
// first and the previous file is restored if the config is rejected.
const FPM_INI_NAME = '99-ps-panel.ini';
async function syncFpmIni(versions) {
  const saved = readPhpIni().settings;
  const lines = PHP_KEYS.filter(k => saved[k] != null).map(k => `${k} = ${saved[k]}`);
  const results = [];
  for (const v of versions) {
    const rt = pickFpm(v);
    if (!rt) { results.push({ version: v, error: 'tidak terpasang' }); continue; }
    const file = path.join(rt.confD, FPM_INI_NAME);
    const next = '; Managed by PS Panel (Settings > PHP Configuration): mirror of /etc/frankenphp/php.ini.\n' + lines.join('\n') + '\n';
    let prev = null; try { prev = fs.readFileSync(file, 'utf8'); } catch {}
    if (prev === next || (prev === null && !lines.length)) { results.push({ version: v, changed: false }); continue; }
    try {
      fs.mkdirSync(rt.confD, { recursive: true });
      fs.writeFileSync(file + '.tmp', next, { mode: 0o644 });
      fs.renameSync(file + '.tmp', file);
      try { await execFileAsync(rt.bin, ['-t'], { timeout: 15000 }); }
      catch (e) {
        if (prev === null) fs.rmSync(file, { force: true }); else fs.writeFileSync(file, prev);
        results.push({ version: v, error: 'php-fpm -t gagal, dikembalikan: ' + String(e.stderr || e.message).trim().split('\n').slice(-2).join(' | ') });
        continue;
      }
      await execFileAsync('systemctl', ['reload', rt.service], { timeout: 20000 });
      results.push({ version: v, changed: true, reloaded: true });
    } catch (e) { results.push({ version: v, error: e.message }); }
  }
  return results;
}

// One probe target per PHP site (default site first): { runtime, version, docroot, host, https, port }.
function probeTargets() {
  const targets = [];
  const d = readDefaultSite();
  if (d && d.runtime && d.docroot)
    targets.push({ label: 'situs default', runtime: d.runtime, version: d.version || (d.runtime === 'fpm' ? (pickFpm() || {}).version : null), docroot: d.docroot, host: null, https: false, port: PROBE_HTTP_PORT });
  try {
    for (const f of fs.readdirSync(VHOSTS_DIR).filter(f => f.endsWith('.conf'))) {
      const content = fs.readFileSync(path.join(VHOSTS_DIR, f), 'utf8');
      const rm = content.match(/root\s+\*\s+(.+?)(?:\n|$)/);
      const r = parseRuntime(content);
      if (!rm || !r.runtime) continue;
      const domain = f.replace(/\.conf$/, '');
      const plain = /^\s*http:\/\//.test(content);   // http:// prefix = no SSL (see vhost creation)
      targets.push({ label: domain, runtime: r.runtime, version: r.version || (r.runtime === 'fpm' ? (pickFpm() || {}).version : null),
                     docroot: rm[1].trim(), host: domain, https: !plain, port: plain ? PROBE_HTTP_PORT : PROBE_HTTPS_PORT });
    }
  } catch {}
  return targets;
}

function probeRequest(t, file) {
  return new Promise(resolve => {
    const opts = { host: '127.0.0.1', port: t.port, path: '/' + file, method: 'GET', timeout: 5000, headers: t.host ? { Host: t.host } : {} };
    if (t.https) { opts.servername = t.host; opts.rejectUnauthorized = false; }
    const req = (t.https ? https : http).request(opts, res => {
      let body = ''; res.setEncoding('utf8');
      res.on('data', c => body += c); res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', e => resolve({ error: e.message }));
    req.end();
  });
}

// Asks the RUNNING web processes what they really use: one probe per distinct runtime
// (FrankenPHP's PHP, and each PHP-FPM version). A throw-away PHP file with a random name is
// placed in a served docroot, requested over localhost, and removed again.
async function probeEffectivePhp(keys = PHP_KEYS) {
  const targets = probeTargets();
  if (!targets.length) return { ok: false, error: 'tidak ada situs PHP yang bisa dipakai untuk memeriksa' };
  const results = [], errors = [], done = new Set();
  for (const t of targets) {
    const rkey = t.runtime === 'fpm' ? `fpm:${t.version || '?'}` : 'frankenphp';
    if (done.has(rkey)) continue;
    if (!fs.existsSync(t.docroot)) { errors.push(`${t.label}: docroot ${t.docroot} tidak ada`); continue; }
    const file = 'psprobe-' + crypto.randomBytes(8).toString('hex') + '.php';
    const full = path.join(t.docroot, file);
    try {
      fs.writeFileSync(full, `<?php header('Content-Type: application/json'); header('Cache-Control: no-store');
$o=['sapi'=>PHP_SAPI,'version'=>PHP_VERSION,'loaded_ini'=>php_ini_loaded_file(),'scanned'=>php_ini_scanned_files(),'values'=>[]];
foreach(json_decode('${JSON.stringify(keys)}') as $k){$o['values'][$k]=ini_get($k);}
echo json_encode($o);\n`, { mode: 0o644 });
      const r = await probeRequest(t, file);
      if (r.error) { errors.push(`${t.label}: ${r.error}`); continue; }
      let j = null; try { j = JSON.parse(r.body); } catch {}
      if (!j || !j.values) { errors.push(`${t.label}: HTTP ${r.status}, bukan respons PHP`); continue; }
      results.push({ runtimeKey: rkey, runtime: t.runtime, version: t.version, via: t.label, sapi: j.sapi, phpVersion: j.version,
                     loadedIni: j.loaded_ini || null, scanned: j.scanned || null, values: j.values });
      done.add(rkey);
    } catch (e) { errors.push(`${t.label}: ${e.message}`); }
    finally { try { fs.rmSync(full, { force: true }); } catch {} }
  }
  return results.length ? { ok: true, results, errors } : { ok: false, error: errors.join('; ') };
}

// After a restart FrankenPHP needs a moment before it answers; retry for up to ~20 s.
async function probeWhenReady(keys, tries = 20) {
  let last = { ok: false, error: 'belum dicoba' };
  for (let i = 0; i < tries; i++) {
    last = await probeEffectivePhp(keys);
    if (last.ok) return last;
    await new Promise(r => setTimeout(r, 1000));
  }
  return last;
}

// Saved (file) vs effective (running process), for every runtime that was probed.
function compareEffective(probe) {
  if (!probe.ok) return { ok: false, error: probe.error };
  const saved = readPhpIni().settings;
  const expectFile = fs.existsSync(PHP_INI_FILE);
  const results = probe.results.map(r => {
    const rows = PHP_KEYS.filter(k => saved[k] != null).map(k => ({
      key: k, saved: saved[k], effective: r.values[k] ?? null, match: sameIniValue(saved[k], r.values[k]),
    }));
    let iniMatch = false, expectedIni;
    if (r.runtime === 'frankenphp') {
      expectedIni = PHP_INI_FILE;
      try { iniMatch = !!r.loadedIni && fs.realpathSync(r.loadedIni) === fs.realpathSync(PHP_INI_FILE); } catch {}
    } else {
      expectedIni = path.join(PHP_ETC, r.version || '?', 'fpm', 'conf.d', FPM_INI_NAME);
      iniMatch = !!r.scanned && r.scanned.includes(FPM_INI_NAME);
    }
    const needIni = expectFile && (r.runtime === 'frankenphp' || rows.length > 0);
    return { ...r, rows, iniMatch, expectedIni, mismatch: rows.some(x => !x.match) || (needIni && !iniMatch) };
  });
  return { ok: true, ...results[0], results, mismatch: results.some(r => r.mismatch) };
}

function readFrankenphpSettings() {
  if (!fs.existsSync(CADDYFILE_PATH)) return { num_threads: null };
  try {
    const content = fs.readFileSync(CADDYFILE_PATH, 'utf8');
    const m = content.match(/num_threads\s+(\d+)/);
    return { num_threads: m ? parseInt(m[1]) : null };
  } catch { return { num_threads: null }; }
}

// Caddy allows exactly ONE global options block and it must be first, and install.sh already
// ships `{ frankenphp }`. So num_threads is merged INTO that block rather than prepended as a
// second block (which made Caddy refuse to start). Also folds in the legacy managed block that
// older panel versions prepended. threads = null removes the setting.
function tuneCaddyContent(content, threads) {
  content = content.replace(/# PS-PANEL-MANAGED-START[\s\S]*?# PS-PANEL-MANAGED-END\n*/, '');
  const tpl = (ind) => `${ind}frankenphp {\n${ind}\tnum_threads ${threads}\n${ind}}`;
  const m = content.match(/^((?:[ \t]*(?:#[^\n]*)?\n)*)\{[ \t]*\n([\s\S]*?)\n\}[ \t]*(?=\n|$)/);
  if (!m) {
    if (threads == null) return content;
    return `{\n${tpl('\t')}\n}\n\n` + content;
  }
  let body = m[2];
  if (/num_threads\s+\d+/.test(body)) {
    body = threads == null ? body.replace(/^[ \t]*num_threads\s+\d+[ \t]*\n?/m, '').replace(/^([ \t]*frankenphp)[ \t]*\{\s*\}[ \t]*$/m, '$1')
                           : body.replace(/(num_threads\s+)\d+/, `$1${threads}`);
  } else if (threads != null) {
    if (/^[ \t]*frankenphp[ \t]*\{/m.test(body))
      body = body.replace(/^([ \t]*)(frankenphp[ \t]*\{[ \t]*\n?)/m, (_, ind, open) => `${ind}${open.replace(/\n$/, '')}\n${ind}\tnum_threads ${threads}\n`);
    else if (/^[ \t]*frankenphp[ \t]*$/m.test(body))
      body = body.replace(/^([ \t]*)frankenphp[ \t]*$/m, (_, ind) => tpl(ind));
    else body = body + '\n' + tpl('\t');
  }
  return content.slice(0, m.index) + m[1] + '{\n' + body + '\n}' + content.slice(m.index + m[0].length);
}

function updateFrankenphpSettings(updates) {
  if (!fs.existsSync(CADDYFILE_PATH)) throw new Error('Caddyfile not found');
  const threads = parseInt(updates.num_threads);
  if (!Number.isInteger(threads) || threads < 1 || threads > 256)
    throw new Error('num_threads must be 1-256');

  fs.copyFileSync(CADDYFILE_PATH, CADDYFILE_PATH + '.bak.' + Date.now());
  fs.writeFileSync(CADDYFILE_PATH, tuneCaddyContent(fs.readFileSync(CADDYFILE_PATH, 'utf8'), threads));
  fmtCaddyfile();
}

// ── Auto-tune: worker capacity (FrankenPHP threads, PHP-FPM pools) + PostgreSQL memory ──
// Everything here is automatic: there is deliberately no way to type a worker count into the panel.
//  WHEN it runs: at boot (ps-panel-autotune.service, always enabled), when core/RAM change, when a
//  site's runtime changes, when php.ini's max_execution_time changes, and every 10 minutes (PHP-FPM
//  only: pm.max_children follows the real memory used per worker).
//  HOW it applies: every file is backed up/validated/rolled back. PHP-FPM is RELOADED (running
//  requests finish). Changes that need a restart (FrankenPHP threads, PostgreSQL memory) are written
//  but only take effect at the next restart/boot; the panel never restarts a serving service by
//  itself (the PHP Worker page offers a confirmed restart). Under high load such writes are deferred.
//  SAFETY NET: if a service restarts more than 3 times within a minute after a change, the previous
//  value is restored, the same values are blocked for 24 h, and an alert is raised.
//  Manual run: node server.js --autotune [--dry-run [--cores=N --ram=MB]]
const os = require('os');
const PG_ETC = process.env.PANEL_PG_ETC || '/etc/postgresql';
const PG_LIB = process.env.PANEL_PG_LIB || '/usr/lib/postgresql';
const AUTOTUNE_PG_FILE = '90-ps-panel-autotune.conf';
const AUTOTUNE_UNIT_NAME = 'ps-panel-autotune';
const AUTOTUNE_UNIT = process.env.PANEL_AUTOTUNE_UNIT || `/etc/systemd/system/${AUTOTUNE_UNIT_NAME}.service`;
const AUTOTUNE_LOG = process.env.PANEL_AUTOTUNE_LOG || '/var/log/ps-panel-autotune.log';
const AUTOTUNE_STATE = process.env.PANEL_AUTOTUNE_STATE || '/root/.pspanel_autotune.json';
const AUTOTUNE_INTERVAL_MS = parseInt(process.env.PANEL_AUTOTUNE_INTERVAL_MS, 10) || 10 * 60 * 1000;
const GUARD_MS = parseInt(process.env.PANEL_AUTOTUNE_GUARD_MS, 10) || 60 * 1000;
const POOL_FILE = 'zz-ps-panel.conf';          // sorts after typical manual zz-*.conf so panel values win
const FPM_STATUS_PATH = '/ps-panel-fpm-status'; // reachable only over FastCGI, never through the web
const POOL_KEYS = ['pm', 'pm.max_children', 'pm.start_servers', 'pm.min_spare_servers', 'pm.max_spare_servers', 'pm.max_requests', 'request_terminate_timeout'];
const POOL_MANAGED = new Set([...POOL_KEYS, 'pm.status_path', 'pm.process_idle_timeout']);
const TUNE_PG_KEYS = ['shared_buffers', 'effective_cache_size', 'work_mem', 'maintenance_work_mem', 'max_connections'];
const FRANKENPHP_THREAD_WARNING = 'FrankenPHP versi lama (mis. v1.3.2) diketahui crash (segfault) bila banyak thread PHP bertemu koneksi HTTPS keluar paralel; versi baru (v1.13+) lolos uji beban, tetapi PHP-FPM tetap disarankan untuk situs yang memanggil API/Google.';

function machineSpecs() {
  const cores = (os.availableParallelism ? os.availableParallelism() : os.cpus().length) || 1;
  return { cores, ramMB: Math.round(os.totalmem() / 1048576) };
}
function cpuModel() {
  try { const m = fs.readFileSync('/proc/cpuinfo', 'utf8').match(/^model name\s*:\s*(.+)$/m); if (m) return m[1].trim(); } catch {}
  return (os.cpus()[0] || {}).model || null;
}

// ── persisted state + history log ──
function loadAutoState() { try { return JSON.parse(fs.readFileSync(AUTOTUNE_STATE, 'utf8')); } catch { return {}; } }
let AUTO = loadAutoState();
for (const k of ['pending', 'watch', 'alerts']) if (!Array.isArray(AUTO[k])) AUTO[k] = [];
for (const k of ['awaitingRestart', 'blocked', 'avgRssMB']) if (!AUTO[k] || typeof AUTO[k] !== 'object') AUTO[k] = {};
function refreshAuto() {
  AUTO = loadAutoState();
  for (const k of ['pending', 'watch', 'alerts']) if (!Array.isArray(AUTO[k])) AUTO[k] = [];
  for (const k of ['awaitingRestart', 'blocked', 'avgRssMB']) if (!AUTO[k] || typeof AUTO[k] !== 'object') AUTO[k] = {};
}
function persistAuto() {
  try { const tmp = AUTOTUNE_STATE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(AUTO, null, 1), { mode: 0o600 }); fs.renameSync(tmp, AUTOTUNE_STATE); }
  catch (e) { console.warn('[autotune] state not saved:', e.message); }
}
function autotuneLog(msg) {
  const line = `${new Date().toISOString()} ps-panel-autotune: ${msg}`;
  console.log(line);
  try { fs.appendFileSync(AUTOTUNE_LOG, line + '\n'); } catch {}
}
function logChange(target, key, oldV, newV, reason) {
  autotuneLog(`CHANGE target=${target} key=${key} old=${oldV ?? '-'} new=${newV ?? '-'} reason="${String(reason).replace(/"/g, "'")}"`);
}
// Raises an alert (history + state). Telegram delivery is hooked in here by the notification settings.
function notify(msg) {
  AUTO.alerts = [{ ts: new Date().toISOString(), msg }, ...AUTO.alerts].slice(0, 20);
  persistAuto();
  autotuneLog(`ALERT ${msg}`);
  try { if (typeof sendTelegram === 'function') sendTelegram('PS Panel: ' + msg); } catch {}
}
function readHistory(limit = 100) {
  let text = '';
  try {
    const st = fs.statSync(AUTOTUNE_LOG), len = Math.min(st.size, 512 * 1024), buf = Buffer.alloc(len);
    const fd = fs.openSync(AUTOTUNE_LOG, 'r'); fs.readSync(fd, buf, 0, len, st.size - len); fs.closeSync(fd);
    text = buf.toString('utf8');
  } catch { return []; }
  const out = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^(\S+) ps-panel-autotune: (CHANGE|ALERT) (.*)$/);
    if (!m) continue;
    if (m[2] === 'CHANGE') {
      const c = m[3].match(/^target=(\S+) key=(.+?) old=(.*?) new=(.*?) reason="(.*)"$/);
      if (c) out.push({ ts: m[1], type: 'change', target: c[1], key: c[2], old: c[3], new: c[4], reason: c[5] });
    } else out.push({ ts: m[1], type: 'alert', message: m[3] });
  }
  return out.slice(-limit).reverse();
}

// ── small system helpers ──
function serviceActive(unit) { return new Promise(r => execFile('systemctl', ['is-active', unit], (e, o) => r(!e && String(o).trim() === 'active'))); }
async function nRestarts(unit) {
  try { return parseInt((await execFileAsync('systemctl', ['show', unit, '-p', 'NRestarts', '--value'], { timeout: 8000 })).stdout.trim(), 10) || 0; } catch { return 0; }
}
async function serviceStartedAfter(unit, iso) {
  try {
    const t = new Date((await execFileAsync('systemctl', ['show', unit, '-p', 'ActiveEnterTimestamp', '--value'], { timeout: 8000 })).stdout.trim()).getTime();
    return !isNaN(t) && t > new Date(iso).getTime();
  } catch { return false; }
}
function lowLoad(cores) {
  if (process.env.PANEL_AUTOTUNE_FORCE_LOW_LOAD === '1') return true;
  if (process.env.PANEL_AUTOTUNE_FORCE_LOW_LOAD === '0') return false;
  return os.loadavg()[0] / Math.max(1, cores) <= 0.4;
}
const pgInstalled = () => !!findPgCluster();
const redisInstalled = () => [process.env.PANEL_REDIS_BIN, '/usr/bin/redis-server', '/usr/local/bin/redis-server'].some(p => p && fs.existsSync(p));
const clampN = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const floorTo = (v, step) => Math.floor(v / step) * step;

// ── pure calculations ──
const pgSharedBuffersMB = ramMB => clampN(floorTo(ramMB * 0.25, 16), 16, 8192);

// PostgreSQL memory profile. `workers` = PHP workers that may each hold a connection.
function computePgProfile(ramMB, workers) {
  ramMB = Math.max(256, parseInt(ramMB, 10) || 256);
  const sb      = pgSharedBuffersMB(ramMB);
  const ecs     = clampN(floorTo(ramMB * 0.5, 64), 128, 65536);
  const maxConn = clampN(Math.ceil(((workers || 0) * 2 + 20) / 50) * 50, 100, 500);
  const wm      = clampN(Math.floor((ramMB - sb) / (maxConn * 3)), 4, 64);
  const mwm     = clampN(floorTo(ramMB / 16, 16), 64, 1024);
  return { shared_buffers: sb + 'MB', effective_cache_size: ecs + 'MB', work_mem: wm + 'MB', maintenance_work_mem: mwm + 'MB', max_connections: maxConn };
}

// PHP-FPM pool: pm.max_children = floor(available RAM / average RSS per worker), lower bound 8.
function computeFpmPool({ availMB, avgRssMB, maxExecSec, cores }) {
  // A freshly started/idle worker is far smaller than one that has served a real app, so a measured
  // value is never trusted below 50 MB (an under-estimate here means OOM). Also never more than
  // 8 workers per core: more only queues work on the CPU and holds DB connections.
  const avg = clampN(avgRssMB || 70, 50, 400);
  const mc = clampN(Math.floor(availMB / avg), 8, clampN((cores || 1) * 8, 8, 400));
  const start = clampN(Math.round(mc * 0.3), 2, mc);
  const minSp = clampN(Math.round(mc * 0.2), 1, start);
  const maxSp = clampN(Math.round(mc * 0.5), start, mc);
  const timeout = Number.isInteger(maxExecSec) && maxExecSec <= 0 ? '0' : ((Number.isInteger(maxExecSec) ? maxExecSec : 30) + 10) + 's';
  return { pm: 'dynamic', 'pm.max_children': mc, 'pm.start_servers': start, 'pm.min_spare_servers': minSp, 'pm.max_spare_servers': maxSp,
           'pm.max_requests': 1000, request_terminate_timeout: timeout };
}

// ctx: { cores, ramMB, use:{frankenphp, fpm:Set}, avgRss:{ver:MB}, measured:{ver:bool}, pgInstalled, redisInstalled, maxExecSec }
function computePlan(ctx) {
  const ramMB = Math.max(256, ctx.ramMB | 0), cores = Math.max(1, ctx.cores | 0);
  const embedded = !!ctx.use.frankenphp;
  const versions = [...ctx.use.fpm].sort(cmpPhpVerDesc);
  const sb = pgSharedBuffersMB(ramMB);
  // The fixed reserves of a big server (768 MB PostgreSQL overhead, 1 GB system) would eat most of a
  // 2 GB VPS (a negative budget, then the 8-worker floor on top of it), so they scale with the RAM
  // and only reach those values from about 8 GB / 5 GB up.
  const reserves = {
    pgMB: ctx.pgInstalled ? sb + clampN(floorTo(ramMB * 0.1, 64), 256, 768) : 0,
    redisMB: ctx.redisInstalled ? clampN(floorTo(ramMB * 0.125, 64), 128, 1024) : 0,
    systemMB: clampN(floorTo(ramMB * 0.2, 128), 512, 1024),
  };
  // FrankenPHP: with embedded PHP in use never above 2 × cores; when it only forwards to PHP-FPM it needs little.
  const threads = embedded ? clampN(Math.min(cores * 2, Math.floor(ramMB * 0.4 / 64)), 2, 256) : 2;
  const frankenphp = {
    num_threads: threads,
    basis: embedded ? `min(2 × ${cores} core, 40% RAM ÷ 64 MB) — batas aman thread FrankenPHP`
                    : (versions.length ? 'semua situs PHP memakai PHP-FPM; FrankenPHP hanya web server (thread kecil)' : 'tidak ada situs yang memakai PHP bawaan FrankenPHP'),
    warning: embedded ? FRANKENPHP_THREAD_WARNING : null,
  };
  let avail = ramMB - reserves.pgMB - reserves.redisMB - reserves.systemMB - (embedded ? threads * 64 : 0);
  const fpm = versions.map(v => {
    const avg = (ctx.avgRss && ctx.avgRss[v]) || 70;
    const availMB = Math.floor(avail / versions.length);
    return { version: v, pool: computeFpmPool({ availMB, avgRssMB: avg, maxExecSec: ctx.maxExecSec, cores }),
             basis: { ramMB, availMB, avgRssMB: Math.max(50, avg), measured: !!(ctx.measured && ctx.measured[v]), coreCap: clampN(cores * 8, 8, 400), reserves } };
  });
  const workers = (embedded ? threads : 0) + fpm.reduce((a, f) => a + f.pool['pm.max_children'], 0);
  // The pool never drops below 8 workers, so on a small server the RAM can be short of what those
  // 8 need: say so (memory pressure ends in swap or the OOM killer), and how much RAM would be enough.
  const warnings = [];
  for (const f of fpm) {
    const b = f.basis, need = 8 * b.avgRssMB;
    if (b.availMB < need) {
      const wantMB = reserves.pgMB + reserves.redisMB + reserves.systemMB + b.coreCap * b.avgRssMB;
      warnings.push({ type: 'low-ram', version: f.version, haveMB: b.availMB, needMB: need, recommendedGB: Math.ceil(wantMB / 1024),
        message: `RAM kurang untuk PHP-FPM ${f.version}: tersedia ${Math.max(0, b.availMB)} MB, 8 worker minimum butuh ${need} MB. Server berisiko memakai swap atau proses dimatikan OOM-killer saat ramai. Disarankan RAM ≥ ${Math.ceil(wantMB / 1024)} GB agar ${b.coreCap} worker muat; tambah RAM atau kurangi isi server.` });
    }
  }
  return { specs: { cores, ramMB }, reserves, frankenphp, fpm, postgres: computePgProfile(ramMB, workers), workers, warnings };
}

// ── PostgreSQL helpers ──
function findPgCluster() {
  try {
    const vers = fs.readdirSync(PG_ETC)
      .filter(v => /^\d+$/.test(v) && fs.existsSync(path.join(PG_ETC, v, 'main', 'postgresql.conf')))
      .sort((a, b) => b - a);
    if (!vers.length) return null;
    const v = vers[0], dir = path.join(PG_ETC, v, 'main');
    return { version: v, dir, conf: path.join(dir, 'postgresql.conf'), confD: path.join(dir, 'conf.d'),
             bin: path.join(PG_LIB, v, 'bin', 'postgres') };
  } catch { return null; }
}
// Returns null when the config parses, an error string when it does not, or 'skip' with no postgres binary.
function pgValidate(pg) {
  if (!fs.existsSync(pg.bin)) return 'skip';
  const r = spawnSync('runuser', ['-u', 'postgres', '--', pg.bin, '-C', 'shared_buffers', '-c', 'config_file=' + pg.conf],
    { encoding: 'utf8', timeout: 15000 });
  return r.status === 0 ? null : ((r.stderr || (r.error && r.error.message) || 'validation failed').trim());
}
function pgTuneFileContent(profile) {
  return '# Managed by PS Panel auto-tune (halaman PHP Worker). Do not edit by hand:\n' +
    '# it is rewritten automatically. Remove this file to revert to PostgreSQL defaults.\n' +
    TUNE_PG_KEYS.map(k => `${k} = ${profile[k]}`).join('\n') + '\n';
}
function ensurePgIncludeDir(pg) {
  const c = fs.readFileSync(pg.conf, 'utf8');
  if (/^\s*include_dir\s*=\s*'conf\.d'/m.test(c)) return;
  fs.copyFileSync(pg.conf, pg.conf + '.bak.' + Date.now());
  fs.appendFileSync(pg.conf, "\ninclude_dir = 'conf.d'\n");
}
// `postgres -C` prints a setting in its INTERNAL unit (8 kB blocks for shared_buffers and
// effective_cache_size, kB for work_mem and maintenance_work_mem), e.g. 253952 for 1984MB.
// Convert to the "NNNMB" form the profile uses so current vs recommended compare correctly.
function pgInternalToMB(key, raw, blockBytes) {
  raw = String(raw).trim();
  if (!/^\d+$/.test(raw)) return raw;               // already carries a unit (e.g. 128MB)
  const n = parseInt(raw, 10);
  let mb;
  if (key === 'shared_buffers' || key === 'effective_cache_size') mb = n * blockBytes / 1048576;
  else if (key === 'work_mem' || key === 'maintenance_work_mem') mb = n / 1024;
  else return raw;                                   // max_connections: plain count
  return `${Math.round(mb * 100) / 100}MB`;
}

// ── PHP-FPM pool helpers ──
const poolDir = rt => path.join(PHP_ETC, rt.version, 'fpm', 'pool.d');
function parseIniLike(text) {
  const o = {};
  if (!text) return o;
  for (const l of text.split('\n')) { const m = l.match(/^\s*([a-z_.]+)\s*=\s*(.+?)\s*$/i); if (m) o[m[1]] = m[2]; }
  return o;
}
function poolFileContent(pool) {
  return '; Managed by PS Panel auto-tune (halaman PHP Worker). Do not edit by hand: values are rewritten\n' +
         '; automatically from cores, RAM and the real memory used per worker.\n[www]\n' +
         POOL_KEYS.map(k => `${k} = ${pool[k]}`).join('\n') + `\npm.status_path = ${FPM_STATUS_PATH}\n`;
}
// Manual pool files that only set panel-managed keys are safe to adopt (the panel file replaces them).
function findManualPoolFiles(rt) {
  let files = []; try { files = fs.readdirSync(poolDir(rt)); } catch { return []; }
  return files.filter(f => f.endsWith('.conf') && f !== 'www.conf' && f !== POOL_FILE).map(f => {
    const p = path.join(poolDir(rt), f);
    let lines = []; try { lines = fs.readFileSync(p, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith(';') && !l.startsWith('#')); } catch {}
    const headers = lines.filter(l => /^\[.+\]$/.test(l)), kvs = lines.filter(l => !/^\[.+\]$/.test(l)).map(l => (l.split('=')[0] || '').trim());
    return { file: f, path: p, onlyManaged: headers.every(h => h === '[www]') && kvs.every(k => POOL_MANAGED.has(k)) };
  });
}
// Effective [www] settings according to php-fpm itself (`php-fpm -tt` prints the merged config).
async function fpmEffective(rt) {
  try {
    const r = await execFileAsync(rt.bin, ['-tt'], { timeout: 15000 });
    const text = String(r.stderr || '') + String(r.stdout || '');
    const out = {}; let inWww = false;
    for (const l of text.split('\n')) {
      const h = l.match(/NOTICE: \[([^\]]+)\]\s*$/);
      if (h) { inWww = h[1] === 'www'; continue; }
      const kv = l.match(/NOTICE: \t(\S+) = (.*)$/);
      if (inWww && kv) out[kv[1]] = kv[2].trim();
    }
    return out;
  } catch { return null; }
}
// Minimal FastCGI client: PHP-FPM's status page is only reachable over its socket.
function fcgiGet(socketPath, scriptName, query = 'json') {
  return new Promise((resolve, reject) => {
    const sock = require('net').createConnection(socketPath);
    let done = false, buf = Buffer.alloc(0); const out = [];
    const finish = (err, val) => { if (done) return; done = true; sock.destroy(); err ? reject(err) : resolve(val); };
    sock.setTimeout(3000, () => finish(new Error('timeout')));
    sock.on('error', finish);
    const rec = (type, body) => { const h = Buffer.alloc(8); h[0] = 1; h[1] = type; h.writeUInt16BE(1, 2); h.writeUInt16BE(body.length, 4); return Buffer.concat([h, body]); };
    const nv = (n, v) => { const a = Buffer.from(n), b = Buffer.from(v); return Buffer.concat([Buffer.from([a.length, b.length]), a, b]); };
    const params = Buffer.concat([nv('SCRIPT_NAME', scriptName), nv('SCRIPT_FILENAME', scriptName), nv('REQUEST_METHOD', 'GET'),
                                  nv('QUERY_STRING', query), nv('SERVER_PROTOCOL', 'HTTP/1.1'), nv('GATEWAY_INTERFACE', 'CGI/1.1')]);
    const begin = Buffer.alloc(8); begin.writeUInt16BE(1, 0);   // role: responder
    sock.write(Buffer.concat([rec(1, begin), rec(4, params), rec(4, Buffer.alloc(0)), rec(5, Buffer.alloc(0))]));
    sock.on('data', d => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 8) {
        const len = buf.readUInt16BE(4), pad = buf[6];
        if (buf.length < 8 + len + pad) break;
        const type = buf[1], body = buf.slice(8, 8 + len); buf = buf.slice(8 + len + pad);
        if (type === 6) out.push(body);
        if (type === 3) return finish(null, Buffer.concat(out).toString('utf8'));
      }
    });
    sock.on('end', () => finish(null, Buffer.concat(out).toString('utf8')));
  });
}
async function fpmStatus(rt) {
  try {
    const raw = await fcgiGet(rt.socket, FPM_STATUS_PATH);
    const j = JSON.parse(raw.split(/\r?\n\r?\n/).slice(1).join('\n\n'));
    return { ok: true, active: j['active processes'], idle: j['idle processes'], total: j['total processes'], maxActive: j['max active processes'],
             maxChildrenReached: j['max children reached'], listenQueue: j['listen queue'], slowRequests: j['slow requests'] };
  } catch (e) { return { ok: false, error: e.message }; }
}
// Average RSS (MB) of the running workers of one PHP-FPM version; null with fewer than 5 workers.
async function fpmAvgRss(rt) {
  try {
    const { stdout } = await execFileAsync('ps', ['-C', `php-fpm${rt.version}`, '-o', 'rss=,args='], { timeout: 8000 });
    const rss = stdout.split('\n').filter(l => /pool /.test(l)).map(l => parseInt(l.trim().split(/\s+/)[0], 10)).filter(n => n > 0);
    if (rss.length < 5) return null;   // too few workers to say anything about a typical one
    return { avgMB: Math.round(rss.reduce((a, b) => a + b, 0) / rss.length / 1024 * 10) / 10, workers: rss.length };
  } catch { return null; }
}

// ── applying a plan ──
async function buildContext(ov = {}) {
  const real = machineSpecs();
  const use = runtimesInUse();
  const avgRss = {}, measured = {};
  for (const v of use.fpm) {
    const rt = pickFpm(v), m = rt ? await fpmAvgRss(rt) : null;
    if (m) { avgRss[v] = m.avgMB; measured[v] = true; } else avgRss[v] = AUTO.avgRssMB[v] || 70;
  }
  const maxExec = parseInt(readPhpIni().settings.max_execution_time, 10);
  return { cores: ov.cores || real.cores, ramMB: ov.ramMB || real.ramMB, use, avgRss, measured,
           pgInstalled: pgInstalled(), redisInstalled: redisInstalled(), maxExecSec: Number.isInteger(maxExec) ? maxExec : null };
}

const isBlocked = (target, sig) => { const b = AUTO.blocked[target]; return b && b.sig === sig && Date.now() < b.until; };

async function applyFrankenThreads(ctx, plan, opts) {
  const steps = [], changes = [], want = plan.frankenphp.num_threads;
  if (!fs.existsSync(CADDYFILE_PATH)) return { steps: [{ name: 'frankenphp', status: 'skipped', detail: 'Caddyfile tidak ditemukan' }], changes };
  const cur = readFrankenphpSettings().num_threads;
  if (cur === want) return { steps: [{ name: 'frankenphp', status: 'unchanged', detail: `num_threads ${want}` }], changes };
  if (isBlocked('frankenphp', String(want))) return { steps: [{ name: 'frankenphp', status: 'blocked', detail: `num_threads ${want} diblokir sementara (restart berulang sebelumnya)` }], changes };
  changes.push({ target: 'frankenphp', key: 'num_threads', old: cur ?? 'default', new: String(want) });
  if (opts.dry) return { steps: [{ name: 'frankenphp', status: 'would-change', detail: `num_threads ${cur ?? 'default'} → ${want}` }], changes };
  const active = await serviceActive('frankenphp');   // at boot this runs BEFORE the service starts → false
  if (active && !lowLoad(ctx.cores)) {
    AUTO.pending.push({ target: 'frankenphp', key: 'num_threads', old: cur ?? 'default', new: want, since: new Date().toISOString(), why: 'beban server tinggi: ditunda sampai beban rendah' });
    return { steps: [{ name: 'frankenphp', status: 'deferred', detail: 'beban tinggi, ditunda' }], changes: [] };
  }
  try {
    const n0 = active ? await nRestarts('frankenphp') : 0;
    updateFrankenphpSettings({ num_threads: want });
    const now = new Date().toISOString();
    if (active) AUTO.awaitingRestart.frankenphp = now;
    AUTO.watch.push({ kind: 'threads', service: 'frankenphp', target: 'frankenphp', sig: String(want), prevThreads: cur ?? null, n0, ts: now });
    steps.push({ name: 'frankenphp', status: 'changed', detail: `num_threads ${want}` + (active ? ' (berlaku setelah FrankenPHP di-restart)' : '') });
  } catch (e) { return { steps: [{ name: 'frankenphp', status: 'error', detail: e.message }], changes: [] }; }
  return { steps, changes };
}

async function applyFpmPool(rt, entry, opts) {
  const name = `php-fpm${rt.version}`, steps = [], changes = [];
  const file = path.join(poolDir(rt), POOL_FILE), next = poolFileContent(entry.pool), sig = JSON.stringify(entry.pool);
  let prev = null; try { prev = fs.readFileSync(file, 'utf8'); } catch {}
  const oldVals = parseIniLike(prev);
  const diffs = POOL_KEYS.filter(k => String(oldVals[k] ?? '') !== String(entry.pool[k]));
  const manual = findManualPoolFiles(rt).filter(m => m.onlyManaged);
  if (opts.periodic && prev !== null && diffs.length) {   // hysteresis: small drift is not worth a reload
    const o = parseInt(oldVals['pm.max_children'], 10) || 0, n = entry.pool['pm.max_children'];
    if (oldVals.request_terminate_timeout === String(entry.pool.request_terminate_timeout) && Math.abs(n - o) < Math.max(3, Math.round(o * 0.1)))
      return { steps: [{ name, status: 'unchanged', detail: `pm.max_children ${o} (selisih kecil, dibiarkan)` }], changes };
  }
  if (!diffs.length && !manual.length && prev !== null) return { steps: [{ name, status: 'unchanged', detail: file }], changes };
  if (isBlocked(name, sig)) return { steps: [{ name, status: 'blocked', detail: 'nilai ini diblokir sementara (restart berulang sebelumnya)' }], changes };
  for (const k of diffs) changes.push({ target: name, key: k, old: oldVals[k] ?? null, new: String(entry.pool[k]) });
  if (opts.dry) { for (const m of manual) changes.push({ target: name, key: `file ${m.file}`, old: 'manual', new: 'diambil alih panel' }); return { steps: [{ name, status: 'would-change', detail: file }], changes }; }

  const adopted = [], undo = () => {
    for (const a of adopted) { try { fs.renameSync(a.to, a.from); } catch {} }
    try { if (prev === null) fs.rmSync(file, { force: true }); else fs.writeFileSync(file, prev); } catch {}
  };
  try {
    const live = await fpmActive(rt);                 // at boot this runs BEFORE php-fpm starts → false
    const n0 = live ? await nRestarts(rt.service) : 0;
    fs.mkdirSync(poolDir(rt), { recursive: true });
    fs.writeFileSync(file + '.tmp', next, { mode: 0o644 }); fs.renameSync(file + '.tmp', file);
    try { await execFileAsync(rt.bin, ['-t'], { timeout: 15000 }); }
    catch (e) { undo(); return { steps: [{ name, status: 'error', detail: 'php-fpm -t gagal, dikembalikan: ' + String(e.stderr || e.message).trim().split('\n').slice(-2).join(' | ') }], changes: [] }; }
    for (const m of manual) {   // adopt: the panel file is now the single source of truth for these keys
      const to = `${m.path}.diambil-alih-panel.${Date.now()}`;
      fs.renameSync(m.path, to); adopted.push({ from: m.path, to });
      changes.push({ target: name, key: `file ${m.file}`, old: 'manual', new: 'diambil alih panel (di-backup)' });
    }
    try { await execFileAsync(rt.bin, ['-t'], { timeout: 15000 }); }
    catch (e) { undo(); return { steps: [{ name, status: 'error', detail: 'php-fpm -t gagal setelah ambil alih, dikembalikan: ' + String(e.stderr || e.message).trim().split('\n').slice(-2).join(' | ') }], changes: [] }; }
    const eff = await fpmEffective(rt);
    let detail = file, status = 'changed';
    if (eff && String(eff['pm.max_children']) !== String(entry.pool['pm.max_children'])) { status = 'warning'; detail += ` (tertimpa konfigurasi lain: efektif pm.max_children=${eff['pm.max_children']})`; }
    if (live) {
      try { await execFileAsync('systemctl', ['reload', rt.service], { timeout: 20000 }); detail += ' (di-reload)'; }
      catch (e) { undo(); return { steps: [{ name, status: 'error', detail: 'reload gagal, dikembalikan: ' + e.message }], changes: [] }; }
    } else detail += ' (berlaku saat service start)';
    AUTO.watch.push({ kind: 'fpm-pool', service: rt.service, target: name, sig, file, prev, adopted, n0, ts: new Date().toISOString() });
    steps.push({ name, status, detail });
  } catch (e) { undo(); return { steps: [{ name, status: 'error', detail: e.message }], changes: [] }; }
  return { steps, changes };
}

async function applyPg(ctx, plan, opts) {
  const pg = findPgCluster();
  if (!pg) return { steps: [{ name: 'postgresql', status: 'skipped', detail: 'cluster PostgreSQL tidak ditemukan' }], changes: [] };
  const file = path.join(pg.confD, AUTOTUNE_PG_FILE), next = pgTuneFileContent(plan.postgres);
  let prev = null; try { prev = fs.readFileSync(file, 'utf8'); } catch {}
  const oldVals = parseIniLike(prev);
  const diffs = TUNE_PG_KEYS.filter(k => String(oldVals[k] ?? '') !== String(plan.postgres[k]));
  if (!diffs.length && prev !== null) return { steps: [{ name: 'postgresql', status: 'unchanged', detail: file }], changes: [] };
  const changes = diffs.map(k => ({ target: 'postgresql', key: k, old: oldVals[k] ?? null, new: String(plan.postgres[k]) }));
  if (opts.dry) return { steps: [{ name: 'postgresql', status: 'would-change', detail: file }], changes };
  try {
    ensurePgIncludeDir(pg);
    fs.mkdirSync(pg.confD, { recursive: true });
    fs.writeFileSync(file + '.tmp', next, { mode: 0o644 }); fs.renameSync(file + '.tmp', file);
    const bad = pgValidate(pg);
    if (bad && bad !== 'skip') {
      if (prev === null) fs.rmSync(file, { force: true }); else fs.writeFileSync(file, prev);
      return { steps: [{ name: 'postgresql', status: 'error', detail: 'validasi gagal, dikembalikan: ' + bad }], changes: [] };
    }
    if (await serviceActive('postgresql')) AUTO.awaitingRestart.postgresql = new Date().toISOString();
    return { steps: [{ name: 'postgresql', status: 'changed', detail: file + (bad === 'skip' ? ' (tidak divalidasi: biner postgres tidak ada)' : '') }], changes };
  } catch (e) { return { steps: [{ name: 'postgresql', status: 'error', detail: e.message }], changes: [] }; }
}

async function applyPlan(ctx, plan, reason, opts = {}) {
  if (!opts.dry) AUTO.pending = [];
  const all = { steps: [], changes: [] };
  const merge = r => { all.steps.push(...r.steps); all.changes.push(...r.changes); };
  merge(await applyFrankenThreads(ctx, plan, opts));
  for (const e of plan.fpm) { const rt = pickFpm(e.version); if (rt) merge(await applyFpmPool(rt, e, opts)); }
  merge(await applyPg(ctx, plan, opts));
  all.ok = !all.steps.some(s => s.status === 'error');
  if (!opts.dry) for (const c of all.changes) logChange(c.target, c.key, c.old, c.new, reason);
  if (!opts.dry) {
    for (const w of AUTO.watch.filter(w => !w.armed)) {
      w.armed = true;
      setTimeout(() => evaluateWatch(w).catch(() => {}), GUARD_MS + 500).unref();
    }
    persistAuto();
  }
  return all;
}

// Restart-storm guard: more than 3 service restarts within the window after a change → roll back.
async function rollbackWatch(w) {
  const reason = 'rollback: service restart berulang setelah perubahan otomatis';
  if (w.kind === 'fpm-pool') {
    const rt = pickFpm(w.service.replace(/^php|-fpm$/g, ''));
    try {
      for (const a of w.adopted || []) { try { fs.renameSync(a.to, a.from); } catch {} }
      if (w.prev === null) fs.rmSync(w.file, { force: true }); else fs.writeFileSync(w.file, w.prev);
      if (rt && await fpmActive(rt)) await execFileAsync('systemctl', ['reload', rt.service], { timeout: 20000 });
    } catch (e) { autotuneLog(`EVENT rollback ${w.target} gagal: ${e.message}`); }
  } else if (w.kind === 'threads') {
    try {
      if (w.prevThreads == null) fs.writeFileSync(CADDYFILE_PATH, tuneCaddyContent(fs.readFileSync(CADDYFILE_PATH, 'utf8'), null));
      else updateFrankenphpSettings({ num_threads: w.prevThreads });
      AUTO.awaitingRestart.frankenphp = new Date().toISOString();
    } catch (e) { autotuneLog(`EVENT rollback ${w.target} gagal: ${e.message}`); }
  }
  AUTO.blocked[w.target] = { sig: w.sig, until: Date.now() + 24 * 3600 * 1000 };
  logChange(w.target, 'rollback', w.sig === undefined ? '-' : 'nilai otomatis', 'nilai sebelumnya', reason);
  notify(`${w.target}: service restart lebih dari 3 kali setelah perubahan otomatis — nilai sebelumnya dikembalikan dan nilai yang sama diblokir 24 jam.`);
}
async function evaluateWatch(w) {
  refreshAuto();
  if (!AUTO.watch.some(x => x.ts === w.ts && x.service === w.service && x.kind === w.kind)) return 'gone';
  const delta = (await nRestarts(w.service)) - (w.n0 || 0);
  const drop = () => { AUTO.watch = AUTO.watch.filter(x => !(x.ts === w.ts && x.service === w.service && x.kind === w.kind)); };
  if (delta > 3) { drop(); await rollbackWatch(w); persistAuto(); return 'rolled-back'; }
  if (Date.now() - new Date(w.ts).getTime() >= GUARD_MS) { drop(); persistAuto(); }
  return 'ok';
}

// If the panel itself restarted between swapping the binary and the end of the watch window, finish the job here.
async function recoverFrankenUpgrade() {
  const p = AUTO.fpUpgradePending;
  if (!p || (FP_JOB && FP_JOB.state === 'running')) return;
  if (Date.now() - new Date(p.ts).getTime() < UPGRADE_WATCH_MS) return;       // still inside the watch window of a live job
  const d = (await nRestarts('frankenphp')) - (p.n0 || 0), active = await serviceActive('frankenphp');
  if (d > 3 || !active) {
    try {
      const staged = FRANKENPHP_BIN + '.new';
      fs.copyFileSync(p.backup, staged); fs.chmodSync(staged, 0o755); fs.renameSync(staged, FRANKENPHP_BIN);
      await execFileAsync('systemctl', ['restart', 'frankenphp'], { timeout: 90000 });
      notify(`Upgrade FrankenPHP (${p.tag}) tidak selesai dipantau dan service tidak stabil (NRestarts +${d}${active ? '' : ', tidak aktif'}): biner lama dipulihkan otomatis.`);
    } catch (e) { notify(`Upgrade FrankenPHP (${p.tag}) bermasalah dan pemulihan biner lama gagal: ${e.message}`); }
  } else autotuneLog(`EVENT upgrade-frankenphp ${p.tag}: pemantauan selesai setelah panel restart, service stabil`);
  delete AUTO.fpUpgradePending; persistAuto();
}

let _autotuneBusy = false;
// reason: 'boot' | 'startup' | 'periodic' | any text (event). Returns { ok, steps, changes } or { skipped }.
async function autotuneTick(reason, opts = {}) {
  if (_autotuneBusy) return { skipped: 'busy' };
  _autotuneBusy = true;
  try {
    refreshAuto();
    await recoverFrankenUpgrade();
    for (const w of [...AUTO.watch]) await evaluateWatch(w);          // a rollback must come before re-planning
    AUTO.watch = AUTO.watch.filter(w => Date.now() - new Date(w.ts).getTime() < 10 * 60 * 1000);
    for (const [t, unit] of [['frankenphp', 'frankenphp'], ['postgresql', pgInstalled() ? `postgresql@${findPgCluster().version}-main` : 'postgresql']]) {
      if (AUTO.awaitingRestart[t] && await serviceStartedAfter(unit, AUTO.awaitingRestart[t])) delete AUTO.awaitingRestart[t];
    }
    const specs = machineSpecs();
    let why = reason;
    if (AUTO.specs && (AUTO.specs.cores !== specs.cores || Math.abs(AUTO.specs.ramMB - specs.ramMB) > 64))
      why = `${reason === 'boot' ? 'boot — ' : ''}core/RAM berubah (${AUTO.specs.cores} core / ${AUTO.specs.ramMB} MB → ${specs.cores} core / ${specs.ramMB} MB)`;
    else if (reason === 'startup') why = 'panel dijalankan';
    const periodic = reason === 'periodic';
    const ctx = await buildContext();
    const plan = computePlan(ctx);
    const lowRam = plan.warnings.filter(w => w.type === 'low-ram'), lrSig = JSON.stringify(lowRam.map(w => [w.version, w.needMB]));
    if (lowRam.length) {
      if (!AUTO.lowRam || AUTO.lowRam.sig !== lrSig || Date.now() - AUTO.lowRam.ts > 24 * 3600e3) { notify(lowRam[0].message); AUTO.lowRam = { sig: lrSig, ts: Date.now() }; }
    } else if (AUTO.lowRam) AUTO.lowRam = null;
    for (const v of Object.keys(ctx.measured)) AUTO.avgRssMB[v] = ctx.avgRss[v];   // the boot run (FPM not up yet) reuses these
    if (periodic) for (const v of Object.keys(ctx.measured)) why = `berkala: memori terukur per proses PHP-FPM ${v} = ${ctx.avgRss[v]} MB (estimasi dipakai ${Math.max(50, ctx.avgRss[v])} MB)`;
    const res = await applyPlan(ctx, plan, why, { ...opts, boot: reason === 'boot', periodic });
    AUTO.specs = specs; AUTO.lastChecked = new Date().toISOString();
    if (res.changes.length) AUTO.lastApplied = AUTO.lastChecked;
    persistAuto();
    return res;
  } finally { _autotuneBusy = false; }
}

// The boot unit must always exist: it applies the plan before PostgreSQL/PHP-FPM/FrankenPHP start.
function bootUnitText() {
  const before = ['postgresql.service'];
  const p = findPgCluster(); if (p) before.push(`postgresql@${p.version}-main.service`);
  for (const rt of fpmRuntimes()) before.push(`${rt.service}.service`);
  before.push('frankenphp.service');
  return `[Unit]
Description=PS Panel auto-tune (PHP worker + PostgreSQL memory) sesuai core & RAM
DefaultDependencies=no
After=local-fs.target
Before=${before.join(' ')}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${process.execPath} ${path.join(PANEL_DIR, 'server.js')} --autotune
TimeoutSec=60

[Install]
WantedBy=multi-user.target
`;
}
async function ensureBootUnit() {
  try {
    const want = bootUnitText();
    let cur = null; try { cur = fs.readFileSync(AUTOTUNE_UNIT, 'utf8'); } catch {}
    if (cur !== want) { fs.writeFileSync(AUTOTUNE_UNIT, want); await execFileAsync('systemctl', ['daemon-reload'], { timeout: 20000 }); autotuneLog('EVENT unit boot auto-tune dipasang/diperbarui'); }
    const en = await new Promise(r => execFile('systemctl', ['is-enabled', AUTOTUNE_UNIT_NAME], (e, o) => r(!e && String(o).trim() === 'enabled')));
    if (!en) await execFileAsync('systemctl', ['enable', AUTOTUNE_UNIT_NAME], { timeout: 20000 });
  } catch (e) { console.warn('[autotune] boot unit:', e.message); }
}

function checkPanelPassword(req, res) {
  const { password } = req.body || {};
  if (typeof password !== 'string' || !bcrypt.compareSync(password, authState.hash)) {
    res.status(403).json({ error: 'Wrong password' }); // not 401: the frontend api() logs out on 401
    return false;
  }
  return true;
}

// ── frontend data ──
let _fpInfoCache = { mtime: 0, phpVersion: null };
async function frankenphpInfo() {
  if (!fs.existsSync(FRANKENPHP_BIN)) return { installed: false };
  let version = null, phpVersion = null;
  try { version = ((await execFileAsync(FRANKENPHP_BIN, ['version'], { timeout: 8000 })).stdout.match(/v?\d+\.\d+\.\d+/) || [])[0] || null; } catch {}
  const mt = fs.statSync(FRANKENPHP_BIN).mtimeMs;
  if (_fpInfoCache.mtime === mt) phpVersion = _fpInfoCache.phpVersion;
  else {
    try {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'psp-')), f = path.join(dir, 'v.php');
      fs.writeFileSync(f, '<?php echo PHP_VERSION;');
      phpVersion = (await execFileAsync(FRANKENPHP_BIN, ['php-cli', f], { timeout: 10000 })).stdout.trim() || null;
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
    _fpInfoCache = { mtime: mt, phpVersion };
  }
  return { installed: true, version, phpVersion };
}

function listSites() {
  const out = [], d = readDefaultSite();
  if (d) out.push({ label: 'situs default (:80)', runtime: d.runtime, version: d.version });
  try {
    for (const f of fs.readdirSync(VHOSTS_DIR).filter(f => f.endsWith('.conf'))) {
      const r = parseRuntime(fs.readFileSync(path.join(VHOSTS_DIR, f), 'utf8'));
      out.push({ label: f.replace(/\.conf$/, ''), runtime: r.runtime, version: r.version });
    }
  } catch {}
  return out;
}

app.get('/api/phpworker', auth, async (req, res) => {
  try {
    const ctx = await buildContext(), plan = computePlan(ctx), specs = machineSpecs();
    const fp = await frankenphpInfo();
    const fpmRts = fpmRuntimes();
    const fpm = await Promise.all(fpmRts.map(async rt => {
      let phpVersion = null;
      try { phpVersion = ((await execFileAsync(rt.bin, ['-v'], { timeout: 8000 })).stdout.match(/^PHP (\S+)/) || [])[1] || null; } catch {}
      const file = path.join(poolDir(rt), POOL_FILE);
      let txt = null; try { txt = fs.readFileSync(file, 'utf8'); } catch {}
      const entry = plan.fpm.find(f => f.version === rt.version);
      return { version: rt.version, phpVersion, active: await fpmActive(rt), nrestarts: await nRestarts(rt.service), inUse: ctx.use.fpm.has(rt.version),
               status: await fpmStatus(rt), pool: parseIniLike(txt), poolFile: file, plan: entry ? entry.pool : null, basis: entry ? entry.basis : null,
               manualFiles: findManualPoolFiles(rt).map(m => ({ file: m.file, onlyManaged: m.onlyManaged })) };
    }));
    res.json({
      ok: true,
      specs: { ...specs, cpuModel: cpuModel(), load1: os.loadavg()[0], lowLoad: lowLoad(specs.cores) },
      sites: listSites(),
      frankenphp: { ...fp, active: await serviceActive('frankenphp'), nrestarts: await nRestarts('frankenphp'),
                    threads: readFrankenphpSettings().num_threads, planThreads: plan.frankenphp.num_threads,
                    basis: plan.frankenphp.basis, warning: plan.frankenphp.warning, embeddedInUse: ctx.use.frankenphp },
      fpm,
      reserves: plan.reserves,
      warnings: plan.warnings,
      state: { lastApplied: AUTO.lastApplied || null, lastChecked: AUTO.lastChecked || null, pending: AUTO.pending, awaitingRestart: AUTO.awaitingRestart,
               alerts: AUTO.alerts, blocked: Object.fromEntries(Object.entries(AUTO.blocked).filter(([, b]) => Date.now() < b.until).map(([k, b]) => [k, new Date(b.until).toISOString()])) },
      history: readHistory(100),
    });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// PostgreSQL memory settings written by auto-tune (shown on the PostgreSQL page).
app.get('/api/autotune', auth, async (req, res) => {
  const ctx = await buildContext(), plan = computePlan(ctx);
  const current = {};
  const pg = findPgCluster();
  if (pg && fs.existsSync(pg.bin)) {
    const pgC = async k => {
      try {
        const { stdout } = await execFileAsync('runuser', ['-u', 'postgres', '--', pg.bin, '-C', k, '-c', 'config_file=' + pg.conf], { timeout: 10000 });
        return stdout.trim();
      } catch { return null; }
    };
    const blockBytes = parseInt(await pgC('block_size'), 10) || 8192;
    await Promise.all(TUNE_PG_KEYS.map(async k => {
      const raw = await pgC(k);
      current[k] = raw == null ? null : pgInternalToMB(k, raw, blockBytes);
    }));
  }
  res.json({ ok: true, specs: plan.specs, profile: plan.postgres, current, postgres: pg ? { version: pg.version } : null,
             awaitingRestart: AUTO.awaitingRestart.postgresql || null, lastApplied: AUTO.lastApplied || null });
});

// Explicit, password-confirmed restart of services whose auto-tuned values need one to take effect.
app.post('/api/phpworker/restart', auth, async (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  const targets = Array.isArray(req.body.targets) ? req.body.targets : [];
  const results = {};
  for (const t of targets) {
    const unit = t === 'frankenphp' ? 'frankenphp' : t === 'postgresql' ? 'postgresql' : null;
    if (!unit) continue;
    try { await execFileAsync('systemctl', ['restart', unit], { timeout: 90000 }); results[t] = null; delete AUTO.awaitingRestart[t]; }
    catch (e) { results[t] = e.message; }
  }
  persistAuto();
  autotuneLog(`EVENT restart manual (dikonfirmasi di UI): ${targets.join(',')}`);
  res.json({ ok: true, results });
});

// ── PHP security (PHP2Shell) ──
// Every runtime that serves web requests is checked against the fix. A runtime is SAFE when its
// version is at/above the upstream fix OR (distro packages) its changelog lists the CVEs: Ubuntu
// backports the fix without changing the upstream number (php8.3 8.3.6-0ubuntu0.24.04.13 is patched
// although 8.3.6 < 8.3.36), so a version-only comparison would flag safe servers.
const PHP_ADVISORY = {
  name: 'PHP2Shell', cves: ['CVE-2026-109618', 'CVE-2026-109619'],
  fixed: { '8.5': '8.5.12', '8.4': '8.4.27', '8.3': '8.3.36', '8.2': '8.2.35' },   // upstream releases of 2026-10-21
};
const DOC_DIR = process.env.PANEL_DOC_DIR || '/usr/share/doc';
const APT_CONF_D = process.env.PANEL_APT_CONF_D || '/etc/apt/apt.conf.d';
const APT_LISTS = process.env.PANEL_APT_LISTS || '/var/lib/apt/lists';
const SYSTEMD_DIR = process.env.PANEL_SYSTEMD_DIR || '/etc/systemd/system';
const UU_DROPIN = '52ps-panel-php-security';
const phpBranch = v => (String(v || '').match(/^(\d+\.\d+)/) || [])[1] || null;

function fetchText(url, ms = 15000) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = (u.protocol === 'http:' ? http : https).get(url, { timeout: ms, family: 4, headers: { 'User-Agent': 'PS-Panel', 'Accept': 'application/json' } }, res => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); }
      let d = ''; res.setEncoding('utf8'); res.on('data', c => d += c); res.on('end', () => resolve(d));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}
// Latest release of a PHP branch from php.net (cached; failures are tolerated: the built-in fix table still applies).
const _phpnet = {};
async function phpNetLatest(branch) {
  const c = _phpnet[branch];
  if (c && Date.now() < c.until) return c.v;
  let v = null;
  try {
    const base = process.env.PANEL_PHPNET_URL || 'https://www.php.net/releases/index.php?json&version=';
    const j = JSON.parse(await fetchText(base + branch));
    if (j && typeof j.version === 'string' && /^\d+\.\d+\.\d+$/.test(j.version) && phpBranch(j.version) === branch) v = j.version;
  } catch {}
  _phpnet[branch] = { v, until: Date.now() + (v ? 6 * 3600e3 : 30 * 60e3) };
  return v;
}
// true = changelog lists all advisory CVEs, false = changelog readable but not listed, null = no changelog
function changelogPatched(rt) {
  for (const pkg of [`php${rt.version}-fpm`, `php${rt.version}-common`, `php${rt.version}-cli`]) {
    try {
      const text = require('zlib').gunzipSync(fs.readFileSync(path.join(DOC_DIR, pkg, 'changelog.Debian.gz'))).toString('utf8');
      return PHP_ADVISORY.cves.every(c => text.includes(c));
    } catch {}
  }
  return null;
}

async function phpSecurityStatus() {
  const sites = listSites();
  const sitesOf = (runtime, ver) => sites.filter(s => s.runtime === runtime && (runtime === 'frankenphp' || !s.version || s.version === ver)).map(s => s.label);
  const rows = [];
  const mk = async ({ key, runtime, label, version, patchedByLog, siteLabels }) => {
    const branch = phpBranch(version), floor = branch ? PHP_ADVISORY.fixed[branch] || null : null;
    const latest = branch ? await phpNetLatest(branch) : null;
    let state, via, message;
    if (!version) { state = 'unknown'; via = 'unknown'; message = 'versi PHP tidak terbaca'; }
    else if (patchedByLog) { state = 'safe'; via = 'changelog'; message = `perbaikan ${PHP_ADVISORY.name} tercantum di changelog paket (backport distro)`; }
    else if (floor && cmpVer(version, floor) >= 0) { state = 'safe'; via = 'version'; message = `PHP ${version} ≥ ${floor}`; }
    else if (floor) { state = 'vulnerable'; via = 'version'; message = `PHP ${version} lebih rendah dari ${floor} — rentan ${PHP_ADVISORY.name}`; }
    else { state = 'vulnerable'; via = 'version'; message = `cabang PHP ${branch || version} tidak punya perbaikan resmi (end-of-life) — rentan ${PHP_ADVISORY.name}`; }
    const behind = state === 'safe' && via === 'version' && !!latest && cmpVer(version, latest) < 0;
    const inUse = siteLabels.length > 0;
    const severity = inUse ? (state === 'vulnerable' ? 'critical' : (behind || state === 'unknown') ? 'warning' : 'ok') : (state === 'vulnerable' ? 'info' : 'ok');
    rows.push({ key, runtime, label, version, branch, minimum: floor, latest, state, via, behind, inUse, sites: siteLabels, severity, message });
  };
  const fp = await frankenphpInfo();
  if (fp.installed) await mk({ key: 'frankenphp', runtime: 'frankenphp', label: `FrankenPHP ${fp.version || ''} (PHP bawaan)`.trim(), version: fp.phpVersion, patchedByLog: false, siteLabels: sitesOf('frankenphp') });
  for (const rt of fpmRuntimes()) {
    let ver = null; try { ver = ((await execFileAsync(rt.bin, ['-v'], { timeout: 8000 })).stdout.match(/^PHP (\S+)/) || [])[1] || null; } catch {}
    await mk({ key: `fpm:${rt.version}`, runtime: 'fpm', label: `PHP-FPM ${rt.version}`, version: ver, patchedByLog: changelogPatched(rt) === true, siteLabels: sitesOf('fpm', rt.version) });
  }
  return { ok: true, advisory: { name: PHP_ADVISORY.name, cves: PHP_ADVISORY.cves, fixed: PHP_ADVISORY.fixed }, checkedAt: new Date().toISOString(), runtimes: rows,
           critical: rows.some(r => r.severity === 'critical'), warning: rows.some(r => r.severity === 'warning') };
}

// ── automatic PHP security updates ──
async function unattendedStatus() {
  let installed = false;
  try { installed = /install ok installed/.test((await execFileAsync('dpkg-query', ['-W', '-f=${Status}', 'unattended-upgrades'], { timeout: 8000 })).stdout); } catch {}
  let origin = null;
  try {
    for (const f of fs.readdirSync(APT_LISTS).filter(f => /ondrej.*(InRelease|_Release)$/.test(f))) {
      const m = fs.readFileSync(path.join(APT_LISTS, f), 'utf8').match(/^Origin:\s*(\S+)/m);
      if (m) { origin = m[1]; break; }
    }
  } catch {}
  const timer = await new Promise(r => execFile('systemctl', ['is-enabled', 'apt-daily-upgrade.timer'], (e, o) => r(!e && /enabled/.test(String(o)))));
  return { installed, suryOrigin: origin, configured: fs.existsSync(path.join(APT_CONF_D, UU_DROPIN)), timerEnabled: timer };
}
// Allow the Sury PPA in unattended-upgrades (Ubuntu's own origins do not include it, so PHP from the
// PPA would otherwise never be updated automatically).
async function ensureUnattendedSury() {
  try {
    const st = await unattendedStatus();
    if (!st.installed || !st.suryOrigin) return st;
    const want = `// Managed by PS Panel: automatic security updates for PHP packages from the Ondrej (Sury) PPA.\nUnattended-Upgrade::Allowed-Origins { "${st.suryOrigin}:\${distro_codename}"; };\n`;
    const file = path.join(APT_CONF_D, UU_DROPIN);
    let cur = null; try { cur = fs.readFileSync(file, 'utf8'); } catch {}
    if (cur !== want) { fs.writeFileSync(file, want); autotuneLog('EVENT unattended-upgrades: origin Sury diizinkan untuk pembaruan keamanan PHP'); st.configured = true; }
    return st;
  } catch (e) { console.warn('[security] unattended-upgrades:', e.message); return null; }
}
async function aptPolicy(pkg) {
  try {
    const out = (await execFileAsync('apt-cache', ['policy', pkg], { timeout: 15000 })).stdout;
    return { installed: (out.match(/Installed:\s*(\S+)/) || [])[1] || null, candidate: (out.match(/Candidate:\s*(\S+)/) || [])[1] || null };
  } catch { return { installed: null, candidate: null }; }
}
async function restartQueueWorkers() {
  const units = [];
  try { for (const f of fs.readdirSync(SYSTEMD_DIR).filter(f => f.endsWith('.service'))) if (/queue:work/.test(fs.readFileSync(path.join(SYSTEMD_DIR, f), 'utf8'))) units.push(f); } catch {}
  for (const u of units) { try { await execFileAsync('systemctl', ['restart', u], { timeout: 60000 }); } catch (e) { autotuneLog(`EVENT restart queue worker ${u} gagal: ${e.message}`); } }
  return units;
}
async function afterPhpPackagesChanged(why) {
  const reloaded = [];
  for (const rt of fpmRuntimes()) if (await fpmActive(rt)) { try { await execFileAsync('systemctl', ['reload', rt.service], { timeout: 20000 }); reloaded.push(rt.service); } catch {} }
  const queues = await restartQueueWorkers();
  autotuneLog(`EVENT paket PHP berubah (${why}): reload ${reloaded.join(',') || '-'}; restart queue worker ${queues.join(',') || '-'}`);
}

// Runs from the periodic tick: raises the alert, notices package updates done by unattended-upgrades,
// and updates vulnerable PHP-FPM packages itself — deferred while the server is busy, but at most 24 h.
async function securityTick() {
  const st = await phpSecurityStatus();
  const crit = st.runtimes.filter(r => r.severity === 'critical');
  const sig = JSON.stringify(crit.map(r => `${r.key}:${r.version}`));
  refreshAuto();
  if (crit.length) {
    if (!AUTO.secAlert || AUTO.secAlert.sig !== sig || Date.now() - AUTO.secAlert.ts > 24 * 3600e3) {
      notify(`${PHP_ADVISORY.name}: ${crit.map(r => `${r.label} (${r.message})`).join('; ')}`);
      AUTO.secAlert = { sig, ts: Date.now() };
    }
  } else AUTO.secAlert = null;
  // a PHP package changed (unattended-upgrades or by hand): graceful reload + queue workers pick up the new binary
  const pkgSig = {};
  for (const rt of fpmRuntimes()) pkgSig[rt.version] = (await aptPolicy(`php${rt.version}-fpm`)).installed;
  if (AUTO.phpPkg && JSON.stringify(AUTO.phpPkg) !== JSON.stringify(pkgSig)) await afterPhpPackagesChanged('versi paket berubah');
  AUTO.phpPkg = pkgSig;
  // own update path for vulnerable, in-use PHP-FPM packages
  const vuln = st.runtimes.filter(r => r.runtime === 'fpm' && r.inUse && r.state === 'vulnerable');
  if (!vuln.length || process.env.PANEL_SECURITY_APT === '0') { delete AUTO.secUpdate; persistAuto(); return st; }
  const su = AUTO.secUpdate = AUTO.secUpdate || { since: new Date().toISOString() };
  const lows = lowLoad(machineSpecs().cores), overdue = Date.now() - new Date(su.since).getTime() >= 24 * 3600e3;
  if (su.lastTry && Date.now() - new Date(su.lastTry).getTime() < 6 * 3600e3) { persistAuto(); return st; }
  if (!lows && !overdue) { su.note = 'ditunda: beban server tinggi (paling lambat 24 jam sejak terdeteksi)'; persistAuto(); return st; }
  const pkgs = [];
  for (const r of vuln) {
    const pol = await aptPolicy(`php${r.key.slice(4)}-fpm`);
    if (!pol.candidate || pol.candidate === pol.installed) { su.note = `php${r.key.slice(4)}-fpm: belum ada pembaruan di repo (terpasang ${pol.installed || '?'})`; continue; }
    try { for (const p of (await execFileAsync('dpkg-query', ['-W', '-f=${Package}\\n', `php${r.key.slice(4)}-*`], { timeout: 15000 })).stdout.split('\n').filter(Boolean)) pkgs.push(p); } catch {}
  }
  if (!pkgs.length) { persistAuto(); return st; }
  su.lastTry = new Date().toISOString(); su.note = 'memperbarui paket PHP...'; persistAuto();
  const env = { ...process.env, DEBIAN_FRONTEND: 'noninteractive' };
  try {
    await execFileAsync('apt-get', ['update', '-qq'], { timeout: 180000, env });
    await execFileAsync('apt-get', ['install', '-y', '-qq', '--only-upgrade', '-o', 'Dpkg::Options::=--force-confold', ...pkgs], { timeout: 600000, env });
    autotuneLog(`EVENT pembaruan keamanan PHP otomatis: ${[...new Set(pkgs)].join(' ')} (${lows ? 'beban rendah' : 'batas 24 jam'})`);
    await afterPhpPackagesChanged('pembaruan keamanan otomatis');
    su.note = 'paket diperbarui';
    for (const rt of fpmRuntimes()) pkgSig[rt.version] = (await aptPolicy(`php${rt.version}-fpm`)).installed;   // our own update must not trigger the "changed" path again
    AUTO.phpPkg = pkgSig;
  } catch (e) { su.note = 'gagal memperbarui: ' + String(e.stderr || e.message).trim().split('\n').slice(-2).join(' | '); autotuneLog(`EVENT pembaruan keamanan PHP gagal: ${su.note}`); }
  persistAuto();
  return st;
}

// One button: move every php_server site (and the default site) to a PHP-FPM that is not vulnerable.
async function switchAllToFpm() {
  const st = await phpSecurityStatus();
  const rt = pickFpm();
  if (!rt) return { ok: false, error: 'PHP-FPM belum terpasang' };
  const row = st.runtimes.find(r => r.key === `fpm:${rt.version}`);
  if (!row || row.state !== 'safe') return { ok: false, error: `PHP-FPM ${rt.version} sendiri belum aman (${row ? row.message : 'status tidak diketahui'}). Perbarui paketnya dulu (apt-get update && apt-get upgrade).` };
  const targets = [];
  const d = readDefaultSite(); if (d && d.runtime === 'frankenphp') targets.push('default');
  try { for (const f of fs.readdirSync(VHOSTS_DIR).filter(f => f.endsWith('.conf'))) if (parseRuntime(fs.readFileSync(path.join(VHOSTS_DIR, f), 'utf8')).runtime === 'frankenphp') targets.push(f.replace(/\.conf$/, '')); } catch {}
  if (!targets.length) return { ok: true, results: [], note: 'tidak ada situs yang memakai PHP bawaan FrankenPHP' };
  const results = [];
  for (const t of targets) {
    const r = await convertRuntime(t, 'fpm', rt.version);
    results.push({ target: t, ok: !r.error, error: r.error || null });
    if (r.error) break;
  }
  let fpmIni = null; try { fpmIni = await syncFpmIni([rt.version]); } catch {}
  const reloaded = await new Promise(resolve => reloadFrankenPHP(err => resolve(!err)));
  autotuneLog(`EVENT keamanan: ${results.filter(x => x.ok).length}/${targets.length} situs dialihkan ke PHP-FPM ${rt.version}`);
  setImmediate(() => autotuneTick('runtime situs berubah (dialihkan ke PHP-FPM karena keamanan)').catch(() => {}));
  return { ok: results.every(x => x.ok), results, reloaded, fpmIni, phpVersion: rt.version };
}

app.get('/api/security/php', auth, async (req, res) => {
  try {
    const st = await phpSecurityStatus();
    refreshAuto();
    res.json({ ...st, autoUpdate: await unattendedStatus(), secUpdate: AUTO.secUpdate || null, fpmAvailable: !!pickFpm() });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});
app.post('/api/security/switch-to-fpm', auth, async (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  try { const r = await switchAllToFpm(); res.status(r.ok ? 200 : 400).json(r); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Safe FrankenPHP upgrade ──
// The new binary is downloaded to a temp dir, started on TEMPORARY ports and hit with the traffic
// that crashed v1.3.2 (parallel HTTPS from PHP threads: cURL + OpenSSL) BEFORE the installed binary
// is touched. An old CPU can also reject a new build (SIGILL on the first PHP request), which
// `frankenphp version`/`validate` do not reveal. After the swap the service is watched for 60 s and
// the old binary is restored automatically if it keeps restarting.
const UPGRADE_WATCH_MS = parseInt(process.env.PANEL_UPGRADE_WATCH_MS, 10) || 60000;
let FP_JOB = null;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => { const s = require('net').createServer(); s.on('error', reject); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });

function downloadTo(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = (u.protocol === 'http:' ? http : https).get(url, { timeout: 60000, family: 4, headers: { 'User-Agent': 'PS-Panel' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) { res.resume(); return resolve(downloadTo(new URL(res.headers.location, url).toString(), dest, redirects - 1)); }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('HTTP ' + res.statusCode)); }
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve(parseInt(res.headers['content-length'], 10) || fs.statSync(dest).size)));
      file.on('error', reject); res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout'))); req.on('error', reject);
  });
}

async function resolveFrankenphpTag() {
  for (const repo of ['php/frankenphp', 'dunglas/frankenphp']) {
    try { const j = JSON.parse(await fetchText(`https://api.github.com/repos/${repo}/releases/latest`)); if (j.tag_name) return { repo, tag: j.tag_name }; } catch {}
  }
  return null;
}
const frankenAssets = () => {
  if (process.env.PANEL_FRANKENPHP_ASSETS) return process.env.PANEL_FRANKENPHP_ASSETS.split(',').map(x => x.trim()).filter(Boolean);
  const arch = os.arch() === 'arm64' ? 'aarch64' : 'x86_64';
  return [`frankenphp-linux-${arch}`, `frankenphp-linux-${arch}-gnu`];   // static build first, then the glibc variant
};
const frankenAssetUrl = (repo, tag, asset) => process.env.PANEL_FRANKENPHP_URL_BASE ? `${process.env.PANEL_FRANKENPHP_URL_BASE}/${asset}` : `https://github.com/${repo}/releases/download/${tag}/${asset}`;

// Starts the candidate on temporary ports and stresses cURL + OpenSSL from several PHP threads at once.
async function testFrankenBinary(bin, workDir, say) {
  const out = { ok: false, detail: '', frankenVersion: null, phpVersion: null };
  try { out.frankenVersion = ((await execFileAsync(bin, ['version'], { timeout: 15000 })).stdout.match(/v?\d+\.\d+\.\d+/) || [])[0] || null; }
  catch (e) { out.detail = `\`version\` gagal: ${(e.signal || e.message)}`; return out; }
  const t = fs.mkdtempSync(path.join(workDir, 'try-'));
  const root = path.join(t, 'www'); fs.mkdirSync(root);
  // the embedded PHP must start at all (an unsupported CPU dies here with SIGILL)
  fs.writeFileSync(path.join(root, 'v.php'), '<?php echo PHP_VERSION;');
  try { out.phpVersion = (await execFileAsync(bin, ['php-cli', path.join(root, 'v.php')], { timeout: 20000, env: { ...process.env, HOME: t } })).stdout.trim(); }
  catch (e) { out.detail = `PHP bawaan tidak bisa dijalankan: ${e.signal || e.message}`; fs.rmSync(t, { recursive: true, force: true }); return out; }
  say(`PHP bawaan ${out.phpVersion} berjalan; uji lalu lintas HTTPS paralel di port sementara...`);
  const p1 = await freePort(), p2 = await freePort();
  fs.writeFileSync(path.join(root, 'ping.txt'), 'pong');
  fs.writeFileSync(path.join(root, 'probe.php'), `<?php
$n = 12; $mh = curl_multi_init(); $hs = [];
for ($i = 0; $i < $n; $i++) { $ch = curl_init('https://localhost:${p2}/ping.txt'); curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => 1, CURLOPT_SSL_VERIFYPEER => 0, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_TIMEOUT => 15]); curl_multi_add_handle($mh, $ch); $hs[] = $ch; }
do { curl_multi_exec($mh, $run); curl_multi_select($mh, 0.2); } while ($run > 0);
$ok = 0; $err = []; foreach ($hs as $h) { if (curl_errno($h) === 0 && curl_getinfo($h, CURLINFO_HTTP_CODE) === 200) $ok++; else $err[] = curl_error($h); }
$k = function_exists('openssl_pkey_new') ? (openssl_pkey_new(['private_key_bits' => 1024]) ? 1 : 0) : -1;
header('Content-Type: application/json'); echo json_encode(['ok' => $ok, 'n' => $n, 'err' => array_values(array_unique($err)), 'openssl' => $k]);
`);
  const cfg = path.join(t, 'Caddyfile');
  fs.writeFileSync(cfg, `{\n\tadmin off\n\tlocal_certs\n\tskip_install_trust\n\tauto_https disable_redirects\n\tfrankenphp {\n\t\tnum_threads 4\n\t}\n}\n\nhttp://127.0.0.1:${p1} {\n\troot * ${root}\n\tphp_server\n}\n\nhttps://localhost:${p2} {\n\troot * ${root}\n\tfile_server\n}\n`);
  const env = { ...process.env, HOME: t, XDG_DATA_HOME: path.join(t, 'data'), XDG_CONFIG_HOME: path.join(t, 'config') };   // never touch production's TLS storage
  const child = spawn(bin, ['run', '--config', cfg, '--adapter', 'caddyfile'], { cwd: t, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let exited = null, tail = '';
  child.on('exit', (code, sig) => { exited = { code, sig }; });
  for (const s of [child.stdout, child.stderr]) s.on('data', d => { tail = (tail + d).slice(-1500); });
  const kill = async () => { if (!exited) { child.kill('SIGTERM'); for (let i = 0; i < 10 && !exited; i++) await sleep(300); if (!exited) child.kill('SIGKILL'); } };
  try {
    let up = false;
    for (let i = 0; i < 60 && !exited; i++) { if ((await fetchText(`http://127.0.0.1:${p1}/ping.txt`, 2000).catch(() => null)) === 'pong') { up = true; break; } await sleep(500); }
    if (!up) { out.detail = exited ? `proses mati saat start (${exited.sig || 'kode ' + exited.code})` : 'tidak mau melayani permintaan di port sementara'; return out; }
    const results = await Promise.all(Array.from({ length: 8 }, () => fetchText(`http://127.0.0.1:${p1}/probe.php`, 40000).then(b => ({ b: JSON.parse(b) }), e => ({ e: e.message }))));
    if (exited) { out.detail = `proses mati saat menerima lalu lintas: ${exited.sig || 'kode ' + exited.code}`; return out; }
    const bad = results.filter(r => r.e || !r.b || r.b.ok !== r.b.n || r.b.openssl === 0);
    if (bad.length) { const x = bad[0]; out.detail = `${bad.length}/8 permintaan gagal: ${x.e || JSON.stringify(x.b.err || x.b)}`; return out; }
    await sleep(500);
    if (exited) { out.detail = `proses mati setelah uji: ${exited.sig || 'kode ' + exited.code}`; return out; }
    out.ok = true; out.detail = '8 permintaan paralel × 12 koneksi HTTPS (cURL + OpenSSL) lolos, proses tetap hidup';
    return out;
  } finally { await kill(); fs.rmSync(t, { recursive: true, force: true }); }
}

function jobSay(job, msg, level = 'info') { job.steps.push({ ts: new Date().toISOString(), level, msg }); autotuneLog(`EVENT upgrade-frankenphp ${msg}`); }
async function runFrankenUpgrade(job, opts) {
  const say = (m, l) => jobSay(job, m, l);
  let work = null;
  try {
    if (!fs.existsSync(FRANKENPHP_BIN)) throw new Error('biner FrankenPHP tidak ditemukan di ' + FRANKENPHP_BIN);
    const before = await frankenphpInfo();
    say(`terpasang: FrankenPHP ${before.version || '?'} · PHP ${before.phpVersion || '?'} · CPU: ${cpuModel() || '?'}`);
    let repo = 'php/frankenphp', tag = opts.tag;
    if (!tag) { const r = await resolveFrankenphpTag(); if (!r) throw new Error('tidak bisa menentukan rilis terbaru (GitHub tidak terjangkau)'); repo = r.repo; tag = r.tag; }
    say(`rilis target: ${tag}`);
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'psp-fpup-'));
    let chosen = null;
    for (const asset of frankenAssets()) {
      const dest = path.join(work, asset);
      say(`mengunduh ${asset}...`);
      try { const size = await downloadTo(frankenAssetUrl(repo, tag, asset), dest); say(`terunduh ${(size / 1048576).toFixed(0)} MB`); }
      catch (e) { say(`${asset}: unduhan gagal (${e.message}), dilewati`, 'warn'); continue; }
      const magic = Buffer.alloc(4); const fd = fs.openSync(dest, 'r'); fs.readSync(fd, magic, 0, 4, 0); fs.closeSync(fd);
      if (magic.toString('latin1') !== '\x7fELF' || fs.statSync(dest).size < 10 * 1048576) { say(`${asset}: bukan biner ELF yang valid, dilewati`, 'warn'); continue; }
      fs.chmodSync(dest, 0o755);
      const t = await testFrankenBinary(dest, work, say);
      if (t.ok) { say(`${asset}: LOLOS uji — ${t.detail} (FrankenPHP ${t.frankenVersion}, PHP ${t.phpVersion})`, 'ok'); chosen = { asset, path: dest, ...t }; break; }
      say(`${asset}: GAGAL uji — ${t.detail}`, 'warn');
    }
    if (!chosen) throw new Error(`tidak ada build yang cocok dengan server ini (CPU: ${cpuModel() || '?'}). Biner lama tidak diubah. Pastikan situs memakai PHP-FPM, bukan PHP bawaan FrankenPHP.`);
    if (before.phpVersion && chosen.phpVersion && cmpVer(chosen.phpVersion, before.phpVersion) < 0) throw new Error(`PHP bawaan build ini (${chosen.phpVersion}) lebih rendah dari yang terpasang (${before.phpVersion}); dibatalkan`);
    const br = phpBranch(chosen.phpVersion), floor = br ? PHP_ADVISORY.fixed[br] : null;
    if (!floor || cmpVer(chosen.phpVersion, floor) < 0) say(`⚠ PHP bawaan ${chosen.phpVersion} masih di bawah rilis perbaikan ${PHP_ADVISORY.name}${floor ? ' (' + floor + ')' : ''}; gunakan PHP-FPM untuk situs produksi`, 'warn');
    // install: backup → stage → atomic rename
    const backup = `${FRANKENPHP_BIN}.bak-${Date.now()}`, staged = `${FRANKENPHP_BIN}.new`;
    fs.copyFileSync(FRANKENPHP_BIN, backup); fs.chmodSync(backup, 0o755);
    say(`biner lama disimpan: ${backup}`);
    fs.copyFileSync(chosen.path, staged); fs.chmodSync(staged, 0o755);
    try { await execFileAsync('setcap', ['cap_net_bind_service=+ep', staged], { timeout: 10000 }); } catch {}
    fs.renameSync(staged, FRANKENPHP_BIN);
    const n0 = await nRestarts('frankenphp');
    // survives a panel restart in the middle of the watch window (recoverFrankenUpgrade finishes the job)
    refreshAuto(); AUTO.fpUpgradePending = { backup, n0, ts: new Date().toISOString(), tag }; persistAuto();
    say('me-restart FrankenPHP dan memantau selama ' + Math.round(UPGRADE_WATCH_MS / 1000) + ' dtk...');
    await execFileAsync('systemctl', ['restart', 'frankenphp'], { timeout: 90000 });
    const deadline = Date.now() + UPGRADE_WATCH_MS; let bad = null;
    while (Date.now() < deadline) {
      await sleep(Math.min(5000, Math.max(500, UPGRADE_WATCH_MS / 6)));
      const d = (await nRestarts('frankenphp')) - n0;
      if (d > 3) { bad = `NRestarts naik ${d}×`; break; }
    }
    if (!bad && !(await serviceActive('frankenphp'))) bad = 'service tidak aktif setelah restart';
    if (bad) {
      say(`${bad} — mengembalikan biner lama`, 'error');
      fs.copyFileSync(backup, staged); fs.chmodSync(staged, 0o755); fs.renameSync(staged, FRANKENPHP_BIN);
      try { await execFileAsync('systemctl', ['restart', 'frankenphp'], { timeout: 90000 }); } catch {}
      notify(`Upgrade FrankenPHP ke ${tag} dibatalkan otomatis: ${bad}. Biner lama dipulihkan.`);
      refreshAuto(); delete AUTO.fpUpgradePending; persistAuto();
      throw new Error(`${bad}; biner lama dipulihkan otomatis`);
    }
    // keep the three newest backups
    try { const base = path.basename(FRANKENPHP_BIN) + '.bak-'; const olds = fs.readdirSync(path.dirname(FRANKENPHP_BIN)).filter(f => f.startsWith(base)).sort(); for (const f of olds.slice(0, -3)) fs.rmSync(path.join(path.dirname(FRANKENPHP_BIN), f), { force: true }); } catch {}
    refreshAuto(); delete AUTO.fpUpgradePending; AUTO.fpUpgrade = { ts: new Date().toISOString(), from: before.version, to: chosen.frankenVersion || tag, asset: chosen.asset, phpVersion: chosen.phpVersion }; persistAuto();
    say(`selesai: FrankenPHP ${chosen.frankenVersion || tag} · PHP ${chosen.phpVersion} berjalan stabil`, 'ok');
    job.state = 'done';
  } catch (e) { say(e.message, 'error'); job.state = 'failed'; job.error = e.message; }
  finally { if (work) fs.rmSync(work, { recursive: true, force: true }); job.finishedAt = new Date().toISOString(); }
}

app.get('/api/frankenphp/upgrade', auth, async (req, res) => {
  const fp = await frankenphpInfo();
  refreshAuto();
  res.json({ ok: true, current: { ...fp, bin: FRANKENPHP_BIN }, cpuModel: cpuModel(), cores: machineSpecs().cores, job: FP_JOB, last: AUTO.fpUpgrade || null, assets: frankenAssets() });
});
app.post('/api/frankenphp/upgrade/check', auth, async (req, res) => {
  const r = await resolveFrankenphpTag();
  if (!r) return res.status(502).json({ ok: false, error: 'GitHub tidak terjangkau dari server ini' });
  res.json({ ok: true, ...r });
});
app.post('/api/frankenphp/upgrade/start', auth, (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  if (FP_JOB && FP_JOB.state === 'running') return res.status(409).json({ ok: false, error: 'upgrade sedang berjalan' });
  const tag = req.body && req.body.tag;
  if (tag !== undefined && tag !== '' && !/^v\d+\.\d+\.\d+$/.test(String(tag))) return res.status(400).json({ ok: false, error: 'tag harus berbentuk vX.Y.Z' });
  FP_JOB = { id: crypto.randomBytes(6).toString('hex'), state: 'running', startedAt: new Date().toISOString(), steps: [] };
  runFrankenUpgrade(FP_JOB, { tag: tag || null }).catch(e => { FP_JOB.state = 'failed'; FP_JOB.error = e.message; });
  res.json({ ok: true, id: FP_JOB.id });
});

app.get('/api/settings', auth, (req, res) => {
  try {
    const php = readPhpIni();
    res.json({
      ok: true,
      php: php.settings,
      phpIniPath: php.path,
    });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// What the running web processes really use (not just what is in the files).
app.get('/api/settings/effective', auth, async (req, res) => {
  try { res.json(compareEffective(await probeEffectivePhp())); }
  catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/settings/update', auth, async (req, res) => {
  const { password, php, frankenphp } = req.body || {};
  if (!password || !bcrypt.compareSync(password, authState.hash))
    return res.status(401).json({ error: 'Wrong password' });
  // Worker capacity (FrankenPHP threads, PHP-FPM pool) is automatic: never accepted from the user.
  if (frankenphp !== undefined)
    return res.status(400).json({ error: 'Jumlah worker diatur otomatis oleh auto-tune (halaman PHP Worker) dan tidak bisa diubah manual' });

  try {
    let phpPath = null;
    if (php && typeof php === 'object' && Object.keys(php).length) {
      phpPath = updatePhpIni(php);
    }
    const use = runtimesInUse();
    // PHP-FPM pools: mirror the ini and RELOAD (never restart: running requests finish).
    const fpmIni = use.fpm.size ? await syncFpmIni([...use.fpm]) : [];
    // FrankenPHP's own PHP needs PHPRC on the service or it never reads the php.ini we wrote,
    // and a restart to pick it up. Sites on PHP-FPM don't need FrankenPHP restarted for php.ini.
    let phprc = { changed: false }, phprcError = null;
    const restartNeeded = use.frankenphp || (!use.fpm.size);
    if (use.frankenphp || !use.fpm.size) { try { phprc = await ensurePhprc(); } catch (e) { phprcError = e.message; } }
    let restart = { err: null, se: null };
    if (restartNeeded) restart = await new Promise(resolve => exec('systemctl restart frankenphp', (err, _, se) => resolve({ err, se })));
    // A graceful FPM reload lets new workers pick the ini up a moment later: re-check briefly.
    let effective = null;
    if (!restart.err) {
      for (let i = 0; i < 6; i++) {
        effective = compareEffective(await probeWhenReady(PHP_KEYS));
        if (!effective.ok || !effective.mismatch) break;
        await new Promise(r => setTimeout(r, 1000));
      }
    }
    res.json({
      ok: true,
      phpIniPath: phpPath,
      restarted: restartNeeded,
      restartOk: !restart.err,
      restartError: restart.err ? (restart.se || restart.err.message) : null,
      phprcInstalled: phprc.changed,
      phprcError,
      fpmIni,
      effective,
    });
    // request_terminate_timeout follows php.ini's max_execution_time
    if (php && php.max_execution_time !== undefined) setImmediate(() => autotuneTick('php.ini: max_execution_time berubah').catch(() => {}));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ── Laravel operations: .env checks, storage, queue workers, scheduler ──
const CRON_DIR = process.env.PANEL_CRON_DIR || '/etc/cron.d';
const STORAGE_WARN_MB = parseInt(process.env.PANEL_STORAGE_WARN_MB, 10) || 1024;
const QUEUE_PREFIX = 'ps-queue-';

// Project root (the directory with `artisan`) behind a virtual host: its docroot, or the parent of public/.
function laravelRootFor(domain) {
  const cands = [];
  try {
    const m = fs.readFileSync(path.join(VHOSTS_DIR, `${domain}.conf`), 'utf8').match(/root\s+\*\s+(.+?)(?:\n|$)/);
    if (m) { const d = m[1].trim(); cands.push(path.basename(d) === 'public' ? path.dirname(d) : d, d); }
  } catch {}
  cands.push(`/var/www/${domain}`);
  return cands.find(r => fs.existsSync(path.join(r, 'artisan'))) || null;
}
function laravelRootForPath(p) {
  if (fs.existsSync(path.join(p, 'artisan'))) return p;
  const up = path.dirname(p);
  return path.basename(p) === 'public' && fs.existsSync(path.join(up, 'artisan')) ? up : p;
}
function listLaravelSites() {
  const out = [];
  try {
    for (const f of fs.readdirSync(VHOSTS_DIR).filter(f => f.endsWith('.conf'))) {
      const domain = f.replace(/\.conf$/, ''), root = laravelRootFor(domain);
      if (root) out.push({ domain, root, ...parseRuntime(fs.readFileSync(path.join(VHOSTS_DIR, f), 'utf8')) });
    }
  } catch {}
  return out;
}
function usesInertia(root) {
  try { if (/inertiajs\/inertia-laravel/.test(fs.readFileSync(path.join(root, 'composer.json'), 'utf8'))) return true; } catch {}
  return fs.existsSync(path.join(root, 'storage', 'inertia-devtools'));
}

// Production hygiene. Returns warnings only (a deploy is never failed by them).
function checkLaravelEnv(root) {
  const envPath = path.join(root, '.env');
  if (!fs.existsSync(envPath)) return { exists: false, values: {}, warnings: ['.env belum ada'] };
  const env = parseEnvFile(envPath), w = [];
  const appEnv = (env.APP_ENV || '').toLowerCase(), debug = /^(true|1)$/i.test(env.APP_DEBUG || '');
  if (env.APP_ENV !== undefined && appEnv !== 'production') w.push(`APP_ENV=${env.APP_ENV} — seharusnya production`);
  if (debug) w.push('APP_DEBUG=true — nonaktifkan di produksi (log berat dan detail error terbuka)');
  if (usesInertia(root)) {
    const v = env.INERTIA_DEVTOOLS_ENABLED;
    if ((v !== undefined && !/^(false|0)$/i.test(v)) || (v === undefined && (debug || (env.APP_ENV !== undefined && appEnv !== 'production'))))
      w.push(`INERTIA_DEVTOOLS_ENABLED=${v === undefined ? '(tidak diatur)' : v} — setel false: DevTools menulis file per request ke storage/ dan mengunci satu file _meta.json sehingga semua proses PHP antre`);
  }
  return { exists: true, values: { APP_ENV: env.APP_ENV, APP_DEBUG: env.APP_DEBUG, INERTIA_DEVTOOLS_ENABLED: env.INERTIA_DEVTOOLS_ENABLED, QUEUE_CONNECTION: env.QUEUE_CONNECTION }, warnings: w };
}
// Size of storage/ (+ biggest sub-folders) and the Inertia DevTools leftovers.
async function storageReport(root) {
  const dir = path.join(root, 'storage');
  if (!fs.existsSync(dir)) return null;
  const sizes = {};
  try {
    const out = (await execFileAsync('du', ['-k', '--max-depth=1', dir], { timeout: 30000 })).stdout;
    for (const l of out.split('\n').filter(Boolean)) { const [kb, p] = l.split('\t'); sizes[p] = parseInt(kb, 10) * 1024; }
  } catch {}
  const bytes = sizes[dir] ?? null;
  let devFiles = 0; try { devFiles = fs.readdirSync(path.join(dir, 'inertia-devtools')).length; } catch {}
  const top = Object.entries(sizes).filter(([p]) => p !== dir).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([p, b]) => ({ name: path.basename(p), bytes: b }));
  const w = [];
  if (bytes != null && bytes > STORAGE_WARN_MB * 1048576) w.push(`storage/ ${bytes >= 1073741824 ? (bytes / 1073741824).toFixed(2) + ' GB' : (bytes / 1048576).toFixed(0) + ' MB'} melebihi ambang ${STORAGE_WARN_MB >= 1024 ? (STORAGE_WARN_MB / 1024) + ' GB' : STORAGE_WARN_MB + ' MB'}${top[0] ? ` (terbesar: ${top[0].name} ${(top[0].bytes / 1048576).toFixed(0)} MB)` : ''}`);
  if (devFiles > 0) w.push(`storage/inertia-devtools berisi ${devFiles} entri — hapus dan setel INERTIA_DEVTOOLS_ENABLED=false`);
  return { bytes, top, devtoolsFiles: devFiles, warnings: w };
}
// One text block for Deploy History ("sebelum"/"sesudah" deploy).
async function laravelPreflight(root) {
  const env = checkLaravelEnv(root), st = await storageReport(root);
  const warnings = [...env.warnings, ...(st ? st.warnings : [])];
  const lines = [`.env: ${env.exists ? `APP_ENV=${env.values.APP_ENV ?? '-'} APP_DEBUG=${env.values.APP_DEBUG ?? '-'}` : 'belum ada'}`,
                 `storage/: ${st && st.bytes != null ? (st.bytes / 1048576).toFixed(0) + ' MB' : '-'}`, ...warnings.map(x => '⚠ ' + x)];
  return { warnings, text: lines.join('\n') };
}

// ── queue workers (systemd) ──
const queueUnit = domain => `${QUEUE_PREFIX}${domain}.service`;
async function phpBin() {
  if (process.env.PANEL_PHP_BIN) return process.env.PANEL_PHP_BIN;
  try { return (await execFileAsync('which', ['php'], { timeout: 5000 })).stdout.trim() || '/usr/bin/php'; } catch { return '/usr/bin/php'; }
}
async function queueUnitText(domain, root) {
  return `[Unit]
Description=PS Panel Laravel queue worker (${domain})
After=network.target postgresql.service redis-server.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=${root}
# No connection argument: the worker follows QUEUE_CONNECTION in the site's .env
ExecStart=${await phpBin()} artisan queue:work --sleep=3 --tries=3 --max-time=3600
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`;
}
// Other systemd units (hand-made, e.g. ayoujian-queue.service) that already run queue:work for this project.
function unmanagedQueueUnits(root) {
  const out = [];
  try {
    for (const f of fs.readdirSync(SYSTEMD_DIR).filter(f => f.endsWith('.service') && !f.startsWith(QUEUE_PREFIX))) {
      const t = fs.readFileSync(path.join(SYSTEMD_DIR, f), 'utf8');
      if (/queue:work/.test(t) && t.includes(root)) out.push(f);
    }
  } catch {}
  return out;
}
async function queueStatus(domain, root) {
  const unit = queueUnit(domain), file = path.join(SYSTEMD_DIR, unit), installed = fs.existsSync(file);
  const env = checkLaravelEnv(root);
  const st = { unit, installed, active: false, enabled: false, nrestarts: 0, adoptable: unmanagedQueueUnits(root), connection: env.values.QUEUE_CONNECTION || '(default .env)' };
  if (installed) {
    st.active = await serviceActive(unit);
    st.enabled = await new Promise(r => execFile('systemctl', ['is-enabled', unit], (e, o) => r(!e && /enabled/.test(String(o)))));
    st.nrestarts = await nRestarts(unit);
  }
  return st;
}
async function queueEnable(domain, root, adopt) {
  const others = unmanagedQueueUnits(root);
  if (others.length && !adopt) return { ok: false, needsAdopt: others, error: `sudah ada worker manual untuk proyek ini (${others.join(', ')}); konfirmasi ambil alih agar tidak ada dua worker` };
  const adopted = [];
  for (const f of others) {   // stop the hand-made unit and keep its file (renamed so systemd no longer loads it)
    try { await execFileAsync('systemctl', ['disable', '--now', f], { timeout: 60000 }); } catch {}
    const p = path.join(SYSTEMD_DIR, f), to = `${p}.diambil-alih-panel.${Date.now()}`;
    fs.renameSync(p, to); adopted.push({ unit: f, backup: to });
  }
  fs.writeFileSync(path.join(SYSTEMD_DIR, queueUnit(domain)), await queueUnitText(domain, root));
  await execFileAsync('systemctl', ['daemon-reload'], { timeout: 20000 });
  await execFileAsync('systemctl', ['enable', '--now', queueUnit(domain)], { timeout: 60000 });
  autotuneLog(`EVENT queue worker ${domain}: dibuat/diaktifkan${adopted.length ? '; mengambil alih ' + adopted.map(a => a.unit).join(',') : ''}`);
  return { ok: true, adopted };
}
async function queueDisable(domain) {
  const unit = queueUnit(domain), file = path.join(SYSTEMD_DIR, unit);
  try { await execFileAsync('systemctl', ['disable', '--now', unit], { timeout: 60000 }); } catch {}
  try { fs.rmSync(file, { force: true }); await execFileAsync('systemctl', ['daemon-reload'], { timeout: 20000 }); } catch {}
  autotuneLog(`EVENT queue worker ${domain}: dinonaktifkan dan unit dihapus`);
  return { ok: true };
}
// After .env changes the worker must restart (it keeps the old config in memory).
async function restartQueueForDomain(domain) {
  const unit = queueUnit(domain);
  if (!fs.existsSync(path.join(SYSTEMD_DIR, unit)) || !(await serviceActive(unit))) return false;
  try { await execFileAsync('systemctl', ['restart', unit], { timeout: 60000 }); autotuneLog(`EVENT queue worker ${domain}: di-restart karena .env berubah`); return true; } catch { return false; }
}

// ── scheduler (cron.d) ──
const cronName = domain => 'ps-scheduler-' + domain.replace(/[^A-Za-z0-9_-]/g, '-');   // cron ignores file names with dots
function schedulerManual(root) {
  try {
    for (const f of fs.readdirSync(CRON_DIR).filter(f => !f.startsWith('ps-scheduler-')))
      { const t = fs.readFileSync(path.join(CRON_DIR, f), 'utf8'); if (/schedule:run/.test(t) && t.includes(root)) return f; }
  } catch {}
  return null;
}
async function schedulerStatus(domain, root) {
  refreshAuto();
  return { managed: fs.existsSync(path.join(CRON_DIR, cronName(domain))), manual: schedulerManual(root), optOut: !!(AUTO.laravelOptOut && AUTO.laravelOptOut[domain] && AUTO.laravelOptOut[domain].scheduler) };
}
async function schedulerEnable(domain, root, adopt) {
  const manual = schedulerManual(root);
  if (manual && !adopt) return { ok: false, needsAdopt: [manual], error: `sudah ada cron scheduler manual (${manual}); konfirmasi ambil alih agar tidak berjalan dua kali` };
  const adopted = [];
  if (manual) { const p = path.join(CRON_DIR, manual), to = `${p}.diambil-alih-panel.${Date.now()}`; fs.renameSync(p, to); adopted.push({ file: manual, backup: to }); }
  fs.mkdirSync(CRON_DIR, { recursive: true });
  fs.writeFileSync(path.join(CRON_DIR, cronName(domain)),
    `# Managed by PS Panel: Laravel scheduler for ${domain}\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n* * * * * www-data cd ${root} && [ -f artisan ] && ${await phpBin()} artisan schedule:run >> /dev/null 2>&1\n`, { mode: 0o644 });
  refreshAuto(); if (AUTO.laravelOptOut && AUTO.laravelOptOut[domain]) { delete AUTO.laravelOptOut[domain].scheduler; persistAuto(); }
  autotuneLog(`EVENT scheduler ${domain}: cron dibuat${adopted.length ? '; mengambil alih ' + adopted[0].file : ''}`);
  return { ok: true, adopted };
}
async function schedulerDisable(domain) {
  try { fs.rmSync(path.join(CRON_DIR, cronName(domain)), { force: true }); } catch {}
  refreshAuto(); AUTO.laravelOptOut = AUTO.laravelOptOut || {}; AUTO.laravelOptOut[domain] = { ...(AUTO.laravelOptOut[domain] || {}), scheduler: true }; persistAuto();
  autotuneLog(`EVENT scheduler ${domain}: dinonaktifkan (tidak dibuat otomatis lagi)`);
  return { ok: true };
}
// Every Laravel vhost gets a scheduler unless one already exists or the admin turned it off.
async function ensureSchedulers() {
  for (const s of listLaravelSites()) {
    const st = await schedulerStatus(s.domain, s.root);
    if (!st.managed && !st.manual && !st.optOut) { try { await schedulerEnable(s.domain, s.root, false); } catch (e) { console.warn('[laravel] scheduler', s.domain, e.message); } }
  }
}

app.get('/api/laravel', auth, async (req, res) => {
  try {
    const sites = await Promise.all(listLaravelSites().map(async s => ({
      domain: s.domain, root: s.root, runtime: s.runtime, phpVersion: s.version,
      env: checkLaravelEnv(s.root), storage: await storageReport(s.root),
      queue: await queueStatus(s.domain, s.root), scheduler: await schedulerStatus(s.domain, s.root),
    })));
    res.json({ ok: true, sites, storageWarnMB: STORAGE_WARN_MB });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});
app.post('/api/laravel/:domain/queue/:action', auth, async (req, res) => {
  const { domain, action } = req.params;
  const root = /^[a-zA-Z0-9.\-]+$/.test(domain) ? laravelRootFor(domain) : null;
  if (!root) return res.status(404).json({ ok: false, error: 'situs Laravel tidak ditemukan' });
  const unit = queueUnit(domain);
  try {
    if (action === 'enable' || action === 'disable') {
      if (!checkPanelPassword(req, res)) return;
      return res.json(action === 'enable' ? await queueEnable(domain, root, !!req.body.adopt) : await queueDisable(domain));
    }
    if (!['start', 'stop', 'restart'].includes(action)) return res.status(400).json({ ok: false, error: 'aksi tidak dikenal' });
    if (!fs.existsSync(path.join(SYSTEMD_DIR, unit))) return res.status(400).json({ ok: false, error: 'worker belum diaktifkan' });
    await execFileAsync('systemctl', [action, unit], { timeout: 60000 });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: String(e.stderr || e.message).trim() }); }
});
app.get('/api/laravel/:domain/queue/logs', auth, async (req, res) => {
  if (!/^[a-zA-Z0-9.\-]+$/.test(req.params.domain)) return res.status(400).json({ ok: false, error: 'domain tidak valid' });
  try { res.json({ ok: true, logs: (await execFileAsync('journalctl', ['-u', queueUnit(req.params.domain), '-n', '120', '--no-pager', '-o', 'short-iso'], { timeout: 15000 })).stdout }); }
  catch (e) { res.json({ ok: true, logs: '' }); }
});
app.post('/api/laravel/:domain/scheduler/:action', auth, async (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  const { domain, action } = req.params;
  const root = /^[a-zA-Z0-9.\-]+$/.test(domain) ? laravelRootFor(domain) : null;
  if (!root) return res.status(404).json({ ok: false, error: 'situs Laravel tidak ditemukan' });
  try { res.json(action === 'enable' ? await schedulerEnable(domain, root, !!req.body.adopt) : action === 'disable' ? await schedulerDisable(domain) : { ok: false, error: 'aksi tidak dikenal' }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Health checks + Telegram notifications (runs inside the panel process, no extra service) ──
const NOTIFY_FILE = process.env.PANEL_NOTIFY_FILE || '/root/.pspanel_notify';
const TELEGRAM_API = process.env.PANEL_TELEGRAM_API || 'https://api.telegram.org';
const HEALTH_INTERVAL_MS = parseInt(process.env.PANEL_HEALTH_INTERVAL_MS, 10) || 60 * 1000;
const HEALTH_WINDOW_MS = parseInt(process.env.PANEL_HEALTH_WINDOW_MS, 10) || 5 * 60 * 1000;
const ALERT_COOLDOWN_MS = parseInt(process.env.PANEL_ALERT_COOLDOWN_MS, 10) || 30 * 60 * 1000;
function readNotifyCfg() {
  try { const j = JSON.parse(fs.readFileSync(NOTIFY_FILE, 'utf8')); return { token: String(j.token || ''), chatId: String(j.chatId || ''), restartThreshold: Math.max(1, parseInt(j.restartThreshold, 10) || 3) }; }
  catch { return { token: '', chatId: '', restartThreshold: 3 }; }
}
function writeNotifyCfg(c) {
  const tmp = NOTIFY_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(c), { mode: 0o600 }); fs.renameSync(tmp, NOTIFY_FILE);
}
// Never throws; resolves { ok, error }. The token is only ever used in the request path, never logged.
function sendTelegram(text) {
  return new Promise(resolve => {
    const c = readNotifyCfg();
    if (!c.token || !c.chatId) return resolve({ ok: false, error: 'Telegram belum dikonfigurasi' });
    let u; try { u = new URL(`${TELEGRAM_API}/bot${c.token}/sendMessage`); } catch { return resolve({ ok: false, error: 'URL API tidak valid' }); }
    const body = JSON.stringify({ chat_id: c.chatId, text: `[${os.hostname()}] ${text}`.slice(0, 3900), disable_web_page_preview: true });
    const lib = u.protocol === 'http:' ? http : https;
    const rq = lib.request(u, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }, timeout: 10000 }, r => {
      let d = ''; r.on('data', x => d += x); r.on('end', () => {
        let j = {}; try { j = JSON.parse(d); } catch {}
        resolve(r.statusCode === 200 && j.ok !== false ? { ok: true } : { ok: false, error: `Telegram menolak (${r.statusCode}): ${j.description || 'tanpa keterangan'}` });
      });
    });
    rq.on('timeout', () => rq.destroy(new Error('timeout')));
    rq.on('error', e => resolve({ ok: false, error: String(e.message).replace(c.token, '***') }));
    rq.end(body);
  });
}
app.get('/api/notify', auth, (req, res) => {
  const c = readNotifyCfg();
  res.json({ ok: true, configured: !!(c.token && c.chatId), tokenSet: !!c.token, chatId: c.chatId, restartThreshold: c.restartThreshold, windowMin: Math.round(HEALTH_WINDOW_MS / 60000) });
});
app.post('/api/notify', auth, (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  const b = req.body || {}, cur = readNotifyCfg();
  const token = b.token ? String(b.token).trim() : cur.token, chatId = b.chatId != null ? String(b.chatId).trim() : cur.chatId;
  if (token && !/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) return res.status(400).json({ ok: false, error: 'format bot token tidak valid (contoh 123456:ABC...)' });
  if (chatId && !/^-?\d+$|^@[A-Za-z0-9_]{5,}$/.test(chatId)) return res.status(400).json({ ok: false, error: 'chat id harus angka (atau @namachannel)' });
  const thr = b.restartThreshold != null ? parseInt(b.restartThreshold, 10) : cur.restartThreshold;
  if (!(thr >= 1 && thr <= 100)) return res.status(400).json({ ok: false, error: 'ambang restart harus 1–100' });
  try { writeNotifyCfg({ token, chatId, restartThreshold: thr }); } catch (e) { return res.status(500).json({ ok: false, error: e.message }); }
  res.json({ ok: true, configured: !!(token && chatId) });
});
app.post('/api/notify/test', auth, async (req, res) => {
  if (!checkPanelPassword(req, res)) return;
  res.json(await sendTelegram('Tes notifikasi PS Panel: pengiriman berhasil.'));
});

const HEALTH = { restarts: {}, seen: new Set(), baselined: false, lastAlert: {}, kernel: { at: 0, count24h: 0, samples: [] }, fpmMax: {}, running: false };
function healthAlert(key, msg) {
  if (Date.now() - (HEALTH.lastAlert[key] || 0) < ALERT_COOLDOWN_MS) return;
  HEALTH.lastAlert[key] = Date.now();
  notify(msg);
}
async function readLogLines(args, fileEnv) {
  if (fileEnv && process.env[fileEnv]) { try { return fs.readFileSync(process.env[fileEnv], 'utf8').split('\n'); } catch { return []; } }
  try { return (await execFileAsync('journalctl', args, { timeout: 15000, maxBuffer: 16 * 1024 * 1024 })).stdout.split('\n'); } catch { return []; }
}
async function kernelLines() {
  let lines = await readLogLines(['-k', '--since', '24 hours ago', '--no-pager', '-o', 'short-iso'], 'PANEL_KERNEL_LOG_FILE');
  if (!lines.length && !process.env.PANEL_KERNEL_LOG_FILE) { try { lines = (await execFileAsync('dmesg', ['-T'], { timeout: 8000, maxBuffer: 16 * 1024 * 1024 })).stdout.split('\n'); } catch {} }
  return lines.filter(l => /segfault|invalid opcode/i.test(l));
}
async function healthTick() {
  if (HEALTH.running) return; HEALTH.running = true;
  try {
    const cfg = readNotifyCfg(), now = Date.now();
    // 1. service restarts within the window
    const units = ['frankenphp', ...fpmRuntimes().map(r => r.service)];
    for (const u of units) {
      const n = await nRestarts(u), h = (HEALTH.restarts[u] = (HEALTH.restarts[u] || []).filter(x => now - x.ts <= HEALTH_WINDOW_MS));
      if (h.length && n < h[h.length - 1].n) h.length = 0;   // counter reset (manual restart): start over
      h.push({ ts: now, n });
      const delta = n - h[0].n;
      if (delta >= cfg.restartThreshold) healthAlert('restart:' + u, `${u} restart otomatis ${delta}× dalam ${Math.round(HEALTH_WINDOW_MS / 60000)} menit terakhir (ambang ${cfg.restartThreshold}) — cek: journalctl -u ${u} -n 50`);
    }
    // 2. kernel log: segfault / invalid opcode
    const kl = await kernelLines();
    const fresh = kl.filter(l => !HEALTH.seen.has(l));
    HEALTH.kernel = { at: now, count24h: kl.length, samples: kl.slice(-3) };
    // 3. PHP-FPM: pool exhausted
    const maxLines = [];
    for (const rt of fpmRuntimes()) {
      const ls = (await readLogLines([ '-u', rt.service, '--since', '24 hours ago', '--no-pager', '-o', 'short-iso' ], 'PANEL_FPM_LOG_FILE')).filter(l => /server reached pm\.max_children/i.test(l));
      for (const l of ls) maxLines.push({ rt, l });
    }
    const freshMax = maxLines.filter(x => !HEALTH.seen.has(x.l));
    if (HEALTH.baselined) {
      if (fresh.length) healthAlert('kernel', `kernel mencatat ${fresh.length} kejadian segfault/invalid opcode baru: ${fresh.slice(-2).map(l => l.replace(/^\S+\s+\S+\s+/, '').slice(0, 160)).join(' | ')}`);
      if (freshMax.length) healthAlert('maxchildren', `PHP-FPM ${[...new Set(freshMax.map(x => x.rt.version))].join(', ')} mencatat "server reached pm.max_children" (${freshMax.length}×) — antrean request menumpuk; periksa halaman PHP Worker`);
    }
    for (const l of [...kl, ...maxLines.map(x => x.l)]) HEALTH.seen.add(l);
    if (HEALTH.seen.size > 5000) HEALTH.seen = new Set([...HEALTH.seen].slice(-2500));
    HEALTH.baselined = true;
  } catch (e) { console.warn('[health]', e.message); }
  finally { HEALTH.running = false; }
}
app.get('/api/health', auth, async (req, res) => {
  try {
    if (Date.now() - HEALTH.kernel.at > 2 * HEALTH_INTERVAL_MS) {   // tick not run yet (or stalled): do a read-only scan
      const kl = await kernelLines(); HEALTH.kernel = { at: Date.now(), count24h: kl.length, samples: kl.slice(-3) };
    }
    let fv = { version: null, php: null };
    try { const o = (await execFileAsync(FRANKENPHP_BIN, ['version'], { timeout: 8000 })).stdout; fv = { version: (o.match(/v?\d+\.\d+\.\d+/) || [])[0] || null, php: (o.match(/PHP (\d+\.\d+\.\d+)/) || [])[1] || null }; } catch {}
    const fpm = await Promise.all(fpmRuntimes().map(async rt => ({ version: rt.version, service: rt.service, active: await serviceActive(rt.service), nrestarts: await nRestarts(rt.service), pool: await fpmStatus(rt) })));
    refreshAuto();
    const c = readNotifyCfg();
    res.json({ ok: true, frankenphp: { ...fv, active: await serviceActive('frankenphp'), nrestarts: await nRestarts('frankenphp') }, fpm,
      kernel: { segfaults24h: HEALTH.kernel.count24h, samples: HEALTH.kernel.samples }, alerts: (AUTO.alerts || []).slice(0, 5),
      telegram: !!(c.token && c.chatId), restartThreshold: c.restartThreshold });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ── Webhooks (Auto Deploy) ──
const WEBHOOKS_FILE = path.join(__dirname, 'webhooks.json');
function loadWebhooks() {
  try { return JSON.parse(fs.readFileSync(WEBHOOKS_FILE, 'utf8')); } catch { return []; }
}
function saveWebhooks(hooks) {
  fs.writeFileSync(WEBHOOKS_FILE, JSON.stringify(hooks, null, 2));
}
// Parse a Laravel .env file into a plain object (handles simple KEY=VALUE lines,
// optionally quoted). Good enough for the values we read here.
function parseEnvFile(envPath) {
  const env = {};
  if (!fs.existsSync(envPath)) return env;
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) env[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
  });
  return env;
}

// Does this app have a frontend build step (Vite/Mix)? Most modern Laravel apps
// (Inertia/Vue/React) need `npm run build` to produce public/build/manifest.json
// before Blade can render — skip silently for API-only apps with no such script.
function hasFrontendBuild(dir) {
  const pkgPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pkgPath)) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    return !!(pkg.scripts && pkg.scripts.build);
  } catch { return false; }
}

// Building straight into public/build makes Vite empty that folder first, so
// any request that lands during the build (10+ seconds) fails with "Vite
// manifest not found" — and a failed build leaves the site broken outright.
// Instead build into public/build-next and swap it in: new (content-hashed,
// non-colliding) assets are copied first, the manifest is replaced by an
// atomic rename, and stale assets are removed last. Only for the standard
// setup (build script is a bare `vite build`, default buildDirectory) —
// anything else falls back to a plain build.
const VITE_BUILD_SWAP_SH = `
set -e
N=public/build-next; B=public/build
test -f "$N/manifest.json" || { echo "incomplete build: $N/manifest.json is missing" >&2; exit 1; }
mkdir -p "$B"
for d in "$N"/*/; do [ -d "$d" ] && cp -pR "$d" "$B/"; done
for f in "$N"/*; do [ -f "$f" ] || continue; n=$(basename "$f"); cp -p "$f" "$B/.$n.tmp"; mv -f "$B/.$n.tmp" "$B/$n"; done
(cd "$B" && find . -type f) | while IFS= read -r f; do [ -e "$N/$f" ] || rm -f "$B/$f"; done
find "$B" -mindepth 1 -type d -empty -delete
rm -rf "$N"
echo "public/build updated: $(find "$B" -type f | wc -l) files"
`;
function canStageViteBuild(dir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    if (!/^\s*vite build[^&|;]*$/.test((pkg.scripts && pkg.scripts.build) || '')) return false;
    const cfg = ['vite.config.js', 'vite.config.ts', 'vite.config.mjs']
      .map(f => path.join(dir, f)).find(f => fs.existsSync(f));
    return !!cfg && !/buildDirectory|outDir/.test(fs.readFileSync(cfg, 'utf8'));
  } catch { return false; }
}

// ── Deploy history ──
const DEPLOY_HISTORY_FILE = path.join(__dirname, 'deploy-history.json');
const DEPLOY_HISTORY_MAX = 50;
const DEPLOY_STEP_OUTPUT_MAX = 20000;
function loadDeployHistory() {
  try { return JSON.parse(fs.readFileSync(DEPLOY_HISTORY_FILE, 'utf8')); } catch { return []; }
}
function recordDeploy(entry) {
  try {
    const history = loadDeployHistory();
    const steps = (entry.steps || []).map(s => ({ ...s, output: (s.output || '').slice(0, DEPLOY_STEP_OUTPUT_MAX) }));
    history.unshift({ ...entry, steps });
    fs.writeFileSync(DEPLOY_HISTORY_FILE, JSON.stringify(history.slice(0, DEPLOY_HISTORY_MAX), null, 2));
  } catch (e) { console.error('[Deploy] Failed to record deploy history:', e.message); }
}

// Which PHP runtime serves the site whose docroot is this deploy path (or its public/)?
function vhostRuntimeForPath(p) {
  const norm = x => path.resolve(String(x).trim());
  const want = new Set([norm(p), norm(path.join(p, 'public'))]);
  if (path.basename(norm(p)) === 'public') want.add(norm(path.dirname(p)));
  try {
    for (const f of fs.readdirSync(VHOSTS_DIR).filter(f => f.endsWith('.conf'))) {
      const c = fs.readFileSync(path.join(VHOSTS_DIR, f), 'utf8'), m = c.match(/root\s+\*\s+(.+?)(?:\n|$)/);
      if (m && want.has(norm(m[1]))) return { domain: f.replace(/\.conf$/, ''), ...parseRuntime(c) };
    }
  } catch {}
  return null;
}

// Full first-deploy pipeline for a Laravel app: git pull → ensure .env exists →
// ensure its database exists → composer install → frontend build (if any) →
// fix storage ownership → migrate → storage:link → cache. Each step's output is
// collected so both the manual "Deploy" button and the webhook auto-deploy path
// can show/log it, and so it can be persisted to deploy history.
//
// This exists because a bare `composer install && migrate` (the old behavior)
// silently does the wrong thing on a brand new app: with no .env, Laravel falls
// back to DB_CONNECTION=sqlite and migrate runs against the wrong database, or
// fails outright once it hits Postgres-only migration syntax.
async function runDeploySteps(hook) {
  const outParts = [];
  const steps = [];
  const log = (s) => outParts.push(s);
  const sshKey = '/root/.ssh/ps-panel-deploy';
  const gitEnv = fs.existsSync(sshKey)
    ? { ...process.env, GIT_SSH_COMMAND: `ssh -i ${sshKey} -o StrictHostKeyChecking=no` }
    : process.env;
  const appPath = hook.path;
  const safeBranch = (hook.branch || 'main').replace(/[^a-zA-Z0-9._\/-]/g, '');

  async function run(cmd, args, opts = {}) {
    const label = `${cmd} ${args.join(' ')}`;
    log(`\n$ ${label}\n`);
    try {
      const { stdout, stderr } = await execFileAsync(cmd, args, {
        cwd: opts.cwd || appPath,
        timeout: opts.timeout || 300000,
        env: opts.env || process.env,
      });
      if (stdout) log(stdout);
      if (stderr) log(stderr);
      steps.push({ cmd: label, ok: true, output: (stdout || '') + (stderr || '') });
      return true;
    } catch (e) {
      const errOutput = (e.stdout || '') + (e.stderr || '');
      if (e.stdout) log(e.stdout);
      if (e.stderr) log(e.stderr);
      if (e.code === 'ENOENT') log(`\n[ERROR] Command "${cmd}" not found. Please ensure it's installed and in PATH.\n`);
      else if (e.code) log(`\n[ERROR] Exit code: ${e.code}\n`);
      if (e.message && !e.stderr) log(`[ERROR] ${e.message}\n`);
      log('\n[FAILED]\n');
      steps.push({ cmd: label, ok: false, output: errOutput || e.message || 'failed' });
      return false;
    }
  }

  // .env / storage hygiene BEFORE the deploy. Warnings only: they are shown in the output and in
  // Deploy History but never fail a deploy.
  if (hook.laravel) {
    try {
      const pf = await laravelPreflight(laravelRootForPath(appPath));
      log(`\n[CEK sebelum deploy]\n${pf.text}\n`);
      steps.push({ cmd: 'cek .env & storage (sebelum deploy)', ok: true, warn: pf.warnings.length > 0, output: pf.text });
    } catch (e) { log(`\n[WARN] cek .env/storage gagal: ${e.message}\n`); }
  }

  // Uncommitted changes on the server (a manual hotfix, or package-lock.json
  // rewritten by `npm install`) make `git pull` abort with "local changes would
  // be overwritten", and then nothing else in the deploy runs. Stash them first
  // so the server always ends up matching the repo — they stay recoverable via
  // `git stash list`. Exits 0 with "No local changes to save" on a clean tree.
  if (!await run('git', ['-C', appPath, '-c', 'user.name=PS Panel', '-c', 'user.email=ps-panel@localhost',
                         'stash', 'push', '-m', 'ps-panel auto-stash before deploy']))
    return { ok: false, output: outParts.join(''), steps };

  if (!await run('git', ['-C', appPath, 'pull', 'origin', safeBranch], { env: gitEnv }))
    return { ok: false, output: outParts.join(''), steps };

  if (hook.laravel) {
    // 0. Sanity-check the path before doing anything else. `git pull` above
    //    succeeds even if `hook.path` points at the app's `public/` docroot
    //    instead of its project root, because git walks up to find `.git` —
    //    but composer/artisan don't do that, so composer install would fail
    //    several steps later with a confusing "no composer.json" error and
    //    nothing after it (build, migrate, cache) would ever run. Catch the
    //    common mistake here with a message that names the actual fix.
    if (!fs.existsSync(path.join(appPath, 'composer.json'))) {
      const parentComposer = path.join(appPath, '..', 'composer.json');
      const hint = fs.existsSync(parentComposer)
        ? ` This looks like the app's "public/" docroot — use "${path.dirname(appPath)}" instead (the directory containing composer.json and artisan).`
        : ' Check that this webhook/deploy path points at the Laravel project root, not a subdirectory.';
      log(`\n[ERROR] No composer.json found in "${appPath}".${hint}\n[FAILED]\n`);
      steps.push({ cmd: 'verify composer.json', ok: false, output: `composer.json missing in ${appPath}.${hint}` });
      return { ok: false, output: outParts.join(''), steps };
    }

    // 1. Ensure .env exists — without it Laravel silently falls back to sqlite
    //    and migrate either hits the wrong DB or fails on Postgres-only syntax.
    const envPath = path.join(appPath, '.env');
    const examplePath = path.join(appPath, '.env.example');
    if (!fs.existsSync(envPath) && fs.existsSync(examplePath)) {
      try {
        fs.copyFileSync(examplePath, envPath);
        log(`\n[SETUP] .env not found — created from .env.example\n`);
      } catch (e) {
        log(`\n[SETUP] Failed to create .env from .env.example: ${e.message}\n`);
      }
    }

    // 2. Ensure the target Postgres database exists (only when the app is
    //    actually configured for pgsql — leave sqlite/mysql apps alone).
    const env = parseEnvFile(envPath);
    if (env.DB_CONNECTION === 'pgsql' && env.DB_DATABASE && /^[a-z0-9_]+$/i.test(env.DB_DATABASE)) {
      try {
        const creds = getCreds();
        const pool = new Pool({
          host: env.DB_HOST || 'localhost', user: 'postgres',
          password: creds.PG_PASSWORD || '', database: 'postgres',
          connectionTimeoutMillis: 3000,
        });
        const r = await pool.query('SELECT 1 FROM pg_database WHERE datname=$1', [env.DB_DATABASE]);
        if (r.rowCount === 0) {
          await pool.query(`CREATE DATABASE "${env.DB_DATABASE}"`);
          log(`\n[SETUP] Database "${env.DB_DATABASE}" did not exist — created it\n`);
        }
        await pool.end();
      } catch (e) {
        log(`\n[SETUP] Could not verify/create database "${env.DB_DATABASE}": ${e.message}\n`);
      }
    }

    // 3. Install dependencies
    if (!await run('composer', ['install', '--optimize-autoloader', '--no-dev', '--no-interaction']))
      return { ok: false, output: outParts.join(''), steps };

    // 3b. Generate APP_KEY if missing (fresh .env from .env.example has none)
    const envAfterComposer = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
    if (!/^APP_KEY=.+/m.test(envAfterComposer)) {
      await run('php', ['artisan', 'key:generate', '--force']);
    }

    // 3c. Frontend build (Vite/Mix) — skipped for apps with no build script.
    // Some hosts have broken IPv6 routing (Vite fetches Google/Bunny fonts at
    // build time and Node's resolver doesn't fall back to IPv4 as readily as
    // curl does, hanging the build); force IPv4 resolution as a safety net.
    // npm can be much slower than other steps here, hence the longer timeout.
    if (hasFrontendBuild(appPath)) {
      const buildEnv = { ...process.env, NODE_OPTIONS: '--dns-result-order=ipv4first' };
      if (!await run('npm', ['install'], { env: buildEnv, timeout: 600000 }))
        return { ok: false, output: outParts.join(''), steps };
      if (canStageViteBuild(appPath)) {
        if (!await run('npm', ['run', 'build', '--', '--outDir', 'public/build-next'], { env: buildEnv, timeout: 600000 }))
          return { ok: false, output: outParts.join(''), steps };
        if (!await run('sh', ['-c', VITE_BUILD_SWAP_SH]))
          return { ok: false, output: outParts.join(''), steps };
      } else if (!await run('npm', ['run', 'build'], { env: buildEnv, timeout: 600000 })) {
        return { ok: false, output: outParts.join(''), steps };
      }
      if (!fs.existsSync(path.join(appPath, 'public/build/manifest.json'))) {
        log('\n[ERROR] npm run build finished but public/build/manifest.json was not produced.\n[FAILED]\n');
        steps.push({ cmd: 'verify public/build/manifest.json', ok: false, output: 'manifest.json missing after build' });
        return { ok: false, output: outParts.join(''), steps };
      }
    }

    // 4. Migrate
    if (!await run('php', ['artisan', 'migrate', '--force']))
      return { ok: false, output: outParts.join(''), steps };

    // 5. Storage symlink (safe to re-run — artisan skips if it already exists)
    await run('php', ['artisan', 'storage:link']);

    // 6. Cache
    await run('php', ['artisan', 'config:cache']);
    await run('php', ['artisan', 'route:cache']);
    await run('php', ['artisan', 'view:cache']);

    // 7. Tell running queue workers to exit after their current job so their
    //    supervisor (systemd/pm2/supervisord) starts them on the new code —
    //    a long-lived `queue:work` otherwise keeps executing the old job
    //    classes. Harmless when no worker is running (it only sets a cache key).
    await run('php', ['artisan', 'queue:restart']);

    // 8. Fix ownership so the web server user (www-data) can actually write
    //    logs/cache/uploads. This must run AFTER every artisan call above: they
    //    run as root, so view:cache, queue:restart (file cache) etc. would
    //    otherwise leave fresh root-owned files in storage/ that www-data then
    //    can't overwrite.
    await run('chown', ['-R', 'www-data:www-data', 'storage', 'bootstrap/cache']);

    // 9. Reload the PHP runtime that serves this app. Blade views recompile on their own, but OPcache
    //    does NOT invalidate PHP source files (Controllers, Models, ...) the same way — a deploy that
    //    only touches PHP code can report every step green while the site keeps serving the old code.
    //    PHP-FPM sites: graceful `systemctl reload php<ver>-fpm`; FrankenPHP's own PHP: reload FrankenPHP;
    //    a site the panel does not know about gets both. Soft-fail: a hiccup never fails the deploy.
    const rtInfo = vhostRuntimeForPath(appPath);
    if (!rtInfo || rtInfo.runtime === 'fpm') {
      const fr = pickFpm(rtInfo && rtInfo.version || null);
      if (fr && await fpmActive(fr)) {
        log(`\n$ reload PHP-FPM ${fr.version} (apply PHP source changes)\n`);
        try { await execFileAsync('systemctl', ['reload', fr.service], { timeout: 30000 }); log('PHP-FPM reloaded.\n'); steps.push({ cmd: `reload PHP-FPM ${fr.version}`, ok: true, output: 'reloaded' }); }
        catch (e) { log(`[WARN] Failed to reload PHP-FPM ${fr.version}: ${e.message}\n`); steps.push({ cmd: `reload PHP-FPM ${fr.version}`, ok: false, output: e.message }); }
      } else if (rtInfo) {
        log('\n[WARN] Situs memakai PHP-FPM tetapi service-nya tidak aktif; kode baru belum berlaku.\n');
        steps.push({ cmd: 'reload PHP-FPM', ok: false, output: 'php-fpm tidak aktif' });
      }
    }
    if (!rtInfo || rtInfo.runtime === 'frankenphp') {
      log('\n$ reload FrankenPHP (apply PHP source changes)\n');
      try {
        await reloadFrankenPHPAsync();
        log('FrankenPHP reloaded.\n');
        steps.push({ cmd: 'reload FrankenPHP', ok: true, output: 'reloaded' });
      } catch (e) {
        log(`[WARN] Failed to reload FrankenPHP — PHP source changes may not take effect until a manual restart: ${e.message}\n`);
        steps.push({ cmd: 'reload FrankenPHP', ok: false, output: e.message });
      }
    }

    // 10. .env / storage hygiene AFTER the deploy (the app is now fully in place), and make sure the
    //     scheduler exists for this app.
    try {
      const pf = await laravelPreflight(laravelRootForPath(appPath));
      log(`\n[CEK sesudah deploy]\n${pf.text}\n`);
      steps.push({ cmd: 'cek .env & storage (sesudah deploy)', ok: true, warn: pf.warnings.length > 0, output: pf.text });
    } catch (e) { log(`\n[WARN] cek .env/storage gagal: ${e.message}\n`); }
    ensureSchedulers().catch(() => {});
  }

  return { ok: true, output: outParts.join(''), steps };
}

// Runs the deploy pipeline and persists the result to deploy history regardless
// of trigger source, so a silently-failing webhook deploy is no longer invisible.
async function deployAndRecord(hook, trigger) {
  const startedAt = new Date().toISOString();
  const result = await runDeploySteps(hook);
  const finishedAt = new Date().toISOString();
  recordDeploy({
    trigger, path: hook.path, branch: hook.branch || 'main', laravel: !!hook.laravel,
    startedAt, finishedAt, ok: result.ok, steps: result.steps || [],
    warnings: (result.steps || []).filter(x => x.warn).length,
  });
  return result;
}
app.get('/api/webhooks', auth, (req, res) => res.json(loadWebhooks().map(h => ({...h, secret: undefined}))));
app.post('/api/webhooks', auth, (req, res) => {
  const { path: p, branch, laravel } = req.body;
  if (!p || !path.isAbsolute(p)) return res.status(400).json({ error:'Absolute path required' });
  // Catch the most common setup mistake up front: pointing this at the app's
  // `public/` docroot (what the *vhost* should use) instead of the project
  // root (what git/composer/npm need). `git pull` alone wouldn't reveal this
  // — it only breaks once a real deploy reaches `composer install` — so we
  // check it here instead of letting it fail silently later.
  if (laravel && !fs.existsSync(path.join(p, 'composer.json'))) {
    const parentComposer = path.join(p, '..', 'composer.json');
    const hint = fs.existsSync(parentComposer)
      ? `This looks like the app's "public/" docroot — use "${path.dirname(p)}" instead (the directory containing composer.json and artisan).`
      : `No composer.json found in "${p}". For a Laravel app, this should be the project root (the directory containing artisan and composer.json), not a subdirectory.`;
    return res.status(400).json({ error: hint });
  }
  const hooks = loadWebhooks();
  const id     = crypto.randomBytes(8).toString('hex');
  const secret = crypto.randomBytes(20).toString('hex');
  hooks.push({ id, path:p, branch:branch||'main', laravel:!!laravel, secret });
  saveWebhooks(hooks);
  res.json({ ok:true, id, secret });
});
app.delete('/api/webhooks/:id', auth, (req, res) => {
  saveWebhooks(loadWebhooks().filter(h => h.id !== req.params.id));
  res.json({ ok:true });
});
// Public endpoint — GitHub calls this
app.post('/api/webhook/:id', (req, res) => {
  // Every early return below used to be silent, so a misconfigured webhook
  // (wrong secret, wrong content type, stale URL) looked exactly like "GitHub
  // never called us". Log each rejection so it shows up in `pm2 logs ps-panel`.
  const event = req.headers['x-github-event'] || '-';
  const delivery = req.headers['x-github-delivery'] || '-';
  const reject = (status, reason, body) => {
    console.warn(`[Webhook] ${req.params.id} event=${event} delivery=${delivery} rejected (${status}): ${reason}`);
    return body ? res.status(status).json(body) : res.status(status).end();
  };
  const hook = loadWebhooks().find(h => h.id === req.params.id);
  if (!hook) return reject(404, 'unknown webhook id');
  if (event === 'ping') return res.json({ ok:true, pong:true });
  const sig = req.headers['x-hub-signature-256'] || '';
  const expected = 'sha256=' + crypto.createHmac('sha256', hook.secret).update(req.rawBody||'').digest('hex');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig)))
    return reject(401, sig ? 'signature mismatch (check the webhook secret)' : 'missing X-Hub-Signature-256 (secret not set on GitHub?)');
  let payload = req.body || {};
  if (typeof payload.payload === 'string') {
    try { payload = JSON.parse(payload.payload); } catch { return reject(400, 'unparseable form payload'); }
  }
  const pushedBranch = (payload.ref || '').replace('refs/heads/', '');
  if (pushedBranch !== hook.branch)
    return reject(200, `ref "${payload.ref || '(none)'}" is not branch "${hook.branch}"`, { skipped:true });
  console.log(`[Webhook] ${hook.id} delivery=${delivery} push to ${hook.branch} — deploying ${hook.path}`);
  res.json({ ok:true });
  deployAndRecord(hook, 'webhook')
    .then(r => { if (!r.ok) console.error(`[Deploy] webhook ${hook.id} (${hook.path}) failed:\n${r.output}`); })
    .catch(e => console.error(`[Deploy] webhook ${hook.id} (${hook.path}) threw:`, e));
});
app.get('/api/deploy-history', auth, (req, res) => res.json({ history: loadDeployHistory() }));

// ── SSH Deploy Key ──
const DEPLOY_KEY = '/root/.ssh/ps-panel-deploy';
app.get('/api/deploy-key', auth, (req, res) => {
  const pubPath = DEPLOY_KEY + '.pub';
  const sshDir = path.dirname(DEPLOY_KEY);

  // Jika key sudah ada, return
  if (fs.existsSync(pubPath)) {
    try {
      const key = fs.readFileSync(pubPath, 'utf8').trim();
      return res.json({ key });
    } catch(e) {
      return res.status(500).json({ error: 'Cannot read deploy key: ' + e.message });
    }
  }

  // Create .ssh directory jika belum ada
  if (!fs.existsSync(sshDir)) {
    try {
      fs.mkdirSync(sshDir, { mode: 0o700, recursive: true });
    } catch(e) {
      return res.status(500).json({ error: 'Cannot create .ssh directory: ' + e.message });
    }
  }

  // Generate key baru
  exec(`ssh-keygen -t ed25519 -C "ps-panel-deploy" -f ${DEPLOY_KEY} -N ""`, (err, stdout, stderr) => {
    if (err) {
      const errMsg = stderr || err.message || 'Unknown error';
      console.error('[Deploy Key]', errMsg);
      return res.status(500).json({ error: 'Failed to generate key: ' + errMsg });
    }
    try {
      const key = fs.readFileSync(pubPath, 'utf8').trim();
      res.json({ key });
    } catch(e) {
      res.status(500).json({ error: 'Generated but cannot read key: ' + e.message });
    }
  });
});

// ── Git Clone ──
app.post('/api/clone', auth, (req, res) => {
  const { repoUrl, path: targetPath, force } = req.body || {};
  if (!repoUrl || !targetPath)
    return res.status(400).json({ error: 'repoUrl and path are required' });
  if (!path.isAbsolute(targetPath))
    return res.status(400).json({ error: 'Path must be absolute' });
  // Only allow git/ssh/https URLs
  if (!/^(git@|https?:\/\/)[\w.\-/:]+\.git$/.test(repoUrl))
    return res.status(400).json({ error: 'Invalid repository URL. Use SSH (git@github.com:...) or HTTPS format.' });

  let output = '';

  // Handle force flag - delete existing directory if needed
  if (force && fs.existsSync(targetPath)) {
    try {
      output += `[FORCE] Deleting existing directory: ${targetPath}\n`;
      const files = fs.readdirSync(targetPath);
      for (const file of files) {
        const filePath = path.join(targetPath, file);
        if (fs.lstatSync(filePath).isDirectory()) {
          fs.rmSync(filePath, { recursive: true, force: true });
        } else {
          fs.unlinkSync(filePath);
        }
      }
      output += '[FORCE] Cleanup complete\n';
    } catch (e) {
      return res.status(400).json({ error: 'Cannot delete directory: ' + e.message });
    }
  } else if (!force) {
    // Check if target directory already has files (non-empty)
    try {
      if (fs.existsSync(targetPath)) {
        const files = fs.readdirSync(targetPath).filter(f => f !== '.git');
        if (files.length > 0)
          return res.status(400).json({ error: `Directory ${targetPath} is not empty. Remove existing files first or check "Force" option to replace.` });
      }
    } catch (e) {
      return res.status(400).json({ error: 'Cannot check target directory: ' + e.message });
    }
  }

  // Create directory if doesn't exist
  try {
    fs.mkdirSync(targetPath, { recursive: true });
  } catch (e) {
    return res.status(400).json({ error: 'Cannot create directory: ' + e.message });
  }

  // Run git clone — use GIT_SSH_COMMAND to use ps-panel deploy key if it exists
  const sshKey = '/root/.ssh/ps-panel-deploy';
  const sshCmd = fs.existsSync(sshKey)
    ? `GIT_SSH_COMMAND="ssh -i ${sshKey} -o StrictHostKeyChecking=no"`
    : '';
  const cmd = `${sshCmd} git clone ${repoUrl} ${targetPath} 2>&1`;

  output += `[CLONE] Starting git clone...\n`;
  exec(cmd, { timeout: 120000 }, (err, stdout, stderr) => {
    const cmdOutput = (stdout || '') + (stderr || '');
    output += cmdOutput;
    if (err) return res.json({ ok: false, output });
    res.json({ ok: true, output });
  });
});

// ── Deploy ──
app.post('/api/deploy', auth, async (req,res)=>{
  let {path:p,branch,laravel}=req.body;
  if(!p||!path.isAbsolute(p)) return res.status(400).json({error:'Absolute path required'});
  // The Deploy page's vhost dropdown sends the vhost docroot, which for a
  // Laravel app is `<project>/public` — but git/composer/npm/artisan must run
  // in the project root. Step up to it instead of failing at composer install.
  if (laravel && !fs.existsSync(path.join(p, 'composer.json'))
      && path.basename(p) === 'public' && fs.existsSync(path.join(p, '..', 'composer.json'))) {
    p = path.dirname(p);
  }
  const result = await deployAndRecord({ path:p, branch, laravel }, 'manual');
  res.json(result);
});

// ── File Manager ──
// Admin panel runs as root → full filesystem access (like cPanel File Manager).
const FM_MAX_EDIT = 2 * 1024 * 1024; // 2MB max for in-browser text editing

// Resolve + normalize an absolute path; reject null bytes / non-absolute input.
function fmResolve(p){
  if(typeof p !== 'string' || !p || p.includes('\0')) return null;
  const resolved = path.resolve(p);
  if(!path.isAbsolute(resolved)) return null;
  return resolved;
}
// Build a metadata object for a directory entry (handles symlinks).
function fmStat(full){
  const st = fs.lstatSync(full);
  const isLink = st.isSymbolicLink();
  let real = st;
  if(isLink){ try { real = fs.statSync(full); } catch { real = st; } }
  return {
    type: real.isDirectory() ? 'dir' : 'file',
    isLink,
    size: st.size,
    mtime: st.mtime,
    mode: (st.mode & 0o777).toString(8).padStart(3,'0'),
  };
}

// List a directory
app.get('/api/files', auth, (req,res)=>{
  const dir = fmResolve(req.query.path || '/var/www');
  if(!dir) return res.status(400).json({error:'Invalid path'});
  try {
    if(!fs.statSync(dir).isDirectory()) return res.status(400).json({error:'Not a directory'});
    const entries = fs.readdirSync(dir).map(name=>{
      const full = path.join(dir, name);
      try { return { name, ...fmStat(full) }; }
      catch { return { name, type:'file', size:0, mode:'---', error:true }; }
    });
    // Folders first, then alphabetical (case-insensitive)
    entries.sort((a,b)=> a.type===b.type
      ? a.name.toLowerCase().localeCompare(b.name.toLowerCase())
      : (a.type==='dir'?-1:1));
    res.json({ path: dir, parent: dir==='/'?null:path.dirname(dir), entries });
  } catch(e){ res.status(400).json({error:e.message}); }
});

// Read a text file for editing
app.get('/api/files/read', auth, (req,res)=>{
  const f = fmResolve(req.query.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  try {
    const st = fs.statSync(f);
    if(st.isDirectory()) return res.status(400).json({error:'Is a directory'});
    if(st.size > FM_MAX_EDIT)
      return res.status(413).json({error:`File too large to edit (${(st.size/1048576).toFixed(1)}MB > 2MB). Download instead.`});
    const buf = fs.readFileSync(f);
    if(buf.subarray(0, 8000).includes(0))
      return res.status(415).json({error:'Binary file — cannot edit as text. Download instead.'});
    res.json({ path:f, content: buf.toString('utf8'), size: st.size, mode:(st.mode&0o777).toString(8).padStart(3,'0') });
  } catch(e){ res.status(400).json({error:e.message}); }
});

// Write/save a text file
app.post('/api/files/write', auth, (req,res)=>{
  const f = fmResolve(req.body?.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  if(typeof req.body.content !== 'string') return res.status(400).json({error:'content required'});
  try { fs.writeFileSync(f, req.body.content, 'utf8'); res.json({ok:true}); }
  catch(e){ res.status(400).json({error:e.message}); }
});

// Create a directory
app.post('/api/files/mkdir', auth, (req,res)=>{
  const f = fmResolve(req.body?.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  try {
    if(fs.existsSync(f)) return res.status(400).json({error:'Already exists'});
    fs.mkdirSync(f, {recursive:true});
    res.json({ok:true});
  } catch(e){ res.status(400).json({error:e.message}); }
});

// Create an empty file
app.post('/api/files/create', auth, (req,res)=>{
  const f = fmResolve(req.body?.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  try { fs.writeFileSync(f, '', {flag:'wx'}); res.json({ok:true}); }
  catch(e){ res.status(400).json({error: e.code==='EEXIST'?'Already exists':e.message}); }
});

// Rename / move
app.post('/api/files/rename', auth, (req,res)=>{
  const from = fmResolve(req.body?.path);
  const to   = fmResolve(req.body?.newPath);
  if(!from || !to) return res.status(400).json({error:'Invalid path'});
  try {
    if(!fs.existsSync(from)) return res.status(404).json({error:'Source not found'});
    if(fs.existsSync(to)) return res.status(400).json({error:'Destination already exists'});
    fs.renameSync(from, to);
    res.json({ok:true});
  } catch(e){ res.status(400).json({error:e.message}); }
});

// Delete file or directory (recursive)
app.post('/api/files/delete', auth, (req,res)=>{
  const f = fmResolve(req.body?.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  if(f === '/') return res.status(400).json({error:'Refusing to delete /'});
  try {
    if(fs.lstatSync(f).isDirectory()) fs.rmSync(f, {recursive:true, force:true});
    else fs.unlinkSync(f);
    res.json({ok:true});
  } catch(e){ res.status(400).json({error:e.message}); }
});

// Change permissions (octal)
app.post('/api/files/chmod', auth, (req,res)=>{
  const f = fmResolve(req.body?.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  if(!/^[0-7]{3,4}$/.test(req.body?.mode||'')) return res.status(400).json({error:'Invalid mode (use octal e.g. 644, 755)'});
  try { fs.chmodSync(f, parseInt(req.body.mode, 8)); res.json({ok:true}); }
  catch(e){ res.status(400).json({error:e.message}); }
});

// Upload a file (base64 body). Token via header (auth middleware).
app.post('/api/files/upload', auth, (req,res)=>{
  const dir  = fmResolve(req.body?.path);
  const name = req.body?.name;
  const data = req.body?.data;
  if(!dir || !name || typeof data !== 'string') return res.status(400).json({error:'path, name, data required'});
  if(/[\/\\\0]/.test(name)) return res.status(400).json({error:'Invalid file name'});
  try {
    if(!fs.statSync(dir).isDirectory()) return res.status(400).json({error:'Target is not a directory'});
    const buf = Buffer.from(data, 'base64');
    fs.writeFileSync(path.join(dir, name), buf);
    res.json({ok:true, name, size:buf.length});
  } catch(e){ res.status(400).json({error:e.message}); }
});

// Download a file. Token via query param so a plain browser link works (same as WebSocket).
app.get('/api/files/download', (req,res)=>{
  try { verifyToken(req.query.token); }
  catch { return res.status(401).json({error:'Unauthorized'}); }
  const f = fmResolve(req.query.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  try {
    if(fs.statSync(f).isDirectory()) return res.status(400).json({error:'Cannot download a directory'});
    res.download(f);
  } catch(e){ res.status(400).json({error:e.message}); }
});

// ── Mail / SMTP ──
// App-level outgoing email: panel stores SMTP creds in each vhost's Laravel .env
// and can send a test email to verify credentials before deploy.

// Quote an .env value only when it contains spaces/special chars.
function envQuote(v){
  v = String(v == null ? '' : v);
  if(v === '') return '';
  if(/^[A-Za-z0-9_.\-:\/@]+$/.test(v)) return v;          // simple → no quotes
  return '"' + v.replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"';
}
// Replace existing KEY= lines, append the rest — preserves the rest of the file.
function updateEnvVars(content, vars){
  const keys = Object.keys(vars);
  const seen = {};
  let lines = content.split('\n').map(line=>{
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=/);
    if(m && keys.includes(m[1])){ seen[m[1]] = true; return `${m[1]}=${vars[m[1]]}`; }
    return line;
  });
  keys.forEach(k=>{ if(!seen[k]) lines.push(`${k}=${vars[k]}`); });
  return lines.join('\n');
}

// Read current MAIL_* values from a vhost .env (to pre-fill the form)
app.get('/api/mail/:domain', auth, (req,res)=>{
  const envPath = getVhostEnvPath(req.params.domain);
  if(!envPath) return res.status(400).json({error:'Invalid domain'});
  const out = { exists:false, path:envPath, mail:{} };
  try {
    if(fs.existsSync(envPath)){
      out.exists = true;
      fs.readFileSync(envPath,'utf8').split('\n').forEach(line=>{
        const m = line.match(/^\s*(MAIL_[A-Z_]+)\s*=\s*(.*)$/);
        if(m){
          let v = m[2].trim();
          if((v.startsWith('"')&&v.endsWith('"'))||(v.startsWith("'")&&v.endsWith("'"))) v = v.slice(1,-1);
          out.mail[m[1]] = v;
        }
      });
    }
    res.json(out);
  } catch(e){ res.status(500).json({error:'Cannot read .env: '+e.message}); }
});

// Send a test email using the supplied SMTP settings (not yet saved)
app.post('/api/mail/test', auth, async (req,res)=>{
  let nodemailer;
  try { nodemailer = require('nodemailer'); }
  catch { return res.status(500).json({error:'nodemailer belum terinstall. Jalankan: cd /opt/ps-panel && npm install nodemailer, lalu pm2 restart ps-panel'}); }
  const { host, port, username, password, encryption, fromAddress, fromName, to } = req.body || {};
  if(!host || !port || !to) return res.status(400).json({error:'host, port, dan email tujuan wajib diisi'});
  const portNum = Number(port);
  const secure = encryption === 'ssl' || portNum === 465;   // SSL on 465, STARTTLS otherwise
  try {
    const transporter = nodemailer.createTransport({
      host, port: portNum, secure,
      auth: (username || password) ? { user: username, pass: password } : undefined,
      tls: { rejectUnauthorized: false }, // diagnostic test tool → accept self-signed (does not affect the app's own sending)
      connectionTimeout: 15000, greetingTimeout: 15000,
    });
    const from = fromName ? `"${fromName}" <${fromAddress || username}>` : (fromAddress || username);
    const info = await transporter.sendMail({
      from, to,
      subject: 'PS Panel — Test Email ✓',
      text: 'Konfigurasi SMTP Anda berhasil. Email ini dikirim dari PS Panel sebagai test. Aplikasi siap mengirim reset password, OTP, dll.',
      html: '<div style="font-family:sans-serif;line-height:1.6"><h2 style="color:#10b981;margin:0 0 8px">✓ SMTP Berhasil!</h2><p>Konfigurasi SMTP Anda <b>berhasil</b>. Email ini dikirim dari <b>PS Panel</b> sebagai test.</p><p>Aplikasi Anda siap mengirim <b>reset password</b>, <b>OTP</b>, dan notifikasi lainnya.</p></div>',
    });
    res.json({ ok:true, messageId: info.messageId, response: info.response });
  } catch(e){
    res.status(400).json({ ok:false, error: e.message });
  }
});

// Write MAIL_* into a vhost's .env (backup .bak, preserve other keys)
app.post('/api/mail/:domain/save', auth, (req,res)=>{
  const envPath = getVhostEnvPath(req.params.domain);
  if(!envPath) return res.status(400).json({error:'Invalid domain'});
  const parentDir = path.dirname(envPath);
  if(!fs.existsSync(parentDir)) return res.status(400).json({error:'Vhost directory not found: '+parentDir});
  const { host, port, username, password, encryption, fromAddress, fromName } = req.body || {};
  if(!host || !port) return res.status(400).json({error:'SMTP host & port wajib diisi'});
  const vars = {
    MAIL_MAILER:       'smtp',
    MAIL_HOST:         envQuote(host),
    MAIL_PORT:         envQuote(String(port)),
    MAIL_USERNAME:     envQuote(username || ''),
    MAIL_PASSWORD:     envQuote(password || ''),
    MAIL_ENCRYPTION:   encryption === 'none' ? 'null' : envQuote(encryption || 'tls'),
    MAIL_FROM_ADDRESS: envQuote(fromAddress || username || ''),
    MAIL_FROM_NAME:    envQuote(fromName || '${APP_NAME}'),
  };
  try {
    let content = fs.existsSync(envPath) ? fs.readFileSync(envPath,'utf8') : '';
    if(fs.existsSync(envPath)) fs.copyFileSync(envPath, envPath + '.bak');
    content = updateEnvVars(content, vars);
    fs.writeFileSync(envPath, content);
    try { fs.chmodSync(envPath, 0o644); } catch {}
    res.json({ ok:true });
  } catch(e){ res.status(500).json({error:'Cannot save .env: '+e.message}); }
});

// ── Self-update ──
// Standard installs are NOT git repos (install.sh wget's individual files), so
// updates work by downloading the latest files over HTTPS from GITHUB_RAW and
// comparing a version manifest (version.json) rather than using `git pull`.

// Files refreshed during an update, relative to PANEL_DIR.
const UPDATE_FILES = ['server.js', 'public/index.html', 'install.sh', 'version.json'];

// Read the locally-installed version (version.json → package.json → unknown).
function localVersion(){
  try { return JSON.parse(fs.readFileSync(path.join(PANEL_DIR,'version.json'),'utf8')); }
  catch {}
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(PANEL_DIR,'package.json'),'utf8'));
    return { version: pkg.version || '0.0.0', notes: [] };
  } catch {}
  return { version: '0.0.0', notes: [] };
}

// Compare two dotted version strings → 1 / 0 / -1.
function cmpVer(a,b){
  const pa = String(a).split('.').map(n=>parseInt(n,10)||0);
  const pb = String(b).split('.').map(n=>parseInt(n,10)||0);
  for(let i=0;i<3;i++){ if((pa[i]||0)>(pb[i]||0)) return 1; if((pa[i]||0)<(pb[i]||0)) return -1; }
  return 0;
}

// Node's connect failures are often an AggregateError with an empty .message; surface the code/cause.
function errMsg(e){
  if(!e) return 'unknown error';
  const parts = e.errors && e.errors.length ? e.errors.map(x=>x.code||x.message) : [];
  return [e.message, e.code, ...parts].filter(Boolean).join(' ') || String(e);
}

// GET a URL, returning the body as a string (follows one redirect).
function httpsGet(url, redirects=2){
  return new Promise((resolve,reject)=>{
    const req = https.get(url, { timeout: 20000, family: 4, headers:{'User-Agent':'PS-Panel'} }, res=>{
      if(res.statusCode>=300 && res.statusCode<400 && res.headers.location && redirects>0){
        res.resume(); return resolve(httpsGet(res.headers.location, redirects-1));
      }
      if(res.statusCode!==200){ res.resume(); return reject(new Error('HTTP '+res.statusCode+' for '+url)); }
      let data=''; res.setEncoding('utf8');
      res.on('data',c=>data+=c); res.on('end',()=>resolve(data));
    });
    req.on('timeout',()=>req.destroy(new Error('Request timeout')));
    req.on('error',reject);
  });
}

// Download a URL to a destination file (follows one redirect).
function httpsDownload(url, dest, redirects=2){
  return new Promise((resolve,reject)=>{
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { timeout: 60000, family: 4, headers:{'User-Agent':'PS-Panel'} }, res=>{
      if(res.statusCode>=300 && res.statusCode<400 && res.headers.location && redirects>0){
        res.resume(); file.close(); fs.unlink(dest,()=>{});
        return resolve(httpsDownload(res.headers.location, dest, redirects-1));
      }
      if(res.statusCode!==200){ res.resume(); file.close(); fs.unlink(dest,()=>{}); return reject(new Error('HTTP '+res.statusCode+' for '+url)); }
      res.pipe(file);
      file.on('finish',()=>file.close(()=>resolve()));
    });
    req.on('timeout',()=>req.destroy(new Error('Request timeout')));
    req.on('error',e=>{ file.close(); fs.unlink(dest,()=>{}); reject(e); });
  });
}

// Run a command, resolving with {err,stdout,stderr} (never rejects).
function runCmd(cmd, args, opts={}){
  return new Promise(resolve=>{
    execFile(cmd, args, { timeout: 60000, ...opts }, (err,stdout,stderr)=>{
      resolve({ err, stdout:(stdout||'').toString(), stderr:(stderr||'').toString() });
    });
  });
}

// Check whether a newer panel version is available.
app.get('/api/update/check', auth, async (req,res)=>{
  const local = localVersion();
  try {
    const raw = await httpsGet(`${GITHUB_RAW}/version.json?t=${Date.now()}`);
    let remote;
    try { remote = JSON.parse(raw); } catch { return res.status(502).json({error:'Manifest versi remote tidak valid'}); }
    const updateAvailable = cmpVer(remote.version, local.version) > 0;
    res.json({
      current: local.version,
      latest:  remote.version,
      released: remote.released || null,
      notes:   Array.isArray(remote.notes) ? remote.notes : [],
      updateAvailable,
    });
  } catch(e){
    res.status(502).json({ error:'Tidak bisa cek update: '+errMsg(e)+' ('+GITHUB_RAW+')', current: local.version });
  }
});

// Download latest files, npm install, then restart via PM2.
app.post('/api/update/apply', auth, async (req,res)=>{
  let out='';
  const tmpDir = path.join(PANEL_DIR, '.update-tmp');
  try {
    // 1. Download every file to a temp dir first (so a failed download can't leave a half-updated panel).
    fs.mkdirSync(tmpDir, { recursive: true });
    out += '── Downloading latest files ──\n';
    for(const rel of UPDATE_FILES){
      const url = `${GITHUB_RAW}/${rel}?t=${Date.now()}`;
      const tmp = path.join(tmpDir, rel.replace(/[\/]/g,'__'));
      try { await httpsDownload(url, tmp); out += `  ✓ ${rel}\n`; }
      catch(e){
        // version.json may not exist on very old branches — skip it, fail hard on the rest.
        if(rel==='version.json'){ out += `  • ${rel} (lewati, opsional)\n`; continue; }
        out += `  ✗ ${rel} — ${errMsg(e)}\n[GAGAL] Download dibatalkan, tidak ada file yang diubah.\n`;
        fs.rmSync(tmpDir,{recursive:true,force:true});
        return res.json({ ok:false, output:out });
      }
    }
    // 2. Move downloaded files into place (backup .bak of the existing one).
    out += '\n── Applying ──\n';
    for(const rel of UPDATE_FILES){
      const tmp = path.join(tmpDir, rel.replace(/[\/]/g,'__'));
      if(!fs.existsSync(tmp)) continue;
      const target = path.join(PANEL_DIR, rel);
      fs.mkdirSync(path.dirname(target),{recursive:true});
      try { if(fs.existsSync(target)) fs.copyFileSync(target, target+'.bak'); } catch {}
      fs.copyFileSync(tmp, target);
      out += `  ✓ ${rel}\n`;
    }
    fs.rmSync(tmpDir,{recursive:true,force:true});
    if(syncPackageVersion()) out += '  ✓ package.json (versi) diselaraskan dengan version.json\n';

    // 3. Ensure dependencies are installed (nodemailer, etc.).
    out += '\n── npm install ──\n';
    const npm = await runCmd('npm', ['install','--no-audit','--no-fund','--omit=dev'], { cwd: PANEL_DIR, timeout: 300000 });
    out += (npm.stdout||'') + (npm.stderr||'');
    if(npm.err && npm.err.code==='ENOENT'){
      out += '\n[ERROR] npm tidak ditemukan di PATH. Jalankan "npm install" manual lalu restart.\n';
      return res.json({ ok:false, output:out });
    }

    out += '\n✓ Update selesai. Panel akan restart dalam beberapa detik...\n';
    res.json({ ok:true, output:out, restarting:true });

    // 4. Restart after the response is flushed. PM2 will respawn the process.
    setTimeout(()=>{
      exec('pm2 restart ps-panel --update-env', (err)=>{
        // If not under PM2 (dev mode), just exit and let any supervisor restart us.
        if(err) process.exit(0);
      });
    }, 1500);
  } catch(e){
    try { fs.rmSync(tmpDir,{recursive:true,force:true}); } catch {}
    out += '\n[ERROR] '+e.message+'\n';
    res.json({ ok:false, output:out });
  }
});

// ── WebSocket real-time ──
wss.on('connection', (ws, req)=>{
  const url = new URL(req.url, 'http://localhost');
  try { verifyToken(url.searchParams.get('token')); }
  catch { ws.close(4001, 'Unauthorized'); return; }
  const iv = setInterval(async()=>{
    if(ws.readyState!==WebSocket.OPEN){clearInterval(iv);return;}
    try {
      const [cpu,mem,net] = await Promise.all([si.currentLoad(),si.mem(),si.networkStats()]);
      const n = net.find(x=>x.iface!=='lo')||net[0]||{};
      ws.send(JSON.stringify({
        cpu: Math.round(cpu.currentLoad),
        mem: Math.round(mem.used/mem.total*100),
        rxSec: n.rx_sec||0, txSec: n.tx_sec||0,
      }));
    } catch{}
  }, 2000);
  ws.on('close',()=>clearInterval(iv));
});

// CLI: node server.js --autotune [--dry-run [--cores=N --ram=MB]]  (boot unit entry point)
const AUTOTUNE_CLI = process.argv.includes('--autotune');
if (AUTOTUNE_CLI) {
  (async () => {
    const dry = process.argv.includes('--dry-run');
    const argNum = n => { const a = process.argv.find(x => x.startsWith(`--${n}=`)); return a ? parseInt(a.split('=')[1], 10) : null; };
    if (dry) {
      const ctx = await buildContext({ cores: argNum('cores'), ramMB: argNum('ram') });
      const plan = computePlan(ctx);
      console.log(`DRY-RUN (tidak ada yang diubah, log/state tidak ditulis): ${plan.specs.cores} core / ${plan.specs.ramMB} MB`);
      console.log(JSON.stringify({ frankenphp: plan.frankenphp, fpm: plan.fpm, postgres: plan.postgres, reserves: plan.reserves }, null, 2));
      const res = await applyPlan(ctx, plan, 'dry-run', { dry: true, boot: true });
      res.changes.forEach(c => console.log(`  ${c.target} ${c.key}: ${c.old ?? '-'} -> ${c.new}`));
      process.exit(0);
    }
    const res = await autotuneTick('boot');
    (res.steps || []).forEach(x => autotuneLog(`${x.name}: ${x.status} — ${x.detail}`));
    process.exit(res.ok === false ? 1 : 0);
  })().catch(e => { console.error('[autotune]', e); process.exit(1); });
} else {
server.listen(PORT,'0.0.0.0',()=>console.log(`PS Panel → http://0.0.0.0:${PORT}`));

// Run the Caddyfile self-heal once per boot. On an install that predates this
// fix, this repairs the file and reloads FrankenPHP automatically the moment
// the panel is updated/restarted — no manual Caddyfile surgery required.
try {
  if (ensureFrankenPHPGlobalBlock()) {
    console.log('[Startup] Caddyfile was missing the global `frankenphp` block (PHP requests would hang forever) — fixed and reloading FrankenPHP');
    reloadFrankenPHP((err) => {
      if (err) console.error('[Startup] FrankenPHP reload after Caddyfile fix failed:', err.message||err);
      else console.log('[Startup] FrankenPHP reloaded successfully');
    });
  }
} catch (e) {
  console.error('[Startup] ensureFrankenPHPGlobalBlock check failed:', e.message);
}

// Small self-heals: package.json's version (shown by pm2) and the Caddy config dir drop-in.
try { if (syncPackageVersion()) console.log('[Startup] package.json version diselaraskan dengan version.json'); } catch {}
setTimeout(() => { ensureCaddyConfigDir().catch(() => {}); }, 3000).unref();

// Auto-tune: make sure the boot unit exists, run once shortly after start (this also adopts
// existing manual PHP-FPM pool files and picks up core/RAM changes), then every 10 minutes.
setTimeout(() => { ensureBootUnit().then(() => autotuneTick('startup')).then(() => ensureUnattendedSury()).then(() => ensureSchedulers()).then(() => securityTick()).catch(e => console.error('[autotune]', e.message)); }, 5000).unref();
setTimeout(() => { healthTick(); setInterval(healthTick, HEALTH_INTERVAL_MS).unref(); }, 15000).unref();
setInterval(() => { autotuneTick('periodic').then(() => securityTick()).catch(e => console.error('[autotune]', e.message)); }, AUTOTUNE_INTERVAL_MS).unref();
}
