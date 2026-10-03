const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { exec, execFile } = require('child_process');
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
      const [k,v] = l.split('='); if(k&&v) c[k.trim()]=v.trim();
    });
  return c;
}

// ── Auth ──
// Persistent auth state lives in AUTH_FILE (mode 600): { hash, secret, tv }.
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
const authState = loadAuthState();
let dirty = false;
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

// CLI: node server.js --reset-password [newpassword]
if (process.argv.includes('--reset-password')) {
  const i = process.argv.indexOf('--reset-password');
  const pw = process.argv[i + 1] && !process.argv[i + 1].startsWith('--')
    ? process.argv[i + 1]
    : crypto.randomBytes(9).toString('base64url');
  if (pw.length < MIN_PASS_LEN) { console.error(`Password minimal ${MIN_PASS_LEN} karakter.`); process.exit(1); }
  setPassword(pw);
  console.log(`Password panel direset. Password baru: ${pw}`);
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
  if(typeof req.body.password === 'string' && bcrypt.compareSync(req.body.password, authState.hash))
    res.json({token: signToken()});
  else res.status(401).json({error:'Wrong password'});
});

app.post('/api/password', auth, (req, res) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (checkRateLimit('pw:' + ip)) return res.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
  const { oldPassword, newPassword } = req.body || {};
  if (typeof oldPassword !== 'string' || typeof newPassword !== 'string')
    return res.status(400).json({error:'Password lama dan baru wajib diisi'});
  if (!bcrypt.compareSync(oldPassword, authState.hash))
    return res.status(401).json({error:'Password lama salah'});
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
    });
  } catch(e){ res.json({ok:false, error:e.message}); }
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
const CADDYFILE_PATH = '/etc/frankenphp/Caddyfile';

// CRITICAL self-heal: FrankenPHP's PHP app is only provisioned if the Caddyfile's
// global options block (the very first block, before any site) declares
// `frankenphp`. Without it, `php_server` directives still show up in the routing
// table, but every request that hits one hangs forever — no error, no log entry,
// nothing — because the PHP runtime behind it was never started. Older installs
// (before this was added to install.sh) shipped without this block by default,
// and it only ever got added as an accidental side effect of changing the
// num_threads setting. Check for it on every reload and repair it if missing.
function ensureFrankenPHPGlobalBlock() {
  if (!fs.existsSync(CADDYFILE_PATH)) return false;
  const content = fs.readFileSync(CADDYFILE_PATH, 'utf8');
  const stripped = content.split('\n').filter(l => !l.trim().startsWith('#')).join('\n').trim();
  if (stripped.startsWith('{')) {
    const firstBlock = stripped.match(/^\{([\s\S]*?)\n\}/);
    if (firstBlock && /frankenphp/.test(firstBlock[1])) return false; // already present
  }
  fs.copyFileSync(CADDYFILE_PATH, CADDYFILE_PATH + '.bak.' + Date.now());
  fs.writeFileSync(CADDYFILE_PATH, '{\n\tfrankenphp\n}\n\n' + content);
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
app.get('/api/vhosts', auth,(req,res)=>{
  const files = fs.existsSync(VHOSTS_DIR)?fs.readdirSync(VHOSTS_DIR):[];
  res.json(files.map(f=>{
    const fpath=path.join(VHOSTS_DIR,f);
    const content=fs.readFileSync(fpath,'utf8');
    const stats=fs.statSync(fpath);
    const domain=f.replace('.conf','');
    // Parse document root
    const m=content.match(/root\s+\*\s+(.+?)(?:\n|$)/);
    const docroot=m?m[1].trim():'/var/www/'+domain;
    // Check if PHP enabled
    const phpEnabled=content.includes('php_server');
    // Check if SSL enabled
    const sslEnabled=!content.match(/^http:\/\//m);
    return {
      file:f,
      domain,
      content,
      docroot,
      phpEnabled,
      ssl:sslEnabled?'HTTPS':'HTTP',
      created:new Date(stats.mtime).toLocaleDateString('id-ID',{year:'numeric',month:'short',day:'numeric'}),
      size:Math.round(stats.size/1024)+'KB'
    };
  }));
});
app.post('/api/vhosts', auth,(req,res)=>{
  const {domain,root,php,ssl,laravel}=req.body;
  if(!domain) return res.status(400).json({error:'Domain required'});
  if(!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(domain)) return res.status(400).json({error:'Invalid domain name'});
  const projectRoot = root||`/var/www/${domain}`;
  if(!path.isAbsolute(projectRoot)) return res.status(400).json({error:'Document root must be an absolute path'});
  fs.mkdirSync(projectRoot,{recursive:true});
  // Laravel's index.php lives in <project>/public, not the project root — pointing
  // Caddy at the project root means every request 404s straight from Caddy before
  // the app ever runs, which looks like "the server can't find anything" even
  // though the deployed app itself is perfectly fine.
  const docroot = laravel ? path.join(projectRoot,'public') : projectRoot;
  const host = ssl ? domain : `http://${domain}`;
  const config = php
    ? `${host} {\n  root * ${docroot}\n  php_server\n}\n`
    : `${host} {\n  root * ${docroot}\n  file_server\n}\n`;
  fs.writeFileSync(path.join(VHOSTS_DIR,`${domain}.conf`),config);
  reloadFrankenPHP((err)=>{
    res.json({ok:true, reloaded:!err, reloadError: err ? String(err.message||err) : null});
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
    res.json({ok:true});
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
const PHP_INI_PATHS = [
  '/etc/php/8.3/embed/php.ini',
  '/etc/php/8.3/cli/php.ini',
  '/etc/php/8.3/fpm/php.ini',
];

const PHP_KEYS = [
  'upload_max_filesize',
  'post_max_size',
  'memory_limit',
  'max_execution_time',
  'max_input_vars',
  'max_input_time',
];

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
};

function findPhpIni() {
  for (const p of PHP_INI_PATHS) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function readPhpIni() {
  const iniPath = findPhpIni();
  const settings = {};
  for (const k of PHP_KEYS) settings[k] = null;
  if (!iniPath) return { path: null, settings };
  try {
    const content = fs.readFileSync(iniPath, 'utf8');
    for (const k of PHP_KEYS) {
      const m = content.match(new RegExp(`^\\s*${k}\\s*=\\s*(.+?)\\s*$`, 'm'));
      if (m) settings[k] = m[1].trim();
    }
  } catch {}
  return { path: iniPath, settings };
}

function updatePhpIni(updates) {
  const iniPath = findPhpIni();
  if (!iniPath) throw new Error('php.ini not found');
  // Validate
  for (const [k, v] of Object.entries(updates)) {
    if (!PHP_KEYS.includes(k)) throw new Error(`Unknown key: ${k}`);
    if (!PHP_VALIDATORS[k].test(String(v))) throw new Error(`Invalid value for ${k}: ${v}`);
  }
  // Backup
  fs.copyFileSync(iniPath, iniPath + '.bak.' + Date.now());
  let content = fs.readFileSync(iniPath, 'utf8');
  for (const [k, v] of Object.entries(updates)) {
    const re = new RegExp(`^(\\s*;?\\s*)${k}(\\s*=\\s*).+$`, 'm');
    if (re.test(content)) {
      content = content.replace(re, `${k}$2${v}`);
    } else {
      content += `\n${k} = ${v}\n`;
    }
  }
  fs.writeFileSync(iniPath, content);
  return iniPath;
}

function readFrankenphpSettings() {
  if (!fs.existsSync(CADDYFILE_PATH)) return { num_threads: null };
  try {
    const content = fs.readFileSync(CADDYFILE_PATH, 'utf8');
    const m = content.match(/num_threads\s+(\d+)/);
    return { num_threads: m ? parseInt(m[1]) : null };
  } catch { return { num_threads: null }; }
}

function updateFrankenphpSettings(updates) {
  if (!fs.existsSync(CADDYFILE_PATH)) throw new Error('Caddyfile not found');
  const threads = parseInt(updates.num_threads);
  if (!Number.isInteger(threads) || threads < 1 || threads > 256)
    throw new Error('num_threads must be 1-256');

  // Backup
  fs.copyFileSync(CADDYFILE_PATH, CADDYFILE_PATH + '.bak.' + Date.now());
  let content = fs.readFileSync(CADDYFILE_PATH, 'utf8');

  const MARK_START = '# PS-PANEL-MANAGED-START';
  const MARK_END   = '# PS-PANEL-MANAGED-END';
  const block =
`${MARK_START}
{
\tfrankenphp {
\t\tnum_threads ${threads}
\t}
}
${MARK_END}`;

  const blockRe = new RegExp(`${MARK_START}[\\s\\S]*?${MARK_END}`);
  if (blockRe.test(content)) {
    content = content.replace(blockRe, block);
  } else {
    content = block + '\n\n' + content;
  }
  fs.writeFileSync(CADDYFILE_PATH, content);
}

app.get('/api/settings', auth, (req, res) => {
  try {
    const php = readPhpIni();
    const fp  = readFrankenphpSettings();
    res.json({
      ok: true,
      php: php.settings,
      phpIniPath: php.path,
      frankenphp: fp,
    });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/settings/update', auth, (req, res) => {
  const { password, php, frankenphp } = req.body || {};
  if (!password || !bcrypt.compareSync(password, authState.hash))
    return res.status(401).json({ error: 'Wrong password' });

  try {
    let phpPath = null;
    if (php && typeof php === 'object' && Object.keys(php).length) {
      phpPath = updatePhpIni(php);
    }
    let fpUpdated = false;
    if (frankenphp && frankenphp.num_threads != null) {
      updateFrankenphpSettings(frankenphp);
      fpUpdated = true;
    }
    // Restart FrankenPHP to apply
    exec('systemctl restart frankenphp', (err, _, se) => {
      res.json({
        ok: true,
        phpIniPath: phpPath,
        frankenphpUpdated: fpUpdated,
        restartOk: !err,
        restartError: err ? (se || err.message) : null,
      });
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
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

    // 9. Reload FrankenPHP. Blade views recompile on their own when their source
    //    changes, but FrankenPHP's OPcache does NOT invalidate PHP source files
    //    (Controllers, Models, etc.) the same way — a deploy that only touches
    //    PHP code can report every step green while the live site keeps serving
    //    the pre-deploy code until the process restarts. Soft-fail: don't mark
    //    the whole deploy as failed just because the reload itself hiccuped.
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
