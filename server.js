const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { exec, execFile } = require('child_process');
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

const SECRET = process.env.PANEL_SECRET || require('crypto').randomBytes(32).toString('hex');
const PORT = process.env.PANEL_PORT || 8765;
const CREDS_FILE = '/root/.pspanel_credentials';

app.use(express.json({ limit: '100mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
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
const ADMIN_HASH = bcrypt.hashSync(process.env.PANEL_PASS || 'admin123', 10);
function auth(req,res,next){
  const t = req.headers.authorization?.split(' ')[1];
  if(!t) return res.status(401).json({error:'Unauthorized'});
  try { req.user = jwt.verify(t,SECRET); next(); }
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
  if(bcrypt.compareSync(req.body.password, ADMIN_HASH))
    res.json({token: jwt.sign({role:'admin'},SECRET,{expiresIn:'8h'})});
  else res.status(401).json({error:'Wrong password'});
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
  const {domain,root,php,ssl}=req.body;
  if(!domain) return res.status(400).json({error:'Domain required'});
  if(!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(domain)) return res.status(400).json({error:'Invalid domain name'});
  const docroot = root||`/var/www/${domain}`;
  if(!path.isAbsolute(docroot)) return res.status(400).json({error:'Document root must be an absolute path'});
  fs.mkdirSync(docroot,{recursive:true});
  const host = ssl ? domain : `http://${domain}`;
  const config = php
    ? `${host} {\n  root * ${docroot}\n  php_server\n}\n`
    : `${host} {\n  root * ${docroot}\n  file_server\n}\n`;
  fs.writeFileSync(path.join(VHOSTS_DIR,`${domain}.conf`),config);
  res.json({ok:true});
});
app.delete('/api/vhosts/:domain', auth,(req,res)=>{
  const f=path.join(VHOSTS_DIR,`${req.params.domain}.conf`);
  if(fs.existsSync(f)) fs.unlinkSync(f);
  res.json({ok:true});
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
const PHP_INI_PATHS = [
  '/etc/php/8.3/embed/php.ini',
  '/etc/php/8.3/cli/php.ini',
  '/etc/php/8.3/fpm/php.ini',
];
const CADDYFILE_PATH = '/etc/frankenphp/Caddyfile';

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
  if (!password || !bcrypt.compareSync(password, ADMIN_HASH))
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
function runDeploy(hook) {
  // Setup SSH key environment untuk git operations
  const sshKey = '/root/.ssh/ps-panel-deploy';
  const gitEnv = fs.existsSync(sshKey)
    ? { ...process.env, GIT_SSH_COMMAND: `ssh -i ${sshKey} -o StrictHostKeyChecking=no` }
    : process.env;

  const steps = [
    { cmd:'git', args:['-C', hook.path, 'pull', 'origin', hook.branch], useGitEnv:true },
    ...(hook.laravel ? [
      { cmd:'composer', args:['install','--optimize-autoloader','--no-dev','--no-interaction'], cwd:hook.path },
      { cmd:'php', args:['artisan','migrate','--force'],  cwd:hook.path },
      { cmd:'php', args:['artisan','config:cache'],       cwd:hook.path },
      { cmd:'php', args:['artisan','route:cache'],        cwd:hook.path },
      { cmd:'php', args:['artisan','view:cache'],         cwd:hook.path },
    ] : []),
  ];
  let i = 0;
  function next() {
    if (i >= steps.length) return;
    const { cmd, args, cwd, useGitEnv } = steps[i++];
    const execOpts = {
      cwd: cwd || hook.path,
      timeout: 300000,
      env: useGitEnv ? gitEnv : process.env,
    };
    execFile(cmd, args, execOpts, (err) => { if (!err) next(); });
  }
  next();
}
app.get('/api/webhooks', auth, (req, res) => res.json(loadWebhooks().map(h => ({...h, secret: undefined}))));
app.post('/api/webhooks', auth, (req, res) => {
  const { path: p, branch, laravel } = req.body;
  if (!p || !path.isAbsolute(p)) return res.status(400).json({ error:'Absolute path required' });
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
  const hook = loadWebhooks().find(h => h.id === req.params.id);
  if (!hook) return res.status(404).end();
  const sig = req.headers['x-hub-signature-256'] || '';
  const expected = 'sha256=' + crypto.createHmac('sha256', hook.secret).update(req.rawBody||'').digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected.padEnd(71,'0')), Buffer.from(sig.padEnd(71,'0'))) || expected !== sig)
    return res.status(401).end();
  const pushedBranch = (req.body.ref || '').replace('refs/heads/', '');
  if (pushedBranch !== hook.branch) return res.json({ skipped:true });
  res.json({ ok:true });
  runDeploy(hook);
});

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
app.post('/api/deploy', auth,(req,res)=>{
  const {path:p,branch,laravel}=req.body;
  if(!p||!path.isAbsolute(p)) return res.status(400).json({error:'Absolute path required'});
  const safeBranch=(branch||'main').replace(/[^a-zA-Z0-9._\/-]/g,'');

  // Setup SSH key environment untuk git operations (sama dengan clone endpoint)
  const sshKey = '/root/.ssh/ps-panel-deploy';
  const gitEnv = fs.existsSync(sshKey)
    ? { ...process.env, GIT_SSH_COMMAND: `ssh -i ${sshKey} -o StrictHostKeyChecking=no` }
    : process.env;

  const steps=[
    {cmd:'git',  args:['-C',p,'pull','origin',safeBranch], useGitEnv:true},
    ...(laravel?[
      {cmd:'composer',args:['install','--optimize-autoloader','--no-dev','--no-interaction'],cwd:p},
      {cmd:'php',     args:['artisan','migrate','--force'],  cwd:p},
      {cmd:'php',     args:['artisan','config:cache'],       cwd:p},
      {cmd:'php',     args:['artisan','route:cache'],        cwd:p},
      {cmd:'php',     args:['artisan','view:cache'],         cwd:p},
    ]:[]),
  ];
  let out=''; let i=0;
  function next(){
    if(i>=steps.length) return res.json({ok:true, output:out});
    const {cmd,args,cwd,useGitEnv}=steps[i++];
    out+=`\n$ ${cmd} ${args.join(' ')}\n`;
    const execOpts = {
      cwd: cwd||p,
      timeout: 300000,
      env: useGitEnv ? gitEnv : process.env,
    };
    execFile(cmd,args,execOpts,(err,stdout,stderr)=>{
      // Capture all output (both stdout and stderr)
      if(stdout) out+=stdout;
      if(stderr) out+=stderr;
      if(err){
        // Show detailed error info
        if(err.code==='ENOENT') out+=`\n[ERROR] Command "${cmd}" not found. Please ensure it's installed and in PATH.\n`;
        else if(err.code) out+=`\n[ERROR] Exit code: ${err.code}\n`;
        if(err.message && !stderr) out+=`[ERROR] ${err.message}\n`;
        out+='\n[FAILED]\n';
        return res.json({ok:false, output:out});
      }
      next();
    });
  }
  next();
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
  try { jwt.verify(req.query.token, SECRET); }
  catch { return res.status(401).json({error:'Unauthorized'}); }
  const f = fmResolve(req.query.path);
  if(!f) return res.status(400).json({error:'Invalid path'});
  try {
    if(fs.statSync(f).isDirectory()) return res.status(400).json({error:'Cannot download a directory'});
    res.download(f);
  } catch(e){ res.status(400).json({error:e.message}); }
});

// ── WebSocket real-time ──
wss.on('connection', (ws, req)=>{
  const url = new URL(req.url, 'http://localhost');
  try { jwt.verify(url.searchParams.get('token'), SECRET); }
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
