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

app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
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
  php_fpm:    {name:'PHP-FPM',    unit:'php8.3-fpm'},
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

// ── PHP-FPM stats ──
app.get('/api/phpfpm', auth,(req,res)=>{
  // Read php-fpm status via socket
  exec(`SCRIPT_NAME=/status SCRIPT_FILENAME=/status REQUEST_METHOD=GET cgi-fcgi -bind -connect /run/php/php8.3-fpm.sock 2>/dev/null || echo "error"`, (err,stdout)=>{
    if(err||stdout.includes('error')||!stdout.trim()){
      // Fallback: parse systemd journal
      exec(`systemctl status php8.3-fpm --no-pager -l 2>/dev/null | head -20`, (e2,o2)=>{
        const active = !e2 && o2.includes('active (running)');
        res.json({ok:active, error: active?null:'PHP-FPM status unavailable (install cgi-fcgi or enable status page)'});
      });
      return;
    }
    const parse = (key) => { const m=stdout.match(new RegExp(key+':\\s*(.+)')); return m?m[1].trim():null; };
    res.json({
      ok: true,
      pool:           parse('pool'),
      processManager: parse('process manager'),
      startTime:      parse('start time'),
      startSince:     parse('start since'),
      acceptedConn:   parse('accepted conn'),
      listenQueue:    parse('listen queue'),
      maxListenQueue: parse('max listen queue'),
      idleProcesses:  parse('idle processes'),
      activeProcesses:parse('active processes'),
      totalProcesses: parse('total processes'),
      maxActiveProcs: parse('max active processes'),
      slowRequests:   parse('slow requests'),
    });
  });
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
  res.json(files.map(f=>({file:f, content:fs.readFileSync(path.join(VHOSTS_DIR,f),'utf8')})));
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

// ── Webhooks (Auto Deploy) ──
const WEBHOOKS_FILE = path.join(__dirname, 'webhooks.json');
function loadWebhooks() {
  try { return JSON.parse(fs.readFileSync(WEBHOOKS_FILE, 'utf8')); } catch { return []; }
}
function saveWebhooks(hooks) {
  fs.writeFileSync(WEBHOOKS_FILE, JSON.stringify(hooks, null, 2));
}
function runDeploy(hook) {
  const steps = [
    { cmd:'git', args:['-C', hook.path, 'pull', 'origin', hook.branch] },
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
    const { cmd, args, cwd } = steps[i++];
    execFile(cmd, args, { cwd: cwd || hook.path, timeout: 300000 }, (err) => { if (!err) next(); });
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
  if (fs.existsSync(pubPath)) {
    return res.json({ key: fs.readFileSync(pubPath, 'utf8').trim() });
  }
  exec(`ssh-keygen -t ed25519 -C "ps-panel-deploy" -f ${DEPLOY_KEY} -N ""`, (err, _, se) => {
    if (err) return res.status(500).json({ error: se });
    res.json({ key: fs.readFileSync(pubPath, 'utf8').trim() });
  });
});

// ── Deploy ──
app.post('/api/deploy', auth,(req,res)=>{
  const {path:p,branch,laravel}=req.body;
  if(!p||!path.isAbsolute(p)) return res.status(400).json({error:'Absolute path required'});
  const safeBranch=(branch||'main').replace(/[^a-zA-Z0-9._\/-]/g,'');
  const steps=[
    {cmd:'git',  args:['-C',p,'pull','origin',safeBranch]},
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
    const {cmd,args,cwd}=steps[i++];
    out+=`\n$ ${cmd} ${args.join(' ')}\n`;
    execFile(cmd,args,{cwd:cwd||p, timeout:300000},(err,stdout,stderr)=>{
      out+=stdout||stderr||'';
      if(err){out+='\n[FAILED]\n'; return res.json({ok:false, output:out});}
      next();
    });
  }
  next();
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
