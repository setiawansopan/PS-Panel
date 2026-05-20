const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { exec, execFile } = require('child_process');
const si = require('systeminformation');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const Redis = require('ioredis');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const SECRET = process.env.PANEL_SECRET || require('crypto').randomBytes(32).toString('hex');
const PORT = process.env.PANEL_PORT || 8765;
const CREDS_FILE = '/root/.pspanel_credentials';

app.use(express.json());
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
    const [cpu, mem, disk, net, procs, temp] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize(),
      si.networkStats(),
      si.processes(),
      si.cpuTemperature().catch(()=>null),
    ]);
    // Top 5 processes by CPU
    const topProcs = (procs.list||[])
      .sort((a,b)=>b.pcpu-a.pcpu)
      .slice(0,5)
      .map(p=>({name:p.name, pid:p.pid, cpu:p.pcpu.toFixed(1), mem:p.pmem.toFixed(1), memVsz: p.mem_vsz}));

    const netIface = net.find(n=>n.iface!=='lo') || net[0] || {};

    res.json({
      cpu: { pct: Math.round(cpu.currentLoad), cores: cpu.cpus?.length||1, speed: cpu.currentLoad.toFixed(1) },
      mem: { used:mem.used, total:mem.total, free:mem.free, pct:Math.round(mem.used/mem.total*100), cached:mem.cached },
      disk: disk[0] ? {used:disk[0].used, size:disk[0].size, pct:Math.round(disk[0].use), fs:disk[0].fs} : null,
      load: [cpu.avgLoad1?.toFixed(2), cpu.avgLoad5?.toFixed(2), cpu.avgLoad15?.toFixed(2)],
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

// ── Deploy ──
app.post('/api/deploy', auth,(req,res)=>{
  const {path:p,branch}=req.body;
  if(!p||!path.isAbsolute(p)) return res.status(400).json({error:'Absolute path required'});
  const safeBranch=(branch||'main').replace(/[^a-zA-Z0-9._\/-]/g,'');
  execFile('git',['-C',p,'pull','origin',safeBranch],(err,stdout,stderr)=>{
    res.json({ok:!err, output:stdout||stderr});
  });
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
