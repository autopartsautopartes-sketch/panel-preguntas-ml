const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
// ==================== CONFIG ====================
const CONFIG_PATH = path.join(__dirname, '.env');
const config = {};
try {
  const envContent = fs.readFileSync(CONFIG_PATH, 'utf8');
  envContent.split('\n').forEach(line => {
    const [key, ...vals] = line.split('=');
    if (key && vals.length) config[key.trim()] = vals.join('=').trim();
  });
} catch (e) {}
const PORT = config.PORT || process.env.PORT || 3000;
const BASE_URL = config.BASE_URL || process.env.BASE_URL || `http://localhost:${PORT}`;
const ML_CLIENT_ID = config.ML_CLIENT_ID || process.env.ML_CLIENT_ID;
const ML_CLIENT_SECRET = config.ML_CLIENT_SECRET || process.env.ML_CLIENT_SECRET;
const SESSION_SECRET = config.SESSION_SECRET || process.env.SESSION_SECRET || 'panel-secret-key';
// ==================== DIRECTORIO DE DATOS PERSISTENTE ====================
// Todos los archivos de datos (usuarios, costos, enriquecimiento, ledger, ventas 90d) se guardan acá.
// Por defecto es la carpeta del proyecto (se pierde en cada deploy de Render). Si configurás la env var
// DATA_DIR apuntando a un DISCO PERSISTENTE de Render (ej. /var/data), NUNCA se pierden entre deploys.
const DATA_DIR = config.DATA_DIR || process.env.DATA_DIR || __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}
try { console.log('[DATA] Directorio de datos:', DATA_DIR, DATA_DIR === __dirname ? '(EFÍMERO — configurá DATA_DIR a un disco persistente para no perder datos)' : '(persistente)'); } catch (e) {}
// ==================== PASSWORD HASHING ====================
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === testHash;
}
// ==================== JSON DATABASE (persistent across deploys) ====================
const DB_PATH = path.join(DATA_DIR, 'data.json');
let DB_BACKUP_ENV = process.env.DB_BACKUP; // base64-encoded backup from env var
// Si el respaldo crecio y ya no entra en una env var (limite ~128KB de Render),
// leerlo desde un Secret File. Render los monta en /etc/secrets/<nombre>.
if (!DB_BACKUP_ENV) {
  for (const bp of ['/etc/secrets/db_backup.txt', path.join(__dirname, 'db_backup.txt')]) {
    try {
      const v = fs.readFileSync(bp, 'utf8').trim();
      if (v) { DB_BACKUP_ENV = v; break; }
    } catch (e) {}
  }
}
function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) {
    return null;
  }
}
function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}
// On startup: restore from DB_BACKUP env var if data.json doesn't exist or is empty
let db = loadDB();
if (!db || !db.users || db.users.length === 0) {
  if (DB_BACKUP_ENV) {
    try {
      const restored = JSON.parse(Buffer.from(DB_BACKUP_ENV, 'base64').toString('utf8'));
      if (restored.users && restored.users.length > 0) {
        saveDB(restored);
        db = restored;
        console.log('[STARTUP] Base de datos restaurada desde DB_BACKUP env var (' + restored.users.length + ' usuarios, ' + (restored.ml_accounts || []).length + ' cuentas ML)');
      }
    } catch (e) {
      console.error('[STARTUP] Error restaurando DB_BACKUP:', e.message);
    }
  }
}
if (!db) db = { users: [], ml_accounts: [], nextUserId: 1, nextAccountId: 1 };
// Init admin if no users exist
if (db.users.length === 0) {
  db.users.push({
    id: db.nextUserId++,
    username: 'admin',
    password: hashPassword('admin123'),
    role: 'admin',
    alerts_questions: true,
    alerts_messages: true,
    view_dashboard: true,
    created_at: new Date().toISOString()
  });
  saveDB(db);
  console.log('Usuario admin creado: admin / admin123');
  console.warn('[SEGURIDAD] Estas usando la contraseña por defecto (admin123). Cambiala lo antes posible desde el panel de usuarios.');
} else {
  saveDB(db); // ensure file exists on disk
}
// Migrate existing users: add alert fields if missing
const dbMigrate = loadDB();
let migrated = false;
for (const u of dbMigrate.users) {
  if (u.alerts_questions === undefined) { u.alerts_questions = true; migrated = true; }
  if (u.alerts_messages === undefined) { u.alerts_messages = true; migrated = true; }
  if (u.view_dashboard === undefined) { u.view_dashboard = true; migrated = true; }
}
if (migrated) saveDB(dbMigrate);
// Migrate: add prep permission fields to users
const dbMigrate2 = loadDB();
let migrated2 = false;
for (const u of dbMigrate2.users) {
  if (u.can_prep_manage === undefined) { u.can_prep_manage = false; migrated2 = true; }
  if (u.can_prep_operate === undefined) { u.can_prep_operate = false; migrated2 = true; }
}
if (!dbMigrate2.prep_orders) { dbMigrate2.prep_orders = []; migrated2 = true; }
if (!dbMigrate2.dismissed_msg_packs) { dbMigrate2.dismissed_msg_packs = {}; migrated2 = true; }
if (migrated2) saveDB(dbMigrate2);
// Migrate: add can_view_dashboard field (default false for non-admin, admin always has access)
const dbMigrate3 = loadDB();
let migrated3 = false;
for (const u of dbMigrate3.users) {
  if (u.can_view_dashboard === undefined) { u.can_view_dashboard = false; migrated3 = true; }
}
if (migrated3) saveDB(dbMigrate3);
// Migrate: add section visibility permissions (default true = keeps existing behavior for current users)
const dbMigrate4 = loadDB();
let migrated4 = false;
for (const u of dbMigrate4.users) {
  if (u.can_view_questions === undefined) { u.can_view_questions = true; migrated4 = true; }
  if (u.can_view_messages === undefined) { u.can_view_messages = true; migrated4 = true; }
  if (u.can_view_sales === undefined) { u.can_view_sales = true; migrated4 = true; }
}
if (migrated4) saveDB(dbMigrate4);
// Migrate: add can_search_update permission (default false for non-admin)
const dbMigrate5 = loadDB();
let migrated5 = false;
for (const u of dbMigrate5.users) {
  if (u.can_search_update === undefined) { u.can_search_update = false; migrated5 = true; }
}
if (migrated5) saveDB(dbMigrate5);
// Migrate: add can_bulk_update permission — acceso a descarga/subida de Excel (default false para no-admin)
const dbMigrate6 = loadDB();
let migrated6 = false;
for (const u of dbMigrate6.users) {
  if (u.can_bulk_update === undefined) { u.can_bulk_update = false; migrated6 = true; }
}
if (migrated6) saveDB(dbMigrate6);
// Migrate: add can_view_promos permission — acceso a la sección Promociones (default false para no-admin)
const dbMigrate7 = loadDB();
let migrated7 = false;
for (const u of dbMigrate7.users) {
  if (u.can_view_promos === undefined) { u.can_view_promos = false; migrated7 = true; }
}
if (!dbMigrate7.bulk_completed_jobs) { dbMigrate7.bulk_completed_jobs = []; migrated7 = true; }
if (migrated7) saveDB(dbMigrate7);
// Migrate: add sale_orders array
const dbMigrateOrders = loadDB();
if (!dbMigrateOrders.sale_orders) { dbMigrateOrders.sale_orders = []; saveDB(dbMigrateOrders); }
// Migrate: add can_view_orders permission (default false para no-admin)
const dbMigrate8 = loadDB();
let migrated8 = false;
for (const u of dbMigrate8.users) {
  if (u.can_view_orders === undefined) { u.can_view_orders = false; migrated8 = true; }
}
if (migrated8) saveDB(dbMigrate8);
// ==================== SESSION STORE (persistent) ====================
const SESSIONS_PATH = path.join(DATA_DIR, 'sessions.json');
function loadSessions() {
  try {
    return JSON.parse(fs.readFileSync(SESSIONS_PATH, 'utf8'));
  } catch (e) {
    return {};
  }
}
function saveSessions() {
  try { fs.writeFileSync(SESSIONS_PATH, JSON.stringify(sessions, null, 2)); } catch(e) {}
}
let sessions = loadSessions();
// If sessions.json was empty but DB_BACKUP had sessions, restore them
if (Object.keys(sessions).length === 0 && db.sessions && Object.keys(db.sessions).length > 0) {
  sessions = db.sessions;
  saveSessions();
  console.log(`[STARTUP] Sesiones restauradas desde DB_BACKUP: ${Object.keys(sessions).length}`);
} else {
  console.log(`[STARTUP] Sesiones restauradas: ${Object.keys(sessions).length}`);
}
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}
function getSession(req) {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (sid && sessions[sid]) return sessions[sid];
  return null;
}
// Detect if the request reached us over HTTPS (Render terminates TLS at its
// edge proxy, so we check the standard forwarded-proto header it sets).
function isHttps(req) {
  return req.headers['x-forwarded-proto'] === 'https' || !!req.socket?.encrypted;
}
function createSession(req, res) {
  const sid = generateSessionId();
  sessions[sid] = { created: Date.now() };
  const secureFlag = isHttps(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax${secureFlag}`);
  saveSessions();
  return sessions[sid];
}
function destroySession(req, res) {
  const cookies = parseCookies(req);
  if (cookies.sid) delete sessions[cookies.sid];
  const secureFlag = isHttps(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `sid=; HttpOnly; Path=/; Max-Age=0${secureFlag}`);
  saveSessions();
}
function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [key, ...vals] = c.trim().split('=');
    if (key) cookies[key] = vals.join('=');
  });
  return cookies;
}
// ==================== LOGIN RATE LIMITING (brute force protection) ====================
const loginAttempts = {}; // ip -> { count, firstAttempt, blockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;   // 15 min window to count failed attempts
const BLOCK_DURATION_MS = 15 * 60 * 1000; // 15 min block once exceeded
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}
function checkLoginRateLimit(ip) {
  const entry = loginAttempts[ip];
  if (!entry) return { allowed: true };
  if (entry.blockedUntil) {
    if (Date.now() < entry.blockedUntil) {
      return { allowed: false, retryAfter: Math.ceil((entry.blockedUntil - Date.now()) / 1000) };
    }
    delete loginAttempts[ip];
  }
  return { allowed: true };
}
function recordFailedLogin(ip) {
  const now = Date.now();
  let entry = loginAttempts[ip];
  if (!entry || (now - entry.firstAttempt) > LOGIN_WINDOW_MS) {
    entry = { count: 0, firstAttempt: now };
    loginAttempts[ip] = entry;
  }
  entry.count++;
  if (entry.count >= MAX_LOGIN_ATTEMPTS) {
    entry.blockedUntil = now + BLOCK_DURATION_MS;
    console.log(`[SECURITY] IP bloqueada por intentos de login fallidos: ${ip}`);
  }
}
function recordSuccessfulLogin(ip) {
  delete loginAttempts[ip];
}
// Periodically clean up old rate-limit entries to avoid unbounded memory growth
setInterval(() => {
  const now = Date.now();
  for (const ip of Object.keys(loginAttempts)) {
    const entry = loginAttempts[ip];
    if (entry.blockedUntil && now > entry.blockedUntil) delete loginAttempts[ip];
    else if (!entry.blockedUntil && (now - entry.firstAttempt) > LOGIN_WINDOW_MS) delete loginAttempts[ip];
  }
}, 10 * 60 * 1000);
// ==================== PREP PERMISSION HELPERS ====================
function canPrepManage(sess) {
  if (!sess) return false;
  if (sess.role === 'admin') return true;
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  return user?.can_prep_manage === true;
}
function canPrepOperate(sess) {
  if (!sess) return false;
  if (sess.role === 'admin') return true;
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  return user?.can_prep_operate === true || user?.can_prep_manage === true;
}
// ==================== SECURITY HEADERS ====================
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' https://api.mercadolibre.com; " +
    "manifest-src 'self'; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "frame-ancestors 'none'"
  );
}
// ==================== HTTP HELPERS ====================
async function mlGet(url, token, params = {}, extraHeaders = {}) {
  const qs = new URLSearchParams(params).toString();
  const fullUrl = qs ? `${url}?${qs}` : url;
  const res = await fetch(fullUrl, {
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...extraHeaders }
  });
  const data = await res.json();
  if (!res.ok) throw { response: { data, status: res.status } };
  return data;
}
async function mlPut(url, body, token) {
  const res = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw { response: { data, status: res.status } };
  return data;
}
async function mlPost(url, body, token) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw { response: { data, status: res.status } };
  return data;
}
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}
const MAX_BODY_BYTES = 25 * 1024 * 1024; // 25MB: permite Excel grandes de actualización masiva
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) return;
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
        reject(Object.assign(new Error('Payload demasiado grande'), { statusCode: 413 }));
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (tooLarge) return;
      try { resolve(JSON.parse(body)); } catch (e) { resolve({}); }
    });
    req.on('error', () => {
      if (!tooLarge) resolve({});
    });
  });
}
function requireAuth(req) {
  const sess = getSession(req);
  return sess && sess.userId ? sess : null;
}
// ==================== TOKEN REFRESH ====================
async function refreshToken(account) {
  try {
    const data = await mlPost('https://api.mercadolibre.com/oauth/token', {
      grant_type: 'refresh_token',
      client_id: ML_CLIENT_ID,
      client_secret: ML_CLIENT_SECRET,
      refresh_token: account.refresh_token
    });
    const { access_token, refresh_token, expires_in } = data;
    const expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
    const db = loadDB();
    const acc = db.ml_accounts.find(a => a.id === account.id);
    if (acc) {
      acc.access_token = access_token;
      acc.refresh_token = refresh_token;
      acc.token_expires_at = expiresAt;
      saveDB(db);
    }
    return access_token;
  } catch (err) {
    console.error(`Error refreshing token for ${account.name}:`, err.response?.data || err.message || err);
    return null;
  }
}
async function getValidToken(account) {
  if (new Date(account.token_expires_at) <= new Date()) {
    return await refreshToken(account);
  }
  return account.access_token;
}
// ==================== ROUTE HANDLERS ====================
const routes = {};
function route(method, path, handler) {
  routes[`${method}:${path}`] = handler;
}
// Proxy de imágenes: sirve las miniaturas de MercadoLibre desde NUESTRO dominio.
// Esto evita dos problemas del navegador del usuario: (1) bloqueo de contenido
// mixto (http dentro de página https) y (2) bloqueo del CDN de ML por parte de
// extensiones / ad-blockers. Al servirlas desde 'self' entran siempre.
function imgProxy(u) {
  if (!u) return '';
  const https = String(u).replace(/^http:\/\//i, 'https://');
  return '/img?u=' + encodeURIComponent(https);
}
route('GET', '/img', async (req, res) => {
  let target = '';
  try { target = new URL(req.url, 'http://localhost').searchParams.get('u') || ''; } catch (e) { target = ''; }
  target = target.replace(/^http:\/\//i, 'https://');
  // Seguridad (anti-SSRF): solo permitimos imágenes de dominios de MercadoLibre.
  let host = '';
  try { host = new URL(target).hostname.toLowerCase(); } catch (e) { host = ''; }
  const ok = host && (host.endsWith('mlstatic.com') || host.endsWith('mercadolibre.com') || host.endsWith('mercadolibre.com.ar'));
  if (!ok) { res.writeHead(400); return res.end('bad url'); }
  try {
    const r = await fetch(target);
    if (!r.ok) { res.writeHead(502); return res.end('upstream error'); }
    const ct = r.headers.get('content-type') || 'image/jpeg';
    const buf = Buffer.from(await r.arrayBuffer());
    res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'public, max-age=86400' });
    res.end(buf);
  } catch (e) {
    res.writeHead(502); res.end('fetch failed');
  }
});
// AUTH
// Proxy de librerías JS (XLSX, Chart.js): las servimos desde NUESTRO dominio para que el panel no
// dependa de un CDN externo (que puede caerse o ser bloqueado por el navegador/ad-blocker del usuario).
// El server las baja UNA vez del CDN y las cachea en memoria.
const _vendorCache = {};
async function serveVendor(res, key, url) {
  try {
    if (!_vendorCache[key]) {
      const r = await fetch(url);
      if (!r.ok) throw new Error('cdn ' + r.status);
      _vendorCache[key] = Buffer.from(await r.arrayBuffer());
    }
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=604800' });
    res.end(_vendorCache[key]);
  } catch (e) {
    res.writeHead(502, { 'Content-Type': 'application/javascript' });
    res.end('/* no se pudo cargar la librería: ' + (e.message || 'error') + ' */');
  }
}
route('GET', '/vendor/xlsx.js', async (req, res) => serveVendor(res, 'xlsx', 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js'));
route('GET', '/vendor/chart.js', async (req, res) => serveVendor(res, 'chart', 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js'));
route('POST', '/api/login', async (req, res) => {
  const ip = getClientIp(req);
  const rl = checkLoginRateLimit(ip);
  if (!rl.allowed) {
    res.setHeader('Retry-After', String(rl.retryAfter));
    return sendJSON(res, 429, { error: `Demasiados intentos fallidos. Intenta de nuevo en ${Math.ceil(rl.retryAfter / 60)} minuto(s).` });
  }
  const { username, password } = await parseBody(req);
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !verifyPassword(password, user.password)) {
    recordFailedLogin(ip);
    return sendJSON(res, 401, { error: 'Usuario o contraseña incorrectos' });
  }
  recordSuccessfulLogin(ip);
  const sess = createSession(req, res);
  sess.userId = user.id;
  sess.username = user.username;
  sess.role = user.role;
  sendJSON(res, 200, { username: user.username, role: user.role });
});
route('POST', '/api/logout', async (req, res) => {
  destroySession(req, res);
  sendJSON(res, 200, { ok: true });
});
route('GET', '/api/me', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  const isAdmin = sess.role === 'admin';
  sendJSON(res, 200, {
    username: sess.username, role: sess.role,
    firma: user?.firma || '',
    saludo: db.saludo_inicial ?? 'Hola, Gracias por tu consulta,',
    alerts_questions: user?.alerts_questions ?? true,
    alerts_messages: user?.alerts_messages ?? true,
    view_dashboard: user?.view_dashboard !== false,
    can_view_dashboard: isAdmin || user?.can_view_dashboard === true,
    can_view_questions: isAdmin || user?.can_view_questions !== false,
    can_view_messages: isAdmin || user?.can_view_messages !== false,
    can_view_sales: isAdmin || user?.can_view_sales !== false,
    can_prep_manage: user?.can_prep_manage === true,
    can_prep_operate: user?.can_prep_operate === true,
    can_search_update: isAdmin || user?.can_search_update === true,
    can_bulk_update: isAdmin || user?.can_bulk_update === true,
    can_view_promos: isAdmin || user?.can_view_promos === true,
    can_view_orders: isAdmin || user?.can_view_orders === true
  });
});
// USERS
route('GET', '/api/users', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const db = loadDB();
  sendJSON(res, 200, db.users.map(u => ({
    id: u.id, username: u.username, role: u.role,
    alerts_questions: u.alerts_questions ?? true,
    alerts_messages: u.alerts_messages ?? true,
    view_dashboard: u.view_dashboard !== false,
    can_view_dashboard: u.role === 'admin' || u.can_view_dashboard === true,
    can_view_questions: u.role === 'admin' || u.can_view_questions !== false,
    can_view_messages: u.role === 'admin' || u.can_view_messages !== false,
    can_view_sales: u.role === 'admin' || u.can_view_sales !== false,
    can_prep_manage: u.can_prep_manage === true,
    can_prep_operate: u.can_prep_operate === true,
    can_search_update: u.role === 'admin' || u.can_search_update === true,
    can_bulk_update: u.role === 'admin' || u.can_bulk_update === true,
    can_view_promos: u.role === 'admin' || u.can_view_promos === true,
    can_view_orders: u.role === 'admin' || u.can_view_orders === true,
    created_at: u.created_at
  })));
});
route('POST', '/api/users/alerts', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { id, alerts_questions, alerts_messages, view_dashboard, can_view_dashboard, can_view_questions, can_view_messages, can_view_sales, can_prep_manage, can_prep_operate, can_search_update, can_bulk_update, can_view_promos, can_view_orders } = await parseBody(req);
  const db = loadDB();
  const user = db.users.find(u => u.id === parseInt(id));
  if (!user) return sendJSON(res, 404, { error: 'Usuario no encontrado' });
  if (alerts_questions !== undefined) user.alerts_questions = !!alerts_questions;
  if (alerts_messages !== undefined) user.alerts_messages = !!alerts_messages;
  if (view_dashboard !== undefined) user.view_dashboard = !!view_dashboard;
  if (can_view_dashboard !== undefined) user.can_view_dashboard = !!can_view_dashboard;
  if (can_view_questions !== undefined) user.can_view_questions = !!can_view_questions;
  if (can_view_messages !== undefined) user.can_view_messages = !!can_view_messages;
  if (can_view_sales !== undefined) user.can_view_sales = !!can_view_sales;
  if (can_prep_manage !== undefined) user.can_prep_manage = !!can_prep_manage;
  if (can_prep_operate !== undefined) user.can_prep_operate = !!can_prep_operate;
  if (can_search_update !== undefined) user.can_search_update = !!can_search_update;
  if (can_bulk_update !== undefined) user.can_bulk_update = !!can_bulk_update;
  if (can_view_promos !== undefined) user.can_view_promos = !!can_view_promos;
  if (can_view_orders !== undefined) user.can_view_orders = !!can_view_orders;
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
route('POST', '/api/users/password', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Solo el administrador puede cambiar contraseñas' });
  const { id, new_password } = await parseBody(req);
  if (!new_password || new_password.length < 4) return sendJSON(res, 400, { error: 'La contraseña debe tener al menos 4 caracteres' });
  const db = loadDB();
  const targetUser = id ? db.users.find(u => u.id === parseInt(id)) : db.users.find(u => u.id === sess.userId);
  if (!targetUser) return sendJSON(res, 404, { error: 'Usuario no encontrado' });
  targetUser.password = hashPassword(new_password);
  saveDB(db);
  console.log(`[PASS] Contraseña cambiada: usuario "${targetUser.username}" por admin "${sess.username}"`);
  sendJSON(res, 200, { ok: true });
});
// Resuelve el user_product_id de una publicacion multiorigen (stock en deposito).
// OJO: el GET "pelado" de /items y la lista corta ?attributes=id,user_product_id
// NO devuelven user_product_id de forma confiable. Hay que pedirlo con la MISMA
// lista de atributos que usa /api/debug-item (verificada en vivo: devuelve el
// campo). Si la publicacion tiene variaciones, el id vive dentro de cada una.
async function resolveUpid(itemId, token) {
  try {
    const it = await mlGet(`https://api.mercadolibre.com/items/${itemId}?attributes=id,catalog_product_id,catalog_listing,domain_id,user_product_id,inventory_id,seller_custom_field,status,attributes,variations`, token);
    if (it && it.user_product_id) return it.user_product_id;
    if (it && Array.isArray(it.variations)) {
      const v = it.variations.find(v => v && v.user_product_id);
      if (v) return v.user_product_id;
    }
  } catch (e) {}
  return null;
}
// Stock por deposito (multiorigen / user_products): el stock de estos items NO va por /items
// (devuelve item.available_quantity.not_updatable). Se actualiza con
//   PUT /user-products/{upid}/stock/type/{type}
//   body: {"locations":[{"store_id":..,"quantity":N}]}
//   header X-Version: <numero que devuelve el GET /user-products/{upid}/stock>
// Devuelve null si OK, o un string con el error.
async function putUserProductStock(upid, qty, account) {
  const stockUrl = `https://api.mercadolibre.com/user-products/${upid}/stock`;
  let token = await getValidToken(account);
  async function leerStock() {
    const g = await fetch(stockUrl, { headers: { Authorization: `Bearer ${token}` } });
    const xv = g.headers.get('x-version');
    const t = await g.text();
    let d = {}; try { d = t ? JSON.parse(t) : {}; } catch (e) {}
    return { xver: xv, loc: (d.locations || [])[0] || {} };
  }
  let xver = null, loc = {};
  try { const s = await leerStock(); xver = s.xver; loc = s.loc; } catch (e) {}
  const type = loc.type || 'seller_warehouse';
  const url = `${stockUrl}/type/${type}`;
  const location = { quantity: qty };
  if (loc.store_id != null) location.store_id = loc.store_id;
  if (loc.network_node_id != null) location.network_node_id = loc.network_node_id;
  const body = { locations: [location] };
  for (let attempt = 0; attempt < 4; attempt++) {
    const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
    if (xver != null) headers['X-Version'] = String(xver);
    let r;
    try { r = await fetch(url, { method: 'PUT', headers, body: JSON.stringify(body) }); }
    catch (e) { if (attempt === 3) return String(e.message || e); await new Promise(rr => setTimeout(rr, 1500)); continue; }
    if (r.ok) return null;
    const text = await r.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { raw: text }; }
    if (r.status === 401) { const rf = await refreshToken(account); if (rf) { token = rf; continue; } return 'token expirado'; }
    if (r.status === 429) { await new Promise(rr => setTimeout(rr, [15000, 35000, 70000, 120000][attempt] || 120000)); continue; }
    const msg = String((data && (data.message || data.error)) || '').toLowerCase();
    if (r.status === 409 || msg.includes('version')) { try { const s2 = await leerStock(); xver = s2.xver; } catch (e) {} continue; }
    return (data && (data.message || data.error)) || `stock HTTP ${r.status}`;
  }
  return 'stock: agotados los reintentos';
}
// Helper: build ML item update payload from row data (excluye flex — se maneja por separado)
function buildItemPayload(item) {
  const payload = {};
  if (item.available_quantity !== '' && item.available_quantity != null) {
    const qty = parseInt(item.available_quantity);
    if (!isNaN(qty)) payload.available_quantity = qty;
  }
  const _st = String(item.status == null ? '' : item.status).trim().toLowerCase();
  if (_st === 'active' || _st === 'paused') payload.status = _st;
  if (item.price !== '' && item.price != null) {
    const p = parseFloat(item.price);
    if (!isNaN(p)) payload.price = p;
  }
  const attrs = [];
  if (item.item_sku !== '' && item.item_sku != null) {
    payload.seller_custom_field = String(item.item_sku);
    attrs.push({ id: 'SELLER_SKU', value_name: String(item.item_sku) }); // que ML lo muestre en la pagina
  }
  if (item.marca !== '' && item.marca != null) attrs.push({ id: 'BRAND', value_name: item.marca });
  if (attrs.length) payload.attributes = attrs;
  return payload;
}
// Helper: activar/desactivar flex via PUT /items/{id} con logistic_type
// self_service = flex activado | not_specified = flex desactivado
async function updateFlexForItem(itemId, flexStr, token) {
  const enable = ['si', 'sí', 'yes', 'true', '1'].includes(flexStr);
  const disable = ['no', 'false', '0'].includes(flexStr);
  if (!enable && !disable) return null;
  const payload = {
    shipping: {
      logistic_type: enable ? 'self_service' : 'not_specified'
    }
  };
  const url = `https://api.mercadolibre.com/items/${itemId}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });
  if (res.status === 200) return null; // ok
  let rawText = '';
  try { rawText = await res.text(); } catch(e) {}
  console.log(`[FLEX ERROR] ${itemId} HTTP ${res.status}: ${rawText}`);
  let errMsg = `flex HTTP ${res.status}`;
  try {
    const d = JSON.parse(rawText);
    errMsg = d.message || d.error || d.cause?.[0]?.description || errMsg;
  } catch(e) {
    if (rawText) errMsg = `flex ${res.status}: ${rawText.slice(0, 100)}`;
  }
  return errMsg;
}
// ==================== PROMO SAFETY BEFORE ITEM UPDATE ====================
// ML no permite modificar algunos campos cuando la publicación participa en promociones.
// Antes de actualizar una publicación, buscamos promociones activas y las removemos.
// Si no hay promociones activas o ML no devuelve datos, continúa normalmente.
//
// SERIALIZACIÓN POR CAMPAÑA: cuando muchas publicaciones comparten la MISMA campaña
// (ej. "TOTAL_MARA0807") y se las saca en paralelo, la API de ML (Fury/KVS) devuelve
// 409 Conflict porque el objeto campaña se muta concurrentemente. Para evitarlo,
// serializamos las bajas de una misma promotion_id: solo una baja en vuelo por campaña.
// Campañas distintas siguen en paralelo, y los updates de precio también. Así escala
// a miles de ítems sin conflictos y sin pausar nada a mano.
const _promoLockTails = new Map(); // promotionId -> Promise (cola de la cadena)
async function withPromoLock(key, fn) {
  const prev = _promoLockTails.get(key) || Promise.resolve();
  let releaseFn;
  const gate = new Promise(r => { releaseFn = r; });
  const mine = prev.then(() => gate);
  _promoLockTails.set(key, mine);
  await prev.catch(() => {});      // espera el turno (que termine la baja anterior de esta campaña)
  try {
    return await fn();
  } finally {
    releaseFn();                    // libera al siguiente
    if (_promoLockTails.get(key) === mine) _promoLockTails.delete(key); // limpia cuando queda ociosa
  }
}
function normalizePromoListForItem(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.results)) return raw.results;
  if (Array.isArray(raw.promotions)) return raw.promotions;
  if (Array.isArray(raw.data)) return raw.data;
  if (Array.isArray(raw.items)) return raw.items;
  return [];
}
function promoValueId(p) {
  return String(p?.id || p?.promotion_id || p?.offer_id || p?.campaign_id || '');
}
function promoValueType(p) {
  return String(p?.type || p?.promotion_type || p?.offer_type || '');
}
function isPromoCurrentlyBlocking(p) {
  const st = String(p?.status || p?.promotion_status || p?.state || '').toUpperCase();
  // ACTIVE/STARTED son los más comunes. CANDIDATE puede bloquear según campaña.
  // Evitamos borrar estados claramente terminados/inactivos.
  if (['FINISHED', 'INACTIVE', 'DELETED', 'CANCELLED', 'EXPIRED'].includes(st)) return false;
  return true;
}
async function getActivePromotionsForItemBeforeUpdate(itemId, account, token) {
  const appTok = await getAppToken().catch(() => null);
  const candidates = [
    {
      label: 'old_user_v2',
      url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=v2`,
      token,
      headers: {}
    },
    {
      label: 'old_user_2_0_0',
      url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=2.0.0`,
      token,
      headers: {}
    },
    {
      label: 'marketplace_user_v2',
      url: `${PROMO_BASE}/items/${itemId}?user_id=${account.seller_id}`,
      token,
      headers: promoH()
    },
    {
      label: 'marketplace_app_v2',
      url: `${PROMO_BASE}/items/${itemId}?user_id=${account.seller_id}`,
      token: appTok,
      headers: promoH()
    }
  ];
  const errors = [];
  for (const c of candidates) {
    if (!c.token) continue;
    try {
      const raw = await mlGet(c.url, c.token, {}, c.headers);
      const arr = normalizePromoListForItem(raw).filter(p => promoValueId(p) && promoValueType(p) && isPromoCurrentlyBlocking(p));
      return { promos: arr, source: c.label, errors };
    } catch(e) {
      errors.push({
        tried: c.label,
        status: e?.response?.status || null,
        error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
      });
    }
  }
  return { promos: [], source: null, errors };
}
async function removePromotionFromItemBeforeUpdate(itemId, account, token, promo) {
  const promotionId = promoValueId(promo);
  const promotionType = promoValueType(promo);
  if (!promotionId || !promotionType) return { ok: false, error: 'Promoción sin id/type' };
  const appTok = await getAppToken().catch(() => null);
  const body = { promotion_id: promotionId, promotion_type: promotionType };
  const userQ = `user_id=${account.seller_id}`;
  const candidates = [
    {
      label: 'marketplace_user_v2',
      url: `${PROMO_BASE}/items/${itemId}?${userQ}`,
      token,
      headers: { 'Content-Type': 'application/json', ...promoH() },
      body
    },
    {
      label: 'marketplace_app_v2',
      url: `${PROMO_BASE}/items/${itemId}?${userQ}`,
      token: appTok,
      headers: { 'Content-Type': 'application/json', ...promoH() },
      body
    },
    {
      label: 'old_user_v2',
      url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=v2`,
      token,
      headers: { 'Content-Type': 'application/json' },
      body
    },
    {
      label: 'old_user_2_0_0',
      url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=2.0.0`,
      token,
      headers: { 'Content-Type': 'application/json' },
      body
    }
  ];
  // Serializamos por campaña: una sola baja en vuelo por promotion_id (evita 409).
  return await withPromoLock(promotionId, async () => {
  const errors = [];
  const _sleep = ms => new Promise(r => setTimeout(r, ms));
  for (const c of candidates) {
    if (!c.token) continue;
    // Reintento por candidato ante conflictos transitorios (409 Fury/KVS) o rate limit,
    // que aparecen cuando varias publicaciones se sacan de la MISMA campaña a la vez.
    let lastStatus = null, lastErrTxt = '';
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        const r = await fetch(c.url, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${c.token}`, ...c.headers },
          body: JSON.stringify(c.body)
        });
        const text = await r.text().catch(() => '');
        let data = {};
        try { data = text ? JSON.parse(text) : {}; } catch(e) { data = { raw: text }; }
        if (r.ok || r.status === 204 || r.status === 404) {
          return { ok: true, removed: promotionId, type: promotionType, via: c.label, response: data };
        }
        lastStatus = r.status;
        lastErrTxt = data.message || data.error || text.slice(0, 200);
        if (r.status === 409 || r.status === 429 || r.status >= 500) {
          await _sleep([1500, 4000, 9000, 15000][attempt] + Math.floor(Math.random() * 2500));
          continue; // reintenta el MISMO endpoint
        }
        break; // otro error (400/403/etc.) -> probamos el siguiente candidato
      } catch(e) {
        lastErrTxt = e.message || String(e);
        await _sleep(1500 + Math.floor(Math.random() * 2000));
      }
    }
    errors.push({ tried: c.label, status: lastStatus, error: lastErrTxt });
  }
  return { ok: false, removed: promotionId, type: promotionType, error: errors.map(e => `${e.tried}: ${e.status || ''} ${e.error}`).join(' | ') };
  });
}
async function removeActivePromotionsBeforeItemUpdate(itemId, account, token) {
  const found = await getActivePromotionsForItemBeforeUpdate(itemId, account, token);
  const promos = found.promos || [];
  if (!promos.length) return { ok: true, removed: [], source: found.source, errors: found.errors };
  const removed = [];
  const errors = [];
  for (const promo of promos) {
    const r = await removePromotionFromItemBeforeUpdate(itemId, account, token, promo);
    if (r.ok) removed.push(r);
    else errors.push(r);
  }
  return {
    ok: errors.length === 0,
    source: found.source,
    removed,
    errors
  };
}
// ==================== BACKGROUND JOB STORE (bulk update — opción 4) ====================
const bulkJobs = {};
const BULK_JOB_TTL = 8 * 60 * 60 * 1000; // 8 horas
function cleanBulkJobs() {
  const cutoff = Date.now() - BULK_JOB_TTL;
  for (const id of Object.keys(bulkJobs)) {
    if (bulkJobs[id].created < cutoff) delete bulkJobs[id];
  }
}
async function runBulkJob(jobId, items, account, initialToken) {
  const job = bulkJobs[jobId];
  if (!job) return;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let token = initialToken;
  // Motor v2: cola + workers + rate limit adaptativo.
  // Objetivo: ir más rápido que el modo secuencial sin volver al método viejo de 10 paralelas que genera too_many_requests.
  const MIN_WORKERS = 2;
  const START_WORKERS = 3;
  const MAX_WORKERS = 5;
  let desiredWorkers = START_WORKERS;
  let globalCooldownUntil = 0;
  let successSince429 = 0;
  const SPEEDUP_EVERY = 300;
  const ERROR_ITEMS_MAX = 800;
  // Umbral de envío gratis obligatorio de ML (MLA). Se usa para mandar envío gratis en el
  // PRIMER PUT de los ítems por encima del umbral (ver updateOne → "envío gratis por adelantado").
  // Configurable por env por si ML cambia el valor; el fallback reactivo queda de backstop.
  const UMBRAL_ENVIO_GRATIS = Number(process.env.UMBRAL_ENVIO || 33000) || 33000;
  job.mode = 'smart_workers_v2';
  job.min_workers = MIN_WORKERS;
  job.max_workers = MAX_WORKERS;
  job.desired_workers = desiredWorkers;
  job.active_workers = 0;
  job.rate_limits = 0;
  job.retries = 0;
  job.promotions_removed = 0;
  job.promo_retry_ok = 0;
  job.started_at = Date.now();
  job.velocity = 0;
  function mark429(waitMs) {
    job.rate_limits = (job.rate_limits || 0) + 1;
    desiredWorkers = Math.max(MIN_WORKERS, desiredWorkers - 1);
    job.desired_workers = desiredWorkers;
    job.last_429_at = new Date().toISOString();
    globalCooldownUntil = Math.max(globalCooldownUntil, Date.now() + waitMs);
    successSince429 = 0;
    console.log(`[BG-BULK-v2] 429 detectado — workers => ${desiredWorkers}, cooldown ${waitMs}ms`);
  }
  function markSuccess() {
    successSince429++;
    if (successSince429 >= SPEEDUP_EVERY && desiredWorkers < MAX_WORKERS) {
      desiredWorkers++;
      job.desired_workers = desiredWorkers;
      successSince429 = 0;
      console.log(`[BG-BULK-v2] ${SPEEDUP_EVERY} éxitos sin 429 — workers => ${desiredWorkers}`);
    }
  }
  function parseMLError(e) {
    const data = e?.response?.data || {};
    const cause = data.cause;
    const causeDetail = Array.isArray(cause) && cause.length
      ? cause.map(c => c.description || c.code || JSON.stringify(c)).join('; ')
      : null;
    return causeDetail || data.message || data.error || e?.message || 'Error al actualizar';
  }
  function isPromoBlockingError(errMsg, status) {
    const s = String(errMsg || '').toLowerCase();
    return status === 400 && (
      s.includes('promotion') ||
      s.includes('promoción') ||
      s.includes('promocion') ||
      s.includes('campaign') ||
      s.includes('campaña') ||
      s.includes('offer') ||
      s.includes('deal') ||
      s.includes('participa') ||
      s.includes('belongs to') ||
      s.includes('cannot update price') ||
      s.includes('price is locked')
    );
  }
  async function putWithRetry(url, payload, workerId) {
    let lastErr;
    for (let attempt = 0; attempt < 4; attempt++) {
      if (job.cancelled) throw Object.assign(new Error('Cancelado'), { _cancelled: true });
      const waitGlobal = globalCooldownUntil - Date.now();
      if (waitGlobal > 0) await sleep(waitGlobal);
      try {
        if (attempt > 0) job.retries = (job.retries || 0) + 1;
        return await mlPut(url, payload, token);
      } catch(e) {
        lastErr = e;
        const status = e?.response?.status;
        if (status === 401) {
          const refreshed = await refreshToken(account);
          if (!refreshed) throw Object.assign(new Error('Token expirado, reconectá la cuenta ML desde Configuración → Cuentas'), { response: { status: 401, data: {} } });
          token = refreshed;
          continue;
        }
        if (status === 429) {
          const wait = [15000, 35000, 70000, 120000][attempt] || 120000;
          mark429(wait);
          await sleep(wait);
          continue;
        }
        if (status === 409) {
          // Conflicto transitorio de ML (Fury/KVS 409). Pasa cuando recién sacamos
          // la publicación de una campaña y su registro sigue procesándose, o cuando
          // varios workers tocan la misma campaña a la vez. Reintentamos con backoff
          // + jitter para no volver a chocar en paralelo.
          job.conflicts_409 = (job.conflicts_409 || 0) + 1;
          const base = [1500, 4000, 9000, 15000][attempt] || 15000;
          const jitter = Math.floor(Math.random() * 2500);
          await sleep(base + jitter);
          continue;
        }
        throw e;
      }
    }
    throw lastErr;
  }
  async function flexWithRetry(itemId, flexStr, workerId) {
    let lastErr = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      if (job.cancelled) throw Object.assign(new Error('Cancelado'), { _cancelled: true });
      const waitGlobal = globalCooldownUntil - Date.now();
      if (waitGlobal > 0) await sleep(waitGlobal);
      const err = await updateFlexForItem(itemId, flexStr, token);
      if (!err) return null;
      lastErr = err;
      if (String(err).includes('429') || String(err).toLowerCase().includes('too_many_requests')) {
        const wait = [15000, 35000, 70000][attempt] || 70000;
        mark429(wait);
        await sleep(wait);
        continue;
      }
      return err;
    }
    return lastErr || 'Error flex';
  }
  // Stock por deposito (multiorigen / user_products): el stock NO se actualiza por /items,
  // sino por PUT /user-products/{upid}/stock/type/seller_warehouse con body {quantity}.
  async function updateDepositStock(upid, qty, workerId) {
    if (job.cancelled) throw Object.assign(new Error('Cancelado'), { _cancelled: true });
    return await putUserProductStock(upid, qty, account);
  }
  async function updateOne(item, workerId) {
    if (!item.item_id) return { item_id: '?', ok: false, error: 'Sin item_id' };
    const payload = buildItemPayload(item);
    const cur = currentState[item.item_id];
    // Precio objetivo (para verificar despues que ML lo haya aplicado). Lo guardamos ACA,
    // antes de que el bloque de variaciones lo mueva/borre del payload.
    const _targetPrice = (payload.price != null && payload.price !== '') ? Number(payload.price) : null;
    const _isVariation = !!(cur?.variation_ids?.length);
    // Para ítems con variaciones, ML no acepta price ni available_quantity a nivel raíz.
    // Hay que mandarlos dentro de cada variante: variations: [{id, price, available_quantity}]
    if (cur?.variation_ids?.length) {
      const hasQty   = payload.available_quantity !== undefined;
      const hasPrice = payload.price !== undefined;
      if (hasQty || hasPrice) {
        const qty   = payload.available_quantity;
        const price = payload.price;
        delete payload.available_quantity;
        delete payload.price;
        payload.variations = cur.variation_ids.map(id => {
          const v = { id };
          if (hasQty)   v.available_quantity = qty;
          if (hasPrice) v.price = price;
          return v;
        });
      }
    }
    const flexStr = String(item.flex ?? '').toLowerCase().trim();
    const hasFlex = item.flex !== '' && item.flex != null &&
      ['si','sí','yes','true','1','no','false','0'].includes(flexStr);
    if (!Object.keys(payload).length && !hasFlex) {
      return { item_id: item.item_id, ok: true, warning: 'Sin cambios — se omitió' };
    }
    const warnings = [];
    // FASE A — envío gratis POR ADELANTADO (ahorra 1 llamada por ítem sobre el umbral).
    // Un ítem Mercado Envío (me2) SIN envío gratis cuyo precio nuevo cruza el umbral es
    // rechazado por ML en el primer PUT (mandatory_free_shipping/lost_me1) y recién el
    // fallback lo reintenta con envío gratis => 2 PUTs. Acá lo mandamos ya en el PRIMER PUT.
    // Conservador: solo ítems me2 que NO son flex (self_service) y que hoy no tienen envío
    // gratis. Los flex y cualquier caso raro quedan para el fallback reactivo (backstop).
    if (_targetPrice != null && _targetPrice >= UMBRAL_ENVIO_GRATIS && !hasFlex && cur &&
        String(cur.ship_mode || '').toLowerCase() === 'me2' &&
        String(cur.logistic_type || '').toLowerCase() !== 'self_service' &&
        cur.ship_free !== true) {
      payload.shipping = Object.assign({ mode: 'me2', free_shipping: true }, payload.shipping || {});
      job.freeship_upfront = (job.freeship_upfront || 0) + 1;
    }
    async function attemptUpdateOnce() {
      const errors = [];
      if (Object.keys(payload).length) {
        try {
          await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, payload, workerId);
        } catch(e) {
          if (e._cancelled) throw e;
          const msg = parseMLError(e);
          errors.push({ kind: 'payload', status: e?.response?.status || null, message: msg });
        }
      }
      if (!errors.length && hasFlex) {
        const flexErr = await flexWithRetry(item.item_id, flexStr, workerId);
        if (flexErr) errors.push({ kind: 'flex', status: String(flexErr).includes('429') ? 429 : null, message: flexErr });
      }
      return errors;
    }
    // Fallback SKU repetido: ML agrupa por SELLER_SKU en "user products" y rechaza
    // (user_product.repeated.conflict) cuando dos publicaciones comparten el mismo codigo.
    // Reintentamos sin el atributo SELLER_SKU (y si aun choca, sin seller_custom_field).
    async function trySkuConflictFallback(errs) {
      if (!errs.some(e => /repeated.*conflict|user_product\.repeated/i.test(String(e.message)))) return null;
      // Causa real: al mandar ATRIBUTOS (SELLER_SKU), ML intenta enlazar el item a un
      // user_product por GTIN/catálogo. Si otra publicación ya tiene ese GTIN -> repeated.conflict.
      // No se arregla cambiando el SKU (el GTIN no cambia). Reintentamos SIN atributos:
      // precio/stock/estado/seller_custom_field igual se actualizan.
      const hadAttrs = payload.attributes !== undefined;
      const hadScf = payload.seller_custom_field !== undefined;
      if (!hadAttrs && !hadScf) return null;
      delete payload.attributes;
      let err1 = null;
      if (Object.keys(payload).length) {
        try {
          await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, payload, workerId);
          return { item_id: item.item_id, ok: true, warning: 'SKU no sincronizado en ML (catálogo/GTIN repetido)' };
        } catch (e) { if (e._cancelled) throw e; err1 = parseMLError(e); }
      }
      // si aún choca, sacamos también el seller_custom_field (solo precio/stock/estado)
      if (hadScf) {
        delete payload.seller_custom_field;
        if (Object.keys(payload).length) {
          try {
            await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, payload, workerId);
            return { item_id: item.item_id, ok: true, warning: 'SKU no actualizado (catálogo/GTIN repetido)' };
          } catch (e2) { if (e2._cancelled) throw e2; return { item_id: item.item_id, ok: false, error: `sinAttr:[${err1 || ''}] sinScf:[${parseMLError(e2)}]` }; }
        }
      }
      return { item_id: item.item_id, ok: false, error: `sinAttr:[${err1 || 'payload vacío'}]` };
    }
    // Fallback de stock por deposito: SOLO cuando ML rechaza el stock por /items con not_updatable.
    // Las cuentas con stock tradicional nunca entran acá; solo los items multiorigen (ej. ANTO).
    async function tryDepositFallback(errs) {
      const stockBlocked = errs.some(e => /available_quantity\.not_updatable/i.test(String(e.message)));
      if (!stockBlocked) return null;
      const wantedQty = (item.available_quantity !== '' && item.available_quantity != null) ? parseInt(item.available_quantity) : null;
      // sacamos el stock del payload y reintentamos el resto (precio/status/sku) por /items
      delete payload.available_quantity;
      if (Array.isArray(payload.variations)) {
        payload.variations = payload.variations.map(v => { const c = { ...v }; delete c.available_quantity; return c; });
        if (payload.variations.every(v => Object.keys(v).length <= 1)) delete payload.variations;
      }
      // Resto por /items (precio/status/sku/attrs). Si ML rechaza los atributos, reintento sin ellos.
      let itemErr = null;
      if (Object.keys(payload).length) {
        try { await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, payload, workerId); }
        catch (e) {
          if (e._cancelled) throw e;
          const m = parseMLError(e);
          if (/attributes\.(invalid|duplicated)|repeated.*conflict|user_product\.repeated/i.test(String(m)) && payload.attributes !== undefined) {
            delete payload.attributes;
            if (Object.keys(payload).length) {
              try { await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, payload, workerId); }
              catch (e2) { if (e2._cancelled) throw e2; itemErr = parseMLError(e2); }
            }
          } else { itemErr = m; }
        }
      }
      // el pre-fetch (y la consulta acotada) no traen user_product_id -> lo resolvemos
      // con la lista de atributos explicita que si lo devuelve (ver resolveUpid)
      let upid = cur?.user_product_id || null;
      if (!upid) upid = await resolveUpid(item.item_id, token);
      let depErr = null;
      if (upid && wantedQty != null && !isNaN(wantedQty)) {
        depErr = await updateDepositStock(upid, wantedQty, workerId);
      } else if (wantedQty != null && !isNaN(wantedQty)) {
        depErr = 'no se pudo obtener user_product_id para el stock';
      }
      if (!itemErr && !depErr) return { item_id: item.item_id, ok: true, warning: 'stock por depósito' };
      const parts = [];
      if (itemErr) parts.push(itemErr);
      if (depErr) parts.push('stock depósito: ' + depErr);
      return { item_id: item.item_id, ok: false, error: parts.join(' | ') };
    }
    // Lee el precio actual del item en ML y confirma si quedo aplicado (piso a entero).
    // Devuelve true si coincide o si no se pudo leer (para no bloquear por un error de lectura).
    async function verifyPriceApplied(itemId, target, isVar) {
      try {
        const it = await mlGet(`https://api.mercadolibre.com/items/${itemId}`, token, { attributes: 'price,variations' });
        const tgt = Math.floor(Number(target));
        if (!isFinite(tgt)) return true;
        // Ítems con variaciones: el precio vive dentro de cada variante, no en la raíz.
        // Consideramos aplicado si TODAS las variantes con precio legible coinciden con el objetivo.
        if (isVar && Array.isArray(it.variations) && it.variations.length) {
          const prices = it.variations.map(v => Number(v.price)).filter(p => isFinite(p));
          if (!prices.length) {
            const rp = Number(it.price);
            return !isFinite(rp) || Math.floor(rp) === tgt;
          }
          return prices.every(p => Math.floor(p) === tgt);
        }
        const curP = Number(it && it.price);
        if (!isFinite(curP)) return true;
        return Math.floor(curP) === tgt;
      } catch (e) { return true; }
    }
    // Intenta actualizar y, si hubo cambio de precio, VERIFICA que ML lo haya aplicado de verdad.
    // Si ML devolvio OK pero el precio no cambio (falla silenciosa por promocion), lo marcamos
    // como bloqueo de promo para que el flujo de abajo saque la promo y reintente.
    async function attemptWithVerify() {
      let errs = await attemptUpdateOnce();
      // Verificamos SIEMPRE que haya cambio de precio, tanto en ítems simples como con
      // variaciones. Si ML devolvió OK pero el precio no quedó (falla silenciosa por promo
      // activa), lo marcamos como bloqueo de promo para que el flujo saque la promo y reintente.
      if (!errs.length && _targetPrice != null) {
        const aplicado = await verifyPriceApplied(item.item_id, _targetPrice, _isVariation);
        if (!aplicado) {
          errs = [{ kind: 'promo-silent', status: 400, message: 'promotion: el precio no quedo aplicado (probable promo activa)' }];
        }
      }
      return errs;
    }
    // Fallback envío/atributos: ML rechaza el update cuando el precio nuevo cruza el
    // umbral de envío gratis (mandatory_free_shipping / lost_me1) — el motor YA calculó
    // ese precio CON el costo de envío incluido, así que activar envío gratis es lo correcto.
    // También reintenta SIN atributos cuando la marca es inválida/duplicada. Manda solo
    // precio (en variaciones si corresponde) + stock + estado, sin atributos.
    async function tryShippingAttrsFallback(errs) {
      const msgs = errs.map(e => String(e.message || ''));
      const needFreeShip = msgs.some(m => /mandatory_free_shipping|lost_me1|lost_me2|shipping\.(lost|default)/i.test(m));
      const attrsBad = msgs.some(m => /attributes\.(invalid|duplicated)/i.test(m));
      const priceDropped = msgs.some(m => /item\.price\.dropped/i.test(m));
      if (!needFreeShip && !attrsBad && !priceDropped) return null;
      const clean = {};
      const st = String(item.status == null ? '' : item.status).trim().toLowerCase();
      if (st === 'active' || st === 'paused') clean.status = st;
      const qty = (item.available_quantity !== '' && item.available_quantity != null) ? parseInt(item.available_quantity) : null;
      const price = (item.price !== '' && item.price != null) ? parseFloat(item.price) : null;
      const isVar = !!(cur?.variation_ids?.length);
      if (isVar) {
        clean.variations = cur.variation_ids.map(id => {
          const v = { id };
          if (price != null && !isNaN(price)) v.price = price;
          if (qty != null && !isNaN(qty)) v.available_quantity = qty;
          return v;
        });
      } else {
        if (price != null && !isNaN(price)) clean.price = price;
        if (qty != null && !isNaN(qty)) clean.available_quantity = qty;
      }
      // Envío gratis SOLO si ML lo exige (precio sobre umbral en ítem con Mercado Envío).
      if (needFreeShip) clean.shipping = { mode: 'me2', free_shipping: true };
      // A propósito: NO mandamos attributes ni seller_custom_field (la marca inválida es lo que rompe).
      const hasBody = !!clean.variations || clean.price != null || clean.available_quantity != null || clean.status != null || clean.shipping != null;
      if (!hasBody) return null;
      try {
        await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, clean, workerId);
        // Verificar que el precio realmente haya quedado aplicado (no una FALSA OK por promo
        // que sigue tapando el precio). Si no quedó, lo reportamos como error para que se
        // reintente en la próxima corrida en vez de darlo por bueno.
        if (_targetPrice != null) {
          const okPrice = await verifyPriceApplied(item.item_id, _targetPrice, isVar);
          if (!okPrice) {
            return { item_id: item.item_id, ok: false, error: 'precio no aplicado tras activar envío gratis (probable promo activa) — se reintenta en la próxima corrida' };
          }
        }
        const notes = [];
        if (needFreeShip) notes.push('envío gratis activado (precio sobre umbral)');
        if (attrsBad) notes.push('atributos/marca omitidos (inválidos)');
        if (warnings.length) notes.unshift(...warnings);
        return { item_id: item.item_id, ok: true, warning: notes.join(' | ') };
      } catch (e) {
        if (e._cancelled) throw e;
        // si aún falla por stock de depósito, dejamos que el mensaje real quede registrado
        return { item_id: item.item_id, ok: false, error: parseMLError(e) };
      }
    }
    // 0) PROACTIVO: si hay un cambio de precio, primero miramos si la publicación
    //    tiene una promo/campaña ACTIVA (status "started") que pisa el precio.
    //    Mientras esa promo esté aplicada, ML NO muestra el precio nuevo (lo tapa con
    //    el descuento de la campaña). Por eso la sacamos ANTES de actualizar el precio,
    //    y después vos volvés a aplicar tus promos nuevas.
    //    Solo tocamos las que están APLICADAS (started/active); las "candidate"
    //    (ofrecidas pero no aplicadas) NO se tocan. Controlado por job.remove_promos_before
    //    (default: ON). Si falla la detección, seguimos: el flujo reactivo queda de backstop.
    async function removeAppliedPromosProactive() {
      if (job.remove_promos_before === false) return;
      if (_targetPrice == null) return; // solo cuando cambia el precio
      try {
        const found = await getActivePromotionsForItemBeforeUpdate(item.item_id, account, token);
        const applied = (found.promos || []).filter(p => {
          const st = String(p?.status || p?.promotion_status || p?.state || '').toLowerCase();
          return st === 'started' || st === 'active' || st === 'running' || st === 'on' || st === 'ongoing';
        });
        if (!applied.length) return;
        const removedList = [];
        const failList = [];
        for (const promo of applied) {
          const r = await removePromotionFromItemBeforeUpdate(item.item_id, account, token, promo);
          if (r.ok) removedList.push(`${r.removed}/${r.type}`);
          else failList.push(`${promoValueId(promo)}/${promoValueType(promo)}: ${r.error || 'no se pudo'}`);
        }
        if (removedList.length) {
          job.promotions_removed = (job.promotions_removed || 0) + removedList.length;
          warnings.push(`Promo activa removida antes de actualizar: ${removedList.join(', ')}`);
          // Pausa breve SOLO cuando sacamos una promo: ML necesita un instante para
          // reprocesar la publicación; si hacemos el PUT de precio pegado, devuelve 409.
          await sleep(1800 + Math.floor(Math.random() * 1200));
        }
        if (failList.length) warnings.push(`No se pudo remover promo activa: ${failList.join(' | ')}`);
      } catch (e) {
        if (e._cancelled) throw e;
        // no bloqueamos el update por un error de promos; el reactivo reintenta si hace falta
      }
    }
    await removeAppliedPromosProactive();
    // 1) Intento directo. La mayoría entra por acá y ahorra todas las llamadas de promociones.
    let errors = await attemptWithVerify();
    if (!errors.length) return { item_id: item.item_id, ok: true, warning: warnings.length ? warnings.join(' | ') : undefined };
    // 1b) Fallback de stock por depósito (solo multiorigen; ej. ANTO)
    const depFb = await tryDepositFallback(errors);
    if (depFb) return depFb;
    // 1c) Fallback SKU repetido (user_product.repeated.conflict)
    const skuFb = await trySkuConflictFallback(errors);
    if (skuFb) return skuFb;
    // 2) Solo si ML bloquea por promoción, recién ahí se limpian promociones y se reintenta.
    const promoBlocked = errors.some(e => isPromoBlockingError(e.message, e.status));
    if (promoBlocked) {
      try {
        const promoClean = await removeActivePromotionsBeforeItemUpdate(item.item_id, account, token);
        if (promoClean.removed?.length) {
          job.promotions_removed = (job.promotions_removed || 0) + promoClean.removed.length;
          warnings.push(`Promos removidas: ${promoClean.removed.map(p => `${p.removed}/${p.type}`).join(', ')}`);
        }
        if (!promoClean.ok) {
          return {
            item_id: item.item_id,
            ok: false,
            error: 'ML bloqueó por promoción y no se pudo remover: ' + (promoClean.errors || []).map(e => e.error || JSON.stringify(e)).join(' | ')
          };
        }
        await sleep(2000);
        job.retries = (job.retries || 0) + 1;
        errors = await attemptWithVerify();   // reintento CON verificacion de que el precio quede
        if (!errors.length) {
          job.promo_retry_ok = (job.promo_retry_ok || 0) + 1;
          return { item_id: item.item_id, ok: true, warning: warnings.join(' | ') };
        }
      } catch(e) {
        if (e._cancelled) throw e;
        return { item_id: item.item_id, ok: false, error: parseMLError(e) };
      }
    }
    // 2b) Envío gratis obligatorio (precio sobre umbral) y/o atributos inválidos.
    const shipAttrFb = await tryShippingAttrsFallback(errors);
    if (shipAttrFb) return shipAttrFb;
    // 3) Si ML bloqueó por campos no modificables (precio/atributos), intentar precio y stock
    //    por separado. Si alguno de los dos falla → pausar el ítem directamente.
    const fieldsBlocked = errors.some(e =>
      e.message.includes('item.price.not_modifiable') ||
      e.message.includes('item.attributes.not_modifiable') ||
      e.message.includes('field_not_updatable')
    );
    if (fieldsBlocked) {
      const origPrice = (item.price !== '' && item.price != null) ? parseFloat(item.price) : null;
      const origQty   = (item.available_quantity !== '' && item.available_quantity != null) ? parseInt(item.available_quantity) : null;
      const hasPrice  = origPrice !== null && !isNaN(origPrice);
      const hasStock  = origQty   !== null && !isNaN(origQty);
      // Si no había precio ni stock en el Excel para este ítem, no hay nada que reintentar
      if (!hasPrice && !hasStock) {
        return { item_id: item.item_id, ok: false, error: errors.map(e => e.message).join(' · ') };
      }
      let priceOk = true;
      let stockOk = true;
      // Intento precio solo
      if (hasPrice) {
        const pricePayload = cur?.variation_ids?.length
          ? { variations: cur.variation_ids.map(id => ({ id, price: origPrice })) }
          : { price: origPrice };
        try {
          await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, pricePayload, workerId);
        } catch(e) {
          if (e._cancelled) throw e;
          priceOk = false;
        }
      }
      // Intento stock solo
      if (hasStock) {
        const stockPayload = cur?.variation_ids?.length
          ? { variations: cur.variation_ids.map(id => ({ id, available_quantity: origQty })) }
          : { available_quantity: origQty };
        try {
          await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, stockPayload, workerId);
        } catch(e) {
          if (e._cancelled) throw e;
          stockOk = false;
        }
      }
      // Si falló precio o stock → pausar el ítem
      if ((hasPrice && !priceOk) || (hasStock && !stockOk)) {
        const failedFields = [];
        if (hasPrice && !priceOk) failedFields.push('precio');
        if (hasStock && !stockOk) failedFields.push('stock');
        try {
          await putWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, { status: 'paused' }, workerId);
          return { item_id: item.item_id, ok: false, error: `Pausado automáticamente — no se pudo actualizar: ${failedFields.join(' y ')}` };
        } catch(e2) {
          if (e2._cancelled) throw e2;
          return { item_id: item.item_id, ok: false, error: `${failedFields.join(' y ')} no modificable y falló al pausar: ${parseMLError(e2)}` };
        }
      }
      // Precio y stock actualizados OK — solo atributos/marca fallaron (no bloqueante)
      return { item_id: item.item_id, ok: true, warning: 'Atributos no modificables ignorados — precio y stock actualizados' };
    }
    return { item_id: item.item_id, ok: false, error: errors.map(e => e.message).join(' | ') };
  }
  // currentState declarado aquí (fuera del try) para que updateOne() pueda accederlo
  const currentState = {};
  try {
    // ---- FASE 0: pre-fetch del estado actual en ML ----
    job.phase = 'prefetch';
    const PREFETCH_BATCH = 20;
    const PREFETCH_CONCURRENCY = 5;
    const itemIds = items.map(i => i.item_id).filter(Boolean);
    job.prefetch_total = itemIds.length;
    job.prefetch_done = 0;
    let prefetchOk = true;
    const prefetchBatches = [];
    for (let i = 0; i < itemIds.length; i += PREFETCH_BATCH) prefetchBatches.push(itemIds.slice(i, i + PREFETCH_BATCH));
    for (let i = 0; i < prefetchBatches.length; i += PREFETCH_CONCURRENCY) {
      if (job.cancelled) { job.status = 'cancelled'; job.phase = 'cancelled'; return; }
      const wave = prefetchBatches.slice(i, i + PREFETCH_CONCURRENCY);
      job.prefetch_done = Math.min(i * PREFETCH_BATCH, itemIds.length);
      await Promise.all(wave.map(async batch => {
        try {
          const data = await mlGet(
            `https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=id,price,available_quantity,status,seller_custom_field,shipping,variations,user_product_id`,
            token
          );
          for (const entry of (Array.isArray(data) ? data : [])) {
            if (entry.code === 200 && entry.body) {
              const it = entry.body;
              const varIds = Array.isArray(it.variations) && it.variations.length > 0
                ? it.variations.map(v => v.id).filter(Boolean)
                : null;
              currentState[it.id] = {
                price: it.price ?? null,
                available_quantity: it.available_quantity ?? null,
                status: it.status ?? '',
                seller_custom_field: it.seller_custom_field ?? '',
                logistic_type: it.shipping?.logistic_type ?? '',
                ship_mode: it.shipping?.mode ?? '',
                ship_free: it.shipping?.free_shipping === true,
                variation_ids: varIds,
                user_product_id: it.user_product_id ?? null
              };
            }
          }
        } catch(e) {
          prefetchOk = false;
          console.log(`[BG-BULK-v2] Pre-fetch falló para lote: ${e?.response?.status || e?.message || e}`);
        }
      }));
      if (i + PREFETCH_CONCURRENCY < prefetchBatches.length) await sleep(120);
    }
    job.prefetch_done = itemIds.length;
    function needsUpdate(item) {
      if (!item.item_id) return false;
      const cur = currentState[item.item_id];
      if (!cur) return true;
      const payload = buildItemPayload(item);
      if (Object.keys(payload).length) {
        if (payload.price !== undefined && Math.abs(parseFloat(payload.price) - parseFloat(cur.price ?? 0)) >= 0.01) return true;
        if (payload.available_quantity !== undefined) {
          if (cur.variation_ids?.length) return true; // ítem con variaciones: siempre actualizar si el usuario especificó stock
          if (parseInt(payload.available_quantity) !== parseInt(cur.available_quantity ?? -1)) return true;
        }
        if (payload.status !== undefined && payload.status !== cur.status) return true;
        if (payload.seller_custom_field !== undefined && String(payload.seller_custom_field).trim() !== String(cur.seller_custom_field).trim()) return true;
        if (payload.attributes !== undefined) return true;
      }
      const flexStr = String(item.flex ?? '').toLowerCase().trim();
      if (['si','sí','yes','true','1'].includes(flexStr) && cur.logistic_type !== 'self_service') return true;
      if (['no','false','0'].includes(flexStr) && cur.logistic_type === 'self_service') return true;
      return false;
    }
    const queue = [];
    const skippedItems = [];
    for (const item of items) {
      if (prefetchOk && item.item_id && !needsUpdate(item)) skippedItems.push(item.item_id);
      else queue.push(item);
    }
    job.to_update = queue.length;
    job.skipped = skippedItems.length;
    job.prefetch_ok = prefetchOk;
    job.phase = 'running';
    job.status = 'running';
    job.queue_total = queue.length;
    job.started_updates_at = Date.now();
    console.log(`[BG-BULK-v2] Job ${jobId}: ${queue.length} con cambios, ${skippedItems.length} saltados, workers=${desiredWorkers}-${MAX_WORKERS}`);
    let nextIndex = 0;
    let done = skippedItems.length;
    let okCount = 0;
    let errCount = 0;
    const okItems = [];
    job.done = done;
    job.ok = okCount;
    job.errors = errCount;
    function updateStats() {
      const elapsed = Math.max(1, (Date.now() - job.started_updates_at) / 1000);
      const processedUpdates = okCount + errCount;
      job.velocity = Math.round((processedUpdates / elapsed) * 10) / 10;
      const remaining = Math.max(0, queue.length - processedUpdates);
      job.eta_sec = job.velocity > 0 ? Math.round(remaining / job.velocity) : null;
      job.done = done;
      job.ok = okCount;
      job.errors = errCount;
      job.desired_workers = desiredWorkers;
    }
    async function worker(workerId) {
      while (!job.cancelled) {
        if (workerId > desiredWorkers) {
          if (nextIndex >= queue.length) break; // no quedan ítems — salir aunque esté throttled
          await sleep(500); continue;
        }
        const idx = nextIndex++;
        if (idx >= queue.length) break;
        const item = queue[idx];
        job.active_workers = (job.active_workers || 0) + 1;
        updateStats();
        let r;
        try {
          r = await updateOne(item, workerId);
        } catch(e) {
          if (e._cancelled) { job.status = 'cancelled'; job.phase = 'cancelled'; return; }
          r = { item_id: item.item_id || '?', ok: false, error: parseMLError(e) };
        } finally {
          job.active_workers = Math.max(0, (job.active_workers || 1) - 1);
        }
        done++;
        if (r.ok) {
          okCount++;
          okItems.push(r.item_id);
          markSuccess();
        } else {
          errCount++;
          if (job.error_items.length < ERROR_ITEMS_MAX) job.error_items.push(r);
        }
        updateStats();
      }
    }
    const workers = [];
    for (let w = 1; w <= MAX_WORKERS; w++) workers.push(worker(w));
    await Promise.all(workers);
    if (job.cancelled || job.status === 'cancelled') {
      job.status = 'cancelled';
      job.phase = 'cancelled';
      updateStats();
      return;
    }
    job.status = 'done';
    job.phase = 'done';
    job.done = items.length;
    job.ok = okCount;
    job.errors = errCount;
    job.active_workers = 0;
    job.finished_at = Date.now();
    job.report = { ok_items: okItems, skipped_items: skippedItems, error_items: job.error_items };
    updateStats();
    console.log(`[BG-BULK-v2] Completado job=${jobId}: ${okCount} OK, ${errCount} errores, ${skippedItems.length} saltados, 429=${job.rate_limits}, promos=${job.promotions_removed}`);
    // Persistir reporte en data.json para sobrevivir reinicios del servidor
    try {
      const dbSave = loadDB();
      if (!dbSave.bulk_completed_jobs) dbSave.bulk_completed_jobs = [];
      // Limpiar entradas antiguas (>48h) y limitar a las últimas 20
      const cutoff48h = Date.now() - 48 * 60 * 60 * 1000;
      dbSave.bulk_completed_jobs = dbSave.bulk_completed_jobs
        .filter(j => j.finished_at > cutoff48h)
        .slice(-20);
      dbSave.bulk_completed_jobs.push({
        id: jobId, status: 'done', phase: 'done',
        total: items.length, done: items.length, ok: okCount, errors: errCount,
        skipped: skippedItems.length, to_update: queue.length,
        rate_limits: job.rate_limits || 0, retries: job.retries || 0,
        promotions_removed: job.promotions_removed || 0,
        finished_at: job.finished_at,
        report: job.report
      });
      saveDB(dbSave);
      console.log(`[BG-BULK-v2] Reporte persistido en data.json para job=${jobId}`);
    } catch(eSave) {
      console.error(`[BG-BULK-v2] Error persistiendo reporte: ${eSave.message}`);
    }
  } catch(e) {
    if (!job.cancelled) {
      job.status = 'error';
      job.phase = 'error';
      job.error_msg = e?.message || 'Error inesperado';
      console.log(`[BG-BULK-v2] Error inesperado job=${jobId}: ${e?.message || e}`);
    }
  }
}
// BULK UPDATE — con pre-fetch para saltar ítems sin cambios reales
route('POST', '/api/bulk-update', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'No autenticado' });
  const dbPerm = loadDB();
  const userPerm = dbPerm.users.find(u => u.id === sess.userId);
  const canBulk = sess.role === 'admin' || userPerm?.can_bulk_update === true;
  if (!canBulk) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { account_id, items, skip_promo_clean } = await parseBody(req);
  if (!account_id || !Array.isArray(items) || !items.length) return sendJSON(res, 400, { error: 'Datos inválidos' });
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  let token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido, reconectá la cuenta ML desde Configuración' });
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  // Rate limiter ADAPTATIVO: empieza rápido (300ms/ítem) y se auto-regula.
  let itemPause = 300;
  const PAUSE_MIN = 300;
  const PAUSE_MAX = 4000;
  let successStreak = 0;
  const STREAK_TO_SPEEDUP = 40;
  let rateLimitHit = false;
  async function mlPutWithRetry(url, payload) {
    let lastErr;
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        return await mlPut(url, payload, token);
      } catch(e) {
        lastErr = e;
        const status = e?.response?.status;
        if (status === 401) {
          console.log(`[BULK] 401 — refresh token para ${account.name}`);
          const refreshed = await refreshToken(account);
          if (!refreshed) throw Object.assign(new Error('Token expirado, reconectá la cuenta ML desde Configuración → Cuentas'), { response: { status: 401, data: {} } });
          token = refreshed;
          continue;
        }
        if (status === 429) {
          rateLimitHit = true;
          const wait = [8000, 20000, 40000][attempt] || 40000;
          console.log(`[BULK] 429 — esperando ${wait}ms (intento ${attempt + 1}, pausa=${itemPause}ms)`);
          await sleep(wait);
          continue;
        }
        throw e;
      }
    }
    throw lastErr;
  }
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Transfer-Encoding': 'chunked', 'X-Accel-Buffering': 'no' });
  // ===== FASE 0: PRE-FETCH del estado actual (GET batch de 20, 4 paralelos) =====
  // Objetivo: saber qué ítems realmente cambiaron y saltar los que ya están al día.
  // GET /items?ids=... es mucho más permisivo en rate limit que PUT /items/{id}.
  const PREFETCH_BATCH = 20;
  const PREFETCH_CONCURRENCY = 4;
  const itemIds = items.map(i => i.item_id).filter(Boolean);
  res.write(JSON.stringify({ type: 'prefetch_start', total: items.length, fetching: itemIds.length }) + '\n');
  console.log(`[BULK] Pre-fetch de ${itemIds.length} ítems para ${account.name}...`);
  const currentState = {}; // item_id → {price, available_quantity, status, seller_custom_field, logistic_type}
  let prefetchOk = true;
  try {
    const prefetchBatches = [];
    for (let i = 0; i < itemIds.length; i += PREFETCH_BATCH) {
      prefetchBatches.push(itemIds.slice(i, i + PREFETCH_BATCH));
    }
    for (let i = 0; i < prefetchBatches.length; i += PREFETCH_CONCURRENCY) {
      const wave = prefetchBatches.slice(i, i + PREFETCH_CONCURRENCY);
      await Promise.all(wave.map(async batch => {
        try {
          const data = await mlGet(
            `https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=id,price,available_quantity,status,seller_custom_field,shipping,user_product_id`,
            token
          );
          for (const entry of (Array.isArray(data) ? data : [])) {
            if (entry.code === 200 && entry.body) {
              const it = entry.body;
              currentState[it.id] = {
                price: it.price ?? null,
                available_quantity: it.available_quantity ?? null,
                status: it.status ?? '',
                seller_custom_field: it.seller_custom_field ?? '',
                logistic_type: it.shipping?.logistic_type ?? '',
                user_product_id: it.user_product_id ?? null
              };
            }
          }
        } catch(e) {
          prefetchOk = false;
          console.log(`[BULK] Pre-fetch falló para lote: ${e?.response?.status || e?.message || e}`);
        }
      }));
      if (i + PREFETCH_CONCURRENCY < prefetchBatches.length) await sleep(150);
    }
  } catch(e) {
    prefetchOk = false;
  }
  // Determina si un ítem del archivo realmente difiere del estado actual en ML
  function needsUpdate(item) {
    if (!item.item_id) return false;
    const cur = currentState[item.item_id];
    if (!cur) return true; // sin datos de prefetch → actualizar (safe default)
    const payload = buildItemPayload(item);
    if (!Object.keys(payload).length) {
      // Sin payload, revisar solo flex
    } else {
      if (payload.price !== undefined && Math.abs(parseFloat(payload.price) - parseFloat(cur.price ?? 0)) >= 0.01) return true;
      if (payload.available_quantity !== undefined && parseInt(payload.available_quantity) !== parseInt(cur.available_quantity ?? -1)) return true;
      if (payload.status !== undefined && payload.status !== cur.status) return true;
      if (payload.seller_custom_field !== undefined && String(payload.seller_custom_field).trim() !== String(cur.seller_custom_field).trim()) return true;
      if (payload.attributes !== undefined) return true; // marca: siempre actualizar si viene en el archivo
    }
    const flexStr = String(item.flex ?? '').toLowerCase().trim();
    if (['si','sí','yes','true','1'].includes(flexStr) && cur.logistic_type !== 'self_service') return true;
    if (['no','false','0'].includes(flexStr) && cur.logistic_type === 'self_service') return true;
    return false; // nada cambió
  }
  const totalToUpdate = prefetchOk
    ? items.filter(item => !item.item_id || needsUpdate(item)).length
    : items.length;
  const totalSkipped = items.length - totalToUpdate;
  console.log(`[BULK] Pre-fetch: ${totalToUpdate} necesitan actualización, ${totalSkipped} ya están al día`);
  res.write(JSON.stringify({ type: 'prefetch_done', total: items.length, to_update: totalToUpdate, skipped: totalSkipped, prefetch_ok: prefetchOk }) + '\n');
  res.write(JSON.stringify({ type: 'start', total: items.length }) + '\n');
  // ===== FASE 1: ACTUALIZAR solo los ítems que cambiaron =====
  let done = 0;
  let doneUpdates = 0;
  let startTimeUpdates = null;
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    // Si el pre-fetch fue exitoso y el ítem no cambió: enviar resultado instantáneo, sin pausa
    if (prefetchOk && item.item_id && !needsUpdate(item)) {
      done++;
      res.write(JSON.stringify({ type: 'result', done, total: items.length, item_id: item.item_id, ok: true, warning: 'Sin cambios — ya actualizado' }) + '\n');
      continue;
    }
    // Ítem con cambios: procesar con rate limiter adaptativo
    rateLimitHit = false;
    if (!startTimeUpdates) startTimeUpdates = Date.now();
    let r;
    let madeApiCall = false;
    if (!item.item_id) {
      r = { item_id: '?', ok: false, error: 'Sin item_id' };
    } else {
      try {
        const payload = buildItemPayload(item);
        const curBU = currentState[item.item_id];
        const hasFlex = item.flex !== '' && item.flex != null &&
          ['si','sí','yes','true','1','no','false','0'].includes(String(item.flex).toLowerCase().trim());
        if (!Object.keys(payload).length && !hasFlex) {
          r = { item_id: item.item_id, ok: true, warning: 'Sin cambios — se omitió' };
        } else {
          madeApiCall = true;
          const errors = [], warnings = [];
          if (!skip_promo_clean && (Object.keys(payload).length || hasFlex)) {
            const promoClean = await removeActivePromotionsBeforeItemUpdate(item.item_id, account, token);
            if (promoClean.removed?.length) {
              warnings.push(`Promos removidas: ${promoClean.removed.map(p => `${p.removed}/${p.type}`).join(', ')}`);
            }
            if (!promoClean.ok) {
              errors.push('No se pudieron remover promociones activas: ' + (promoClean.errors || []).map(e => e.error || JSON.stringify(e)).join(' | '));
            }
          }
          if (!errors.length && Object.keys(payload).length) {
            try {
              await mlPutWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, payload);
            } catch(e) {
              const cause = e?.response?.data?.cause;
              const causeDetail = Array.isArray(cause) && cause.length
                ? cause.map(c => c.description || c.code || JSON.stringify(c)).join('; ')
                : null;
              const errMsg = causeDetail || e?.response?.data?.message || e?.response?.data?.error || e?.message || 'Error al actualizar';
              // Fallback multiorigen: si ML rechaza el stock por /items, va al deposito
              if (/available_quantity\.not_updatable/i.test(String(errMsg))) {
                let upid2 = curBU?.user_product_id || null;
                if (!upid2) upid2 = await resolveUpid(item.item_id, token);
                const wq = (item.available_quantity !== '' && item.available_quantity != null) ? parseInt(item.available_quantity) : null;
                const restPayload = { ...payload }; delete restPayload.available_quantity;
                let itemErr2 = null;
                if (Object.keys(restPayload).length) {
                  try { await mlPutWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, restPayload); }
                  catch(e2) { itemErr2 = e2?.response?.data?.message || e2?.message || 'Error'; }
                }
                let dErr = null;
                if (upid2 && wq != null && !isNaN(wq)) dErr = await putUserProductStock(upid2, wq, account);
                else if (wq != null && !isNaN(wq)) dErr = 'no se pudo obtener user_product_id para el stock';
                if (itemErr2) errors.push(itemErr2);
                if (dErr) errors.push('stock depósito: ' + dErr);
              } else if (/repeated.*conflict|user_product\.repeated/i.test(String(errMsg))) {
                // Conflicto por GTIN/catálogo al mandar atributos: reintentar SIN atributos
                let ok2 = false;
                const p2 = { ...payload }; delete p2.attributes;
                if (Object.keys(p2).length) { try { await mlPutWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, p2); ok2 = true; warnings.push('SKU no sincronizado (catálogo/GTIN repetido)'); } catch(e3) {} }
                if (!ok2) { const p3 = { ...p2 }; delete p3.seller_custom_field; if (Object.keys(p3).length) { try { await mlPutWithRetry(`https://api.mercadolibre.com/items/${item.item_id}`, p3); ok2 = true; warnings.push('SKU no actualizado (catálogo/GTIN)'); } catch(e3) {} } }
                if (!ok2) errors.push(errMsg);
              } else {
                console.log(`[BULK] ❌ ${item.item_id} HTTP ${e?.response?.status || '?'} payload=${JSON.stringify(payload)} err=${errMsg}`);
                errors.push(errMsg);
              }
            }
          }
          if (!errors.length && hasFlex) {
            const flexErr = await updateFlexForItem(item.item_id, String(item.flex).toLowerCase().trim(), token);
            if (flexErr) errors.push(flexErr);
          }
          if (errors.length) r = { item_id: item.item_id, ok: false, error: errors.join(' | ') };
          else r = { item_id: item.item_id, ok: true, warning: warnings.join(' | ') };
        }
      } catch(e) {
        r = { item_id: item.item_id, ok: false, error: e?.response?.data?.message || e?.message || 'Error' };
      }
    }
    done++;
    doneUpdates++;
    // ETA basada solo en los ítems que realmente se actualizan (excluye los skipped)
    let etaSec = null;
    if (startTimeUpdates && doneUpdates > 2 && totalToUpdate > doneUpdates) {
      const avgMs = (Date.now() - startTimeUpdates) / doneUpdates;
      etaSec = Math.round(avgMs * (totalToUpdate - doneUpdates) / 1000);
    }
    res.write(JSON.stringify({ type: 'result', done, total: items.length, eta_sec: etaSec, ...r }) + '\n');
    if (i < items.length - 1 && madeApiCall) {
      if (rateLimitHit) {
        itemPause = Math.min(PAUSE_MAX, itemPause * 2);
        successStreak = 0;
        console.log(`[BULK] Rate limit — pausa → ${itemPause}ms`);
      } else {
        successStreak++;
        if (successStreak >= STREAK_TO_SPEEDUP && itemPause > PAUSE_MIN) {
          itemPause = Math.max(PAUSE_MIN, Math.round(itemPause * 0.8));
          successStreak = 0;
          console.log(`[BULK] ${STREAK_TO_SPEEDUP} éxitos — pausa → ${itemPause}ms`);
        }
      }
      await sleep(itemPause);
    }
  }
  res.write(JSON.stringify({ type: 'done', total: items.length }) + '\n');
  res.end();
  console.log(`[BULK] Completado: ${items.length} ítems (${totalToUpdate} actualizados, ${totalSkipped} sin cambios) por ${sess.username}`);
});
// BULK UPDATE BG — versión background job para importación Excel (opción 4)
route('POST', '/api/bulk-update-bg', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'No autenticado' });
  const dbPerm = loadDB();
  const userPerm = dbPerm.users.find(u => u.id === sess.userId);
  const canBulk = sess.role === 'admin' || userPerm?.can_bulk_update === true;
  if (!canBulk) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { account_id, items } = await parseBody(req);
  if (!account_id || !Array.isArray(items) || !items.length) return sendJSON(res, 400, { error: 'Datos inválidos' });
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido, reconectá la cuenta ML desde Configuración' });
  cleanBulkJobs();
  const jobId = `bulk_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  bulkJobs[jobId] = {
    id: jobId,
    status: 'starting',
    phase: 'starting',
    total: items.length,
    done: 0,
    ok: 0,
    errors: 0,
    to_update: null,
    skipped: null,
    eta_sec: null,
    velocity: 0,
    active_workers: 0,
    desired_workers: 3,
    max_workers: 5,
    rate_limits: 0,
    retries: 0,
    promotions_removed: 0,
    promo_retry_ok: 0,
    error_items: [],
    report: null,
    cancelled: false,
    created: Date.now(),
    username: sess.username
  };
  // Fire-and-forget: corre en segundo plano, independiente de la conexión HTTP
  runBulkJob(jobId, items, account, token).catch(e => {
    if (bulkJobs[jobId] && !['done','cancelled'].includes(bulkJobs[jobId].status)) {
      bulkJobs[jobId].status = 'error';
      bulkJobs[jobId].phase = 'error';
      bulkJobs[jobId].error_msg = e?.message || 'Error inesperado';
    }
  });
  console.log(`[BG-BULK] Job ${jobId} creado: ${items.length} ítems para ${account.name} (${sess.username})`);
  return sendJSON(res, 200, { job_id: jobId, total: items.length });
});
// GET /api/bulk-status?job_id=xxx — polling del estado del job
route('GET', '/api/bulk-status', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'No autenticado' });
  const params = new URLSearchParams((req.url.split('?')[1] || ''));
  const jobId = params.get('job_id');
  if (!jobId) return sendJSON(res, 400, { error: 'job_id requerido' });
  const job = bulkJobs[jobId];
  if (!job) {
    // Buscar en reporte persistido (sobrevive reinicios del servidor)
    const dbPersist = loadDB();
    const persisted = (dbPersist.bulk_completed_jobs || []).find(j => j.id === jobId);
    if (persisted) return sendJSON(res, 200, persisted);
    return sendJSON(res, 404, { error: 'Job no encontrado o expirado' });
  }
  return sendJSON(res, 200, job);
});
// POST /api/bulk-cancel — cancelar un job en progreso
route('POST', '/api/bulk-cancel', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'No autenticado' });
  const { job_id } = await parseBody(req);
  if (!job_id) return sendJSON(res, 400, { error: 'job_id requerido' });
  const job = bulkJobs[job_id];
  if (!job) return sendJSON(res, 404, { error: 'Job no encontrado' });
  job.cancelled = true;
  console.log(`[BG-BULK] Job ${job_id} cancelado por ${sess.username}`);
  return sendJSON(res, 200, { ok: true });
});
// SEARCH LISTINGS STREAM — búsqueda progresiva/paginada para título/SKU/item_id
route('POST', '/api/search-listings-stream', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'No autenticado' });
  const dbPerm2 = loadDB();
  const userPerm2 = dbPerm2.users.find(u => u.id === sess.userId);
  const canSearch = sess.role === 'admin' || userPerm2?.can_search_update === true;
  if (!canSearch) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { item_id, sku, title, account_id, cursor, page_size } = await parseBody(req);
  if (!item_id && !sku && !title) return sendJSON(res, 400, { error: 'Ingresá Item ID, SKU o título para buscar' });
  const db = loadDB();
  const allAccounts = db.ml_accounts || [];
  const selectedAccountId = account_id ? parseInt(account_id) : null;
  const targets = selectedAccountId ? allAccounts.filter(a => a.id === selectedAccountId) : allAccounts;
  const PAGE_SIZE = Math.max(10, Math.min(200, parseInt(page_size || '80') || 80));
  const itemIdSearch = item_id ? String(item_id).trim().toUpperCase() : '';
  const skuLower = sku ? String(sku).trim().toLowerCase() : '';
  const titleRaw = title ? String(title).trim() : '';
  function enc(o){ return Buffer.from(JSON.stringify(o)).toString('base64url'); }
  function dec(s){ if(!s) return null; try { return JSON.parse(Buffer.from(String(s), 'base64url').toString('utf8')); } catch(e){ return null; } }
  function norm(s){ return String(s||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,' ').replace(/\s+/g,' ').trim(); }
  const words = norm(titleRaw).split(' ').filter(w => w.length >= 2);
  const hasTitle = words.length > 0;
  // Palabra completa: " gol " no matchea "golpe" ni "paragolpe"
  const titleOk = t => !hasTitle || words.every(w => (' ' + norm(t) + ' ').includes(' ' + w + ' '));
  const skuOk = raw => {
    if (!skuLower) return true;
    const s = String(raw||'').toLowerCase();
    return skuLower.includes('_') ? s.includes(skuLower) : s.split('_')[0].includes(skuLower);
  };
  const getSku = b => b.seller_custom_field || (Array.isArray(b.attributes) ? (b.attributes.find(a => a.id === 'SELLER_SKU')?.value_name || '') : '') || '';
  const row = (b,a) => ({ item_id:b.id, title:b.title||'', available_quantity:b.available_quantity??'', price:b.price??'', seller_sku:getSku(b), status:b.status||'', account_id:a.id, account_name:a.name, permalink:b.permalink || `https://articulo.mercadolibre.com.ar/${b.id}` });
  res.writeHead(200, {'Content-Type':'application/x-ndjson','Transfer-Encoding':'chunked','Cache-Control':'no-cache','X-Accel-Buffering':'no'});
  let sent = 0, seen = new Set();
  const emit = r => { const k = `${r.account_id}:${r.item_id}`; if(seen.has(k)) return; seen.add(k); sent++; res.write(JSON.stringify({type:'item', row:r})+'\n'); };
  async function details(account, token, ids){
    const rows = [];
    for (let i=0;i<ids.length;i+=20){
      const batch = ids.slice(i,i+20);
      try {
        const items = await mlGet(`https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=id,title,available_quantity,price,seller_custom_field,status,attributes,permalink,seller_id`, token);
        for (const it of (Array.isArray(items)?items:[])){
          const b = it.body || it;
          if(!b?.id || b.status==='closed' || b.status==='under_review') continue;
          if(b.seller_id && String(b.seller_id)!==String(account.seller_id)) continue;
          const rawSku = getSku(b);
          if(!skuOk(rawSku) || !titleOk(b.title||'')) continue;
          rows.push(row(b, account));
        }
      } catch(e){}
    }
    return rows;
  }
  try {
    res.write(JSON.stringify({type:'start', page_size: PAGE_SIZE})+'\n');
    if (itemIdSearch) {
      let itemData = null;
      try { itemData = await mlGet(`https://api.mercadolibre.com/items/${itemIdSearch}?attributes=id,title,available_quantity,price,seller_custom_field,status,attributes,permalink,seller_id`); } catch(e){}
      if (!itemData) {
        for (const acc of allAccounts) {
          try { const tok = await getValidToken(acc); if(!tok) continue; itemData = await mlGet(`https://api.mercadolibre.com/items/${itemIdSearch}?attributes=id,title,available_quantity,price,seller_custom_field,status,attributes,permalink,seller_id`, tok); if(itemData?.id) break; } catch(e){}
        }
      }
      if (itemData?.id && itemData.status !== 'closed' && itemData.status !== 'under_review') {
        const owner = allAccounts.find(a => String(a.seller_id) === String(itemData.seller_id || ''));
        if (owner && (!selectedAccountId || owner.id === selectedAccountId) && skuOk(getSku(itemData)) && titleOk(itemData.title||'')) emit(row(itemData, owner));
      }
      res.write(JSON.stringify({type:'done', count:sent, has_more:false})+'\n'); return res.end();
    }
    if (skuLower) {
      const state = dec(cursor);
      const start = state?.mode === 'sku' ? state.acc_index || 0 : 0;
      for (let ai=start; ai<targets.length; ai++) {
        const account = targets[ai], token = await getValidToken(account); if(!token) continue;
        const ids = new Set(), base = String(sku||'').trim();
        const terms = [base];
        if (!skuLower.includes('_')) ['_D','_I','_DM','_IM','_DER','_IZQ','_T','_TD','_TI','_d','_i','_dm','_im','_der','_izq','_t','_1','_2','_3','_A','_B','_C','_E','_F'].forEach(s => terms.push(base+s));
        await Promise.all(terms.map(term => mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search?seller_sku=${encodeURIComponent(term)}&limit=200`, token).then(r => (r.results||[]).forEach(id=>ids.add(id))).catch(()=>{})));
        for (const r of await details(account, token, [...ids])) { emit(r); if(sent>=PAGE_SIZE){ res.write(JSON.stringify({type:'done', count:sent, has_more:ai<targets.length-1, cursor:enc({mode:'sku', acc_index:ai+1})})+'\n'); return res.end(); } }
      }
      res.write(JSON.stringify({type:'done', count:sent, has_more:false})+'\n'); return res.end();
    }
    if (hasTitle) {
      // Búsqueda rápida por índice ML: por cada palabra usa ?q=word, luego intersecta los ID sets (AND).
      // Evita escanear TODO el catálogo con search_type:scan — reduce llamadas de ~120 a ~6-10.
      const statuses = ['active','paused'];
      let totalScanned = 0;
      async function fastWordSearch(sellerId, token, word, status) {
        const ids = new Set();
        let offset = 0;
        const LIMIT = 200;
        let safety = 0;
        while (safety++ < 50) {
          let page;
          try { page = await mlGet(`https://api.mercadolibre.com/users/${sellerId}/items/search?q=${encodeURIComponent(word)}&status=${status}&limit=${LIMIT}&offset=${offset}`, token); } catch(e){ break; }
          const results = page.results || [];
          results.forEach(id => ids.add(id));
          const total = page.paging?.total || 0;
          offset += results.length;
          if (!results.length || offset >= total) break;
        }
        return ids;
      }
      for (const account of targets) {
        const token = await getValidToken(account); if(!token) continue;
        res.write(JSON.stringify({type:'progress', scanned:totalScanned, found:sent, account:account.name, status:'buscando...'})+'\n');
        const allIds = new Set();
        for (const status of statuses) {
          // Para cada palabra obtener IDs y luego intersectar (AND entre palabras)
          const wordSets = await Promise.all(words.map(w => fastWordSearch(account.seller_id, token, w, status)));
          if (!wordSets.length) continue;
          let intersection = wordSets[0];
          for (let i = 1; i < wordSets.length; i++) {
            intersection = new Set([...intersection].filter(id => wordSets[i].has(id)));
          }
          intersection.forEach(id => allIds.add(id));
        }
        totalScanned += allIds.size;
        for (const r of await details(account, token, [...allIds])) emit(r);
        res.write(JSON.stringify({type:'progress', scanned:totalScanned, found:sent, account:account.name, status:'listo'})+'\n');
      }
      res.write(JSON.stringify({type:'done', count:sent, has_more:false, scanned:totalScanned})+'\n'); return res.end();
    }
    res.write(JSON.stringify({type:'done', count:sent, has_more:false})+'\n'); res.end();
  } catch(e) {
    res.write(JSON.stringify({type:'error', error:e?.response?.data?.message || e?.response?.data?.error || e.message || String(e), raw:e?.response?.data || null})+'\n'); res.end();
  }
});
// SEARCH LISTINGS — busca por Item ID, SKU y/o título en una o todas las cuentas
// Motor mejorado:
// - Item ID: detecta dueño real y devuelve una sola fila.
// - SKU: búsqueda rápida por seller_sku.
// - Título: escanea activas/pausadas y filtra localmente por TODAS las palabras.
//   Ej: "faro gol" devuelve títulos que contengan faro AND gol, en cualquier orden.
route('POST', '/api/search-listings', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'No autenticado' });
  const dbPerm2 = loadDB();
  const userPerm2 = dbPerm2.users.find(u => u.id === sess.userId);
  const canSearch = sess.role === 'admin' || userPerm2?.can_search_update === true;
  if (!canSearch) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { item_id, sku, title, account_id } = await parseBody(req);
  if (!item_id && !sku && !title) return sendJSON(res, 400, { error: 'Ingresá Item ID, SKU o título para buscar' });
  const db = loadDB();
  const allAccounts = db.ml_accounts || [];
  const selectedAccountId = account_id ? parseInt(account_id) : null;
  const itemIdSearch = item_id ? String(item_id).trim().toUpperCase() : '';
  const skuLower = sku ? sku.trim().toLowerCase() : '';
  const titleRaw = title ? String(title).trim() : '';
  function normText(s) {
    return String(s || '')
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }
  const titleWords = normText(titleRaw).split(' ').filter(w => w.length >= 2);
  const hasTitleFilter = titleWords.length > 0;
  function titleMatches(t) {
    if (!hasTitleFilter) return true;
    // Palabra completa: rodea con espacios para que "gol" no matchee "golpe" ni "paragolpe"
    const nt = ' ' + normText(t) + ' ';
    return titleWords.every(w => nt.includes(' ' + w + ' '));
  }
  function skuMatches(rawSku) {
    if (!skuLower) return true;
    const itemSku = String(rawSku || '').toLowerCase();
    if (skuLower.includes('_')) return itemSku.includes(skuLower);
    return itemSku.split('_')[0].includes(skuLower);
  }
  function getSkuFromItem(b) {
    return b.seller_custom_field ||
      (Array.isArray(b.attributes) ? (b.attributes.find(a => a.id === 'SELLER_SKU')?.value_name || '') : '') || '';
  }
  function rowFromItem(b, account) {
    const rawSku = getSkuFromItem(b);
    return {
      item_id: b.id,
      title: b.title || '',
      available_quantity: b.available_quantity ?? '',
      price: b.price ?? '',
      seller_sku: rawSku,
      status: b.status || '',
      account_id: account.id,
      account_name: account.name,
      permalink: b.permalink || `https://articulo.mercadolibre.com.ar/${b.id}`
    };
  }
  const results = [];
  // Caso especial: búsqueda directa por item_id.
  if (itemIdSearch) {
    try {
      let itemData = null;
      try {
        itemData = await mlGet(`https://api.mercadolibre.com/items/${itemIdSearch}?attributes=id,title,available_quantity,price,seller_custom_field,status,attributes,permalink,seller_id`);
      } catch(e) {}
      if (!itemData) {
        for (const acc of allAccounts) {
          try {
            const tok = await getValidToken(acc);
            if (!tok) continue;
            itemData = await mlGet(`https://api.mercadolibre.com/items/${itemIdSearch}?attributes=id,title,available_quantity,price,seller_custom_field,status,attributes,permalink,seller_id`, tok);
            if (itemData?.id) break;
          } catch(e) {}
        }
      }
      if (!itemData || !itemData.id) return sendJSON(res, 200, []);
      if (itemData.status === 'closed' || itemData.status === 'under_review') return sendJSON(res, 200, []);
      const realSellerId = String(itemData.seller_id || '');
      const ownerAccount = allAccounts.find(a => String(a.seller_id) === realSellerId);
      if (!ownerAccount) return sendJSON(res, 200, []);
      if (selectedAccountId && ownerAccount.id !== selectedAccountId) return sendJSON(res, 200, []);
      const rawSku = getSkuFromItem(itemData);
      if (!skuMatches(rawSku)) return sendJSON(res, 200, []);
      if (!titleMatches(itemData.title || '')) return sendJSON(res, 200, []);
      return sendJSON(res, 200, [rowFromItem(itemData, ownerAccount)]);
    } catch(e) {
      console.error('[SEARCH item_id]', e?.response?.data || e.message || e);
      return sendJSON(res, 500, { error: e?.response?.data?.message || e.message || 'Error buscando item_id' });
    }
  }
  const targets = selectedAccountId
    ? allAccounts.filter(a => a.id === selectedAccountId)
    : allAccounts;
  // Helper: traer detalles de ids en lotes.
  async function fetchDetailsAndPush(account, token, ids) {
    for (let i = 0; i < ids.length; i += 20) {
      const batch = ids.slice(i, i + 20);
      try {
        const items = await mlGet(
          `https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=id,title,available_quantity,price,seller_custom_field,status,attributes,permalink,seller_id`,
          token
        );
        for (const it of (Array.isArray(items) ? items : [])) {
          const b = it.body || it;
          if (!b || !b.id) continue;
          if (b.status === 'closed' || b.status === 'under_review') continue;
          if (b.seller_id && String(b.seller_id) !== String(account.seller_id)) continue;
          const rawSku = getSkuFromItem(b);
          if (!skuMatches(rawSku)) continue;
          if (!titleMatches(b.title || '')) continue;
          results.push(rowFromItem(b, account));
        }
      } catch(e) {}
    }
  }
  // Búsqueda rápida por índice ML (reemplaza el escaneo total con search_type:scan).
  // Por cada palabra llama a ?q=word&status=..., luego intersecta los IDs (AND).
  async function scanAccountByTitle(account, token) {
    const statuses = ['active', 'paused'];
    async function fastWordIds(sellerId, word, status) {
      const ids = new Set();
      let offset = 0;
      const LIMIT = 200;
      let safety = 0;
      while (safety++ < 50) {
        let page;
        try {
          page = await mlGet(
            `https://api.mercadolibre.com/users/${sellerId}/items/search?q=${encodeURIComponent(word)}&status=${status}&limit=${LIMIT}&offset=${offset}`,
            token
          );
        } catch(e) { break; }
        const results = page.results || [];
        results.forEach(id => ids.add(id));
        const total = page.paging?.total || 0;
        offset += results.length;
        if (!results.length || offset >= total) break;
      }
      return ids;
    }
    const allIds = new Set();
    for (const status of statuses) {
      // Buscar cada palabra en paralelo y luego intersectar (AND entre todas)
      const wordSets = await Promise.all(titleWords.map(w => fastWordIds(account.seller_id, w, status)));
      if (!wordSets.length) continue;
      let intersection = wordSets[0];
      for (let i = 1; i < wordSets.length; i++) {
        intersection = new Set([...intersection].filter(id => wordSets[i].has(id)));
      }
      intersection.forEach(id => allIds.add(id));
    }
    if (allIds.size > 0) {
      await fetchDetailsAndPush(account, token, [...allIds]);
    }
  }
  for (const account of targets) {
    try {
      const token = await getValidToken(account);
      if (!token) continue;
      const sellerId = account.seller_id;
      // Si hay SKU, usamos el método rápido por seller_sku y después filtramos título localmente si corresponde.
      if (skuLower) {
        const itemIds = new Set();
        const skuBase = sku.trim();
        const skuTerms = [skuBase];
        if (!skuLower.includes('_')) {
          const sufijos = ['_D','_I','_DM','_IM','_DER','_IZQ','_T','_TD','_TI',
                           '_d','_i','_dm','_im','_der','_izq','_t',
                           '_1','_2','_3','_A','_B','_C','_E','_F'];
          for (const s of sufijos) skuTerms.push(skuBase + s);
        }
        await Promise.all(skuTerms.map(term =>
          mlGet(`https://api.mercadolibre.com/users/${sellerId}/items/search?seller_sku=${encodeURIComponent(term)}&limit=200`, token)
            .then(r => (r.results || []).forEach(id => itemIds.add(id)))
            .catch(() => {})
        ));
        if (itemIds.size) await fetchDetailsAndPush(account, token, [...itemIds]);
        continue;
      }
      // Si NO hay SKU y hay título, hacemos búsqueda precisa por todas las palabras.
      if (hasTitleFilter) {
        await scanAccountByTitle(account, token);
      }
    } catch(e) {}
  }
  // Orden simple: primero los títulos donde las palabras aparecen más juntas/no muy largo.
  if (hasTitleFilter) {
    results.sort((a, b) => {
      const ta = normText(a.title);
      const tb = normText(b.title);
      const ia = Math.min(...titleWords.map(w => ta.indexOf(w)).filter(i => i >= 0));
      const ib = Math.min(...titleWords.map(w => tb.indexOf(w)).filter(i => i >= 0));
      return (ia - ib) || (ta.length - tb.length);
    });
  }
  sendJSON(res, 200, results);
});
// EXPORT LISTINGS — streaming ndjson con progreso en tiempo real, 5 lotes paralelos
route('GET', '/api/export-listings', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbPermEx = loadDB();
  const userPermEx = dbPermEx.users.find(u => u.id === sess.userId);
  const canExport = sess.role === 'admin' || userPermEx?.can_bulk_update === true;
  if (!canExport) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const urlObj = new URL(req.url, 'http://localhost');
  const accountId = parseInt(urlObj.searchParams.get('account_id'));
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === accountId);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Transfer-Encoding': 'chunked', 'X-Accel-Buffering': 'no' });
  try {
    const LIMIT = 100;
    const BATCH_SIZE = 20;
    const DETAIL_CONCURRENCY = 5;
    let exported = 0;
    // Obtener totales de activas y pausadas por separado
    // (items/search sin status solo devuelve activas por defecto)
    const [activeFirst, pausedFirst] = await Promise.all([
      mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, { limit: 1, status: 'active' }),
      mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, { limit: 1, status: 'paused' }),
    ]);
    const activeTotal = activeFirst.paging?.total || 0;
    const pausedTotal = pausedFirst.paging?.total || 0;
    const total = activeTotal + pausedTotal;
    res.write(JSON.stringify({ type: 'start', total }) + '\n');
    // Helper: exportar todos los ítems de un status usando scroll_id
    const exportByStatus = async (status, statusTotal) => {
      let scrollId = null;
      let fetched = 0;
      while (fetched < statusTotal) {
        const params = { limit: LIMIT, status, search_type: 'scan' };
        if (scrollId) params.scroll_id = scrollId;
        const pageData = await mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, params);
        scrollId = pageData.scroll_id || null;
        const ids = pageData.results || [];
        if (!ids.length) break;
        fetched += ids.length;
        const batches = [];
        for (let j = 0; j < ids.length; j += BATCH_SIZE) batches.push(ids.slice(j, j + BATCH_SIZE));
        for (let j = 0; j < batches.length; j += DETAIL_CONCURRENCY) {
          const concurrent = batches.slice(j, j + DETAIL_CONCURRENCY);
          const responses = await Promise.all(concurrent.map(b =>
            mlGet(`https://api.mercadolibre.com/items?ids=${b.join(',')}&attributes=id,title,available_quantity,status,price,original_price,shipping,seller_custom_field,attributes`, token)
              .catch(() => [])
          ));
          for (const itemsData of responses) {
            for (const entry of (Array.isArray(itemsData) ? itemsData : [])) {
              if (entry.code === 200 && entry.body) {
                const it = entry.body;
                // Excluir publicaciones under_review y closed
                if (it.status === 'under_review' || it.status === 'closed') continue;
                const sh = it.shipping || {};
                const rawMode = sh.mode || sh.logistic_type || 'not_specified';
                const shippingMode = rawMode === 'me2' ? 'ME' : rawMode;
                const shTags = Array.isArray(sh.tags) ? sh.tags : [];
                const flex = shTags.includes('self_service_in') ? 'si'
                           : shTags.includes('self_service_out') ? 'no'
                           : 'not_available';
                const localPickup = sh.local_pick_up ? 'si' : 'no';
                const sku = it.seller_custom_field
                  || (Array.isArray(it.attributes) ? (it.attributes.find(a => a.id === 'SELLER_SKU')?.value_name || '') : '')
                  || '';
                exported++;
                res.write(JSON.stringify({
                  type: 'item', exported, total,
                  row: [it.id, flex, localPickup, shippingMode, it.title || '', it.available_quantity ?? '', it.status ?? '', it.original_price ?? it.price ?? '', sku]
                }) + '\n');
              }
            }
          }
        }
      }
    };
    await exportByStatus('active', activeTotal);
    await exportByStatus('paused', pausedTotal);
    res.write(JSON.stringify({ type: 'done', exported }) + '\n');
  } catch(e) {
    console.error('[EXPORT]', e?.response?.data || e.message);
    res.write(JSON.stringify({ type: 'error', error: e?.response?.data?.message || e.message || 'Error al exportar' }) + '\n');
  }
  res.end();
});
route('POST', '/api/users', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { username, password } = await parseBody(req);
  if (!username || !password) return sendJSON(res, 400, { error: 'Faltan datos' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return sendJSON(res, 400, { error: 'El usuario ya existe' });
  db.users.push({ id: db.nextUserId++, username, password: hashPassword(password), role: 'user', alerts_questions: true, alerts_messages: true, view_dashboard: true, can_view_dashboard: false, can_view_questions: true, can_view_messages: true, can_view_sales: true, can_prep_manage: false, can_prep_operate: false, created_at: new Date().toISOString() });
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// ACCOUNTS
route('GET', '/api/accounts', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  sendJSON(res, 200, db.ml_accounts.map(a => ({ id: a.id, name: a.name, seller_id: a.seller_id, token_expires_at: a.token_expires_at })));
});
// REPUTACIÓN: estado actual de cada cuenta (nivel + métricas de los últimos 60 días).
route('GET', '/api/reputation', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const debug = new URL(req.url, 'http://localhost').searchParams.get('debug') === '1';
  const db = loadDB();
  const out = [];
  await Promise.all((db.ml_accounts || []).map(async (account) => {
    try {
      const token = await getValidToken(account);
      if (!token) { out.push({ account_id: account.id, account_name: account.name, error: 'sin token' }); return; }
      const u = await mlGet(`https://api.mercadolibre.com/users/${account.seller_id}`, token);
      const r = u.seller_reputation || {};
      const m = r.metrics || {};
      const tx = r.transactions || {};
      if (debug) { out.push({ account_name: account.name, _raw: r }); return; }
      const opsBase = (m.sales && m.sales.completed != null) ? m.sales.completed : (tx.completed || 0);
      // Tasa de una métrica. Cuando la cuenta está EN PROTECCIÓN de reputación, ML deja rate/value en 0
      // pero guarda el valor real en metric.excluded.real_rate → usamos ese para reflejar lo real.
      const rateOf = (metric) => {
        if (!metric) return null;
        if (metric.rate != null && Number(metric.rate) > 0) return Number(metric.rate);
        if (metric.excluded && metric.excluded.real_rate != null) return Number(metric.excluded.real_rate);
        if (metric.value != null && opsBase > 0 && Number(metric.value) > 0) return Number(metric.value) / opsBase;
        if (metric.rate != null) return Number(metric.rate);
        return null;
      };
      const valOf = (metric) => {
        if (!metric) return null;
        if (metric.value != null && Number(metric.value) > 0) return Number(metric.value);
        if (metric.excluded && metric.excluded.real_value != null) return Number(metric.excluded.real_value);
        return (metric.value != null) ? Number(metric.value) : null;
      };
      const protUntil = r.protection_end_date || null;
      const isProtected = !!(protUntil && new Date(protUntil).getTime() > Date.now());
      out.push({
        account_id: account.id, account_name: account.name,
        nickname: u.nickname || account.name,
        level_id: r.level_id || '',
        power_seller_status: r.power_seller_status || '',
        period: (m.sales && m.sales.period) || '60 días',
        operaciones: (m.sales && m.sales.completed != null) ? m.sales.completed : (tx.completed != null ? tx.completed : null),
        canceladas_rate: rateOf(m.cancellations),
        canceladas_value: valOf(m.cancellations),
        demorados_rate: rateOf(m.delayed_handling_time),
        demorados_value: valOf(m.delayed_handling_time),
        reclamos_rate: rateOf(m.claims),
        reclamos_value: valOf(m.claims),
        protected: isProtected, protection_end_date: protUntil,
        ratings: tx.ratings || {}, total_tx: tx.total != null ? tx.total : null
      });
    } catch (e) {
      out.push({ account_id: account.id, account_name: account.name, error: (e && e.message) || 'error' });
    }
  }));
  out.sort((a, b) => (a.account_name || '').localeCompare(b.account_name || ''));
  sendJSON(res, 200, out);
});
route('GET', '/auth/mercadolibre', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, `http://localhost`);
  const name = url.searchParams.get('name') || 'Cuenta ML';
  sess.pendingAccountName = name;
  const authUrl = `https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=${ML_CLIENT_ID}&redirect_uri=${encodeURIComponent(BASE_URL + '/callback')}`;
  res.writeHead(302, { Location: authUrl });
  res.end();
});
route('GET', '/callback', async (req, res) => {
  const url = new URL(req.url, `http://localhost`);
  const code = url.searchParams.get('code');
  if (!code) { res.writeHead(302, { Location: '/?error=no_code' }); return res.end(); }
  const sess = getSession(req);
  try {
    const tokenData = await mlPost('https://api.mercadolibre.com/oauth/token', {
      grant_type: 'authorization_code',
      client_id: ML_CLIENT_ID,
      client_secret: ML_CLIENT_SECRET,
      code,
      redirect_uri: BASE_URL + '/callback'
    });
    const { access_token, refresh_token, expires_in } = tokenData;
    const expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();
    const userData = await mlGet('https://api.mercadolibre.com/users/me', access_token);
    const sellerId = userData.id.toString();
    const nickname = userData.nickname || (sess && sess.pendingAccountName) || 'Cuenta ML';
    const db = loadDB();
    const existing = db.ml_accounts.find(a => a.seller_id === sellerId);
    if (existing) {
      existing.access_token = access_token;
      existing.refresh_token = refresh_token;
      existing.token_expires_at = expiresAt;
      existing.name = nickname;
    } else {
      db.ml_accounts.push({
        id: db.nextAccountId++, name: nickname, seller_id: sellerId,
        access_token, refresh_token, token_expires_at: expiresAt,
        user_id: sess?.userId, created_at: new Date().toISOString()
      });
    }
    saveDB(db);
    res.writeHead(302, { Location: '/?success=account_added' });
    res.end();
  } catch (err) {
    console.error('Error en OAuth:', err.response?.data || err.message || err);
    res.writeHead(302, { Location: '/?error=oauth_failed' });
    res.end();
  }
});
// QUESTIONS
// Cache de "el comprador ya compró en esta cuenta" (evita consultar ML en cada refresco de 15s).
const buyerBoughtCache = {}; // clave: accountId:buyerId -> { bought, ts }
const BUYER_BOUGHT_TTL = 60 * 60 * 1000; // 1 hora
// Preguntas respondidas hace poco. ML puede seguir devolviéndolas como UNANSWERED unos
// segundos después de responderlas (lag de su índice), así que reaparecían en la lista y,
// al re-responderlas, ML tiraba error "ya respondida". Las ocultamos por un ratito.
const recentlyAnsweredQuestions = {}; // { question_id: timestamp }
const RECENT_ANSWERED_TTL = 5 * 60 * 1000; // 5 min
route('GET', '/api/questions', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, 'http://localhost');
  const status = url.searchParams.get('status') || 'UNANSWERED';
  const accountFilter = url.searchParams.get('account_id');
  const buyerFilter = url.searchParams.get('buyer_id');
  const db = loadDB();
  let allQuestions = [];
  const targets = accountFilter ? db.ml_accounts.filter(a => a.id === parseInt(accountFilter)) : db.ml_accounts;
  for (const account of targets) {
    const token = await getValidToken(account);
    if (!token) continue;
    try {
      // If filtering by buyer, search both UNANSWERED and ANSWERED
      const statuses = buyerFilter ? ['UNANSWERED', 'ANSWERED'] : [status];
      let questions = [];
      for (const st of statuses) {
        const data = await mlGet('https://api.mercadolibre.com/questions/search', token, {
          seller_id: account.seller_id, status: st, sort_fields: 'date_created', sort_types: 'DESC', limit: 50
        });
        questions.push(...(data.questions || []));
      }
      // If buyer filter, only keep questions from that buyer
      if (buyerFilter) {
        questions = questions.filter(q => q.from?.id?.toString() === buyerFilter);
      }
      const itemIds = [...new Set(questions.map(q => q.item_id))];
      const itemDetails = {};
      // Fetch items using OAuth token (own items)
      for (const itemId of itemIds) {
        try {
          // Method 1: with OAuth token
          let itemData = null;
          try {
            const itemRes1 = await fetch(`https://api.mercadolibre.com/items/${itemId}`, {
              headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
            });
            if (itemRes1.ok) {
              itemData = await itemRes1.json();
            } else {
              const errBody = await itemRes1.text();
              console.log(`Item ${itemId} method1 failed (${itemRes1.status}): ${errBody.substring(0, 200)}`);
            }
          } catch (e1) {
            console.log(`Item ${itemId} method1 error: ${e1.message}`);
          }
          // Method 2: public API with caller.id
          if (!itemData) {
            try {
              const itemRes2 = await fetch(`https://api.mercadolibre.com/items/${itemId}?caller.id=${account.seller_id}`, {
                headers: { 'Accept': 'application/json' }
              });
              if (itemRes2.ok) {
                itemData = await itemRes2.json();
              } else {
                console.log(`Item ${itemId} method2 failed: HTTP ${itemRes2.status}`);
              }
            } catch (e2) {
              console.log(`Item ${itemId} method2 error: ${e2.message}`);
            }
          }
          if (!itemData) throw new Error('All methods failed');
          let sku = itemData.seller_custom_field || '';
          let mpn = '';
          if (itemData.attributes) {
            if (!sku) {
              const skuAttr = itemData.attributes.find(a => a.id === 'SELLER_SKU');
              if (skuAttr) sku = skuAttr.value_name || '';
            }
            const mpnAttr = itemData.attributes.find(a => a.id === 'MPN');
            if (mpnAttr) mpn = mpnAttr.value_name || '';
          }
          let listingType = '';
          const lt = itemData.listing_type_id || '';
          console.log(`Item ${itemId} listing_type_id: ${lt}`);
          if (lt === 'gold_pro') listingType = 'Premium';
          else if (lt === 'gold_special') listingType = 'Clasica';
          else if (lt === 'gold' || lt === 'silver' || lt === 'bronze') listingType = 'Clasica';
          else if (lt === 'free') listingType = 'Gratis';
          else if (lt) listingType = lt;
          itemDetails[itemId] = {
            title: itemData.title,
            thumbnail: imgProxy(itemData.thumbnail),  // sirve la miniatura desde nuestro dominio (evita bloqueos del navegador)
            permalink: itemData.permalink,
            price: itemData.price,
            currency: itemData.currency_id || 'ARS',
            sku: sku,
            mpn: mpn,
            available_quantity: itemData.available_quantity || 0,
            listing_type: listingType,
            publication_id: itemData.id || itemId
          };
        } catch (e) {
          console.error(`Error fetching item ${itemId}:`, e.message || e);
          itemDetails[itemId] = { title: 'Producto no disponible', thumbnail: '', permalink: '', price: 0, currency: 'ARS', sku: '', mpn: '', available_quantity: 0, listing_type: '', publication_id: itemId };
        }
      }
      // ¿El comprador YA compró en esta cuenta? Se avisa en la pregunta. Con cache de 1h por comprador.
      const purchasedBuyers = new Set();
      const uniqueBuyers = [...new Set(questions.map(q => q.from?.id).filter(Boolean))];
      const toQuery = [];
      for (const bid of uniqueBuyers) {
        const c = buyerBoughtCache[account.id + ':' + bid];
        if (c && (Date.now() - c.ts) < BUYER_BOUGHT_TTL) { if (c.bought) purchasedBuyers.add(String(bid)); }
        else toQuery.push(bid);
      }
      for (let i = 0; i < toQuery.length; i += 5) {
        const batch = toQuery.slice(i, i + 5);
        await Promise.allSettled(batch.map(async (bid) => {
          try {
            const od = await mlGet('https://api.mercadolibre.com/orders/search', token, { seller: account.seller_id, buyer: bid, sort: 'date_desc', limit: 10 });
            const results = od.results || [];
            const bought = results.some(o => o.status !== 'cancelled') || (results.length === 0 && od.paging && od.paging.total > 0);
            buyerBoughtCache[account.id + ':' + bid] = { bought, ts: Date.now() };
            if (bought) purchasedBuyers.add(String(bid));
          } catch (e) {}
        }));
      }
      for (const q of questions) {
        allQuestions.push({
          ...q, account_name: account.name, account_id: account.id,
          buyer_has_purchased: purchasedBuyers.has(String(q.from?.id || '')),
          item_title: itemDetails[q.item_id]?.title || '',
          item_thumbnail: itemDetails[q.item_id]?.thumbnail || '',
          item_permalink: itemDetails[q.item_id]?.permalink || '',
          item_price: itemDetails[q.item_id]?.price || 0,
          item_currency: itemDetails[q.item_id]?.currency || 'ARS',
          item_sku: itemDetails[q.item_id]?.sku || '',
          item_mpn: itemDetails[q.item_id]?.mpn || '',
          item_available_quantity: itemDetails[q.item_id]?.available_quantity || 0,
          item_listing_type: itemDetails[q.item_id]?.listing_type || '',
          item_publication_id: itemDetails[q.item_id]?.publication_id || ''
        });
      }
    } catch (err) {
      console.error(`Error questions ${account.name}:`, err.response?.data || err.message || err);
    }
  }
  // De-duplicar por id (evita tarjetas repetidas de la misma pregunta) y ocultar las
  // respondidas hace poco cuando se pide la lista de "sin responder".
  const _nowTs = Date.now();
  for (const k of Object.keys(recentlyAnsweredQuestions)) {
    if (_nowTs - recentlyAnsweredQuestions[k] > RECENT_ANSWERED_TTL) delete recentlyAnsweredQuestions[k];
  }
  const _seenQ = new Set();
  allQuestions = allQuestions.filter(q => {
    const idk = String(q.id);
    if (_seenQ.has(idk)) return false;      // duplicada → la sacamos
    _seenQ.add(idk);
    // Solo ocultamos en la vista "sin responder" (no cuando se filtra por comprador).
    if (status === 'UNANSWERED' && !buyerFilter && recentlyAnsweredQuestions[idk]) return false;
    return true;
  });
  allQuestions.sort((a, b) => new Date(b.date_created) - new Date(a.date_created));
  sendJSON(res, 200, allQuestions);
});
route('POST', '/api/questions/answer', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { question_id, text, account_id } = await parseBody(req);
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  try {
    await mlPost('https://api.mercadolibre.com/answers', { question_id: parseInt(question_id), text }, token);
    // Marcamos la pregunta como respondida hace poco para que NO reaparezca en "sin responder"
    // mientras el índice de ML todavía la sigue listando como UNANSWERED (lag de unos segundos).
    recentlyAnsweredQuestions[String(question_id)] = Date.now();
    sendJSON(res, 200, { ok: true });
  } catch (err) {
    console.error('Error answering:', err.response?.data || err.message || err);
    // Si ML dice que ya estaba respondida, la ocultamos igual y lo tratamos como OK
    // (la respuesta ya existe), para que no quede trabada en la lista.
    const emsg = String(err.response?.data?.message || err.message || '').toLowerCase();
    if (/already|answered|ya\s*(fue)?\s*respond|has an answer|question_id/.test(emsg)) {
      recentlyAnsweredQuestions[String(question_id)] = Date.now();
      return sendJSON(res, 200, { ok: true, already: true });
    }
    sendJSON(res, 500, { error: err.response?.data?.message || 'Error al responder' });
  }
});
// MESSAGES
const msgOrderCache = {}; // cache de órdenes resueltas para packs pendientes (evita recargar en cada poll)
route('GET', '/api/messages', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, 'http://localhost');
  const accountFilter = url.searchParams.get('account_id');
  const statusFilter = url.searchParams.get('status') || 'unread';
  const orderFilter = url.searchParams.get('order_id');
  const buyerFilter = url.searchParams.get('buyer_id');
  const db = loadDB();
  const dismissedPacks = db.dismissed_msg_packs || {};
  let allMessages = [];
  const targets = accountFilter ? db.ml_accounts.filter(a => a.id === parseInt(accountFilter)) : db.ml_accounts;
  // Fetch accounts in parallel
  await Promise.all(targets.map(async (account) => {
    const token = await getValidToken(account);
    if (!token) return;
    try {
      let ordersResults;
      if (orderFilter) {
        try {
          const singleOrder = await mlGet(`https://api.mercadolibre.com/orders/${orderFilter}`, token);
          ordersResults = [singleOrder];
        } catch (e) { ordersResults = []; }
      } else if (buyerFilter) {
        const ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, {
          seller: account.seller_id, buyer: buyerFilter, sort: 'date_desc', limit: 50
        });
        ordersResults = ordersData.results || [];
      } else {
        const ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, {
          seller: account.seller_id, sort: 'date_desc', limit: 50
        });
        ordersResults = ordersData.results || [];
      }
      // Fetch open claims for this seller (one call per account, not per order)
      let claimedOrderIds = new Set();
      try {
        const claimsData = await mlGet('https://api.mercadolibre.com/post-purchase/v1/claims/search', token, {
          seller_id: account.seller_id, status: 'opened', limit: 50
        });
        const claimsList = claimsData.data || claimsData.results || claimsData.claims || [];
        for (const claim of claimsList) {
          if (claim.resource_id) claimedOrderIds.add(String(claim.resource_id));
          if (claim.order_id) claimedOrderIds.add(String(claim.order_id));
        }
      } catch (e) {
        // Claims API might fail or require special permissions, continue without filter
        console.log(`[MESSAGES] No se pudo obtener reclamos para ${account.name}:`, e.response?.data?.message || e.message || '');
      }
      const seenPacks = new Set();
      const uniqueOrders = [];
      for (const order of ordersResults) {
        // Skip cancelled orders and orders with open claims
        if (order.status === 'cancelled') continue;
        if (claimedOrderIds.has(String(order.id))) continue;
        // Also check order tags for mediations/claims
        const tags = order.tags || [];
        if (tags.includes('mediations') || tags.includes('claim')) continue;
        const packId = order.pack_id || order.id;
        if (seenPacks.has(packId)) continue;
        seenPacks.add(packId);
        uniqueOrders.push(order);
      }
      // ===== Traer TODOS los packs con mensajes pendientes (no solo los de las últimas 50 órdenes).
      // ML: GET /messages/packs?role=seller&tag=post_sale devuelve los packs con mensajes sin leer sin
      // importar qué tan vieja es la orden. Resolvemos su orden para no perder conversaciones antiguas.
      if (!orderFilter && !buyerFilter) {
        try {
          // Paginamos para traer TODOS los packs pendientes (no solo la primera página).
          const pendPacks = [];
          let offset = 0;
          for (let page = 0; page < 8; page++) {
            const pend = await mlGet('https://api.mercadolibre.com/messages/packs', token, { role: 'seller', tag: 'post_sale', limit: 50, offset });
            const pr = pend.results || pend.data || [];
            pendPacks.push(...pr);
            const total = (pend.paging && pend.paging.total != null) ? pend.paging.total : pr.length;
            offset += 50;
            if (pr.length < 50 || offset >= total) break;
          }
          for (const pr of pendPacks) {
            // Extraemos el id del pack del recurso (ej. "/packs/123..."). Fallback: primer número largo.
            let mm = String(pr.resource || '').match(/\/packs\/(\d+)/);
            if (!mm) mm = String(pr.resource || pr.id || '').match(/(\d{6,})/);
            const pid = mm ? mm[1] : null;
            if (!pid || seenPacks.has(Number(pid)) || seenPacks.has(pid)) continue;
            // Resolver la orden (comprador + ítem), con cache de 5 min. Si falla, IGUAL incluimos el pack.
            let ord = (msgOrderCache[pid] && (Date.now() - msgOrderCache[pid].ts < 5 * 60 * 1000)) ? msgOrderCache[pid].o : null;
            if (!ord) {
              try { ord = await mlGet(`https://api.mercadolibre.com/orders/${pid}`, token); }
              catch (e1) {
                try {
                  const pk = await mlGet(`https://api.mercadolibre.com/packs/${pid}`, token);
                  const oid = pk.orders && pk.orders[0] && pk.orders[0].id;
                  if (oid) ord = await mlGet(`https://api.mercadolibre.com/orders/${oid}`, token);
                } catch (e2) {}
              }
              if (ord) msgOrderCache[pid] = { o: ord, ts: Date.now() };
            }
            // Solo salteamos canceladas. Los reclamos/mediaciones NO se excluyen: son mensajes que ML
            // cuenta como "sin leer" y el vendedor necesita verlos.
            if (ord && ord.status === 'cancelled') continue;
            const synth = ord || { id: pid, pack_id: pid, buyer: {}, order_items: [] };
            const opk = synth.pack_id || synth.id;
            if (seenPacks.has(opk)) continue;
            seenPacks.add(opk);
            uniqueOrders.push(synth);
          }
        } catch (e) {
          console.log(`[MESSAGES] No se pudo obtener pendientes para ${account.name}:`, e.response?.data?.message || e.message || '');
        }
      }
      // Fetch message packs in parallel (batches of 5 to avoid rate limits)
      for (let i = 0; i < uniqueOrders.length; i += 5) {
        const batch = uniqueOrders.slice(i, i + 5);
        const results = await Promise.allSettled(batch.map(async (order) => {
          const packId = order.pack_id || order.id;
          let msgData;
          try {
            msgData = await mlGet(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}`, token, {
              tag: 'post_sale', limit: 15, mark_as_read: false
            });
          } catch (e) {
            // Retry once after a short delay — avoids transient rate-limit/network blips
            // causing a conversation to flicker in/out of the unread list between polls
            await new Promise(r => setTimeout(r, 400));
            msgData = await mlGet(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}`, token, {
              tag: 'post_sale', limit: 15, mark_as_read: false
            });
          }
          const messages = msgData.messages || [];
          if (messages.length === 0) return null;
          const sellerId = account.seller_id?.toString();
          const mappedMessages = messages.map(m => {
            const fromSeller = m.from?.user_id?.toString() === sellerId;
            const fromRole = fromSeller ? 'seller' : 'buyer';
            // message_date.read === null means the RECIPIENT hasn't read it yet
            // For buyer messages: null read means seller (us) hasn't read it → genuinely unread
            const mlUnread = !fromSeller && !m.message_date?.read;
            // Adjuntos del mensaje: ML puede devolverlos como message_attachments o attachments,
            // y cada uno como string (nombre de archivo) u objeto con filename/original_filename.
            const rawAtt = m.message_attachments || m.attachments || [];
            const atts = (Array.isArray(rawAtt) ? rawAtt : []).map(a => {
              if (typeof a === 'string') return { id: a, name: a, type: '' };
              return { id: a.filename || a.id || '', name: a.original_filename || a.filename || 'archivo', type: a.type || '' };
            }).filter(a => a.id);
            return {
              id: m.id,
              from: fromRole,
              text: m.text || m.plain?.content || '',
              date: m.date_created || m.date || m.created_at || m.date_received || m.message_date?.created || '',
              mlUnread,
              attachments: atts
            };
          });
          // ML returns messages newest first, so [0] is the most recent message
          const lastMsg = mappedMessages[0];
          // "Sin leer" = last msg from buyer (we haven't replied) OR ML marks any buyer msg as unread
          const hasMLUnread = mappedMessages.some(m => m.from === 'buyer' && m.mlUnread);
          let isUnread = lastMsg.from === 'buyer' || hasMLUnread;
          // Check dismissed: if pack was manually dismissed but buyer sent a NEW message after that → auto-un-dismiss
          const packKey = String(packId);
          const dismissedAt = dismissedPacks[packKey];
          let isDismissed = false;
          if (dismissedAt && !buyerFilter && !orderFilter) {
            const newestBuyerMsg = mappedMessages.find(m => m.from === 'buyer');
            const newestBuyerDate = newestBuyerMsg?.date ? new Date(newestBuyerMsg.date) : null;
            if (newestBuyerDate && newestBuyerDate > new Date(dismissedAt)) {
              // Buyer replied after dismiss → auto-un-dismiss
              delete dismissedPacks[packKey];
              db.dismissed_msg_packs = dismissedPacks;
              saveDB(db);
            } else {
              isDismissed = true;
              isUnread = false; // treat as answered
            }
          }
          if (!buyerFilter && !orderFilter) {
            if (statusFilter === 'unread' && (!isUnread || isDismissed)) return null;
            if (statusFilter === 'answered' && isUnread && !isDismissed) return null;
          }
          return {
            order_id: order.id, pack_id: packId, account_name: account.name, account_id: account.id,
            seller_id: account.seller_id, buyer_name: order.buyer?.nickname || 'Comprador',
            buyer_id: order.buyer?.id?.toString() || '',
            item_title: order.order_items?.[0]?.item?.title || 'Producto',
            messages: mappedMessages, is_unread: isUnread, has_ml_unread: hasMLUnread, is_dismissed: isDismissed,
            // messages[0] is newest (ML returns newest-first) — use it for sorting
            last_message_date: messages[0]?.date_created || messages[0]?.date || order.date_created
          };
        }));
        for (const r of results) {
          if (r.status === 'fulfilled' && r.value) allMessages.push(r.value);
        }
      }
    } catch (err) {
      console.error(`Error messages ${account.name}:`, err.response?.data || err.message || err);
    }
  }));
  allMessages.sort((a, b) => new Date(b.last_message_date) - new Date(a.last_message_date));
  sendJSON(res, 200, allMessages);
});
route('POST', '/api/messages/reply', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
    const { order_id, text, account_id, attachments } = await parseBody(req);
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  try {
    const orderData = await mlGet(`https://api.mercadolibre.com/orders/${order_id}`, token);
    const buyerId = orderData.buyer.id;
    const packId = orderData.pack_id || order_id;
    const sellerId = parseInt(account.seller_id);
    console.log('[MSG REPLY] order:', order_id, 'pack_id from order:', orderData.pack_id, 'using pack:', packId, 'seller:', sellerId, 'buyer:', buyerId);
    // ML messages POST requires: tag=post_sale, application_id, Bearer token
    const msgUrl = `https://api.mercadolibre.com/messages/packs/${packId}/sellers/${sellerId}?tag=post_sale&application_id=${ML_CLIENT_ID}`;
    console.log('[MSG REPLY] POST to:', msgUrl);
    const msgBody = {
      from: { user_id: String(sellerId) },
      to: { user_id: String(buyerId) },
      text: text
    };
    if (Array.isArray(attachments) && attachments.length) msgBody.attachments = attachments;
    console.log('[MSG REPLY] Body:', JSON.stringify(msgBody));
    const msgRes = await fetch(msgUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(msgBody)
    });
    const msgData = await msgRes.text();
    console.log('[MSG REPLY] Response status:', msgRes.status, 'body:', msgData.substring(0, 500));
    if (!msgRes.ok) {
      const parsed = JSON.parse(msgData);
      return sendJSON(res, 500, { error: parsed.message || parsed.error || 'Error de ML: ' + msgRes.status });
    }
    // Al responder, mover la conversación a "Respondidos" (sale de "Sin leer").
    // Motivo: ML deja el mensaje del comprador como "no leído" (usamos mark_as_read:false),
    // así que sin esto la conversación reaparecía en "Sin leer" apenas se refrescaba la lista
    // ("las respuestas no se van"). Si el comprador escribe DESPUÉS, la lógica de
    // auto-un-dismiss en GET /api/messages la vuelve a mostrar automáticamente.
    try {
      if (!db.dismissed_msg_packs) db.dismissed_msg_packs = {};
      db.dismissed_msg_packs[String(packId)] = new Date().toISOString();
      saveDB(db);
    } catch (e) { console.log('[MSG REPLY] no se pudo auto-dismiss:', e.message || e); }
    sendJSON(res, 200, { ok: true });
  } catch (err) {
    console.error('Error sending message:', err.response?.data || err.message || err);
    sendJSON(res, 500, { error: err.response?.data?.message || err.message || 'Error al enviar mensaje' });
  }
});
// Subir un adjunto a ML (JPG/PNG/PDF/TXT, hasta ~18MB por el límite del body). Devuelve el id del adjunto.
route('POST', '/api/messages/attachment-upload', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { account_id, filename, content_type, data } = await parseBody(req);
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  if (!data) return sendJSON(res, 400, { error: 'Sin archivo' });
  try {
    const buf = Buffer.from(data, 'base64');
    const fd = new FormData();
    fd.append('file', new Blob([buf], { type: content_type || 'application/octet-stream' }), filename || 'archivo');
    const r = await fetch(`https://api.mercadolibre.com/messages/attachments?tag=post_sale&site_id=${account.site_id || 'MLA'}`, {
      method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: fd
    });
    const txt = await r.text();
    if (!r.ok) { let m = ''; try { m = JSON.parse(txt).message; } catch (e) {} return sendJSON(res, 500, { error: m || ('Error de ML: ' + r.status) }); }
    const j = JSON.parse(txt);
    sendJSON(res, 200, { id: j.id });
  } catch (e) {
    sendJSON(res, 500, { error: e.message || 'Error al subir el adjunto' });
  }
});
// Descargar/servir un adjunto de mensaje desde ML (con el token de la cuenta), para poder verlo en el panel.
route('GET', '/api/messages/attachment', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const u = new URL(req.url, 'http://localhost');
  const accId = u.searchParams.get('account_id');
  const id = u.searchParams.get('id');
  const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(accId));
  if (!account || !id) { res.writeHead(400); return res.end('bad request'); }
  const token = await getValidToken(account);
  if (!token) { res.writeHead(500); return res.end('sin token'); }
  try {
    const r = await fetch(`https://api.mercadolibre.com/messages/attachments/${encodeURIComponent(id)}?tag=post_sale&site_id=${account.site_id || 'MLA'}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!r.ok) { res.writeHead(502); return res.end('no disponible'); }
    const ct = r.headers.get('content-type') || 'application/octet-stream';
    const buf = Buffer.from(await r.arrayBuffer());
    res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'private, max-age=3600' });
    res.end(buf);
  } catch (e) {
    res.writeHead(502); res.end('error');
  }
});
route('POST', '/api/messages/dismiss', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { pack_id } = await parseBody(req);
  if (!pack_id) return sendJSON(res, 400, { error: 'Falta pack_id' });
  const db = loadDB();
  if (!db.dismissed_msg_packs) db.dismissed_msg_packs = {};
  db.dismissed_msg_packs[String(pack_id)] = new Date().toISOString();
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// GET /api/prep/claims — returns {order_id: 'open'|'closed'} for orders with claims (last 90 days)
route('GET', '/api/prep/claims', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  const claimsMap = {};
  await Promise.all(db.ml_accounts.map(async (account) => {
    const token = await getValidToken(account);
    if (!token) return;
    try {
      // Fetch open and closed claims in parallel
      const [openData, closedData] = await Promise.allSettled([
        mlGet('https://api.mercadolibre.com/post-purchase/v1/claims/search', token, {
          seller_id: account.seller_id, status: 'opened', limit: 50
        }),
        mlGet('https://api.mercadolibre.com/post-purchase/v1/claims/search', token, {
          seller_id: account.seller_id, status: 'closed', limit: 50
        })
      ]);
      const processList = (result, status) => {
        if (result.status !== 'fulfilled') return;
        const list = result.value?.data || result.value?.results || result.value?.claims || [];
        for (const c of list) {
          const oid = String(c.resource_id || c.order_id || '');
          if (oid) claimsMap[oid] = status; // open wins over closed
        }
      };
      processList(closedData, 'closed'); // closed first so open can overwrite
      processList(openData, 'open');
    } catch(e) {
      console.log('[CLAIMS] Error:', e.message || e);
    }
  }));
  sendJSON(res, 200, claimsMap);
});
// ===================== RECLAMOS (solo admin) =====================
// Lista de reclamos con filtros, enriquecida con comprador + producto de la orden.
route('GET', '/api/claims', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const u = new URL(req.url, 'http://localhost');
  const status = u.searchParams.get('status') || 'opened'; // opened | closed | all
  const accId = u.searchParams.get('account_id');
  const debugClaims = u.searchParams.get('debug') === '1';
  const db = loadDB();
  const targets = accId ? db.ml_accounts.filter(a => a.id === parseInt(accId)) : db.ml_accounts;
  const out = [];
  await Promise.all(targets.map(async (account) => {
    try {
      const token = await getValidToken(account);
      if (!token) return;
      const statuses = (status === 'all') ? ['opened', 'closed'] : [status];
      let list = [];
      for (const st of statuses) {
        try {
          const data = await mlGet('https://api.mercadolibre.com/post-purchase/v1/claims/search', token, { seller_id: account.seller_id, status: st, limit: 50 });
          const arr = data?.data || data?.results || data?.claims || [];
          list.push(...arr);
        } catch (e) {}
      }
      // Enriquecer con datos de la orden (comprador + producto) y con la fecha límite de respuesta. Reclamos suelen ser pocos.
      await Promise.allSettled(list.map(async (c) => {
        const oid = String(c.resource_id || c.order_id || '');
        let buyer = '', item = '';
        if (oid) {
          try { const od = await mlGet(`https://api.mercadolibre.com/orders/${oid}`, token); buyer = od.buyer?.nickname || ''; item = od.order_items?.[0]?.item?.title || ''; } catch (e) {}
        }
        // Fecha límite + si es devolución + si afecta la reputación.
        let dueDate = null, relatedReturn = false, affectsRep = null, repDue = null;
        // 1) Endpoint "afecta la reputación": trae el PLAZO DE RESOLUCIÓN del reclamo (el que muestra ML,
        //    ej. "hasta el 14") + si afecta o no. Es el plazo autoritativo, tiene prioridad.
        let arRaw = null;
        for (const url of [`https://api.mercadolibre.com/post-purchase/v1/claims/${c.id}/affects-reputation`, `https://api.mercadolibre.com/marketplace/v2/claims/${c.id}/affects-reputation`]) {
          try {
            const ar = await mlGet(url, token);
            if (!ar) continue;
            arRaw = ar;
            if (ar.due_date) repDue = ar.due_date;
            const v = parseAffect(ar.affects_reputation != null ? ar.affects_reputation : (ar.affected != null ? ar.affected : (ar.reputation && ar.reputation.affected != null ? ar.reputation.affected : ar.result)));
            if (v != null) affectsRep = v;
            if (repDue != null || v != null) break;
          } catch (e) {}
        }
        if (debugClaims) { out.push({ __debug: true, account: account.name, claim_id: c.id, type: c.type, stage: c.stage, affects_reputation_raw: arRaw || 'sin respuesta' }); return; }
        // 2) Detalle del reclamo: plazos de acciones (fallback) + si es devolución + reputación de respaldo.
        let actionDues = [];
        try {
          const det = await mlGet(`https://api.mercadolibre.com/post-purchase/v1/claims/${c.id}`, token);
          for (const p of (det.players || [])) for (const ac of (p.available_actions || [])) { if (ac && ac.due_date) actionDues.push(ac.due_date); }
          if (det.due_date) actionDues.push(det.due_date);
          const rel = det.related_entities || det.related_entity || [];
          relatedReturn = Array.isArray(rel) ? rel.some(x => /return/i.test(String(x))) : /return/i.test(String(rel));
          // Nota: NO usamos det.reputation como respaldo porque devolvía "afecta" en casi todos.
          // La reputación solo se marca cuando el endpoint dedicado la confirma explícitamente.
        } catch (e) {}
        // El plazo de resolución (repDue) manda; si no vino, usamos el próximo plazo futuro de las acciones.
        dueDate = repDue || pickDue(actionDues);
        // Reputación CONFIABLE: la leemos del texto del hilo del reclamo (lo que muestra ML).
        try {
          const md = await claimMessagesGet(token, c.id);
          const marr = Array.isArray(md) ? md : (md && (md.messages || md.data)) || [];
          const mmsgs = (marr || []).map(x => ({ text: x.message || x.text || (x.plain && x.plain.content) || '' }));
          const repMsg = repFromMessages(mmsgs);
          if (repMsg != null) affectsRep = repMsg;
        } catch (e) {}
        const kind = (relatedReturn || /return|change|devol|cambio/i.test(String(c.type || ''))) ? 'return' : 'claim';
        // Estado de la devolución: en preparación / enviada / entregada.
        let returnStatus = null;
        if (kind === 'return') {
          for (const url of [`https://api.mercadolibre.com/post-purchase/v1/claims/${c.id}/returns`, `https://api.mercadolibre.com/marketplace/v2/claims/${c.id}/returns`]) {
            try {
              const rt = await mlGet(url, token);
              const r0 = Array.isArray(rt) ? rt[0] : (rt && rt.results ? rt.results[0] : rt);
              if (r0) {
                const sh = r0.shipping || (Array.isArray(r0.shipments) ? r0.shipments[0] : {}) || {};
                const st = String(sh.status || sh.substatus || r0.status || '').toLowerCase();
                if (/deliver|entreg/.test(st)) returnStatus = 'delivered';
                else if (/ship|transit|camino|enviad|handling|ready/.test(st)) returnStatus = 'shipped';
                else returnStatus = 'preparing';
                break;
              }
            } catch (e) {}
          }
          if (!returnStatus) returnStatus = 'preparing';
        }
        out.push({
          id: c.id, account_id: account.id, account_name: account.name,
          status: c.status, stage: c.stage, type: c.type, reason_id: c.reason_id,
          resource: c.resource, order_id: oid || null, kind, affects_reputation: affectsRep, return_status: returnStatus,
          buyer_name: buyer, item_title: item, due_date: dueDate,
          date_created: c.date_created, last_updated: c.last_updated
        });
      }));
    } catch (e) { console.log('[CLAIMS list]', account.name, e.message || ''); }
  }));
  out.sort((a, b) => new Date(b.last_updated || b.date_created) - new Date(a.last_updated || a.date_created));
  sendJSON(res, 200, out);
});
// Interpreta el valor de "afecta la reputación" que puede venir como booleano, string ("affected",
// "not_affected", "no", "yes"…) u objeto. Devuelve true/false/null. Clave: NO tratar el string como
// booleano crudo (¡"not_affected" es truthy!), sino leer su significado.
function parseAffect(v) {
  if (v == null) return null;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v > 0;
  if (typeof v === 'string') {
    const s = v.toLowerCase().trim();
    if (/not[_\s-]?affect|no[_\s-]?afect|no afecta|sin afect|unaffected|^no$|^false$/.test(s)) return false;
    if (/affect|afecta|^yes$|^si$|^true$/.test(s)) return true;
    return null;
  }
  if (typeof v === 'object') { if (v.affected != null) return parseAffect(v.affected); if (v.value != null) return parseAffect(v.value); }
  return null;
}
// Elige el plazo relevante: el próximo VENCIMIENTO FUTURO (no uno ya pasado de otra acción).
// Si todos pasaron, devuelve el más reciente. Así no marca "vencido" cuando todavía hay plazo real.
function pickDue(dues) {
  const now = Date.now();
  const parsed = (dues || []).map(x => ({ raw: x, t: new Date(x).getTime() })).filter(x => !isNaN(x.t));
  if (!parsed.length) return null;
  const future = parsed.filter(x => x.t > now).sort((a, b) => a.t - b.t);
  if (future.length) return future[0].raw;
  return parsed.sort((a, b) => b.t - a.t)[0].raw;
}
// Determina si el reclamo afecta la reputación leyendo el texto del hilo (lo que muestra ML:
// "No afectó tu reputación" / "afectará tu reputación"). Es la fuente confiable.
function repFromMessages(msgs) {
  for (const m of (msgs || [])) {
    const t = String(m.text || '').toLowerCase();
    if (t.indexOf('reputaci') === -1) continue;
    if (/no\s+afect/.test(t)) return false;
    if (/afect/.test(t)) return true;
  }
  return null;
}
// Mensajes de un reclamo. Probamos varias versiones de la API (según permisos del app).
async function claimMessagesGet(token, claimId) {
  const urls = [
    `https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/messages`,
    `https://api.mercadolibre.com/marketplace/v2/claims/${claimId}/messages`,
    `https://api.mercadolibre.com/claims/${claimId}/messages`
  ];
  for (const url of urls) { try { const d = await mlGet(url, token); if (d) return d; } catch (e) {} }
  return null;
}
route('GET', '/api/claims/messages', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const u = new URL(req.url, 'http://localhost');
  const claimId = u.searchParams.get('claim_id');
  const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(u.searchParams.get('account_id')));
  if (!account || !claimId) return sendJSON(res, 400, { error: 'Faltan datos' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  const d = await claimMessagesGet(token, claimId);
  const arr = Array.isArray(d) ? d : (d && (d.messages || d.data)) || [];
  const msgs = (arr || []).map(m => ({
    role: m.sender_role || m.from?.role || '',
    text: m.message || m.text || (m.plain && m.plain.content) || '',
    date: m.date_created || m.date || '',
    attachments: (m.attachments || []).map(a => ({ name: a.original_filename || a.filename || 'archivo', id: a.filename || a.id || '' }))
  }));
  sendJSON(res, 200, { messages: msgs });
});
// Responder un reclamo. receiver_role: complainant (comprador) | mediator.
route('POST', '/api/claims/reply', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { account_id, claim_id, message, receiver_role } = await parseBody(req);
  if (!claim_id || !message) return sendJSON(res, 400, { error: 'Faltan datos' });
  const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  const receiver = receiver_role || 'complainant';
  // Resolver la orden/paquete del reclamo para poder usar la MENSAJERÍA NORMAL (que sí funciona en tu app)
  // cuando la respuesta va al comprador. Los endpoints propios de reclamos no siempre están habilitados.
  let orderId = null, packId = null, buyerId = null;
  try {
    const det = await mlGet(`https://api.mercadolibre.com/post-purchase/v1/claims/${claim_id}`, token);
    orderId = det.resource_id || det.order_id || null;
  } catch (e) {}
  if (orderId) {
    try { const od = await mlGet(`https://api.mercadolibre.com/orders/${orderId}`, token); packId = od.pack_id || orderId; buyerId = od.buyer && od.buyer.id; } catch (e) {}
  }
  const claimBody = JSON.stringify({ receiver_role: receiver, message });
  const attempts = [];
  // Para el COMPRADOR: primero la mensajería normal (confiable).
  if (receiver === 'complainant' && packId && buyerId) {
    attempts.push({
      url: `https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}?tag=post_sale&application_id=${ML_CLIENT_ID}`,
      body: JSON.stringify({ from: { user_id: String(account.seller_id) }, to: { user_id: String(buyerId) }, text: message })
    });
  }
  // Endpoints propios de reclamos (para mediación o como respaldo).
  attempts.push({ url: `https://api.mercadolibre.com/post-purchase/v1/claims/${claim_id}/actions/send-message`, body: claimBody });
  attempts.push({ url: `https://api.mercadolibre.com/marketplace/v2/claims/${claim_id}/actions/send-message`, body: claimBody });
  attempts.push({ url: `https://api.mercadolibre.com/post-purchase/v1/claims/${claim_id}/messages`, body: claimBody });
  // Respaldo final: mensajería normal al comprador aunque el receiver fuera otro.
  if (packId && buyerId) {
    attempts.push({
      url: `https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}?tag=post_sale&application_id=${ML_CLIENT_ID}`,
      body: JSON.stringify({ from: { user_id: String(account.seller_id) }, to: { user_id: String(buyerId) }, text: message })
    });
  }
  let lastErr = '', sawMediationBlock = false;
  for (const at of attempts) {
    try {
      const r = await fetch(at.url, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: at.body });
      const t = await r.text();
      if (r.ok) return sendJSON(res, 200, { ok: true });
      let em = '';
      try { em = JSON.parse(t).message || JSON.parse(t).error || t; } catch (e) { em = (t || '').slice(0, 200); }
      if (/blocked_by_mediation|mediation/i.test(String(em) + String(t))) sawMediationBlock = true;
      lastErr = em;
    } catch (e) { lastErr = e.message || 'error'; }
  }
  if (sawMediationBlock) {
    return sendJSON(res, 409, { error: 'Este reclamo está en mediación de Mercado Libre. Por ahora, mientras esté en mediación, la respuesta hay que enviarla desde el sitio de Mercado Libre (tu aplicación no tiene habilitado el canal de mensajes de mediación).' });
  }
  sendJSON(res, 500, { error: lastErr || 'No se pudo enviar la respuesta al reclamo' });
});
// Descargar/servir un adjunto de un reclamo (imagen que mandó el comprador/mediador), con el token de la cuenta.
route('GET', '/api/claims/attachment', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) { res.writeHead(401); return res.end('no auth'); }
  if (sess.role !== 'admin') { res.writeHead(403); return res.end('denegado'); }
  const u = new URL(req.url, 'http://localhost');
  const claimId = u.searchParams.get('claim_id');
  const id = u.searchParams.get('id');
  const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(u.searchParams.get('account_id')));
  if (!account || !claimId || !id) { res.writeHead(400); return res.end('bad request'); }
  const token = await getValidToken(account);
  if (!token) { res.writeHead(500); return res.end('sin token'); }
  const eid = encodeURIComponent(id);
  const urls = [
    `https://api.mercadolibre.com/marketplace/v2/claims/${claimId}/attachments/${eid}/download`,
    `https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/attachments/${eid}/download`,
    `https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/attachments/${eid}`,
    `https://api.mercadolibre.com/v1/claims/${claimId}/attachments/${eid}`
  ];
  for (const url of urls) {
    try {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!r.ok) continue;
      const ct = r.headers.get('content-type') || 'application/octet-stream';
      const buf = Buffer.from(await r.arrayBuffer());
      res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'private, max-age=3600' });
      return res.end(buf);
    } catch (e) {}
  }
  res.writeHead(502); res.end('no disponible');
});
// Detalle enriquecido de un reclamo: acciones disponibles + producto/precio/comprador de la orden.
route('GET', '/api/claims/detail', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const u = new URL(req.url, 'http://localhost');
  const claimId = u.searchParams.get('claim_id');
  const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(u.searchParams.get('account_id')));
  if (!account || !claimId) return sendJSON(res, 400, { error: 'Faltan datos' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  let claim = null;
  try { claim = await mlGet(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}`, token); } catch (e) {}
  // Motivo del reclamo (texto para el vendedor) + posible recomendación/detalle de ML.
  let reasonText = '', detailText = '';
  if (claim) {
    reasonText = (claim.reason && (claim.reason.detail || claim.reason.name || claim.reason.description)) || '';
    detailText = claim.detail || claim.description || (claim.reason && claim.reason.recommendation) || '';
    if (!reasonText && claim.reason_id) {
      try { const rs = await mlGet(`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/reason`, token); reasonText = rs && (rs.detail || rs.name || rs.description) || ''; } catch (e) {}
    }
  }
  const actions = new Set();
  let due = null;
  if (claim) {
    const dues = [];
    for (const p of (claim.players || [])) for (const ac of (p.available_actions || [])) {
      if (!ac) continue;
      const nm = ac.action || ac.name || (typeof ac === 'string' ? ac : '');
      if (nm) actions.add(String(nm));
      if (ac.due_date) dues.push(ac.due_date);
    }
    if (claim.due_date) dues.push(claim.due_date);
    due = pickDue(dues);
  }
  // Plazo de resolución autoritativo (el que muestra ML, ej. "hasta el 14"): tiene prioridad.
  try {
    for (const url of [`https://api.mercadolibre.com/post-purchase/v1/claims/${claimId}/affects-reputation`, `https://api.mercadolibre.com/marketplace/v2/claims/${claimId}/affects-reputation`]) {
      const ar = await mlGet(url, token);
      if (ar && ar.due_date) { due = ar.due_date; break; }
    }
  } catch (e) {}
  // Datos del producto/orden
  let order = null;
  const orderId = claim ? (claim.resource_id || claim.order_id) : null;
  if (orderId) {
    try {
      const od = await mlGet(`https://api.mercadolibre.com/orders/${orderId}`, token);
      const it = (od.order_items || [])[0] || {};
      let thumb = '';
      try { const itm = await mlGet(`https://api.mercadolibre.com/items/${it.item && it.item.id}`, token); thumb = imgProxy(itm.thumbnail); } catch (e) {}
      order = {
        order_id: orderId,
        title: (it.item && it.item.title) || '', qty: it.quantity || 1,
        unit_price: it.unit_price || 0, currency: od.currency_id || 'ARS',
        total: od.total_amount || 0, thumbnail: thumb,
        buyer: od.buyer && od.buyer.nickname || ''
      };
    } catch (e) {}
  }
  sendJSON(res, 200, {
    claim: claim ? { id: claim.id, status: claim.status, stage: claim.stage, type: claim.type, reason_id: claim.reason_id } : null,
    reason_detail: reasonText, detail_text: detailText,
    actions: [...actions], due_date: due, order
  });
});
// Acciones de resolución de un reclamo: contactar a ML (abrir disputa) o reembolsar (total/parcial).
route('POST', '/api/claims/action', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  if (sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { account_id, claim_id, action, percentage } = await parseBody(req);
  if (!claim_id || !action) return sendJSON(res, 400, { error: 'Faltan datos' });
  const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  let urls = [], body;
  if (action === 'open-dispute') {
    urls = [
      `https://api.mercadolibre.com/post-purchase/v1/claims/${claim_id}/actions/open-dispute`,
      `https://api.mercadolibre.com/marketplace/v2/claims/${claim_id}/actions/open-dispute`
    ];
  } else if (action === 'refund') {
    urls = [`https://api.mercadolibre.com/post-purchase/v1/claims/${claim_id}/expected-resolutions/refund`];
  } else if (action === 'partial-refund') {
    urls = [`https://api.mercadolibre.com/post-purchase/v1/claims/${claim_id}/expected-resolutions/partial-refund`];
    body = JSON.stringify({ percentage: Number(percentage) });
  } else {
    return sendJSON(res, 400, { error: 'Acción no soportada' });
  }
  let lastErr = '';
  for (const url of urls) {
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body });
      const t = await r.text();
      if (r.ok) return sendJSON(res, 200, { ok: true });
      try { lastErr = JSON.parse(t).message || JSON.parse(t).error || t; } catch (e) { lastErr = t; }
    } catch (e) { lastErr = e.message || 'error'; }
  }
  sendJSON(res, 500, { error: lastErr || 'No se pudo ejecutar la acción' });
});
// SALES
// In-memory caches to speed up repeated requests
const itemCache = {}; // cache item thumbnail/sku by item id (rarely changes)
const shipmentCacheGlobal = {}; // cache shipment info by shipping_id
route('GET', '/api/sales', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, 'http://localhost');
  const accountFilter = url.searchParams.get('account_id');
  const orderIdFilter = url.searchParams.get('order_id');
  const statusFilters = url.searchParams.get('status') ? url.searchParams.get('status').split(',') : [];
  const shippingFilters = url.searchParams.get('shipping') ? url.searchParams.get('shipping').split(',') : [];
  const dateFrom = url.searchParams.get('date_from');
  const dateTo = url.searchParams.get('date_to');
  const db = loadDB();
  let rawOrders = [];
  const targets = accountFilter ? db.ml_accounts.filter(a => a.id === parseInt(accountFilter)) : db.ml_accounts;
  // Fetch all accounts in parallel
  await Promise.all(targets.map(async (account) => {
    const token = await getValidToken(account);
    if (!token) return;
    try {
      let ordersData;
      if (orderIdFilter) {
        // Fetch single order by ID
        try {
          const singleOrder = await mlGet(`https://api.mercadolibre.com/orders/${orderIdFilter}`, token);
          ordersData = { results: [singleOrder] };
        } catch(e) {
          ordersData = { results: [] };
        }
      } else {
        const params = { seller: account.seller_id, sort: 'date_desc', limit: 50 };
        if (dateFrom) params['order.date_created.from'] = dateFrom + 'T00:00:00.000-00:00';
        if (dateTo) params['order.date_created.to'] = dateTo + 'T23:59:59.999-00:00';
        ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, params);
      }
      const orders = ordersData.results || [];
      // Step 1: Fetch all unique shipments in parallel
      const uniqueShipIds = [...new Set(orders.map(o => o.shipping?.id).filter(Boolean))];
      const newShipIds = uniqueShipIds.filter(id => !shipmentCacheGlobal[id]);
      if (newShipIds.length > 0) {
        const shipResults = await Promise.allSettled(newShipIds.map(async (sid) => {
          const shipment = await mlGet(`https://api.mercadolibre.com/shipments/${sid}`, token);
          const logType = shipment.logistic_type || '';
          const shippingName = (shipment.shipping_option?.name || '').toLowerCase();
          let sType = 'other';
          if (logType === 'self_service' || shippingName.includes('flex')) sType = 'flex';
          else if (logType === 'drop_off' || logType === 'xd_drop_off' || logType === 'cross_docking' || logType === 'fulfillment') sType = 'drop_off';
          else if (logType === 'custom' || logType === 'not_specified' || logType === '') sType = 'agreement';
          return { id: sid, type: sType, status: shipment.status || '', substatus: shipment.substatus || '' };
        }));
        for (const r of shipResults) {
          if (r.status === 'fulfilled') shipmentCacheGlobal[r.value.id] = r.value;
        }
      }
      // Step 2: Fetch all unique items in parallel
      const allItemIds = [...new Set(orders.flatMap(o => (o.order_items || []).map(oi => oi.item?.id)).filter(Boolean))];
      const newItemIds = allItemIds.filter(id => !itemCache[id]);
      if (newItemIds.length > 0) {
        const itemResults = await Promise.allSettled(newItemIds.map(async (itemId) => {
          const itemData = await mlGet(`https://api.mercadolibre.com/items/${itemId}`, token);
          let sku = itemData.seller_custom_field || '';
          if (!sku && itemData.attributes) {
            const skuAttr = itemData.attributes.find(a => a.id === 'SELLER_SKU');
            if (skuAttr) sku = skuAttr.value_name || '';
          }
          return { id: itemId, thumbnail: imgProxy(itemData.thumbnail), sku };
        }));
        for (const r of itemResults) {
          if (r.status === 'fulfilled') itemCache[r.value.id] = r.value;
        }
      }
      // Step 3: Build orders using cached data (no more API calls)
      for (const order of orders) {
        let shippingType = 'agreement', shippingStatus = '', shippingSubstatus = '';
        const shippingId = order.shipping?.id || null;
        if (shippingId && shipmentCacheGlobal[shippingId]) {
          const cached = shipmentCacheGlobal[shippingId];
          shippingType = cached.type;
          shippingStatus = cached.status;
          shippingSubstatus = cached.substatus;
        }
        let displayStatus = '';
        if (order.status === 'cancelled') displayStatus = 'cancelled';
        else if (shippingSubstatus === 'delayed') displayStatus = 'delayed';
        else if (shippingStatus === 'pending' || shippingStatus === '' || order.status === 'confirmed') displayStatus = 'pending';
        else if (shippingStatus === 'ready_to_ship' && shippingSubstatus === 'ready_to_print') displayStatus = 'ready_to_print';
        else if (shippingStatus === 'ready_to_ship') displayStatus = 'ready_to_ship';
        else if (shippingStatus === 'shipped' || shippingStatus === 'delivering') displayStatus = 'in_transit';
        else if (shippingStatus === 'delivered') displayStatus = 'delivered';
        else if (shippingStatus === 'not_delivered') displayStatus = 'not_completed';
        else displayStatus = shippingStatus || order.status || 'pending';
        if (statusFilters.length > 0 && !statusFilters.includes(displayStatus)) continue;
        if (shippingFilters.length > 0 && !shippingFilters.includes(shippingType)) continue;
        const items = [];
        for (const oi of (order.order_items || [])) {
          const cached = itemCache[oi.item?.id] || {};
          let sku = oi.item?.seller_sku || oi.item?.seller_custom_field || cached.sku || '';
          items.push({
            id: oi.item.id, title: oi.item.title || 'Producto', thumbnail: cached.thumbnail || '',
            quantity: oi.quantity || 1, unit_price: oi.unit_price || 0, sku
          });
        }
        rawOrders.push({
          order_id: order.id, pack_id: order.pack_id || null,
          date_created: order.date_created, status: displayStatus,
          shipping_type: shippingType, shipping_id: shippingId,
          total_amount: order.total_amount || 0,
          buyer_name: order.buyer?.nickname || 'Comprador', buyer_id: order.buyer?.id || '',
          account_name: account.name, account_id: account.id, seller_id: account.seller_id,
          items, affects_reputation: !(shippingStatus === 'cancelled' && shippingSubstatus === 'cancelled_manually')
        });
      }
    } catch (err) {
      console.error(`Error sales ${account.name}:`, err.response?.data || err.message || err);
    }
  }));
  // Group orders by pack_id (packs = multiple orders with same pack_id = ONE shipment)
  const packMap = {};
  const singles = [];
  for (const o of rawOrders) {
    if (o.pack_id) {
      if (!packMap[o.pack_id]) {
        packMap[o.pack_id] = { ...o, order_ids: [o.order_id], items: [...o.items] };
      } else {
        // Merge items and amounts into existing pack
        packMap[o.pack_id].items.push(...o.items);
        packMap[o.pack_id].total_amount += o.total_amount;
        packMap[o.pack_id].order_ids.push(o.order_id);
      }
    } else {
      singles.push({ ...o, order_ids: [o.order_id] });
    }
  }
  const allSales = [...Object.values(packMap), ...singles];
  allSales.sort((a, b) => new Date(b.date_created) - new Date(a.date_created));
  // Notes are fetched client-side to avoid token/timeout issues
  sendJSON(res, 200, allSales);
});
// FETCH NOTES for multiple orders (called by frontend after sales load)
route('POST', '/api/sales/notes/batch', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { orders } = await parseBody(req); // [{order_ids: [...], account_id: N}, ...]
  if (!orders || !Array.isArray(orders)) return sendJSON(res, 400, { error: 'Missing orders' });
  const results = {};
  const db = loadDB();
  for (const item of orders) {
    const orderIds = item.order_ids || [];
    const account = db.ml_accounts.find(a => a.id === parseInt(item.account_id));
    if (!account) continue;
    const token = await getValidToken(account);
    if (!token) continue;
    let foundNote = false;
    for (const orderId of orderIds) {
      if (foundNote) break;
      try {
        const noteRes = await fetch(`https://api.mercadolibre.com/orders/${orderId}/notes`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!noteRes.ok) continue;
        const noteBody = await noteRes.text();
        if (!noteBody) continue;
        let notesData;
        try { notesData = JSON.parse(noteBody); } catch(e) { continue; }
        let notesArray = [];
        if (Array.isArray(notesData)) notesArray = notesData;
        else if (notesData && typeof notesData === 'object') {
          if (Array.isArray(notesData.results)) notesArray = notesData.results;
          else if (notesData.note || notesData.text) notesArray = [notesData];
        }
        if (notesArray.length > 0) {
          const first = notesArray[0];
          results[orderIds[0]] = {
            notes: first.note || first.text || '',
            note_id: first.id || null,
            note_order_id: orderId
          };
          foundNote = true;
        }
      } catch (e) {
        console.error(`Error batch notes order ${orderId}:`, e.message || e);
      }
    }
  }
  sendJSON(res, 200, results);
});
// SALE NOTES - sync with ML API
route('POST', '/api/sales/notes', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { order_id, account_id, note_id, notes } = await parseBody(req);
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  try {
    if (note_id) {
      // Update existing note in ML
      const updateRes = await fetch(`https://api.mercadolibre.com/orders/${order_id}/notes/${note_id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ note: notes })
      });
      const data = await updateRes.json();
      console.log(`NOTE UPDATE order ${order_id}:`, JSON.stringify(data).substring(0, 300));
      if (!updateRes.ok) throw { response: { data } };
      sendJSON(res, 200, { ok: true, note_id });
    } else {
      // Create new note in ML
      const createRes = await fetch(`https://api.mercadolibre.com/orders/${order_id}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ note: notes })
      });
      const data = await createRes.json();
      if (!createRes.ok) throw { response: { data } };
      sendJSON(res, 200, { ok: true, note_id: data.id || null });
    }
  } catch (err) {
    console.error('Error saving note:', err.response?.data || err.message || err);
    sendJSON(res, 500, { error: err.response?.data?.message || 'Error al guardar nota' });
  }
});
// DEBUG NOTES - endpoint to see raw ML response
route('GET', '/api/sales/debug-notes', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, 'http://localhost');
  const orderId = url.searchParams.get('order_id');
  const accountId = url.searchParams.get('account_id');
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(accountId));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  try {
    const noteRes = await fetch(`https://api.mercadolibre.com/orders/${orderId}/notes`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const noteBody = await noteRes.text();
    sendJSON(res, 200, {
      order_id: orderId,
      ml_status: noteRes.status,
      ml_raw_response: noteBody,
      ml_headers: Object.fromEntries(noteRes.headers.entries())
    });
  } catch (e) {
    sendJSON(res, 500, { error: e.message });
  }
});
// GET NOTE for a single order (clean endpoint for frontend)
route('GET', '/api/sales/note', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, 'http://localhost');
  const orderId = url.searchParams.get('order_id');
  const accountId = url.searchParams.get('account_id');
  if (!orderId || !accountId) return sendJSON(res, 400, { error: 'Faltan parametros' });
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(accountId));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  // Re-read account from DB to get the freshest token
  const freshDb = loadDB();
  const freshAccount = freshDb.ml_accounts.find(a => a.id === parseInt(accountId));
  const token = await getValidToken(freshAccount || account);
  if (!token) {
    console.error('[NOTE] No valid token for account', accountId);
    return sendJSON(res, 500, { error: 'Token invalido' });
  }
  try {
    console.log('[NOTE] Fetching ML notes for order', orderId, 'token starts:', token.substring(0, 15));
    const noteRes = await fetch(`https://api.mercadolibre.com/orders/${orderId}/notes`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const noteBody = await noteRes.text();
    console.log('[NOTE] Order', orderId, 'ML status:', noteRes.status, 'body:', noteBody.substring(0, 300));
    // Always include ml_status so frontend can debug
    if (noteRes.status !== 200) {
      return sendJSON(res, 200, { order_id: orderId, note: null, note_id: null, ml_status: noteRes.status, ml_body: noteBody.substring(0, 500) });
    }
    const noteData = JSON.parse(noteBody);
    // ML returns an ARRAY: [{"results":[...],"order_id":N}]
    const entry = Array.isArray(noteData) ? noteData[0] : noteData;
    if (entry && entry.results && entry.results.length > 0) {
      const n = entry.results[0];
      return sendJSON(res, 200, { order_id: orderId, note: n.note, note_id: n.id, ml_status: 200 });
    }
    sendJSON(res, 200, { order_id: orderId, note: null, note_id: null, ml_status: 200, ml_results_count: 0 });
  } catch (e) {
    console.error('[NOTE] Error for order', orderId, e.message);
    sendJSON(res, 200, { order_id: orderId, note: null, note_id: null, error: e.message });
  }
});
// SHIPPING LABEL URL
route('GET', '/api/sales/label', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const url = new URL(req.url, 'http://localhost');
  const shipmentId = url.searchParams.get('shipment_id');
  const accountId = url.searchParams.get('account_id');
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(accountId));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 500, { error: 'Token invalido' });
  try {
    // Get label URL - ML returns a redirect to the PDF
    const labelRes = await fetch(`https://api.mercadolibre.com/shipment_labels?shipment_ids=${shipmentId}&response_type=pdf`, {
      headers: { Authorization: `Bearer ${token}` },
      redirect: 'manual'
    });
    const labelUrl = labelRes.headers.get('location') || `https://api.mercadolibre.com/shipment_labels?shipment_ids=${shipmentId}&response_type=pdf&access_token=${token}`;
    sendJSON(res, 200, { url: labelUrl });
  } catch (err) {
    console.error('Error label:', err.message || err);
    sendJSON(res, 500, { error: 'Error al obtener etiqueta' });
  }
});
// QUICK REPLIES
route('GET', '/api/quick-replies', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  sendJSON(res, 200, db.quick_replies || []);
});
route('POST', '/api/quick-replies', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { replies } = await parseBody(req);
  if (!Array.isArray(replies)) return sendJSON(res, 400, { error: 'Formato invalido' });
  const db = loadDB();
  db.quick_replies = replies;
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// FIRMA (cierre) — cada usuario guarda la suya, para firmar con su nombre.
route('POST', '/api/me/firma', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const { firma } = await parseBody(req);
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  if (!user) return sendJSON(res, 404, { error: 'Usuario no encontrado' });
  user.firma = String(firma || '').slice(0, 500);
  saveDB(db);
  sendJSON(res, 200, { ok: true, firma: user.firma });
});
// SALUDO inicial (global) — solo el admin lo configura.
route('POST', '/api/saludo', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { saludo } = await parseBody(req);
  const db = loadDB();
  db.saludo_inicial = String(saludo ?? '').slice(0, 500);
  saveDB(db);
  sendJSON(res, 200, { ok: true, saludo: db.saludo_inicial });
});
// STATS
route('GET', '/api/stats', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  let totalUnanswered = 0, totalAnsweredToday = 0;
  let salesToday = 0, revenueToday = 0, unitsSoldToday = 0;
  let totalUnreadMessages = 0;
  const salesByAccount = [];
  // Today's date range in Argentina time (UTC-3)
  const now = new Date();
  const argNow = new Date(now.getTime() - 3 * 60 * 60 * 1000);
  const todayStart = new Date(Date.UTC(argNow.getUTCFullYear(), argNow.getUTCMonth(), argNow.getUTCDate(), 3, 0, 0)).toISOString();
  for (const account of db.ml_accounts) {
    const token = await getValidToken(account);
    if (!token) continue;
    try {
      const u = await mlGet('https://api.mercadolibre.com/questions/search', token, { seller_id: account.seller_id, status: 'UNANSWERED', limit: 0 });
      totalUnanswered += u.total || 0;
      // Only today's answered questions
      const a = await mlGet('https://api.mercadolibre.com/questions/search', token, { seller_id: account.seller_id, status: 'ANSWERED', limit: 50 });
      const todayAnswered = (a.questions || []).filter(q => q.date_created && q.date_created >= todayStart).length;
      totalAnsweredToday += todayAnswered;
    } catch (e) {}
    // Count unread messages
    try {
      const msgData = await mlGet('https://api.mercadolibre.com/messages/packs', token, {
        seller: account.seller_id, tag: 'unread', limit: 0
      });
      totalUnreadMessages += msgData.paging?.total || 0;
    } catch (e) {}
    // Fetch today's sales if user has dashboard permission
    if (user?.view_dashboard !== false) {
      let accountSales = 0, accountRevenue = 0, accountUnits = 0;
      try {
        const ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, {
          seller: account.seller_id, sort: 'date_desc',
          'order.date_created.from': todayStart,
          limit: 50
        });
        for (const order of (ordersData.results || [])) {
          if (order.status === 'cancelled') continue;
          salesToday++; accountSales++;
          revenueToday += order.total_amount || 0;
          accountRevenue += order.total_amount || 0;
          for (const item of (order.order_items || [])) {
            unitsSoldToday += item.quantity || 0;
            accountUnits += item.quantity || 0;
          }
        }
      } catch (e) {
        console.error(`Error fetching sales for ${account.name}:`, e.response?.data || e.message || e);
      }
      salesByAccount.push({ name: account.name, sales: accountSales, revenue: accountRevenue, units: accountUnits });
    }
  }
  sendJSON(res, 200, {
    accounts: db.ml_accounts.length, unanswered: totalUnanswered, answered_today: totalAnsweredToday,
    unread_messages: totalUnreadMessages,
    sales_today: salesToday, revenue_today: revenueToday, units_sold_today: unitsSoldToday,
    sales_by_account: salesByAccount,
    can_view_dashboard: user?.view_dashboard !== false
  });
});
// DASHBOARD CHART — datos diarios de ventas/dinero/unidades/preguntas para el período
route('GET', '/api/dashboard-chart', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  if (user?.view_dashboard === false) return sendJSON(res, 403, { error: 'Sin permiso' });
  const urlObj = new URL(req.url, 'http://localhost');
  const accountId = urlObj.searchParams.get('account_id') || '';
  // Argentina = UTC-3
  const now = new Date();
  const argNow = new Date(now.getTime() - 3 * 60 * 60 * 1000);
  // Inicio del día actual en Argentina (= 03:00 UTC)
  const todayArgStart = new Date(Date.UTC(argNow.getUTCFullYear(), argNow.getUTCMonth(), argNow.getUTCDate(), 3, 0, 0));
  // Rango: si vienen from/to (YYYY-MM-DD) se usa ese rango personalizado; si no, el atajo period (1/7/30).
  const _dre = /^\d{4}-\d{2}-\d{2}$/;
  const fromParam = urlObj.searchParams.get('from') || '';
  const toParam = urlObj.searchParams.get('to') || '';
  let period, periodStart;
  if (_dre.test(fromParam) && _dre.test(toParam)) {
    const [fy, fm, fd] = fromParam.split('-').map(Number);
    const [ty, tm, td] = toParam.split('-').map(Number);
    periodStart = new Date(Date.UTC(fy, fm - 1, fd, 3, 0, 0)); // inicio del día ARG de "from"
    const toStart = new Date(Date.UTC(ty, tm - 1, td, 3, 0, 0));
    let days = Math.floor((toStart - periodStart) / (24 * 60 * 60 * 1000)) + 1;
    if (!(days >= 1)) days = 1;
    if (days > 92) { days = 92; periodStart = new Date(toStart.getTime() - 91 * 24 * 60 * 60 * 1000); } // tope 92 días
    period = days;
  } else {
    period = Math.max(1, Math.min(30, parseInt(urlObj.searchParams.get('period') || '7')));
    periodStart = new Date(todayArgStart.getTime() - (period - 1) * 24 * 60 * 60 * 1000);
  }
  const dateFrom = periodStart.toISOString();
  // Mapa de días: clave = 'YYYY-MM-DD' en hora argentina
  const dayData = {};
  for (let i = 0; i < period; i++) {
    const utcMs = periodStart.getTime() + i * 24 * 60 * 60 * 1000;
    const argD = new Date(utcMs - 3 * 60 * 60 * 1000); // display en ARG
    const key = argD.toISOString().slice(0, 10);
    dayData[key] = { sales: 0, revenue: 0, units: 0, questions: 0 };
  }
  const targets = accountId
    ? db.ml_accounts.filter(a => String(a.id) === accountId)
    : db.ml_accounts;
  for (const account of targets) {
    const token = await getValidToken(account);
    if (!token) continue;
    // Ventas del período
    try {
      let offset = 0;
      while (true) {
        const ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, {
          seller: account.seller_id, sort: 'date_desc',
          'order.date_created.from': dateFrom,
          limit: 50, offset
        });
        const results = ordersData.results || [];
        for (const order of results) {
          if (order.status === 'cancelled') continue;
          const orderUtc = new Date(order.date_created);
          const orderArg = new Date(orderUtc.getTime() - 3 * 60 * 60 * 1000);
          const key = orderArg.toISOString().slice(0, 10);
          if (dayData[key]) {
            dayData[key].sales++;
            dayData[key].revenue += order.total_amount || 0;
            for (const it of (order.order_items || [])) dayData[key].units += it.quantity || 0;
          }
        }
        offset += results.length;
        // Tope de órdenes por cuenta: escala con el largo del período (rango personalizado largo → más órdenes).
        const _maxOrders = Math.max(500, period * 60);
        if (!results.length || offset >= (ordersData.paging?.total || 0) || offset >= _maxOrders) break;
      }
    } catch(e) {}
    // Preguntas respondidas en el período
    try {
      const qData = await mlGet('https://api.mercadolibre.com/questions/search', token, {
        seller_id: account.seller_id, status: 'ANSWERED', limit: 50
      });
      for (const q of (qData.questions || [])) {
        if (!q.date_created || q.date_created < dateFrom) continue;
        const qArg = new Date(new Date(q.date_created).getTime() - 3 * 60 * 60 * 1000);
        const key = qArg.toISOString().slice(0, 10);
        if (dayData[key]) dayData[key].questions++;
      }
    } catch(e) {}
  }
  const days = Object.keys(dayData).sort();
  sendJSON(res, 200, {
    days,
    sales: days.map(d => dayData[d].sales),
    revenue: days.map(d => Math.round(dayData[d].revenue)),
    units: days.map(d => dayData[d].units),
    questions: days.map(d => dayData[d].questions),
  });
});
// DELETE ACCOUNT
route('DELETE', '/api/accounts/delete', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { id } = await parseBody(req);
  const db = loadDB();
  const idx = db.ml_accounts.findIndex(a => a.id === parseInt(id));
  if (idx === -1) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  db.ml_accounts.splice(idx, 1);
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// DELETE USER
route('DELETE', '/api/users/delete', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { id } = await parseBody(req);
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === parseInt(id));
  if (idx === -1) return sendJSON(res, 404, { error: 'No encontrado' });
  if (db.users[idx].role === 'admin') return sendJSON(res, 400, { error: 'No se puede eliminar al admin' });
  db.users.splice(idx, 1);
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// ==================== BACKUP / RESTORE ====================
// GET backup - returns current data.json as downloadable JSON (admin only)
route('GET', '/api/backup', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const db = loadDB();
  db.sessions = sessions; // Include sessions in backup
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Disposition': 'attachment; filename="autochap_backup.json"'
  });
  res.end(JSON.stringify(db, null, 2));
});
// GET backup as base64 - returns the string you need to paste in Render DB_BACKUP env var
route('GET', '/api/backup/env', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const db = loadDB();
  // Include sessions in backup so logins persist across deploys
  db.sessions = sessions;
  const b64 = Buffer.from(JSON.stringify(db)).toString('base64');
  sendJSON(res, 200, {
    instructions: 'Copia este valor y pegalo en Render > Environment > Secret Files > db_backup.txt. Asi tus datos se restauran automaticamente en cada deploy.',
    base64: b64,
    users: db.users.length,
    accounts: (db.ml_accounts || []).length,
    quick_replies: (db.quick_replies || []).length,
    sessions: Object.keys(sessions).length
  });
});
// POST restore - restores data.json from uploaded JSON (admin only)
route('POST', '/api/restore', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const body = await parseBody(req);
  if (!body.users || !Array.isArray(body.users)) {
    return sendJSON(res, 400, { error: 'JSON invalido - debe contener users[]' });
  }
  saveDB(body);
  console.log('[RESTORE] Base de datos restaurada:', body.users.length, 'usuarios,', (body.ml_accounts || []).length, 'cuentas ML');
  sendJSON(res, 200, { ok: true, users: body.users.length, accounts: (body.ml_accounts || []).length });
});
// ==================== PREP ROUTES ====================
route('GET', '/api/prep/list', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepOperate(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const url = new URL(req.url, 'http://localhost');
  const statusFilter = url.searchParams.get('status');
  const db = loadDB();
  let orders = db.prep_orders || [];
  if (statusFilter) orders = orders.filter(o => o.status === statusFilter);
  sendJSON(res, 200, orders);
});
route('POST', '/api/prep/add', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const body = await parseBody(req);
  const { order_id, order_ids, pack_id, account_id, account_name, seller_id, buyer_name, buyer_id, items, shipping_id, shipping_type, total_amount, date_created, priority, notes, note_id, finish_type, shipping_data } = body;
  if (!order_id) return sendJSON(res, 400, { error: 'Falta order_id' });
  const validFinishTypes = ['dropshipping', 'puerta'];
  const isDirectDone = validFinishTypes.includes(finish_type);
  const db = loadDB();
  if (!db.prep_orders) db.prep_orders = [];
  const existing = db.prep_orders.find(o => o.order_id === String(order_id));
  if (existing) {
    if (isDirectDone && existing.status !== 'done') {
      existing.status = 'done';
      existing.finish_type = finish_type;
      existing.done_at = new Date().toISOString();
      existing.done_by = sess.username;
    } else {
      existing.priority = priority || existing.priority;
    }
    saveDB(db);
    return sendJSON(res, 200, { ok: true, updated: true });
  }
  const now = new Date().toISOString();
  db.prep_orders.push({
    order_id: String(order_id),
    order_ids: order_ids || [String(order_id)],
    pack_id: pack_id || null,
    account_id, account_name, seller_id,
    buyer_name, buyer_id: String(buyer_id || ''),
    items: items || [],
    shipping_id: shipping_id ? String(shipping_id) : null,
    shipping_type: shipping_type || 'drop_off',
    total_amount: total_amount || 0,
    date_created: date_created || now,
    status: isDirectDone ? 'done' : 'in_prep',
    finish_type: finish_type || 'normal',
    priority: priority || 3,
    notes: notes || '',
    note_id: note_id || null,
    added_at: now,
    added_by: sess.username,
    done_at: isDirectDone ? now : null,
    done_by: isDirectDone ? sess.username : null,
    shipping_data: shipping_data || null
  });
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
route('POST', '/api/prep/shipping', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess) && !canPrepOperate(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { order_id, shipping_data } = await parseBody(req);
  if (!order_id) return sendJSON(res, 400, { error: 'Falta order_id' });
  const db = loadDB();
  const order = (db.prep_orders || []).find(o => o.order_id === String(order_id));
  if (!order) return sendJSON(res, 404, { error: 'Orden no encontrada' });
  order.shipping_data = shipping_data || null;
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
route('POST', '/api/prep/priority', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { order_id, priority } = await parseBody(req);
  if (!order_id) return sendJSON(res, 400, { error: 'Falta order_id' });
  const db = loadDB();
  const order = (db.prep_orders || []).find(o => o.order_id === String(order_id));
  if (!order) return sendJSON(res, 404, { error: 'Orden no encontrada' });
  order.priority = Math.max(1, Math.min(5, parseInt(priority) || 3));
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
route('POST', '/api/prep/finish', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepOperate(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { order_id } = await parseBody(req);
  if (!order_id) return sendJSON(res, 400, { error: 'Falta order_id' });
  const db = loadDB();
  const order = (db.prep_orders || []).find(o => o.order_id === String(order_id));
  if (!order) return sendJSON(res, 404, { error: 'Orden no encontrada' });
  order.status = 'done';
  order.done_at = new Date().toISOString();
  order.done_by = sess.username;
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// ESTADISTICAS DE PREPARACION (solo admin) — pedidos finalizados por rango de fechas
// GET /api/prep/stats?from=YYYY-MM-DD&to=YYYY-MM-DD  (fechas en hora Argentina, UTC-3)
route('GET', '/api/prep/stats', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado (solo admin)' });
  const url = new URL(req.url, 'http://localhost');
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  const ARG = 3 * 3600 * 1000; // UTC-3
  const localDate = iso => new Date(new Date(iso).getTime() - ARG).toISOString().slice(0, 10);
  const localHM = ms => new Date(ms - ARG).toISOString().slice(11, 16);
  const localDT = ms => new Date(ms - ARG).toISOString().replace('T', ' ').slice(0, 16);
  const db = loadDB();
  const done = (db.prep_orders || []).filter(o => o.status === 'done' && o.done_at);
  const inRange = done.filter(o => {
    const d = localDate(o.done_at);
    if (from && d < from) return false;
    if (to && d > to) return false;
    return true;
  });
  const shipKey = t => (t === 'flex') ? 'flex' : (t === 'drop_off') ? 'drop_off' : 'agreement';
  const by_shipping = { flex: 0, drop_off: 0, agreement: 0 };
  const by_user = {};
  const byDay = {};
  for (const o of inRange) {
    by_shipping[shipKey(o.shipping_type)]++;
    const u = o.done_by || '(sin usuario)';
    by_user[u] = (by_user[u] || 0) + 1;
    const day = localDate(o.done_at);
    const ms = new Date(o.done_at).getTime();
    (byDay[day] = byDay[day] || []).push(ms);
  }
  let sumWindowMs = 0;
  const por_dia = [];
  for (const day of Object.keys(byDay).sort()) {
    const t = byDay[day];
    const mn = Math.min.apply(null, t), mx = Math.max.apply(null, t);
    const w = mx - mn;
    sumWindowMs += w;
    por_dia.push({
      dia: day, count: t.length, primer: localHM(mn), ultimo: localHM(mx),
      min_por_pedido: t.length ? Math.round((w / 60000) / t.length * 10) / 10 : 0
    });
  }
  const total = inRange.length;
  const avg_pack_min = total ? Math.round((sumWindowMs / 60000) / total * 10) / 10 : 0;
  const allMs = inRange.map(o => new Date(o.done_at).getTime());
  const by_user_arr = Object.keys(by_user).map(u => ({ user: u, count: by_user[u] })).sort((a, b) => b.count - a.count);
  sendJSON(res, 200, {
    from, to, total, by_shipping, by_user: by_user_arr, avg_pack_min,
    primer: allMs.length ? localDT(Math.min.apply(null, allMs)) : null,
    ultimo: allMs.length ? localDT(Math.max.apply(null, allMs)) : null,
    por_dia
  });
});
// PACE DE EMBALAJE para la solapa "En preparación" — visible para TODOS los usuarios de preparación
// (no solo admin). Devuelve el promedio de embalaje y la ventana (primer→último) de HOY, y el
// promedio de embalaje de los últimos 7 días. "Promedio de embalaje" = ventana / cantidad (mismo
// criterio que /api/prep/stats). Fechas en hora Argentina (UTC-3).
route('GET', '/api/prep/pace', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess) && !canPrepOperate(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const ARG = 3 * 3600 * 1000; // UTC-3
  const localDate = iso => new Date(new Date(iso).getTime() - ARG).toISOString().slice(0, 10);
  const localHM = ms => new Date(ms - ARG).toISOString().slice(11, 16);
  const todayStr = new Date(Date.now() - ARG).toISOString().slice(0, 10);
  const day7 = new Date(Date.now() - ARG - 6 * 86400000).toISOString().slice(0, 10); // hoy y los 6 anteriores
  const db = loadDB();
  const done = (db.prep_orders || []).filter(o => o.status === 'done' && o.done_at);
  const byDay = {};
  for (const o of done) {
    const d = localDate(o.done_at);
    if (d < day7) continue;
    (byDay[d] = byDay[d] || []).push(new Date(o.done_at).getTime());
  }
  const th = byDay[todayStr] || [];
  let hoy;
  if (th.length) {
    const mn = Math.min.apply(null, th), mx = Math.max.apply(null, th);
    const wMin = (mx - mn) / 60000;
    hoy = { count: th.length, primer: localHM(mn), ultimo: localHM(mx), ventana_min: Math.round(wMin), avg_pack_min: Math.round(wMin / th.length * 10) / 10 };
  } else {
    hoy = { count: 0, primer: null, ultimo: null, ventana_min: 0, avg_pack_min: 0 };
  }
  // Últimos 7 días: suma de ventanas diarias / total de pedidos (consistente con /api/prep/stats).
  let sumW = 0, tot = 0, nDays = 0;
  for (const d of Object.keys(byDay)) {
    const t = byDay[d]; if (!t.length) continue;
    sumW += (Math.max.apply(null, t) - Math.min.apply(null, t)); tot += t.length; nDays++;
  }
  const last7 = { count: tot, days: nDays, avg_pack_min: tot ? Math.round((sumW / 60000) / tot * 10) / 10 : 0 };
  sendJSON(res, 200, { today: todayStr, hoy, last7 });
});
route('GET', '/api/prep/export', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const db = loadDB();
  const orders = (db.prep_orders || []).filter(o => o.status === 'done');
  const today = new Date().toISOString().slice(0, 10);
  const BOM = '﻿';
  const headers = ['N° Orden','Pack ID','Cuenta ML','Comprador','Comprador ID','Fecha Compra','Producto(s)','SKU(s)','Cantidad Total','Tipo Envío','Total ARS','Prioridad','Notas','Fecha Agregada','Finalizado Por','Fecha Finalizado','Tipo Finalización'];
  const finishTypeLabel = { dropshipping: 'Dropshipping', puerta: 'Puerta', normal: 'Normal' };
  const rows = orders.map(o => {
    const products = (o.items || []).map(i => i.title).join(' | ');
    const skus = (o.items || []).map(i => i.sku || '').join(' | ');
    const totalQty = (o.items || []).reduce((sum, i) => sum + (i.quantity || 0), 0);
    const shippingLabel = o.shipping_type === 'flex' ? 'FLEX' : o.shipping_type === 'drop_off' ? 'PUNTO DESPACHO' : 'ACORDAR';
    function csvCell(v) { const s = String(v == null ? '' : v); return s.includes(',') || s.includes('"') || s.includes('\n') ? '"' + s.replace(/"/g, '""') + '"' : s; }
    return [
      o.order_id, o.pack_id || '', o.account_name, o.buyer_name, o.buyer_id,
      o.date_created ? new Date(o.date_created).toLocaleString('es-AR') : '',
      products, skus, totalQty, shippingLabel, o.total_amount || 0,
      o.priority || '', o.notes || '',
      o.added_at ? new Date(o.added_at).toLocaleString('es-AR') : '',
      o.done_by || '',
      o.done_at ? new Date(o.done_at).toLocaleString('es-AR') : '',
      finishTypeLabel[o.finish_type] || 'Normal'
    ].map(csvCell).join(',');
  });
  const csv = BOM + [headers.join(','), ...rows].join('\r\n');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="autochap_prep_${today}.csv"`
  });
  res.end(csv);
});
route('POST', '/api/prep/note', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { order_id, notes } = await parseBody(req);
  if (!order_id) return sendJSON(res, 400, { error: 'Falta order_id' });
  const db = loadDB();
  const order = (db.prep_orders || []).find(o => o.order_id === String(order_id));
  if (!order) return sendJSON(res, 404, { error: 'Orden no encontrada' });
  order.notes = notes || '';
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
route('POST', '/api/prep/reset', async (req, res) => {
  const sess = requireAuth(req);
  if (!canPrepManage(sess)) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { order_id } = await parseBody(req);
  if (!order_id) return sendJSON(res, 400, { error: 'Falta order_id' });
  const db = loadDB();
  const idx = (db.prep_orders || []).findIndex(o => o.order_id === String(order_id));
  if (idx === -1) return sendJSON(res, 404, { error: 'Orden no encontrada' });
  const removed = db.prep_orders.splice(idx, 1)[0];
  saveDB(db);
  console.log(`[PREP RESET] Orden ${order_id} devuelta a Sin Preparar por ${sess.username} (estaba en ${removed.status})`);
  sendJSON(res, 200, { ok: true });
});
// ==================== STATIC FILES ====================
const MIME_TYPES = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
};
function serveStatic(req, res) {
  const publicDir = path.join(__dirname, 'public');
  // Decode and normalize the requested path before joining, then verify the
  // resolved path stays inside publicDir to prevent path traversal
  // (e.g. /../../.env or %2e%2e%2f tricks).
  let requestedPath;
  try {
    requestedPath = decodeURIComponent(req.url === '/' ? '/index.html' : req.url.split('?')[0]);
  } catch (e) {
    requestedPath = '/index.html';
  }
  const filePath = path.join(publicDir, requestedPath);
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(publicDir + path.sep) && resolved !== publicDir) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  const ext = path.extname(resolved);
  fs.readFile(resolved, (err, data) => {
    if (err) {
      fs.readFile(path.join(publicDir, 'index.html'), (err2, data2) => {
        if (err2) { res.writeHead(404); return res.end('Not found'); }
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data2);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  });
}
// ==================== PROMOTIONS ====================
const PROMO_BASE = 'https://api.mercadolibre.com/marketplace/seller-promotions';
const PROMO_OLD_BASE = 'https://api.mercadolibre.com/seller-promotions';
// Header obligatorio para la API marketplace de seller-promotions
const promoH = () => ({ 'version': 'v2' });
function arrFromPromoResponse(r) {
  if (Array.isArray(r)) return r;
  return r?.results || r?.items || r?.data || r?.promotions || [];
}
function buildPromoItemsUrl(baseUrl, promoId, sellerId, limit, searchAfter, itemId) {
  let url = baseUrl;
  const sep = url.includes('?') ? '&' : '?';
  url += `${sep}user_id=${encodeURIComponent(sellerId)}&limit=${encodeURIComponent(limit)}`;
  if (itemId) url += `&item_id=${encodeURIComponent(itemId)}`;
  if (searchAfter) url += `&search_after=${encodeURIComponent(searchAfter)}`;
  return url;
}
function promoItemCandidates(account, promoId, userToken, appTok, limit = 50, searchAfter = null, itemId = null) {
  const sid = account.seller_id;
  const appId = String(ML_CLIENT_ID || '');
  const commonNew = `${PROMO_BASE}/promotions/${promoId}/items`;
  const commonOld = `${PROMO_OLD_BASE}/promotions/${promoId}/items`;
  const oldWithApp200 = `${commonOld}?app_id=${encodeURIComponent(appId)}&app_version=2.0.0`;
  const oldWithAppV2 = `${commonOld}?app_id=${encodeURIComponent(appId)}&app_version=v2`;
  const oldPlain = `${commonOld}`;
  return [
    { label: 'marketplace_app_v2', token: appTok, headers: promoH(), url: buildPromoItemsUrl(commonNew, promoId, sid, limit, searchAfter, itemId) },
    { label: 'marketplace_user_v2', token: userToken, headers: promoH(), url: buildPromoItemsUrl(commonNew, promoId, sid, limit, searchAfter, itemId) },
    { label: 'old_user_app_2_0_0', token: userToken, headers: {}, url: buildPromoItemsUrl(oldWithApp200, promoId, sid, limit, searchAfter, itemId) },
    { label: 'old_user_app_v2', token: userToken, headers: {}, url: buildPromoItemsUrl(oldWithAppV2, promoId, sid, limit, searchAfter, itemId) },
    { label: 'old_user_plain', token: userToken, headers: {}, url: buildPromoItemsUrl(oldPlain, promoId, sid, limit, searchAfter, itemId) },
    { label: 'old_app_app_2_0_0', token: appTok, headers: {}, url: buildPromoItemsUrl(oldWithApp200, promoId, sid, limit, searchAfter, itemId) }
  ].filter(c => c.token);
}
async function findWorkingPromoItemsCandidate(account, promoId, userToken, appTok, itemId = null) {
  const debug = [];
  for (const c of promoItemCandidates(account, promoId, userToken, appTok, 50, null, itemId)) {
    try {
      const r = await mlGet(c.url, c.token, {}, c.headers);
      const items = arrFromPromoResponse(r);
      const total = r?.paging?.total ?? r?.total ?? items.length ?? 0;
      debug.push({ tried: c.label, status: 200, total, items: items.length, keys: Object.keys(r || {}) });
      if (items.length > 0 || total > 0) return { candidate: c, firstResponse: r, firstItems: items, debug };
    } catch (e) {
      debug.push({
        tried: c.label,
        status: e?.response?.status || null,
        error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
      });
    }
  }
  return { candidate: null, firstResponse: null, firstItems: [], debug };
}
async function getPromoItemStatus(account, promoId, itemId, userToken, appTok) {
  const found = await findWorkingPromoItemsCandidate(account, promoId, userToken, appTok, itemId);
  const arr = arrFromPromoResponse(found.firstResponse);
  const it = arr.find(x => String(x.item_id || x.id || x.item?.id || '') === String(itemId)) || arr[0] || null;
  if (!it) return { in_promo: false, new_price: null, discount: null, promo_status: null, debug: found.debug };
  const status = String(it.status || it.item_status || '').toUpperCase();
  const active = status && !['INACTIVE','FINISHED','DELETED','REMOVED','CANCELLED'].includes(status);
  return {
    in_promo: !!active,
    new_price: it.new_price ?? it.price ?? it.promotion_price ?? null,
    discount: it.discount ?? it.discount_percentage ?? null,
    promo_status: it.status ?? null,
    debug: found.debug
  };
}
// Token de app (client_credentials) — algunos endpoints ML exigen que el caller sea la APP, no el usuario
let _appToken = null, _appTokenExp = 0;
async function getAppToken() {
  if (_appToken && Date.now() < _appTokenExp) return _appToken;
  try {
    const r = await fetch('https://api.mercadolibre.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=client_credentials&client_id=${ML_CLIENT_ID}&client_secret=${ML_CLIENT_SECRET}`
    });
    if (!r.ok) { console.log('[AppToken] Error:', r.status, await r.text()); return null; }
    const d = await r.json();
    _appToken = d.access_token;
    _appTokenExp = Date.now() + ((d.expires_in || 21600) - 300) * 1000;
    console.log('[AppToken] Obtenido OK');
    return _appToken;
  } catch(e) { console.log('[AppToken] Excepción:', e.message); return null; }
}
// GET /api/promotions?account_id=X — lista campañas
route('GET', '/api/promotions', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbP = loadDB(); const uP = dbP.users.find(u => u.id === sess.userId);
  if (sess.role !== 'admin' && !uP?.can_view_promos) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const urlObj = new URL(req.url, 'http://localhost');
  const accountId = urlObj.searchParams.get('account_id');
  const db = loadDB();
  const targets = accountId
    ? db.ml_accounts.filter(a => a.id === parseInt(accountId))
    : db.ml_accounts;
  const appTok = await getAppToken();
  const results = [];
  const debug = [];
  for (const account of targets) {
    try {
      const token = await getValidToken(account);
      if (!token) { debug.push({ account: account.name, error: 'sin token de usuario' }); continue; }
      const sid = account.seller_id;
      const appId = String(ML_CLIENT_ID || '');
      const candidates = [
        { label: 'old_user_app_2_0_0', url: `${PROMO_OLD_BASE}/users/${sid}?app_id=${encodeURIComponent(appId)}&app_version=2.0.0`, headers: {}, tok: token },
        { label: 'old_user_app_v2',    url: `${PROMO_OLD_BASE}/users/${sid}?app_id=${encodeURIComponent(appId)}&app_version=v2`, headers: {}, tok: token },
        { label: 'old_user_app_v1',    url: `${PROMO_OLD_BASE}/users/${sid}?app_id=${encodeURIComponent(appId)}&app_version=v1`, headers: {}, tok: token },
        { label: 'marketplace_app_v2', url: `${PROMO_BASE}/users/${sid}`, headers: promoH(), tok: appTok },
        { label: 'marketplace_user_v2', url: `${PROMO_BASE}/users/${sid}`, headers: promoH(), tok: token },
      ];
      let found = false;
      for (const c of candidates) {
        if (!c.tok) { debug.push({ account: account.name, tried: c.label, skipped: 'sin token' }); continue; }
        try {
          const r = await mlGet(c.url, c.tok, {}, c.headers);
          const promos = arrFromPromoResponse(r);
          debug.push({ account: account.name, GANADOR: c.label, campañas: promos.length, keys: Object.keys(r || {}) });
          for (const p of promos) {
            results.push({
              ...p,
              account_id: account.id,
              account_name: account.name,
              seller_id: account.seller_id,
              _source: c.label
            });
          }
          found = true;
          break;
        } catch(e) {
          debug.push({
            account: account.name,
            tried: c.label,
            httpStatus: e?.response?.status || null,
            error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
          });
        }
      }
      if (!found) debug.push({ account: account.name, conclusion: 'NINGUNO funcionó' });
    } catch(e) {
      debug.push({ account: account.name, error: e.message || String(e) });
    }
  }
  sendJSON(res, 200, { results, debug });
});
// GET /api/promotion-items-stream?account_id=X&promo_id=Y&promo_type=Z
// v5 inteligente:
// 1) intenta endpoints directos/acotados por campaña
// 2) si no obtiene datos, usa fallback de escaneo completo con search_type=scan
route('GET', '/api/promotion-items-stream', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbP2 = loadDB(); const uP2 = dbP2.users.find(u => u.id === sess.userId);
  if (sess.role !== 'admin' && !uP2?.can_view_promos) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const urlObj = new URL(req.url, 'http://localhost');
  const accountId = parseInt(urlObj.searchParams.get('account_id'));
  const promoId = urlObj.searchParams.get('promo_id');
  const promoType = urlObj.searchParams.get('promo_type') || '';
  const requestedConcurrency = parseInt(urlObj.searchParams.get('concurrency') || '25');
  const safeConcurrency = Math.max(5, Math.min(50, isNaN(requestedConcurrency) ? 25 : requestedConcurrency));
  if (!promoId) return sendJSON(res, 400, { error: 'Falta promo_id' });
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === accountId);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  const appTok = await getAppToken().catch(() => null);
  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson',
    'Transfer-Encoding': 'chunked',
    'Cache-Control': 'no-cache',
    'X-Accel-Buffering': 'no'
  });
  const debug = [];
  let exported = 0;
  function normalizeArray(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (Array.isArray(raw.results)) return raw.results;
    if (Array.isArray(raw.items)) return raw.items;
    if (Array.isArray(raw.data)) return raw.data;
    if (Array.isArray(raw.promotions)) return raw.promotions;
    return [];
  }
  function getPromoId(p) {
    return String(p?.id || p?.promotion_id || p?.offer_id || p?.campaign_id || '');
  }
  function getPromoType(p) {
    return String(p?.type || p?.promotion_type || p?.offer_type || '');
  }
  function isSamePromo(p) {
    const id = getPromoId(p);
    const type = getPromoType(p);
    if (id !== String(promoId)) return false;
    if (promoType && type && type !== promoType) return false;
    return true;
  }
  function normalizeItemRow(it, fallbackPromo = null) {
    const promo = fallbackPromo || it || {};
    const itemId = it.item_id || it.id || it.item?.id || promo.item_id || promo.item?.id || '';
    return {
      item_id: itemId,
      title: it.title || it.item_title || it.name || it.item?.title || '',
      seller_sku: it.seller_sku || it.sku || it.seller_custom_field || it.item?.seller_sku || '',
      original_price: it.original_price ?? it.price ?? it.item?.price ?? '',
      new_price: it.new_price ?? it.offer_price ?? it.price_discounted ?? it.discount_price ?? '',
      discount: it.discount ?? it.discount_percentage ?? it.percent_off ?? '',
      status: it.status || it.promotion_status || '',
      promotion_id: getPromoId(promo) || promoId,
      promotion_type: getPromoType(promo) || promoType,
      item_status: it.item_status || it.item?.status || '',
      raw_status: it.status || ''
    };
  }
  async function getItemDetails(ids) {
    const map = {};
    const BATCH_SIZE = 20;
    for (let i = 0; i < ids.length; i += BATCH_SIZE) {
      const batch = ids.slice(i, i + BATCH_SIZE);
      try {
        const data = await mlGet(
          `https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=id,title,seller_custom_field,price,status,attributes`,
          token
        );
        for (const entry of (Array.isArray(data) ? data : [])) {
          const b = entry.body || entry;
          if (!b || !b.id) continue;
          let sku = b.seller_custom_field || '';
          if (!sku && Array.isArray(b.attributes)) {
            sku = b.attributes.find(a => a.id === 'SELLER_SKU')?.value_name || '';
          }
          map[b.id] = {
            item_id: b.id,
            title: b.title || '',
            seller_sku: sku,
            original_price: b.price ?? '',
            item_status: b.status || ''
          };
        }
      } catch(e) {
        debug.push({
          step: 'item_details',
          ids: batch,
          status: e?.response?.status || null,
          error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
        });
      }
    }
    return map;
  }
  async function emitRows(rows, mode) {
    for (const row of rows) {
      if (!row || !row.item_id) continue;
      exported++;
      res.write(JSON.stringify({ type: 'item', mode, data: row }) + '\n');
      if (exported % 100 === 0) {
        res.write(JSON.stringify({ type: 'progress', mode, done: exported, total: exported, exported }) + '\n');
      }
    }
  }
  async function tryDirectCampaignDownload() {
    const OLD = 'https://api.mercadolibre.com/seller-promotions';
    const directCandidates = [
      {
        label: 'marketplace_app_v2_promo_items',
        url: `${PROMO_BASE}/promotions/${promoId}/items?user_id=${account.seller_id}&limit=50`,
        token: appTok,
        headers: promoH(),
        pagination: 'search_after'
      },
      {
        label: 'marketplace_user_v2_promo_items',
        url: `${PROMO_BASE}/promotions/${promoId}/items?user_id=${account.seller_id}&limit=50`,
        token,
        headers: promoH(),
        pagination: 'search_after'
      },
      {
        label: 'old_user_v2_type_promo_items',
        url: `${OLD}/promotions/${promoId}/items?user_id=${account.seller_id}&promotion_type=${encodeURIComponent(promoType)}&app_version=v2&limit=50`,
        token,
        headers: {},
        pagination: 'offset'
      },
      {
        label: 'old_user_v2_type_promo_items_appid',
        url: `${OLD}/promotions/${promoId}/items?user_id=${account.seller_id}&promotion_type=${encodeURIComponent(promoType)}&app_id=${ML_CLIENT_ID}&app_version=v2&limit=50`,
        token,
        headers: {},
        pagination: 'offset'
      },
      {
        label: 'old_user_2_0_0_type_promo_items_appid',
        url: `${OLD}/promotions/${promoId}/items?user_id=${account.seller_id}&promotion_type=${encodeURIComponent(promoType)}&app_id=${ML_CLIENT_ID}&app_version=2.0.0&limit=50`,
        token,
        headers: {},
        pagination: 'offset'
      },
      {
        label: 'old_app_v2_type_promo_items_appid',
        url: `${OLD}/promotions/${promoId}/items?user_id=${account.seller_id}&promotion_type=${encodeURIComponent(promoType)}&app_id=${ML_CLIENT_ID}&app_version=v2&limit=50`,
        token: appTok,
        headers: {},
        pagination: 'offset'
      }
    ];
    for (const c of directCandidates) {
      if (!c.token) {
        debug.push({ mode: 'direct', tried: c.label, skipped: 'sin token' });
        continue;
      }
      if (c.label.includes('_type') && !promoType) {
        debug.push({ mode: 'direct', tried: c.label, skipped: 'sin promo_type' });
        continue;
      }
      let rows = [];
      let searchAfter = null;
      let offset = 0;
      let page = 0;
      let firstKeys = null;
      try {
        while (true) {
          let url = c.url;
          if (c.pagination === 'search_after' && searchAfter) {
            url += `&search_after=${encodeURIComponent(searchAfter)}`;
          }
          if (c.pagination === 'offset') {
            url += `&offset=${offset}`;
          }
          const raw = await mlGet(url, c.token, {}, c.headers);
          if (!firstKeys && raw && typeof raw === 'object') firstKeys = Object.keys(raw).slice(0, 20);
          const arr = normalizeArray(raw);
          const filtered = arr
            .filter(x => {
              const pid = getPromoId(x);
              if (!pid) return true; // direct endpoint already scoped by promo
              return isSamePromo(x);
            })
            .map(x => normalizeItemRow(x, x));
          rows.push(...filtered);
          const total = raw?.paging?.total ?? raw?.total ?? null;
          res.write(JSON.stringify({
            type: 'debug',
            mode: 'direct',
            tried: c.label,
            page,
            got: arr.length,
            kept: filtered.length,
            total: total ?? undefined
          }) + '\n');
          searchAfter = raw?.paging?.search_after || null;
          page++;
          if (c.pagination === 'search_after') {
            if (!searchAfter || !arr.length) break;
          } else {
            if (!arr.length) break;
            offset += arr.length;
            if (total != null && offset >= total) break;
            if (page > 1000) break;
          }
        }
        debug.push({ mode: 'direct', winner: c.label, rows: rows.length, keys: firstKeys });
        if (rows.length > 0) {
          res.write(JSON.stringify({ type: 'total', total: rows.length, mode: 'direct', winner: c.label }) + '\n');
          await emitRows(rows, 'direct');
          res.write(JSON.stringify({ type: 'done', total: exported, mode: 'direct', winner: c.label, debug }) + '\n');
          return true;
        }
      } catch(e) {
        debug.push({
          mode: 'direct',
          tried: c.label,
          status: e?.response?.status || null,
          error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
        });
      }
    }
    return false;
  }
  async function getItemPromotions(itemId) {
    const candidates = [
      {
        label: 'item_old_v2_type',
        url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=v2&promotion_type=${encodeURIComponent(promoType || '')}`,
        headers: {},
        token
      },
      {
        label: 'item_old_v2_plain',
        url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=v2`,
        headers: {},
        token
      },
      {
        label: 'item_old_2_0_0_type',
        url: `https://api.mercadolibre.com/seller-promotions/items/${itemId}?app_version=2.0.0&promotion_type=${encodeURIComponent(promoType || '')}`,
        headers: {},
        token
      },
      {
        label: 'marketplace_item_v2',
        url: `${PROMO_BASE}/items/${itemId}?user_id=${account.seller_id}`,
        headers: promoH(),
        token
      }
    ];
    for (const c of candidates) {
      if (c.label.includes('_type') && !promoType) continue;
      try {
        const raw = await mlGet(c.url, c.token, {}, c.headers);
        return normalizeArray(raw);
      } catch(e) {
        if (debug.length < 40) {
          debug.push({
            mode: 'scan',
            step: 'item_promos_error',
            tried: c.label,
            item_id: itemId,
            status: e?.response?.status || null,
            error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
          });
        }
      }
    }
    return [];
  }
  async function scanAllListingsFallback() {
    const LIMIT = 100;
    const BATCH_SIZE = 20;
    const DETAIL_CONCURRENCY = 8;
    const PROMO_CONCURRENCY = safeConcurrency;
    let scanned = 0;
    let totalListings = 0;
    async function processIds(ids) {
      const details = await getItemDetails(ids);
      for (let i = 0; i < ids.length; i += PROMO_CONCURRENCY) {
        const chunk = ids.slice(i, i + PROMO_CONCURRENCY);
        const results = await Promise.all(chunk.map(async (itemId) => {
          const promos = await getItemPromotions(itemId);
          const match = promos.find(isSamePromo);
          if (!match) return null;
          const d = details[itemId] || { item_id: itemId, title: '', seller_sku: '', original_price: '' };
          return {
            item_id: itemId,
            title: match.title || match.item_title || d.title || '',
            seller_sku: match.seller_sku || match.sku || d.seller_sku || '',
            original_price: match.original_price ?? match.price ?? d.original_price ?? '',
            new_price: match.new_price ?? match.offer_price ?? match.price_discounted ?? '',
            discount: match.discount ?? match.discount_percentage ?? '',
            status: match.status || match.promotion_status || '',
            promotion_id: getPromoId(match) || promoId,
            promotion_type: getPromoType(match) || promoType,
            item_status: d.item_status || '',
            raw_status: match.status || ''
          };
        }));
        for (const row of results) {
          scanned++;
          if (row) {
            exported++;
            res.write(JSON.stringify({ type: 'item', mode: 'scan', data: row }) + '\n');
          }
        }
        res.write(JSON.stringify({
          type: 'progress',
          mode: 'scan',
          done: scanned,
          total: totalListings,
          exported
        }) + '\n');
      }
    }
    const [activeFirst, pausedFirst] = await Promise.all([
      mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, { limit: 1, status: 'active', search_type: 'scan' }).catch(e => ({ paging: { total: 0 }, _error: e })),
      mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, { limit: 1, status: 'paused', search_type: 'scan' }).catch(e => ({ paging: { total: 0 }, _error: e }))
    ]);
    const activeTotal = activeFirst.paging?.total || 0;
    const pausedTotal = pausedFirst.paging?.total || 0;
    totalListings = activeTotal + pausedTotal;
    res.write(JSON.stringify({ type: 'total', total: totalListings, mode: 'scan_items' }) + '\n');
    async function scanStatus(status, statusTotal) {
      let scrollId = null;
      let fetched = 0;
      while (fetched < statusTotal) {
        const params = { limit: LIMIT, status, search_type: 'scan' };
        if (scrollId) params.scroll_id = scrollId;
        let pageData;
        try {
          pageData = await mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, params);
        } catch(e) {
          debug.push({
            mode: 'scan',
            step: 'items_search',
            status,
            httpStatus: e?.response?.status || null,
            error: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e)
          });
          break;
        }
        scrollId = pageData.scroll_id || null;
        const ids = pageData.results || [];
        if (!ids.length) break;
        fetched += ids.length;
        for (let i = 0; i < ids.length; i += (BATCH_SIZE * DETAIL_CONCURRENCY)) {
          const block = ids.slice(i, i + (BATCH_SIZE * DETAIL_CONCURRENCY));
          await processIds(block);
        }
        if (!scrollId) break;
      }
    }
    await scanStatus('active', activeTotal);
    await scanStatus('paused', pausedTotal);
    res.write(JSON.stringify({
      type: 'done',
      total: exported,
      scanned,
      total_listings: totalListings,
      mode: 'scan',
      pagination_mode: 'search_type_scan',
      promo_concurrency: PROMO_CONCURRENCY,
      detail_concurrency: DETAIL_CONCURRENCY,
      debug
    }) + '\n');
  }
  try {
    res.write(JSON.stringify({ type: 'debug', mode: 'start', promo_id: promoId, promo_type: promoType, concurrency: safeConcurrency }) + '\n');
    const directOk = await tryDirectCampaignDownload();
    if (directOk) return res.end();
    res.write(JSON.stringify({
      type: 'debug',
      mode: 'fallback',
      message: 'No funcionó descarga directa/acotada. Iniciando escaneo completo de publicaciones.'
    }) + '\n');
    await scanAllListingsFallback();
  } catch(e) {
    res.write(JSON.stringify({
      type: 'error',
      status: e?.response?.status || null,
      message: e?.response?.data?.message || e?.response?.data?.error || e?.message || String(e),
      raw: e?.response?.data || null,
      debug
    }) + '\n');
  }
  res.end();
});
// POST /api/promotion-search-items {account_id, promo_id, sku, title}
route('POST', '/api/promotion-search-items', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbP3 = loadDB(); const uP3 = dbP3.users.find(u => u.id === sess.userId);
  if (sess.role !== 'admin' && !uP3?.can_view_promos) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const body = await parseBody(req);
  const { account_id, promo_id, sku, title } = body;
  if (!sku && !title) return sendJSON(res, 400, { error: 'Ingresá SKU o título' });
  if (!promo_id) return sendJSON(res, 400, { error: 'Seleccioná una campaña primero' });
  const db = loadDB();
  const targets = account_id
    ? db.ml_accounts.filter(a => a.id === parseInt(account_id))
    : db.ml_accounts;
  const itemIdSearch = item_id ? String(item_id).trim().toUpperCase() : '';
  const skuLower = sku ? sku.trim().toLowerCase() : '';
  const titleLower = title ? title.trim().toLowerCase() : '';
  const foundItems = [];
  for (const account of targets) {
    try {
      const token = await getValidToken(account);
      if (!token) continue;
      let itemIds = new Set();
      if (skuLower) {
        const skuBase = sku.trim();
        const skuTerms = [skuBase];
        if (!skuLower.includes('_')) {
          for (const s of ['_D','_I','_DM','_IM','_DER','_IZQ','_T','_TD','_TI','_d','_i','_dm','_im','_1','_2','_3','_A','_B'])
            skuTerms.push(skuBase + s);
        }
        await Promise.all(skuTerms.map(term =>
          mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search?seller_sku=${encodeURIComponent(term)}&limit=200`, token)
            .then(r => (r.results || []).forEach(id => itemIds.add(id)))
            .catch(() => {})
        ));
      }
      if (titleLower) {
        try {
          const r = await mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search?q=${encodeURIComponent(title.trim())}&limit=200`, token);
          const titleIds = new Set(r.results || []);
          if (skuLower) { for (const id of [...itemIds]) { if (!titleIds.has(id)) itemIds.delete(id); } }
          else itemIds = titleIds;
        } catch(e) { if (!skuLower) itemIds = new Set(); }
      }
      if (!itemIds.size) continue;
      const idArr = [...itemIds];
      for (let i = 0; i < idArr.length; i += 20) {
        const batch = idArr.slice(i, i + 20);
        try {
          const details = await mlGet(
            `https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=id,title,seller_custom_field,price,status,attributes`,
            token
          );
          for (const it of (Array.isArray(details) ? details : [])) {
            const b = it.body || it;
            if (!b?.id || b.status === 'closed' || b.status === 'under_review') continue;
            const rawSku = b.seller_custom_field ||
              (Array.isArray(b.attributes) ? (b.attributes.find(a => a.id === 'SELLER_SKU')?.value_name || '') : '') || '';
            const itemSku = String(rawSku || '').toLowerCase();
            if (skuLower) {
              if (skuLower.includes('_')) { if (!itemSku.includes(skuLower)) continue; }
              else { if (!itemSku.split('_')[0].includes(skuLower)) continue; }
            }
            if (titleLower && !String(b.title || '').toLowerCase().includes(titleLower)) continue;
            foundItems.push({
              item_id: b.id,
              title: b.title || '',
              sku: rawSku,
              original_price: b.price ?? 0,
              account_id: account.id,
              account_name: account.name,
              seller_id: account.seller_id
            });
          }
        } catch(e) {}
      }
    } catch(e) {}
  }
  if (!foundItems.length) return sendJSON(res, 200, []);
  const appTokForSearch = await getAppToken();
  const results = await Promise.all(foundItems.map(async (item) => {
    const account = targets.find(a => String(a.seller_id) === String(item.seller_id)) || targets[0];
    const userToken = await getValidToken(account);
    try {
      const st = await getPromoItemStatus(account, promo_id, item.item_id, userToken, appTokForSearch);
      return { ...item, ...st };
    } catch(e) {
      return { ...item, in_promo: false, new_price: null, discount: null, promo_status: null };
    }
  }));
  sendJSON(res, 200, results);
});
// POST /api/promotion-toggle {account_id, promo_id, promo_type, item_id, participate, price, discount}
route('POST', '/api/promotion-toggle', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbP4 = loadDB(); const uP4 = dbP4.users.find(u => u.id === sess.userId);
  if (sess.role !== 'admin' && !uP4?.can_view_promos) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const body = await parseBody(req);
  const { account_id, promo_id, promo_type, item_id, participate, price, discount } = body;
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  const isDeal = promo_type === 'DEAL' || promo_type === 'LIGHTNING_DEAL';
  const userQ = `user_id=${account.seller_id}`;
  const endpoints = [
    { label: 'marketplace_user_v2', url: `${PROMO_BASE}/items/${item_id}?${userQ}`, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...promoH() } },
    { label: 'old_user', url: `${PROMO_OLD_BASE}/items/${item_id}?${userQ}&app_id=${encodeURIComponent(ML_CLIENT_ID || '')}&app_version=2.0.0`, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } },
  ];
  try {
    let lastErr = null;
    for (const ep of endpoints) {
      if (participate) {
        const addBody = { promotion_id: promo_id, promotion_type: promo_type };
        if (!isDeal) {
          const p = parseFloat(price) || 0, disc = parseFloat(discount) || 0;
          if (p > 0) addBody.price = p; else if (disc > 0) addBody.discount = disc;
        }
        const r = await fetch(ep.url, { method: 'POST', headers: ep.headers, body: JSON.stringify(addBody) });
        const d = await r.json().catch(() => ({}));
        if (r.ok) return sendJSON(res, 200, { ok: true, endpoint: ep.label });
        lastErr = d.message || d.error || `HTTP ${r.status}`;
      } else {
        const r = await fetch(ep.url, {
          method: 'DELETE',
          headers: ep.headers,
          body: JSON.stringify({ promotion_id: promo_id, promotion_type: promo_type })
        });
        if (r.ok || r.status === 204) return sendJSON(res, 200, { ok: true, endpoint: ep.label });
        const d = await r.json().catch(() => ({}));
        lastErr = d.message || d.error || `HTTP ${r.status}`;
      }
    }
    return sendJSON(res, 400, { error: lastErr || 'No se pudo actualizar la promoción' });
  } catch(e) {
    sendJSON(res, 500, { error: e.message || String(e) });
  }
});
// POST /api/promotion-bulk-stream {account_id, promo_id, promo_type, items:[...]} streaming ndjson
route('POST', '/api/promotion-bulk-stream', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbP5 = loadDB(); const uP5 = dbP5.users.find(u => u.id === sess.userId);
  if (sess.role !== 'admin' && !uP5?.can_view_promos) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const body = await parseBody(req);
  const { account_id, promo_id, promo_type, items } = body;
  if (!items?.length) return sendJSON(res, 400, { error: 'Sin ítems' });
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Transfer-Encoding': 'chunked', 'Cache-Control': 'no-cache' });
  const total = items.length;
  let done = 0, errCount = 0;
  const errorRows = [];
  res.write(JSON.stringify({ type: 'start', total }) + '\n');
  const isDeal = promo_type === 'DEAL' || promo_type === 'LIGHTNING_DEAL';
  const uq = `user_id=${account.seller_id}`;
  const endpointsForItem = (itemId) => [
    { label: 'marketplace_user_v2', url: `${PROMO_BASE}/items/${itemId}?${uq}`, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...promoH() } },
    { label: 'old_user', url: `${PROMO_OLD_BASE}/items/${itemId}?${uq}&app_id=${encodeURIComponent(ML_CLIENT_ID || '')}&app_version=2.0.0`, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
  ];
  for (const item of items) {
    const { item_id, participar, precio_promo, descuento_pct } = item;
    const participate = ['si','sí','yes','true','1'].includes(String(participar || '').toLowerCase().trim());
    let ok = false, errMsg = null;
    for (const ep of endpointsForItem(item_id)) {
      try {
        if (participate) {
          const addBody = { promotion_id: promo_id, promotion_type: promo_type };
          if (!isDeal) {
            const p = parseFloat(precio_promo) || 0, disc = parseFloat(descuento_pct) || 0;
            if (p > 0) addBody.price = p; else if (disc > 0) addBody.discount = disc;
          }
          const r = await fetch(ep.url, { method: 'POST', headers: ep.headers, body: JSON.stringify(addBody) });
          if (r.ok) { ok = true; break; }
          const d = await r.json().catch(() => ({}));
          errMsg = d.message || d.error || `HTTP ${r.status}`;
        } else {
          const r = await fetch(ep.url, {
            method: 'DELETE',
            headers: ep.headers,
            body: JSON.stringify({ promotion_id: promo_id, promotion_type: promo_type })
          });
          if (r.ok || r.status === 204) { ok = true; break; }
          const d = await r.json().catch(() => ({}));
          errMsg = d.message || d.error || `HTTP ${r.status}`;
        }
      } catch(e) {
        errMsg = e.message || String(e);
      }
    }
    done++;
    if (!ok) { errCount++; errorRows.push({ item_id, participar, precio_promo, descuento_pct, error: errMsg || 'Error' }); }
    if (done % 100 === 0 || done === total) {
      res.write(JSON.stringify({ type: 'progress', done, total, errors: errCount }) + '\n');
    }
  }
  res.write(JSON.stringify({ type: 'done', done, total, errors: errCount, errorRows }) + '\n');
  res.end();
});
// POST /api/promotion-create {account_id, name, start_date, end_date}
route('POST', '/api/promotion-create', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const dbP6 = loadDB(); const uP6 = dbP6.users.find(u => u.id === sess.userId);
  if (sess.role !== 'admin' && !uP6?.can_view_promos) return sendJSON(res, 403, { error: 'Acceso denegado' });
  const body = await parseBody(req);
  const { account_id, name, start_date, end_date } = body;
  if (!account_id || !name || !start_date || !end_date) return sendJSON(res, 400, { error: 'Faltan datos' });
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === parseInt(account_id));
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  const payload = {
    type: 'PRICE_DISCOUNT',
    name,
    start_date: new Date(start_date).toISOString(),
    end_date: new Date(end_date).toISOString(),
    status: 'active'
  };
  const endpoints = [
    { label: 'marketplace_user_v2', url: `${PROMO_BASE}/promotions?user_id=${account.seller_id}`, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...promoH() } },
    { label: 'old_user', url: `${PROMO_OLD_BASE}/promotions?user_id=${account.seller_id}&app_id=${encodeURIComponent(ML_CLIENT_ID || '')}&app_version=2.0.0`, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
  ];
  let lastErr = null;
  for (const ep of endpoints) {
    try {
      const r = await fetch(ep.url, { method: 'POST', headers: ep.headers, body: JSON.stringify(payload) });
      const d = await r.json().catch(() => ({}));
      if (r.ok) return sendJSON(res, 200, { ...d, endpoint: ep.label });
      lastErr = d.message || d.error || `HTTP ${r.status}`;
    } catch(e) {
      lastErr = e.message || String(e);
    }
  }
  sendJSON(res, 400, { error: lastErr || 'No se pudo crear la campaña' });
});
// ==================== SERVER ====================
// ==================== API TOKEN (automatización) ====================
const API_TOKEN = config.API_TOKEN || process.env.API_TOKEN || '';
// Verifica el token de API con comparación de tiempo constante (evita timing attacks).
// Preferido por header:  x-api-token: <API_TOKEN>
// Alternativa (solo para pruebas rápidas):  ?token=<API_TOKEN>
function checkApiToken(req) {
  if (!API_TOKEN) return false; // fail-closed: sin token configurado => deshabilitado
  let provided = req.headers['x-api-token'];
  if (!provided) {
    try { provided = new URL(req.url, 'http://localhost').searchParams.get('token') || ''; } catch (e) { provided = ''; }
  }
  if (!provided) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(API_TOKEN);
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(a, b); } catch (e) { return false; }
}
// Resuelve la cuenta por ?account_id=ID o por ?account=NOMBRE (exacto o parcial, case-insensitive)
function resolveApiAccount(db, url) {
  const idRaw = url.searchParams.get('account_id');
  const nameRaw = url.searchParams.get('account');
  if (idRaw && String(idRaw).trim() !== '') {
    const acc = db.ml_accounts.find(a => a.id === parseInt(idRaw));
    if (acc) return acc;
  }
  if (nameRaw) {
    const q = String(nameRaw).trim().toLowerCase();
    return db.ml_accounts.find(a => String(a.name || '').toLowerCase() === q)
        || db.ml_accounts.find(a => String(a.name || '').toLowerCase().includes(q))
        || null;
  }
  return null;
}
// ==================== API AUTOMATIZACIÓN (token) ====================
// GET /api/estado?account=MARA   (o ?account_id=1)
// Header:  x-api-token: <API_TOKEN>
// Exporta el estado actual (activas + pausadas) como NDJSON: una línea JSON por publicación.
route('GET', '/api/estado', async (req, res) => {
  if (!checkApiToken(req)) return sendJSON(res, 401, { error: 'Token de API inválido o ausente' });
  const url = new URL(req.url, 'http://localhost');
  const db = loadDB();
  const account = resolveApiAccount(db, url);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada (usá ?account=NOMBRE o ?account_id=ID)' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token ML inválido, reconectá la cuenta desde Configuración' });
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Transfer-Encoding': 'chunked', 'X-Accel-Buffering': 'no' });
  try {
    const LIMIT = 100, BATCH_SIZE = 20, DETAIL_CONCURRENCY = 5;
    let exported = 0;
    const [activeFirst, pausedFirst] = await Promise.all([
      mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, { limit: 1, status: 'active' }),
      mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, { limit: 1, status: 'paused' }),
    ]);
    const activeTotal = activeFirst.paging?.total || 0;
    const pausedTotal = pausedFirst.paging?.total || 0;
    const total = activeTotal + pausedTotal;
    res.write(JSON.stringify({ type: 'start', account: account.name, total }) + '\n');
    const exportByStatus = async (status, statusTotal) => {
      let scrollId = null, fetched = 0;
      while (fetched < statusTotal) {
        const params = { limit: LIMIT, status, search_type: 'scan' };
        if (scrollId) params.scroll_id = scrollId;
        const pageData = await mlGet(`https://api.mercadolibre.com/users/${account.seller_id}/items/search`, token, params);
        scrollId = pageData.scroll_id || null;
        const ids = pageData.results || [];
        if (!ids.length) break;
        fetched += ids.length;
        const batches = [];
        for (let j = 0; j < ids.length; j += BATCH_SIZE) batches.push(ids.slice(j, j + BATCH_SIZE));
        for (let j = 0; j < batches.length; j += DETAIL_CONCURRENCY) {
          const concurrent = batches.slice(j, j + DETAIL_CONCURRENCY);
          const responses = await Promise.all(concurrent.map(b =>
            mlGet(`https://api.mercadolibre.com/items?ids=${b.join(',')}&attributes=id,title,available_quantity,status,price,original_price,shipping,seller_custom_field,attributes`, token).catch(() => [])
          ));
          for (const itemsData of responses) {
            for (const entry of (Array.isArray(itemsData) ? itemsData : [])) {
              if (entry.code === 200 && entry.body) {
                const it = entry.body;
                if (it.status === 'under_review' || it.status === 'closed') continue;
                const sh = it.shipping || {};
                const rawMode = sh.mode || sh.logistic_type || 'not_specified';
                const shippingMode = rawMode === 'me2' ? 'ME' : rawMode;
                const shTags = Array.isArray(sh.tags) ? sh.tags : [];
                const flex = shTags.includes('self_service_in') ? 'si' : shTags.includes('self_service_out') ? 'no' : 'not_available';
                const localPickup = sh.local_pick_up ? 'si' : 'no';
                const sku = it.seller_custom_field
                  || (Array.isArray(it.attributes) ? (it.attributes.find(a => a.id === 'SELLER_SKU')?.value_name || '') : '')
                  || '';
                exported++;
                res.write(JSON.stringify({
                  type: 'item',
                  item_id: it.id, flex, local_pick_up: localPickup, shipping: shippingMode,
                  titulo: it.title || '', available_quantity: it.available_quantity ?? '',
                  status: it.status ?? '', price: it.original_price ?? it.price ?? '', item_sku: sku
                }) + '\n');
              }
            }
          }
        }
      }
    };
    await exportByStatus('active', activeTotal);
    await exportByStatus('paused', pausedTotal);
    res.write(JSON.stringify({ type: 'done', exported }) + '\n');
  } catch (e) {
    console.error('[API-ESTADO]', e?.response?.data || e.message);
    res.write(JSON.stringify({ type: 'error', error: e?.response?.data?.message || e.message || 'Error al exportar' }) + '\n');
  }
  res.end();
});
// POST /api/actualizar   — aplica cambios en segundo plano (mismo motor que la carga manual)
// Header:  x-api-token: <API_TOKEN>
// Body JSON: { "account": "MARA" (o "account_id": 1), "items": [ {item_id, available_quantity, status, price, marca, flex, item_sku}, ... ] }
route('POST', '/api/actualizar', async (req, res) => {
  if (!checkApiToken(req)) return sendJSON(res, 401, { error: 'Token de API inválido o ausente' });
  const body = await parseBody(req);
  const items = body.items;
  if (!Array.isArray(items) || !items.length) return sendJSON(res, 400, { error: 'Falta items[] en el body' });
  const db = loadDB();
  let account = null;
  if (body.account_id) account = db.ml_accounts.find(a => a.id === parseInt(body.account_id));
  if (!account && body.account) {
    const q = String(body.account).trim().toLowerCase();
    account = db.ml_accounts.find(a => String(a.name || '').toLowerCase() === q)
           || db.ml_accounts.find(a => String(a.name || '').toLowerCase().includes(q));
  }
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada (usá account o account_id)' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token ML inválido, reconectá la cuenta' });
  cleanBulkJobs();
  const jobId = `api_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  bulkJobs[jobId] = {
    id: jobId, status: 'starting', phase: 'starting', total: items.length, done: 0, ok: 0, errors: 0,
    to_update: null, skipped: null, eta_sec: null, velocity: 0, active_workers: 0, desired_workers: 3,
    max_workers: 5, rate_limits: 0, retries: 0, promotions_removed: 0, promo_retry_ok: 0,
    error_items: [], report: null, cancelled: false, created: Date.now(), username: 'api',
    // Sacar promos/campañas ACTIVAS antes de cambiar el precio (default ON).
    // Se puede desactivar mandando "quitar_promos": false en el body.
    remove_promos_before: body.quitar_promos !== false
  };
  runBulkJob(jobId, items, account, token).catch(e => {
    if (bulkJobs[jobId] && !['done','cancelled'].includes(bulkJobs[jobId].status)) {
      bulkJobs[jobId].status = 'error'; bulkJobs[jobId].phase = 'error';
      bulkJobs[jobId].error_msg = e?.message || 'Error inesperado';
    }
  });
  console.log(`[API-ACTUALIZAR] Job ${jobId}: ${items.length} ítems para ${account.name}`);
  return sendJSON(res, 200, { job_id: jobId, total: items.length, account: account.name });
});
// ==================== SALE ORDERS (PEDIDOS) ====================
// POST /api/sale-orders/close  — must be registered BEFORE /api/sale-orders (exact match used, but keeping order clear)
route('POST', '/api/sale-orders/close', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autenticado' });
  const body = await parseBody(req);
  const { id } = body;
  if (!id) return sendJSON(res, 400, { error: 'Missing id' });
  const db = loadDB();
  const order = (db.sale_orders || []).find(o => o.id === id);
  if (!order) return sendJSON(res, 404, { error: 'Not found' });
  order.status = 'closed';
  order.closed_at = Date.now();
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});
// POST /api/sale-orders  — Create or update (upsert) order for a sale
route('POST', '/api/sale-orders', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autenticado' });
  const body = await parseBody(req);
  const { order_id, account_id, account_name, date, items, type } = body;
  if (!order_id || !account_id) return sendJSON(res, 400, { error: 'Missing fields' });
  const orderType = type === 'drop' ? 'drop' : 'pedido';
  const db = loadDB();
  if (!db.sale_orders) db.sale_orders = [];
  const idx = db.sale_orders.findIndex(o => o.order_id === String(order_id) && String(o.account_id) === String(account_id) && o.status === 'open' && o.type === orderType);
  let order;
  if (idx !== -1) {
    db.sale_orders[idx].items = items || [];
    db.sale_orders[idx].updated_at = Date.now();
    order = db.sale_orders[idx];
  } else {
    order = {
      id: crypto.randomUUID(),
      order_id: String(order_id),
      account_id,
      account_name: account_name || '',
      date: date || '',
      items: items || [],
      type: orderType,
      status: 'open',
      created_at: Date.now(),
      updated_at: Date.now()
    };
    db.sale_orders.push(order);
  }
  saveDB(db);
  sendJSON(res, 200, { ok: true, order });
});
// GET /api/sale-orders  — List orders with optional filters
route('GET', '/api/sale-orders', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autenticado' });
  const url = new URL(req.url, 'http://localhost');
  const status = url.searchParams.get('status') || 'open';
  const account_id = url.searchParams.get('account_id');
  const order_id = url.searchParams.get('order_id');
  const date_from = url.searchParams.get('date_from');
  const date_to = url.searchParams.get('date_to');
  const proveedor = url.searchParams.get('proveedor');
  const codigo = url.searchParams.get('codigo');
  const typeFilter = url.searchParams.get('type'); // 'pedido' | 'drop' | null=all
  const db = loadDB();
  let orders = db.sale_orders || [];
  if (status !== 'all') orders = orders.filter(o => o.status === status);
  // When listing open orders without an explicit type filter, exclude drops (Actuales view shows only pedidos)
  if (status === 'open' && !typeFilter) orders = orders.filter(o => (o.type || 'pedido') !== 'drop');
  if (typeFilter) orders = orders.filter(o => (o.type || 'pedido') === typeFilter);
  if (account_id) orders = orders.filter(o => String(o.account_id) === String(account_id));
  if (order_id) orders = orders.filter(o => String(o.order_id) === String(order_id));
  if (date_from) orders = orders.filter(o => (o.date || '') >= date_from);
  if (date_to) orders = orders.filter(o => (o.date || '') <= date_to);
  if (codigo) orders = orders.filter(o => (o.items || []).some(i => (i.codigo || '').toLowerCase().includes(codigo.toLowerCase())));
  if (proveedor) orders = orders.filter(o => (o.items || []).some(i => (i.proveedor || '').toLowerCase().includes(proveedor.toLowerCase())));
  orders = orders.sort((a, b) => b.created_at - a.created_at);
  sendJSON(res, 200, orders);
});
// GET /api/actualizar-estado?job_id=xxx   — progreso/resultado del job (token)
route('GET', '/api/actualizar-estado', async (req, res) => {
  if (!checkApiToken(req)) return sendJSON(res, 401, { error: 'Token de API inválido o ausente' });
  const url = new URL(req.url, 'http://localhost');
  const jobId = url.searchParams.get('job_id');
  if (!jobId) return sendJSON(res, 400, { error: 'job_id requerido' });
  const job = bulkJobs[jobId];
  if (!job) {
    const dbP = loadDB();
    const persisted = (dbP.bulk_completed_jobs || []).find(j => j.id === jobId);
    if (persisted) return sendJSON(res, 200, persisted);
    return sendJSON(res, 404, { error: 'Job no encontrado o expirado' });
  }
  return sendJSON(res, 200, job);
});
// GET /api/ads/costs/export?account_id=N  — exporta la tabla de costos ENRIQUECIDA de una
// cuenta en NDJSON (una linea por publicacion). Auth: token de API (para el motor) o admin.
// Lo usa la FASE 3 del motor Python para leer la comision y la cuota REALES por publicacion
// (del enriquecimiento con el simulador de ML) y fijar el precio al margen objetivo.
route('GET', '/api/ads/costs/export', async (req, res) => {
  try {
    const okApi = checkApiToken(req);
    const sess = okApi ? null : requireAuth(req);
    if (!okApi && (!sess || sess.role !== 'admin')) return sendJSON(res, 403, { error: 'Acceso denegado (admin o token de API)' });
    const url = new URL(req.url, 'http://localhost');
    const accountId = parseInt(url.searchParams.get('account_id'));
    if (!accountId) return sendJSON(res, 400, { error: 'account_id requerido' });
    const dbX = (typeof loadDB === 'function') ? loadDB() : {};
    const account = ((dbX && dbX.ml_accounts) || []).find(a => a.id === accountId);
    if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
    // Leemos el archivo de costos por cuenta DIRECTO con fs (las funciones
    // loadAccountCosts/accountCostsPath viven en otro scope y no son visibles aca).
    // Mismo path que usa el panel: DATA_DIR/ads_costs_<sellerId>.json
    let table = {};
    try {
      const costPath = path.join(DATA_DIR, 'ads_costs_' + String(account.seller_id) + '.json');
      const parsed = JSON.parse(fs.readFileSync(costPath, 'utf8'));
      table = (parsed && parsed.costs) || {};
    } catch (e) { table = {}; }
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no' });
    let n = 0;
    for (const id in table) {
      const c = table[id];
      if (c == null || c.simFee == null) continue;   // solo los que estan enriquecidos
      res.write(JSON.stringify({
        item_id: id,
        price: Number(c.price) || Number(c.listPrice) || 0,
        cost: Number(c.cost) || 0,
        cost_ship: Number(c.costShip) || 0,
        ship: c.ship || 'NO',
        sim_fee: Number(c.simFee) || 0,
        sim_fixed: Number(c.simFixed) || 0,
        sim_cuotas: Number(c.simCuotas) || 0,
        sim_imp: Number(c.simImp) || 0,
        sim_envio: Number(c.simEnvio) || 0,
        listing_type: c.listingType || '',
        account_id: c.account_id != null ? c.account_id : accountId,
      }) + '\n');
      n++;
    }
    res.write(JSON.stringify({ _resumen: true, total: n, account: account.name }) + '\n');
    res.end();
  } catch (e) {
    console.error('[ads/costs/export] error:', e);
    if (!res.headersSent) return sendJSON(res, 500, { error: 'export fallo: ' + (e && (e.message || String(e))) });
    try { res.end(); } catch (_) {}
  }
});
// POST /api/ads/costs/restore  — RESTAURA el enriquecimiento (simFee, simEnvio, ...) en la
// tabla de costos de una cuenta, MERGEANDO sin pisar el resto. Sirve para recuperar el
// enriquecimiento desde los _COMPLETO ya generados (sin re-llamar a ML). Auth: token o admin.
// body: { account_id, items: [{item_id, sim_fee, sim_fixed, sim_cuotas, sim_imp, sim_envio, price}] }
route('POST', '/api/ads/costs/restore', async (req, res) => {
  try {
    const okApi = checkApiToken(req);
    const sess = okApi ? null : requireAuth(req);
    if (!okApi && (!sess || sess.role !== 'admin')) return sendJSON(res, 403, { error: 'Acceso denegado (admin o token de API)' });
    const body = await parseBody(req);
    const accountId = parseInt(body.account_id);
    const items = Array.isArray(body.items) ? body.items : [];
    if (!accountId) return sendJSON(res, 400, { error: 'account_id requerido' });
    const account = ((loadDB() || {}).ml_accounts || []).find(a => a.id === accountId);
    if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
    const costPath = path.join(DATA_DIR, 'ads_costs_' + String(account.seller_id) + '.json');
    let file = { costs: {} };
    try { file = JSON.parse(fs.readFileSync(costPath, 'utf8')) || { costs: {} }; } catch (e) { file = { costs: {} }; }
    if (!file.costs) file.costs = {};
    const nowIso = new Date().toISOString();
    let restored = 0, nuevos = 0;
    for (const it of items) {
      const id = String(it.item_id || '').trim();
      if (!id) continue;
      const prev = file.costs[id] || null;
      const base = prev || { seller_id: account.seller_id, account_id: accountId, account_name: account.name };
      if (!prev) nuevos++;
      const num = v => { const n = Number(v); return isFinite(n) ? n : 0; };
      file.costs[id] = {
        ...base,
        price: it.price != null ? num(it.price) : (base.price || 0),
        simFee: num(it.sim_fee),
        simFixed: num(it.sim_fixed),
        simCuotas: num(it.sim_cuotas),
        simImp: num(it.sim_imp),
        simEnvio: num(it.sim_envio),
        enrichAt: nowIso,
        enrichSrc: 'restore',
      };
      restored++;
    }
    file.updated = nowIso;
    fs.writeFileSync(costPath, JSON.stringify(file));
    if (typeof bustStrat === 'function') { try { bustStrat(); } catch (e) {} }
    return sendJSON(res, 200, { ok: true, restored, nuevos, total_tabla: Object.keys(file.costs).length, account: account.name });
  } catch (e) {
    console.error('[ads/costs/restore] error:', e);
    if (!res.headersSent) return sendJSON(res, 500, { error: 'restore fallo: ' + (e && (e.message || String(e))) });
  }
});
// GET /api/ads/costs/legacy-migrate?account_id=N[&dry=1]  — RECUPERA el enriquecimiento
// desde los archivos VIEJOS costos_reales_<sellerId>.json (del sistema anterior, que quedaron
// en el disco persistente) y los convierte al formato ads (simFee...), mergeando. Con dry=1
// solo informa si el archivo existe y cuántos ítems trae, sin escribir nada. Auth: token o admin.
route('GET', '/api/ads/costs/legacy-migrate', async (req, res) => {
  try {
    const okApi = checkApiToken(req);
    const sess = okApi ? null : requireAuth(req);
    if (!okApi && (!sess || sess.role !== 'admin')) return sendJSON(res, 403, { error: 'Acceso denegado (admin o token de API)' });
    const url = new URL(req.url, 'http://localhost');
    const accountId = parseInt(url.searchParams.get('account_id'));
    const dry = url.searchParams.get('dry') === '1';
    if (!accountId) return sendJSON(res, 400, { error: 'account_id requerido' });
    const account = ((loadDB() || {}).ml_accounts || []).find(a => a.id === accountId);
    if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
    const legacyPath = path.join(DATA_DIR, 'costos_reales_' + String(account.seller_id) + '.json');
    let legacy = null;
    try { legacy = JSON.parse(fs.readFileSync(legacyPath, 'utf8')); } catch (e) {}
    if (!legacy || !legacy.costs) {
      return sendJSON(res, 200, { ok: false, existe: false, account: account.name,
        msg: 'no encontre costos_reales_<sellerId>.json en el disco persistente', path: legacyPath });
    }
    const src = legacy.costs;
    const ids = Object.keys(src);
    const enriquecido = c => c && (Number(c.comision_amount) > 0 || Number(c.comision_pct) > 0);
    const conEnriq = ids.filter(id => enriquecido(src[id])).length;
    if (dry) {
      const ej = src[ids.find(id => enriquecido(src[id])) || ids[0]] || null;
      return sendJSON(res, 200, { ok: true, existe: true, account: account.name,
        total: ids.length, enriquecidos: conEnriq, ejemplo: ej });
    }
    // migrar -> ads (merge, sin pisar el resto del registro)
    const costPath = path.join(DATA_DIR, 'ads_costs_' + String(account.seller_id) + '.json');
    let file = { costs: {} };
    try { file = JSON.parse(fs.readFileSync(costPath, 'utf8')) || { costs: {} }; } catch (e) { file = { costs: {} }; }
    if (!file.costs) file.costs = {};
    const nowIso = new Date().toISOString();
    const num = v => { const n = Number(v); return isFinite(n) ? n : 0; };
    let migr = 0;
    for (const id of ids) {
      const c = src[id];
      if (!enriquecido(c)) continue;
      const comAmt = num(c.comision_amount);
      const fijo = num(c.costo_fijo);
      const price = num(c.price);
      // si no vino comision_amount pero sí comision_pct + price, lo reconstruimos
      const comFinal = comAmt > 0 ? comAmt : (num(c.comision_pct) * price / 100);
      const prev = file.costs[id] || { seller_id: account.seller_id, account_id: accountId, account_name: account.name };
      file.costs[id] = {
        ...prev,
        price: price || prev.price || 0,
        simFee: comFinal + fijo,                 // comision total = variable + cargo fijo
        simFixed: fijo,
        simCuotas: num(c.cuota_amount),
        simImp: num(c.impuestos_amount),
        simEnvio: num(c.envio),
        enrichAt: nowIso,
        enrichSrc: 'legacy-migrate',
      };
      migr++;
    }
    file.updated = nowIso;
    fs.writeFileSync(costPath, JSON.stringify(file));
    if (typeof bustStrat === 'function') { try { bustStrat(); } catch (e) {} }
    return sendJSON(res, 200, { ok: true, migrados: migr, total_tabla: Object.keys(file.costs).length, account: account.name });
  } catch (e) {
    console.error('[ads/costs/legacy-migrate] error:', e);
    if (!res.headersSent) return sendJSON(res, 500, { error: 'legacy-migrate fallo: ' + (e && (e.message || String(e))) });
  }
});
// DEBUG temporal: ver la estructura de stock por deposito de un item (user_products)
route('GET', '/api/debug-userstock', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const u = new URL(req.url, 'http://localhost');
  const itemId = u.searchParams.get('item_id');
  const accountId = parseInt(u.searchParams.get('account_id'));
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === accountId);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  try {
    const item = await mlGet(`https://api.mercadolibre.com/items/${itemId}?attributes=id,available_quantity,status,seller_custom_field,user_product_id,inventory_id,variations,shipping`, token);
    const upid = item.user_product_id;
    let stock = null, stockErr = null;
    if (upid) {
      try { stock = await mlGet(`https://api.mercadolibre.com/user-products/${upid}/stock`, token); }
      catch (e) { stockErr = (e && e.response && e.response.data) || String(e.message || e); }
    }
    sendJSON(res, 200, { item_id: itemId, user_product_id: upid || null, item_available_quantity: item.available_quantity, user_product_stock: stock, user_product_stock_error: stockErr });
  } catch (e) {
    sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
  }
});
// DEBUG temporal: PRUEBA SEGURA de escritura de stock por deposito (user_products).
// Manda un PUT con la cantidad indicada (o la actual si no se pasa qty) y reporta
// que formato acepto ML + como quedo el stock. Con qty = cantidad actual, no cambia nada.
route('GET', '/api/debug-userstock-write', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const u = new URL(req.url, 'http://localhost');
  const itemId = u.searchParams.get('item_id');
  const accountId = parseInt(u.searchParams.get('account_id'));
  const qtyParam = u.searchParams.get('qty');
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === accountId);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  try {
    const item = await mlGet(`https://api.mercadolibre.com/items/${itemId}?attributes=id,user_product_id`, token);
    const upid = item.user_product_id;
    if (!upid) return sendJSON(res, 400, { error: 'El item no tiene user_product_id (no usa deposito)' });
    const stockUrl = `https://api.mercadolibre.com/user-products/${upid}/stock`;
    // GET crudo: necesitamos el header x-version (obligatorio para escribir stock)
    const g = await fetch(stockUrl, { headers: { Authorization: `Bearer ${token}` } });
    const xver = g.headers.get('x-version');
    const gtext = await g.text();
    let cur = {}; try { cur = gtext ? JSON.parse(gtext) : {}; } catch (e) { cur = { raw: gtext }; }
    const loc = (cur.locations || [])[0] || {};
    const locType = loc.type || 'seller_warehouse';
    const qty = (qtyParam === null || qtyParam === '') ? loc.quantity : parseInt(qtyParam);
    const putUrl = `https://api.mercadolibre.com/user-products/${upid}/stock/type/${locType}`;
    const body = { locations: [{ store_id: loc.store_id, quantity: qty }] };
    const r = await fetch(putUrl, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Version': String(xver), Authorization: `Bearer ${token}` },
      body: JSON.stringify(body)
    });
    const ptext = await r.text();
    let pdata; try { pdata = ptext ? JSON.parse(ptext) : {}; } catch (e) { pdata = { raw: ptext }; }
    const after = await mlGet(stockUrl, token).catch(() => null);
    return sendJSON(res, 200, { upid, type: locType, x_version_usado: xver, qty_actual: loc.quantity, qty_enviado: qty, sent: body, put_status: r.status, put_ok: r.ok, put_result: pdata, stock_despues: after });
  } catch (e) {
    sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
  }
});
// DEBUG PROMO: diagnostico completo del bloqueo por promocion en un item.
// Por defecto SOLO LEE (no toca nada). Muestra el estado real del item en ML,
// las promos que ML reporta (respuestas CRUDAS de cada endpoint), y las promos
// que el panel detecta/normaliza. Opcionalmente prueba sacar la promo (&remove=1)
// y/o cambiar el precio (&set_price=NUM) y hace read-back para ver que quedo.
// Auth: sesion admin  O  token de API (?token= / x-api-token).
route('GET', '/api/debug-promo', async (req, res) => {
  const sess = requireAuth(req);
  const isAdmin = !!(sess && sess.role === 'admin');
  if (!isAdmin && !checkApiToken(req)) return sendJSON(res, 403, { error: 'Acceso denegado (admin o token)' });
  const u = new URL(req.url, 'http://localhost');
  const itemId = u.searchParams.get('item_id');
  const db = loadDB();
  const account = resolveApiAccount(db, u) || (u.searchParams.get('account_id') ? db.ml_accounts.find(a => a.id === parseInt(u.searchParams.get('account_id'))) : null);
  if (!itemId) return sendJSON(res, 400, { error: 'Falta ?item_id=' });
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada (usá ?account_id=ID o ?account=NOMBRE)' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token ML inválido, reconectá la cuenta' });
  const doRemove = ['1', 'true', 'si', 'yes'].includes(String(u.searchParams.get('remove') || '').toLowerCase());
  const setPriceRaw = u.searchParams.get('set_price');
  const setPrice = (setPriceRaw != null && setPriceRaw !== '') ? Number(setPriceRaw) : null;
  const out = { item_id: itemId, account: account.name, seller_id: account.seller_id, steps: {} };
  // Helper: GET crudo con status + cuerpo, sin lanzar.
  async function rawGet(url, tok, headers = {}) {
    try {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${tok}`, ...headers } });
      const text = await r.text().catch(() => '');
      let data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { _raw: text.slice(0, 400) }; }
      return { status: r.status, ok: r.ok, body: data };
    } catch (e) { return { status: null, ok: false, error: String(e.message || e) }; }
  }
  try {
    // 1) Item real en ML (campos relevantes al precio/promo)
    out.steps['1_item'] = await rawGet(
      `https://api.mercadolibre.com/items/${itemId}?attributes=id,price,base_price,original_price,status,sub_status,deal_ids,tags,catalog_listing,catalog_product_id,variations,shipping`,
      token
    );
    // 2) Respuestas CRUDAS de cada endpoint de promociones (para ver tipo/estado real)
    const appTok = await getAppToken().catch(() => null);
    const promoEndpoints = [
      { label: 'old_user_v2',            url: `${PROMO_OLD_BASE}/items/${itemId}?app_version=v2`,               tok: token,  headers: {} },
      { label: 'old_user_2_0_0',         url: `${PROMO_OLD_BASE}/items/${itemId}?app_version=2.0.0`,            tok: token,  headers: {} },
      { label: 'marketplace_user_v2',    url: `${PROMO_BASE}/items/${itemId}?user_id=${account.seller_id}`,     tok: token,  headers: promoH() },
      { label: 'marketplace_app_v2',     url: `${PROMO_BASE}/items/${itemId}?user_id=${account.seller_id}`,     tok: appTok, headers: promoH() },
    ];
    out.steps['2_promos_raw'] = {};
    for (const ep of promoEndpoints) {
      if (!ep.tok) { out.steps['2_promos_raw'][ep.label] = { skipped: 'sin token' }; continue; }
      out.steps['2_promos_raw'][ep.label] = await rawGet(ep.url, ep.tok, ep.headers);
    }
    // 3) Lo que el panel detecta/normaliza (la logica real que usa el bulk update)
    const detected = await getActivePromotionsForItemBeforeUpdate(itemId, account, token);
    out.steps['3_panel_detecta'] = {
      source: detected.source,
      count: (detected.promos || []).length,
      promos: (detected.promos || []).map(p => ({ id: promoValueId(p), type: promoValueType(p), status: p.status || p.promotion_status || p.state || null, _full: p })),
      errors: detected.errors,
    };
    // 4) OPCIONAL: sacar la promo
    if (doRemove) {
      out.steps['4_remove'] = await removeActivePromotionsBeforeItemUpdate(itemId, account, token);
    }
    // 5) OPCIONAL: cambiar el precio y verificar
    if (setPrice != null && isFinite(setPrice)) {
      const before = out.steps['1_item']?.body?.price ?? null;
      let putRes;
      try {
        const r = await fetch(`https://api.mercadolibre.com/items/${itemId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ price: setPrice })
        });
        const text = await r.text().catch(() => '');
        let data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { _raw: text.slice(0, 400) }; }
        putRes = { status: r.status, ok: r.ok, body: data };
      } catch (e) { putRes = { status: null, ok: false, error: String(e.message || e) }; }
      // read-back
      const after = await rawGet(`https://api.mercadolibre.com/items/${itemId}?attributes=id,price,base_price,original_price`, token);
      out.steps['5_set_price'] = {
        target: setPrice,
        price_antes: before,
        put: putRes,
        price_despues: after?.body?.price ?? null,
        base_price_despues: after?.body?.base_price ?? null,
        aplicado: Math.floor(Number(after?.body?.price)) === Math.floor(setPrice),
      };
    }
    // 6) OPCIONAL: replay del UPDATE REAL sobre item con variaciones, probando combinaciones
    //    para aislar el bloqueo (envío gratis / atributos / precio). NO usa fallbacks: manda
    //    tal cual para ver la respuesta CRUDA de ML.
    //    ?varprice=N            -> precio N dentro de cada variación
    //    &freeship=1            -> agrega shipping {mode:me2, free_shipping:true}
    //    &withattrs=MARCA       -> agrega attributes [{BRAND: MARCA}]
    const varPriceRaw = u.searchParams.get('varprice');
    const varPrice = (varPriceRaw != null && varPriceRaw !== '') ? Number(varPriceRaw) : null;
    if (varPrice != null && isFinite(varPrice)) {
      const it = out.steps['1_item']?.body || {};
      const varIds = Array.isArray(it.variations) ? it.variations.map(v => v.id) : [];
      const payload = {};
      if (varIds.length) payload.variations = varIds.map(id => ({ id, price: varPrice }));
      else payload.price = varPrice;
      const freeship = ['1', 'true', 'si', 'yes'].includes(String(u.searchParams.get('freeship') || '').toLowerCase());
      if (freeship) payload.shipping = { mode: 'me2', free_shipping: true };
      const withAttrs = u.searchParams.get('withattrs');
      if (withAttrs) payload.attributes = [{ id: 'BRAND', value_name: String(withAttrs) }];
      let putRes;
      try {
        const r = await fetch(`https://api.mercadolibre.com/items/${itemId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(payload)
        });
        const text = await r.text().catch(() => '');
        let data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { _raw: text.slice(0, 600) }; }
        putRes = { status: r.status, ok: r.ok, body: data };
      } catch (e) { putRes = { status: null, ok: false, error: String(e.message || e) }; }
      const after = await rawGet(`https://api.mercadolibre.com/items/${itemId}?attributes=id,price,variations,shipping`, token);
      out.steps['6_var_update'] = {
        payload_enviado: payload,
        put: putRes,
        precio_var_despues: after?.body?.variations?.[0]?.price ?? after?.body?.price ?? null,
        free_shipping_despues: after?.body?.shipping?.free_shipping ?? null,
      };
    }
    return sendJSON(res, 200, out);
  } catch (e) {
    out.error = (e && e.response && e.response.data) || String(e.message || e);
    return sendJSON(res, 500, out);
  }
});
// Marcador de version: para confirmar que este deploy quedo live (sin auth, inofensivo)
route('GET', '/api/version', async (req, res) => {
  sendJSON(res, 200, { version: '2026-07-20-faseB-v19', features: ['anto_deposito', 'catalogo_gtin', 'prep_stats_admin', 'promo_proactive_remove', 'conflict_409_retry', 'promo_serialize_per_campaign', 'debug_var_update', 'freeship_attrs_fallback', 'vendor_libs_gestion', 'verify_price_all_paths', 'freeship_upfront', 'msg_reply_auto_dismiss', 'questions_no_reappear', 'questions_dedupe', 'gestion_hoy_ayer_cuenta_sincosto', 'dashboard_reputacion_col', 'dashboard_custom_range'] });
});
// DEBUG: inspecciona la estructura de un item y (opcional) prueba un cambio de SKU, devolviendo la respuesta CRUDA de ML
route('GET', '/api/debug-item', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const u = new URL(req.url, 'http://localhost');
  const itemId = u.searchParams.get('item_id');
  const accountId = parseInt(u.searchParams.get('account_id'));
  const testSku = u.searchParams.get('sku');
  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === accountId);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
  const token = await getValidToken(account);
  if (!token) return sendJSON(res, 401, { error: 'Token inválido' });
  const out = {};
  try {
    const it = await mlGet(`https://api.mercadolibre.com/items/${itemId}?attributes=id,catalog_product_id,catalog_listing,domain_id,user_product_id,inventory_id,seller_custom_field,status,attributes,variations`, token);
    out.item = {
      catalog_product_id: it.catalog_product_id, catalog_listing: it.catalog_listing, domain_id: it.domain_id,
      user_product_id: it.user_product_id, inventory_id: it.inventory_id, seller_custom_field: it.seller_custom_field, status: it.status,
      has_variations: Array.isArray(it.variations) && it.variations.length > 0,
      sku_attrs: (it.attributes || []).filter(a => ['SELLER_SKU', 'GTIN', 'MPN'].includes(a.id)).map(a => ({ id: a.id, value_name: a.value_name })),
      variations: (it.variations || []).map(v => ({ id: v.id, user_product_id: v.user_product_id, seller_custom_field: v.seller_custom_field }))
    };
  } catch (e) { out.item_error = (e && e.response && e.response.data) || String(e.message || e); }
  if (testSku) {
    const body = { seller_custom_field: testSku, attributes: [{ id: 'SELLER_SKU', value_name: testSku }] };
    try {
      const r = await fetch(`https://api.mercadolibre.com/items/${itemId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
      const text = await r.text(); let data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { raw: text }; }
      out.put = { sent: body, status: r.status, ok: r.ok, response: data };
    } catch (e) { out.put_error = String(e.message || e); }
  }
  sendJSON(res, 200, out);
});

// ==================== MÓDULO ESTRATEGIA · MERCADO ADS (inline) ====================
(function(){
// ============================================================================
//  ads.js — Automatización de Mercado Ads (Product Ads) con COSTO REAL por producto
//  Autochap Autopartes Rufino
//
//  Se ACOPLA a tu server.js de "AUTOMATIZACION": reutiliza tus cuentas ML ya
//  conectadas, tu refresh de token y tus helpers (mlGet, mlPut, getValidToken,
//  loadDB, saveDB, sendJSON, requireAuth, parseBody). NO toca tu lógica actual.
//
//  NOVEDAD v2 — Costo real por producto:
//   Importás tu Excel procesado (formato ANTO_COMPLETO.xlsx). El módulo arma una
//   tabla de costos por item_id (MLA) y calcula el MARGEN REAL de cada producto,
//   recalculado al PRECIO EFECTIVAMENTE COBRADO (promo incluida, porque las
//   ventas que reporta la API de ads ya vienen con el descuento aplicado).
//   Con eso decide por GANANCIA NETA después de publicidad, no por un margen
//   global aproximado.
//
//  Integración (2 líneas en server.js, antes de "const server = http.createServer"):
//     const { registerAds } = require('./ads');
//     registerAds({ route, mlGet, mlPut, getValidToken, refreshToken,
//                   loadDB, saveDB, sendJSON, requireAuth, parseBody, ML_CLIENT_ID });
//
//  Seguridad: arranca en DRY-RUN (no pausa nada) hasta ADS_AUTO_PAUSE=true.
//  Solo automatiza lo defensivo (pausar lo que pierde). Nunca sube presupuesto/puja.
// ============================================================================

'use strict';

const ADS_BASE = 'https://api.mercadolibre.com/advertising';
const ADS_HEADERS = { 'Api-Version': '1' };

// Endpoints de Product Ads. La API de Mercado Ads tuvo varias versiones y el
// advertiser_id va DENTRO de la ruta. En vez de casarnos con un formato,
// probamos varios candidatos y cacheamos el que responde OK en tu cuenta.
const EP = {
  advertisers: () => `${ADS_BASE}/advertisers?product_id=PADS`,
};
// Candidatos para LISTAR campañas (con métricas). Se prueban en orden.
function campaignCandidates(adv, site) {
  return [
    { url: `${ADS_BASE}/advertisers/${adv}/product_ads/campaigns`, headers: { 'Api-Version': '1' } },
    { url: `${ADS_BASE}/advertisers/${adv}/product_ads/campaigns`, headers: { 'Api-Version': '2' } },
    { url: `https://api.mercadolibre.com/marketplace/advertising/${site}/advertisers/${adv}/product_ads/campaigns/search`, headers: { 'Api-Version': '2' } },
    { url: `${ADS_BASE}/product_ads/campaigns`, headers: { 'Api-Version': '1' }, extra: { advertiser_id: adv } },
  ];
}
// Candidatos para listar AVISOS (ítems) de una campaña.
function itemCandidates(adv, site, campId) {
  return [
    { url: `${ADS_BASE}/advertisers/${adv}/product_ads/campaigns/${campId}/items`, headers: { 'Api-Version': '1' } },
    { url: `${ADS_BASE}/advertisers/${adv}/product_ads/campaigns/${campId}/items`, headers: { 'Api-Version': '2' } },
    { url: `https://api.mercadolibre.com/marketplace/advertising/${site}/advertisers/${adv}/product_ads/ads/search`, headers: { 'Api-Version': '2' }, extra: { campaign_id: campId } },
  ];
}
// Candidatos para cambiar estado de una campaña (PUT).
function statusCandidates(adv, campId) {
  return [
    `${ADS_BASE}/advertisers/${adv}/product_ads/campaigns/${campId}`,
    `${ADS_BASE}/product_ads/campaigns/${campId}`,
  ];
}

// ---------------------------------------------------------------------------
// Fechas (sin librerías). La API limita métricas a 90 días.
// ---------------------------------------------------------------------------
const ymd = (d) => d.toISOString().slice(0, 10);
// Fecha (YYYY-MM-DD) en hora argentina (UTC-3) a partir de un date_created UTC de ML.
const argDate = (iso) => { if (!iso) return ''; const t = new Date(iso).getTime(); if (isNaN(t)) return String(iso).slice(0, 10); return new Date(t - 3 * 3600 * 1000).toISOString().slice(0, 10); };
const daysAgo = (n) => { const d = new Date(); d.setDate(d.getDate() - n); return d; };
const daysBetween = (from, to) => { if (!from || !to) return 30; const a = new Date(from + 'T00:00:00Z'), b = new Date(to + 'T00:00:00Z'); return Math.max(1, Math.round((b - a) / 86400000) + 1); };

function asList(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  for (const k of ['results', 'campaigns', 'ads', 'items', 'advertisers', 'data']) {
    if (Array.isArray(raw[k])) return raw[k];
  }
  return [];
}

// Extrae métricas de campaña/aviso sin importar cómo las anide la API.
function readMetrics(obj) {
  const m = obj.metrics || obj.metric || obj || {};
  const num = (...keys) => {
    for (const k of keys) {
      const v = (m[k] ?? obj[k]);
      if (v !== undefined && v !== null && v !== '') return Number(v) || 0;
    }
    return 0;
  };
  const clicks = num('clicks', 'clics');
  const prints = num('prints', 'impressions', 'impresiones');
  const cost = num('cost', 'investment', 'inversion', 'amount_spent');
  let revenue = num('total_amount', 'amount', 'revenue', 'sales');
  if (!revenue) revenue = num('direct_amount') + num('indirect_amount');
  let units = num('units_quantity', 'units', 'total_units', 'sold_quantity');
  if (!units) units = num('direct_units') + num('indirect_units');
  let acos = m.acos ?? obj.acos;
  acos = (acos !== undefined && acos !== null && acos !== '') ? Number(acos) : (revenue > 0 ? (cost / revenue) * 100 : null);
  const roas = cost > 0 ? revenue / cost : null;
  return { clicks, prints, cost, revenue, units, acos, roas };
}

// ---------------------------------------------------------------------------
// Config global (fallback cuando no hay costo real de un producto).
// ---------------------------------------------------------------------------
function getAdsConfig(loadDB) {
  const db = loadDB();
  const c = db.ads_config || {};
  return {
    margin: c.margin ?? 12,          // margen global de respaldo (%)
    acosTarget: c.acosTarget ?? 7,    // objetivo global de respaldo (%)
    minClicks: c.minClicks ?? 30,
    windowDays: c.windowDays ?? 14,
    freeShipThreshold: c.freeShipThreshold ?? 33000, // envío gratis desde este monto
    facturaPct: c.facturaPct ?? 5,   // FACTURA % GLOBAL (cargo mensual de ML) — una sola para todas las cuentas, default 5
    autoPause: process.env.ADS_AUTO_PAUSE === 'true' || c.autoPause === true,
  };
}

// ---------------------------------------------------------------------------
// TABLA DE COSTOS por item_id (MLA). Se llena importando tu Excel procesado.
// Estructura por item:
//   cost      = precio costo (col P)               → costo cuando NO absorbés envío
//   costShip  = costo/gastos (col T = P + envío)   → costo cuando SÍ absorbés envío
//   ship      = 'ME' (Mercado Envío) | 'NO'        → col D (shipping)
//   commission= costo por vender (fracción, ej 0.24 según listing_type: 0.18/0.24/0.32)
//   listPrice = precio final (col U) | marginList = margen de ganancia (col Y)
//
// Regla de costo (la tuya): si es MERCADO ENVIO y el precio efectivo cobrado supera
// el umbral de envío gratis (33.000 por defecto), el envío lo absorbés vos → costo = costShip (T).
// Si es NO ENVIO, o es MERCADO ENVIO pero el precio quedó por debajo del umbral → costo = cost (P).
// ---------------------------------------------------------------------------
// Los costos viven en su PROPIO archivo (ads_costs.json), NO dentro de data.json.
// Así tu automatización de precios no reescribe esta tabla enorme en cada saveDB.
const _fsCosts = require('fs');
const _pathCosts = require('path');
function costsFilePath() { return _pathCosts.join(DATA_DIR, 'ads_costs.json'); }   // legacy (un solo archivo)
// UN ARCHIVO POR CUENTA: importar/enriquecer una cuenta escribe SOLO su archivo (rápido y sin pisar a las demás).
function accountCostsPath(sellerId) { return _pathCosts.join(DATA_DIR, 'ads_costs_' + String(sellerId) + '.json'); }
function loadAccountCosts(sellerId) { try { return JSON.parse(_fsCosts.readFileSync(accountCostsPath(sellerId), 'utf8')) || { costs: {} }; } catch (e) { return { costs: {} }; } }
function saveAccountCosts(sellerId, obj) { _fsCosts.writeFileSync(accountCostsPath(sellerId), JSON.stringify(obj)); }
// Lectura combinada: junta el legacy + todos los archivos por cuenta en una sola tabla { costs, updated }.
function loadCostsFile() {
  const merged = {}; let updated = null;
  try { const f = JSON.parse(_fsCosts.readFileSync(costsFilePath(), 'utf8')); if (f && f.costs) { Object.assign(merged, f.costs); if (f.updated && (!updated || f.updated > updated)) updated = f.updated; } } catch (e) {}
  try {
    for (const fn of _fsCosts.readdirSync(DATA_DIR)) {
      if (!/^ads_costs_.+\.json$/.test(fn)) continue;
      try { const f = JSON.parse(_fsCosts.readFileSync(_pathCosts.join(DATA_DIR, fn), 'utf8')); if (f && f.costs) { Object.assign(merged, f.costs); if (f.updated && (!updated || f.updated > updated)) updated = f.updated; } } catch (e) {}
    }
  } catch (e) {}
  return { costs: merged, updated };
}
function saveCostsFile(obj) { _fsCosts.writeFileSync(costsFilePath(), JSON.stringify(obj)); }   // legacy (compat)

// ---------------------------------------------------------------------------
// LEDGER HISTORICO DE VENTAS: congela el costo/margen al momento de cada venta.
// Estructura: { sales: { "<accountId>:<orderId>:<itemId>": { ...snapshot } }, updated }
// Asi el margen de una venta vieja NO se recalcula con el costo de hoy: queda fijo.
// ---------------------------------------------------------------------------
function histFilePath() { return _pathCosts.join(DATA_DIR, 'ads_ventas_hist.json'); }
function loadHistFile() { try { return JSON.parse(_fsCosts.readFileSync(histFilePath(), 'utf8')) || { sales: {} }; } catch (e) { return { sales: {} }; } }
function saveHistFile(obj) { try { _fsCosts.writeFileSync(histFilePath(), JSON.stringify(obj)); } catch (e) {} }

// ---------------------------------------------------------------------------
// SNAPSHOTS DIARIOS DE GESTIÓN (solapa Histórico): al tocar "Guardar día" congelamos
// las ventas de ESE día junto con la lista de precios/costos vigente al momento de guardar.
// Cada día tiene su propia foto y NO se recalcula con costos nuevos.
// Estructura: { days: { "YYYY-MM-DD": { date, savedAt, savedBy, taxPct, scope, totals, sales:[...] } }, updated }
// ---------------------------------------------------------------------------
function gestionDaysPath() { return _pathCosts.join(DATA_DIR, 'gestion_dias.json'); }
function loadGestionDays() { try { return JSON.parse(_fsCosts.readFileSync(gestionDaysPath(), 'utf8')) || { days: {} }; } catch (e) { return { days: {} }; } }
function saveGestionDays(obj) { try { _fsCosts.writeFileSync(gestionDaysPath(), JSON.stringify(obj)); } catch (e) {} }

// VENTAS por publicación de los ÚLTIMOS 90 DÍAS (para el "vende" de Estrategia).
// Estructura: { accounts: { <accountId>: { computedAt, days, map: { <itemId>: unidades } } } }
function sold90Path() { return _pathCosts.join(DATA_DIR, 'ads_sold90.json'); }
function loadSold90File() { try { return JSON.parse(_fsCosts.readFileSync(sold90Path(), 'utf8')) || { accounts: {} }; } catch (e) { return { accounts: {} }; } }
function saveSold90File(obj) { try { _fsCosts.writeFileSync(sold90Path(), JSON.stringify(obj)); } catch (e) {} }
// Mapa item_id -> unidades vendidas (paid, sin canceladas) en [from,to].
async function fetchSold90Map(engine, account, from, to) {
  const orders = await engine.fetchSales(account, from, to);
  const units = {};   // item_id -> unidades vendidas (90d)
  const take = {};     // item_id -> { rev, fee } → tasa REAL de ML (comisión+cargo+CUOTAS) para el margen exacto
  for (const o of orders) {
    if (String(o.status || '').toLowerCase() === 'cancelled') continue;
    for (const it of (o.items || [])) {
      if (!it.item_id) continue;
      const qty = Number(it.qty) || 0;
      units[it.item_id] = (units[it.item_id] || 0) + qty;
      // El "sale_fee" de una orden REAL ya incluye comisión + cargo fijo + costo de cuotas/financiación.
      // Acumulamos ingreso y cargo para despejar la tasa efectiva real de ML por publicación.
      const rev = (Number(it.unit_price) || 0) * qty;
      const fee = (Number(it.sale_fee) || 0) * qty;
      if (rev > 0) { const t = take[it.item_id] || { rev: 0, fee: 0 }; t.rev += rev; t.fee += fee; take[it.item_id] = t; }
    }
  }
  return { units, take };
}

// Ejecuta fn sobre items con CONCURRENCIA limitada (para acelerar sin saturar la API de ML).
async function mapLimit(items, limit, fn) {
  let i = 0;
  const worker = async () => { while (i < items.length) { const idx = i++; await fn(items[idx], idx); } };
  const n = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: n }, () => worker()));
}

// Normaliza un titulo para cruzar publicaciones iguales entre cuentas (dedup por titulo).
function normTitle(s) {
  return String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, ' ').replace(/\s+/g, ' ').trim();
}
// Marca si una orden NO sirve para rentabilidad: SOLO canceladas o con reclamo cerrado
// con devolución al comprador. OJO: "not_delivered" / "shipped" / "pending" son ventas
// válidas todavía no entregadas — esas SÍ cuentan (no las ocultamos).
function isDeadOrder(order, shipStatus) {
  const st = String(shipStatus || '').toLowerCase();
  if (['cancelled', 'canceled', 'returned'].includes(st)) return true;         // envío cancelado o devuelto al vendedor
  if (String(order.status || '').toLowerCase() === 'cancelled') return true;    // orden cancelada (incluye reclamos cerrados con reembolso)
  const tags = (order.tags || []).map(t => String(t).toLowerCase());
  // Solo etiquetas explícitas de reembolso/reversa (NO "not_delivered", que es "en camino").
  if (tags.some(t => ['refunded', 'order_refunded', 'reversed', 'return_in_process'].includes(t))) return true;
  return false;
}
function loadCosts(loadDB) {
  const f = loadCostsFile();
  if (f && f.costs && Object.keys(f.costs).length) return f.costs;
  // compat: si quedó algo viejo dentro de data.json, lo usamos igual
  try { const c = loadDB && loadDB().ads_costs; if (c && Object.keys(c).length) return c; } catch (e) {}
  return {};
}

// Margen de contribución REAL de un ítem al precio efectivamente cobrado.
// Devuelve { marginPct, profitPerUnit, floorUsed, freeShip } o null si no hay costo.
function realMarginAtPrice(costRow, price, freeShipThreshold = 33000) {
  if (!costRow || !price || price <= 0) return null;
  const cost = Number(costRow.cost) || 0;
  const costShip = Number(costRow.costShip) || cost;
  const absorbsShip = (costRow.ship === 'ME') && (price > freeShipThreshold);
  const floor = absorbsShip ? costShip : cost;
  const commission = price * (Number(costRow.commission) || 0);
  const profit = price - commission - floor;
  return { marginPct: (profit / price) * 100, profitPerUnit: profit, floorUsed: floor, freeShip: absorbsShip };
}

// ---------------------------------------------------------------------------
// Motor: helpers que hablan con la API usando TUS funciones.
// ---------------------------------------------------------------------------
function makeEngine(deps) {
  const { mlGet, mlPut, getValidToken, loadDB, saveDB } = deps;
  const METRICS = 'clicks,prints,cost,acos,total_amount,units_quantity';

  function cacheOnAccount(account, patch) {
    const db = loadDB(); const acc = db.ml_accounts.find(a => a.id === account.id);
    if (acc) { Object.assign(acc, patch); saveDB(db); }
    Object.assign(account, patch);
  }

  // Resuelve advertiser_id + site (MLA, etc.) y los cachea en la cuenta.
  async function getAdvertiser(account) {
    if (account.advertiser_id) return { id: account.advertiser_id, site: account.ads_site || 'MLA' };
    const token = await getValidToken(account);
    if (!token) throw new Error('token inválido');
    const raw = await mlGet(EP.advertisers(), token, {}, ADS_HEADERS);
    const adv = asList(raw)[0];
    const id = adv && (adv.advertiser_id || adv.id);
    const site = (adv && (adv.site_id || adv.site)) || 'MLA';
    if (!id) throw new Error('no se encontró advertiser_id (¿Product Ads activado en la cuenta?)');
    cacheOnAccount(account, { advertiser_id: id, ads_site: site });
    return { id, site };
  }
  async function getAdvertiserId(account) { return (await getAdvertiser(account)).id; }

  // Prueba una lista de candidatos {url, headers, extra} y devuelve el primero que responde OK.
  async function tryCandidates(cands, token, params) {
    let lastErr;
    for (const c of cands) {
      try {
        const data = await mlGet(c.url, token, { ...(params || {}), ...(c.extra || {}) }, c.headers || ADS_HEADERS);
        return { data, used: c.url, headers: c.headers || ADS_HEADERS };
      } catch (e) { lastErr = e; }
    }
    throw lastErr;
  }

  async function listCampaigns(account, from, to) {
    const token = await getValidToken(account);
    const { id, site } = await getAdvertiser(account);
    const params = { date_from: from, date_to: to, metrics: METRICS, limit: 200 };
    const cands = campaignCandidates(id, site);
    // si ya sabemos cuál funcionó antes, lo probamos primero
    if (account.ads_campaigns_ep) cands.unshift({ url: account.ads_campaigns_ep, headers: account.ads_campaigns_hdr || ADS_HEADERS });
    const r = await tryCandidates(cands, token, params);
    if (r.used !== account.ads_campaigns_ep) cacheOnAccount(account, { ads_campaigns_ep: r.used, ads_campaigns_hdr: r.headers });
    return asList(r.data);
  }

  // Avisos (ítems) de una campaña — best-effort. Si la API no los expone, seguimos a nivel campaña.
  async function listCampaignItems(account, campaignId, from, to) {
    const token = await getValidToken(account);
    const { id, site } = await getAdvertiser(account);
    try {
      const r = await tryCandidates(itemCandidates(id, site, campaignId), token,
        { date_from: from, date_to: to, metrics: METRICS, limit: 200 });
      return asList(r.data);
    } catch (e) { return []; }
  }

  async function setCampaignStatus(account, campaignId, status) {
    const token = await getValidToken(account);
    const { id } = await getAdvertiser(account);
    let lastErr;
    for (const url of statusCandidates(id, campaignId)) {
      try { return await mlPut(url, { status }, token); } catch (e) { lastErr = e; }
    }
    throw lastErr;
  }

  // Trae info en vivo de publicaciones desde ML (multiget de a 20, lotes EN PARALELO).
  async function fetchItems(account, ids, attrs) {
    const token = await getValidToken(account);
    const out = {};
    const batches = [];
    for (let i = 0; i < ids.length; i += 20) batches.push(ids.slice(i, i + 20));
    await mapLimit(batches, 8, async (batch) => {
      try {
        const arr = await mlGet(`https://api.mercadolibre.com/items?ids=${batch.join(',')}&attributes=${attrs}`, token);
        for (const el of (arr || [])) { const b = el.body || el; if (b && b.id) out[b.id] = b; }
      } catch (e) {}
    });
    return out;
  }

  // Visitas por publicación (demanda real).
  // OJO IMPORTANTE: el endpoint MULTI-ítem por rango (/items/visits?ids=...&date_from&date_to) devuelve
  // los datos en un formato que NO es 1 objeto por ítem → quedaban casi todas en 0 (bug histórico).
  // El endpoint POR ÍTEM (/items/{id}/visits?date_from&date_to) SÍ responde bien. Por eso, con rango,
  // pedimos DE A UNA (con concurrencia). Sin rango (acumulado), el multi-ítem /visits/items sí anda.
  async function fetchVisits(account, ids, from, to) {
    const token = await getValidToken(account);
    const out = {};
    const useRange = !!(from && to);
    if (useRange) {
      await mapLimit(ids, 6, async (id) => {   // concurrencia baja: evita el pico de memoria que crasheaba Render
        try {
          const d = await mlGet('https://api.mercadolibre.com/items/' + id + '/visits', token, { date_from: from, date_to: to });
          const v = d && (d.total_visits != null ? d.total_visits : d.visits);
          if (v != null) out[id] = Number(v) || 0;
        } catch (e) { /* sin dato; el respaldo acumulado lo cubre */ }
      });
      return out;
    }
    // ACUMULADO (histórico): el multi-ítem /visits/items?ids= sí devuelve por ítem. Lotes de 50 en paralelo.
    const parseInto = (data) => {
      if (Array.isArray(data)) { for (const d of data) { if (d && d.item_id != null) out[d.item_id] = Number(d.total_visits != null ? d.total_visits : d.visits) || 0; } }
      else if (data && typeof data === 'object') { for (const k in data) { const v = data[k]; out[k] = typeof v === 'number' ? v : Number(v && (v.total_visits != null ? v.total_visits : v.visits)) || 0; } }
    };
    const batches = [];
    for (let i = 0; i < ids.length; i += 50) batches.push(ids.slice(i, i + 50));
    await mapLimit(batches, 6, async (batch) => {
      try { parseInto(await mlGet('https://api.mercadolibre.com/visits/items', token, { ids: batch.join(',') })); } catch (e) {}
    });
    return out;
  }

  // PRECIO DE VENTA REAL (con promo). El campo item.sale_price a veces viene null, pero /items/{id}/prices
  // expone la entrada type=promotion/deal con su vigencia (start_time/end_time). Ese es el precio que paga
  // el comprador. Devuelve id -> { sell, list, promo }. Por ítem (no hay multi-id), concurrencia baja.
  async function fetchItemPrices(account, ids) {
    const token = await getValidToken(account);
    const out = {};
    const now = Date.now();
    await mapLimit(ids, 6, async (id) => {
      try {
        const d = await mlGet('https://api.mercadolibre.com/items/' + id + '/prices', token);
        const arr = (d && d.prices) || [];
        const std = arr.find(p => String(p.type) === 'standard');
        const listP = std ? Number(std.amount) : null;
        let promoP = null;
        for (const p of arr) {
          if (!/promotion|deal/i.test(String(p.type || ''))) continue;
          const cnd = p.conditions || {};
          const st = cnd.start_time ? Date.parse(cnd.start_time) : null;
          const en = cnd.end_time ? Date.parse(cnd.end_time) : null;
          if (st && now < st) continue;         // todavía no arrancó
          if (en && now > en) continue;         // ya venció
          const amt = Number(p.amount);
          if (amt > 0 && (promoP == null || amt < promoP)) promoP = amt;   // la más baja vigente
        }
        const sell = (promoP != null && (listP == null || promoP < listP)) ? promoP : listP;
        out[id] = { sell: sell != null ? sell : null, list: listP, promo: promoP != null };
      } catch (e) { /* sin dato de precios: cae al price del multiget */ }
    });
    return out;
  }

  // Trae las VENTAS reales de ML por cuenta en el rango [from, to] (YYYY-MM-DD).
  // Devuelve órdenes con sus ítems y el shipment_id (para el envío real).
  // maxOrders = tope de órdenes a traer (por velocidad). La paginación va EN PARALELO:
  // pedimos la 1ª página para saber el total y luego el resto en simultáneo (mucho más rápido → evita timeouts).
  async function fetchSales(account, from, to, maxOrders) {
    const token = await getValidToken(account);
    const CAP = Math.min(maxOrders || 5000, 20000);
    const p = { seller: account.seller_id, 'order.status': 'paid', sort: 'date_desc', limit: 50 };
    // Ventana en hora ARGENTINA (UTC-3), igual que el Dashboard, para que el día coincida.
    if (from) p['order.date_created.from'] = from + 'T00:00:00.000-03:00';
    if (to) p['order.date_created.to'] = to + 'T23:59:59.999-03:00';
    const orders = [];
    const mapOrder = (o) => {
      // Impuesto REAL que ML retiene en la venta (la línea "Impuestos" del resumen),
      // sumando lo que informan los pagos de la orden. Si no viene, queda null (usa fallback %).
      let taxReal = null, installments = 0;
      for (const pm of (o.payments || [])) {
        const t = Number(pm.taxes_amount); if (!isNaN(t)) taxReal = (taxReal || 0) + t;
        const inst = Number(pm.installments); if (!isNaN(inst) && inst > installments) installments = inst;  // cuotas del pago
      }
      return {
        order_id: o.id, pack_id: o.pack_id || o.id,   // pack_id = "Venta #" que ML muestra en el detalle (el que copia el usuario)
        date: argDate(o.date_created),   // fecha en hora argentina (consistente con el Dashboard)
        shipment_id: o.shipping && o.shipping.id,
        payment_ids: (o.payments || []).map(p => p.id).filter(Boolean),   // pagos de MP (para traer la retención/impuesto real)
        status: o.status, tags: o.tags || [], tax_real: taxReal, installments,
        items: (o.order_items || []).map(it => ({
          item_id: it.item && it.item.id, title: (it.item && it.item.title) || '',
          qty: Number(it.quantity) || 0, unit_price: Number(it.unit_price) || 0, sale_fee: Number(it.sale_fee) || 0,
        })),
      };
    };
    // 1ª página (para conocer paging.total) y luego el resto en paralelo.
    let first;
    try { first = await mlGet('https://api.mercadolibre.com/orders/search', token, { ...p, offset: 0 }); }
    catch (e) { return orders; }
    for (const o of ((first && first.results) || [])) orders.push(mapOrder(o));
    const total = Math.min((first && first.paging && first.paging.total) || orders.length, CAP);
    const offsets = [];
    for (let off = 50; off < total; off += 50) offsets.push(off);
    await mapLimit(offsets, 6, async (off) => {
      try { const d = await mlGet('https://api.mercadolibre.com/orders/search', token, { ...p, offset: off }); for (const o of ((d && d.results) || [])) orders.push(mapOrder(o)); }
      catch (e) {}
    });
    return orders;
  }

  // Envío REAL de ML: costo que absorbió el vendedor + estado del envío.
  async function fetchShipping(account, shipmentId) {
    if (!shipmentId) return { cost: null, status: null, logistic: null, bonus: null };
    const token = await getValidToken(account);
    let cost = null, status = null, logistic = null, bonus = null, s = null;
    try { s = await mlGet(`https://api.mercadolibre.com/shipments/${shipmentId}`, token, {}, { 'x-format-new': 'true' }); status = s && (s.status || null); logistic = s && (s.logistic_type || (s.logistic && s.logistic.type) || null); } catch (e) {}
    try {
      const c = await mlGet(`https://api.mercadolibre.com/shipments/${shipmentId}/costs`, token, {}, { 'x-format-new': 'true' });
      if (c) {
        const snd = Array.isArray(c.senders) ? c.senders[0] : null;
        const rcv = c.receiver;
        if (snd && snd.cost != null) cost = Number(snd.cost) || 0;   // costo REAL neto que absorbe el vendedor
        else if (c.gross_amount != null) cost = Math.max(0, Number(c.gross_amount) - (Number(c.receiver_shipping_cost) || 0));
        if (snd) {
          // BONIFICACIÓN de ML por envío Flex. NO afecta la ganancia.
          //  - Ventas CARAS (el vendedor absorbe parte del envío): el bono es el "save" del sender (ej. 869).
          //  - Ventas BARATAS (envío gratis, el vendedor no paga): ML le acredita el envío completo; ese monto está
          //    en el "save" del receiver (comprador) — ej. 8690. Lo tomamos cuando el costo del sender es 0.
          const sndSave = Number(snd.save) || 0;
          const sndCost = Number(snd.cost) || 0;
          const rcvSave = (rcv && Number(rcv.save)) || 0;
          if (sndSave > 0) bonus = sndSave;
          else if (sndCost === 0 && rcvSave > 0) bonus = rcvSave;
          else {
            // Otros casos: la bonificación puede venir como "compensation", como COSTO NEGATIVO del sender
            // (ML te acredita), o —en Flex donde el comprador pagó el envío— es ese envío que vos cobrás
            // por hacer la entrega (receiver.cost). Según la regla: precio ≤ 32999 → todo va a bonificación.
            const sndComp = Number(snd.compensation) || 0;
            const rcvComp = (rcv && Number(rcv.compensation)) || 0;
            const rcvCost = (rcv && Number(rcv.cost)) || 0;
            if (sndComp > 0) bonus = sndComp;
            else if (rcvComp > 0) bonus = rcvComp;
            else if (sndCost < 0) bonus = -sndCost;
            else if (logistic === 'self_service' && rcvCost > 0) bonus = rcvCost;
          }
        }
      }
    } catch (e) {}
    if (cost == null && s && s.base_cost != null) cost = Number(s.base_cost) || 0;
    return { cost, status, logistic, bonus };
  }

  // IMPUESTO REAL (retenciones IIBB/SIRTAC/etc.) de una venta. NO viene en la orden: vive en el pago
  // de Mercado Pago, en charges_details con type="tax". Sumamos esos cargos de todos los pagos de la orden.
  async function fetchPaymentTax(account, paymentIds) {
    if (!paymentIds || !paymentIds.length) return null;
    const token = await getValidToken(account);
    let tax = 0, got = false;
    for (const pid of paymentIds) {
      try {
        const mp = await mlGet('https://api.mercadopago.com/v1/payments/' + pid, token, {});
        for (const ch of (mp && mp.charges_details) || []) {
          if (String(ch.type) === 'tax') { const a = Number(ch.amounts && ch.amounts.original); if (!isNaN(a)) { tax += a; got = true; } }
        }
      } catch (e) {}
    }
    return got ? tax : null;
  }

  // SIMULAR COSTOS de ML (el "simular costos" de la web): comisión + cargo fijo EXACTOS
  // para un precio/categoría/tipo, sin necesidad de una venta. Endpoint público listing_prices.
  // Devuelve { sale_fee, fixed_fee, percentage_fee, listing_type_id } o null.
  const _simCache = {};
  async function simulateFee(account, price, categoryId, listingType) {
    const p = Math.round(Number(price) || 0);
    if (p <= 0) return null;
    const key = [categoryId || '', listingType || '', p].join('|');
    if (_simCache[key] !== undefined) return _simCache[key];
    const token = await getValidToken(account);
    const params = { price: p };
    if (categoryId) params.category_id = categoryId;
    if (listingType) params.listing_type_id = listingType;
    let out = null;
    try {
      const data = await mlGet('https://api.mercadolibre.com/sites/MLA/listing_prices', token, params);
      const pick = Array.isArray(data)
        ? (data.find(d => String(d.listing_type_id) === String(listingType)) || data.find(d => String(d.listing_type_id) === 'gold_special') || data[0])
        : data;
      if (pick) {
        const det = pick.sale_fee_details || {};
        out = {
          sale_fee: Number(pick.sale_fee_amount) || 0,            // "Cargo por vender" = comisión + cargo fijo
          fixed_fee: Number(det.fixed_fee) || 0,                  // cargo fijo por unidad
          percentage_fee: Number(det.percentage_fee) || 0,        // % de comisión
          gross_amount: Number(det.gross_amount) || 0,
          financing: Number(det.financing_add_on_fee) || 0,       // "Costo por ofrecer cuotas" (si viene)
          listing_type_id: pick.listing_type_id,
        };
      }
    } catch (e) { out = null; }
    _simCache[key] = out;
    return out;
  }

  // Actualiza el PRECIO de una publicación en ML (PUT /items/{id}).
  async function setItemPrice(account, itemId, price) {
    const token = await getValidToken(account);
    return await mlPut('https://api.mercadolibre.com/items/' + itemId, { price: Math.round(Number(price)) }, token);
  }

  return { getAdvertiser, getAdvertiserId, listCampaigns, listCampaignItems, setCampaignStatus, fetchItems, fetchSales, fetchShipping, fetchPaymentTax, simulateFee, fetchVisits, fetchItemPrices, setItemPrice };
}

// ===========================================================================
// ACTUALIZADOR DE PRECIOS: matemática de precio a partir del costo EXACTO de ML.
// Usa los datos guardados al enriquecer (comisión, cargo fijo, cuotas, envío, impuestos)
// para: 1) calcular el margen a cualquier precio, 2) despejar el precio que da un margen objetivo.
// ===========================================================================
// Factores de costo (tasas) de un producto ya enriquecido. taxPct = factura mensual %.
function priceFactors(c, taxPct) {
  const price = Number(c.price) || 0;
  if (!price || c.simFee == null) return null;                       // necesita estar enriquecido
  const commPct = (Number(c.simFee) - (Number(c.simFixed) || 0)) / price;  // % comisión (tasa)
  const cuotasPct = (Number(c.simCuotas) || 0) / price;             // % cuotas (tasa)
  const retPct = (Number(c.simImp) || 0) / price;                   // % retenciones (tasa)
  const facturaPct = ((taxPct != null ? taxPct : 5)) / 100;          // factura mensual
  return { commPct, cuotasPct, retPct, facturaPct, fixedFee: Number(c.simFixed) || 0, envio: Number(c.simEnvio) || 0, cost: Number(c.cost) || 0 };
}
// Margen neto % a un precio dado (con la estructura de costos de ML).
function marginAtPrice(f, price) {
  if (!f || !price || price <= 0) return null;
  const net = price * (1 - f.commPct - f.cuotasPct - f.retPct - f.facturaPct) - f.fixedFee - f.envio - f.cost;
  return net / price * 100;
}
// Precio que hace falta para llegar a un margen objetivo %. null si es inalcanzable.
function priceForMargin(f, targetPct) {
  if (!f) return null;
  const K = 1 - f.commPct - f.cuotasPct - f.retPct - f.facturaPct - targetPct / 100;
  if (K <= 0.01) return null;                                        // margen imposible con esos costos
  const P = (f.fixedFee + f.envio + f.cost) / K;
  return P > 0 ? Math.round(P) : null;
}

// ---------------------------------------------------------------------------
// Margen REAL de una venta = precio − comisión real de ML − costo (P/T del Excel) − impuesto.
// Reconstruye tu misma cuenta: GANANCIA = QUEDA(precio−comisión−envío) − COSTO − FACTURA.
// Acá usamos la comisión REAL de ML (sale_fee) y el costo/envío del _COMPLETO.
// ---------------------------------------------------------------------------
// Dos cargas DISTINTAS y ambas van:
//  - IMPUESTO (tax): lo que ML retiene en CADA venta (línea "Impuestos" del resumen). Real de ML por venta.
//  - FACTURA (factura): el % de arriba. Es un cargo que ML factura UNA VEZ AL MES → parte del COSTO.
// realShip = envío real de ML (si se pudo obtener). Si es null, usa la estimación del Excel.
// realTax  = impuesto REAL retenido por ML en la venta. Si no viene, queda 0 (no inventamos impuesto).
// isFlex: la venta es Mercado Envíos Flex. En Flex ML NO descuenta el envío del depósito
// (el flex se cobra aparte), así que el "QUEDÓ EN CUENTA" real = precio − comisión − impuesto.
// En Correo/ME ML SÍ descuenta el envío del depósito → queda = precio − comisión − envío − impuesto.
// La GANANCIA cuenta el envío como costo en ambos casos (idéntica a antes); solo cambia dónde se muestra.
function saleNet(sale, costRow, cfg, realShip, realTax, isFlex) {
  const qty = sale.qty || 0;
  const revenue = (sale.unit_price || 0) * qty;
  const fee = sale.sale_fee || 0;                                   // comisión real de ML ("Cargo por venta total")
  const taxReal = (realTax != null && !isNaN(realTax));
  const tax = taxReal ? realTax : 0;                                // impuesto REAL de ML por venta (0 si ML no lo informa)
  const factura = revenue * ((cfg.taxPct != null ? cfg.taxPct : 5) / 100); // "factura" mensual de ML → parte del costo
  const shipReal = (realShip != null && !isNaN(realShip));
  if (!costRow) {
    const e = shipReal ? realShip : 0;
    const shipDed = isFlex ? 0 : e;                                 // ML descuenta el envío del depósito solo si NO es Flex
    return { revenue, fee, envio: e, envioReal: shipReal, tax, taxReal, factura, queda: revenue - fee - shipDed - tax, cost: null, net: null, marginPct: null, known: false };
  }
  const pcost = Number(costRow.cost) || 0;
  let envio;
  if (shipReal) { envio = realShip; }                              // envío REAL de ML
  else { const rm = realMarginAtPrice(costRow, sale.unit_price, cfg.freeShipThreshold); const floor = rm ? rm.floorUsed : pcost; envio = Math.max(0, floor - pcost) * qty; }
  const cost = pcost * qty;                                        // costo del producto
  const shipDed = isFlex ? 0 : envio;                              // envío descontado del depósito (0 en Flex)
  const queda = revenue - fee - shipDed - tax;                     // QUEDÓ EN CUENTA REAL de ML
  const net = revenue - fee - envio - tax - cost - factura;        // ganancia (el modelo Flex definitivo se ajusta tras el diagnóstico)
  return { revenue, fee, envio, envioReal: shipReal, tax, taxReal, factura, queda, cost, net, marginPct: revenue > 0 ? (net / revenue) * 100 : null, known: true };
}

async function analyzeVentas(engine, account, cfg, costs, from, to, hist) {
  const orders = await engine.fetchSales(account, from, to);
  const SHIP_CAP = cfg.shipCap || 200;                 // tope de envíos reales a consultar (por velocidad)
  let facturacion = 0, factConocida = 0, ganancia = 0, conocidas = 0, perdida = 0, sinCosto = 0, shipFetched = 0;
  let hidden = 0, savedCount = 0, freshCount = 0, taxRealCount = 0, keptOrders = 0, taxFixedCount = 0, costFixedCount = 0;  // ocultas, congeladas, nuevas, con impuesto real, órdenes válidas, impuestos corregidos, costos rellenados
  // Acumuladores EXTRA (para el resumen ampliado y el XLSX estilo RESUMEN DIARIO):
  let unidades = 0, feeTotal = 0, envioTotal = 0, taxTotal = 0, facturaTotal = 0, quedaTotal = 0;
  let costTotal = 0, costStockTotal = 0, gananciaSinFlex = 0, perdidaMonto = 0, cuotasCount = 0, bonoTotal = 0;
  const sales = (hist && hist.sales) || null;
  const nowIso = new Date().toISOString();
  const rows = [];
  // ===== VENTAS EN CARRITO: varias órdenes comparten un mismo PAQUETE (pack_id). El envío se cobra
  // UNA sola vez por paquete → se lo asignamos al ítem de MAYOR valor; el resto del carrito lleva envío $0.
  // Primero traemos el envío UNA vez por shipment (más rápido y sin duplicar el costo).
  const shipInfo = {};   // shipment_id -> { cost, status, logistic }
  let sIdx = 0;
  for (const o of orders) {
    const sid = o.shipment_id;
    if (!sid || shipInfo[sid] !== undefined) continue;
    if (sIdx < SHIP_CAP) { const sh = await engine.fetchShipping(account, sid); shipInfo[sid] = { cost: sh.cost, status: sh.status, logistic: sh.logistic, bonus: sh.bonus }; if (sh.cost != null) shipFetched++; sIdx++; }
    else { shipInfo[sid] = { cost: null, status: null, logistic: null, bonus: null }; }
  }
  // ===== IMPUESTO REAL (retención IIBB/SIRTAC/etc.) por orden, del PAGO de Mercado Pago (no viene en la orden).
  // Solo lo traemos para las órdenes que lo necesitan: nuevas, o congeladas con impuesto 0 (para corregirlas).
  const taxByOrder = {};
  {
    const need = [];
    for (const o of orders) {
      let some = false;
      for (const it of o.items) { const fr = sales && sales[account.id + ':' + o.order_id + ':' + it.item_id]; if (!fr || !(fr.tax > 0)) { some = true; break; } }
      if (some && o.payment_ids && o.payment_ids.length) need.push(o);
    }
    await mapLimit(need.slice(0, SHIP_CAP), 6, async (o) => {
      const t = await engine.fetchPaymentTax(account, o.payment_ids);
      if (t != null) taxByOrder[o.order_id] = t;
    });
  }
  // ===== Agrupamos por PAQUETE (pack_id = "Venta #" de ML): en un carrito el envío se cobra UNA vez
  // para todo el paquete. Lo asignamos al ítem de MAYOR valor del paquete; el resto → envío 0.
  // El envío del paquete = suma de los costos de sus shipments DISTINTOS (normalmente uno solo).
  const packOwner = {}, packCount = {}, packEnvio = {}, packBono = {};
  {
    const bestByPack = {}, shipmentsSeen = {};
    for (const o of orders) {
      const sid = o.shipment_id;
      const st = (sid && shipInfo[sid]) ? shipInfo[sid].status : null;
      if (isDeadOrder(o, st)) continue;
      const pk = o.pack_id || o.order_id;
      if (sid && shipInfo[sid] && !(shipmentsSeen[pk] && shipmentsSeen[pk][sid])) {
        if (shipInfo[sid].cost != null) packEnvio[pk] = (packEnvio[pk] || 0) + shipInfo[sid].cost;   // envío del paquete (una vez por shipment)
        if (shipInfo[sid].bonus != null) packBono[pk] = (packBono[pk] || 0) + shipInfo[sid].bonus;   // bonificación Flex del paquete (solo informativa)
        (shipmentsSeen[pk] = shipmentsSeen[pk] || {})[sid] = true;
      }
      for (const it of o.items) {
        packCount[pk] = (packCount[pk] || 0) + 1;
        const value = (it.unit_price || 0) * (it.qty || 0);
        const b = bestByPack[pk];
        if (!b || value > b.value) bestByPack[pk] = { key: o.order_id + ':' + it.item_id, value };
      }
    }
    for (const pk in bestByPack) packOwner[pk] = bestByPack[pk].key;
  }
  for (const o of orders) {
    const sid = o.shipment_id;
    const info = sid ? shipInfo[sid] : null;
    const status = info ? info.status : null, logistic = info ? info.logistic : null;
    // Ocultar SOLO canceladas y reclamos cerrados con devolución: el resto (en camino, pendientes, entregadas) cuenta.
    if (isDeadOrder(o, status)) { hidden++; continue; }
    keptOrders++;
    const pk = o.pack_id || o.order_id;
    const n = o.items.length || 1;
    // Impuesto REAL de la orden: primero el de Mercado Pago (retenciones); si no, el de la orden.
    const realTaxOrder = (taxByOrder[o.order_id] != null) ? taxByOrder[o.order_id] : (o.tax_real != null ? o.tax_real : null);
    const taxPart = (realTaxOrder != null && !isNaN(realTaxOrder)) ? realTaxOrder / n : null;
    if (taxByOrder[o.order_id] != null && taxByOrder[o.order_id] > 0) taxRealCount++;
    for (const it of o.items) {
      const cr = costs[String(it.item_id)];
      const itemKey = o.order_id + ':' + it.item_id;
      // Envío del CARRITO: solo el ítem de MAYOR valor del PAQUETE se lleva el envío; los demás → 0.
      let shipPart;
      if (packOwner[pk] != null) shipPart = (packOwner[pk] === itemKey) ? ((packEnvio[pk] != null) ? packEnvio[pk] : null) : 0;
      else shipPart = (info && info.cost != null) ? info.cost : null;   // fallback: sin dueño calculado
      const key = account.id + ':' + o.order_id + ':' + it.item_id;
      const frozen = sales && sales[key];
      // Datos EXTRA (columnas del Excel): stock propio, cantidad, código/SKU, proveedor y cuotas.
      // Se congelan junto con la venta para que el histórico quede fiel al día.
      let stockFlag = frozen ? !!frozen.stock : !!(cr && cr.stock);
      const qty = it.qty || 0;
      // SKU/proveedor son de REFERENCIA (no financieros): preferimos el del _COMPLETO actual (cr) para
      // reflejar el "código utilizado" real; si no hay costo, caemos al valor congelado.
      let sku = (cr && cr.sku) ? cr.sku : ((frozen && frozen.sku != null) ? frozen.sku : '');
      let proveedor = (cr && cr.proveedor) ? cr.proveedor : ((frozen && frozen.proveedor != null) ? frozen.proveedor : '');
      const cuotas = (frozen && frozen.cuotas != null) ? frozen.cuotas : (o.installments || 0);
      const flex = (frozen && frozen.flex != null) ? frozen.flex : (logistic === 'self_service');  // Mercado Envíos Flex
      const pack = (frozen && frozen.pack != null) ? frozen.pack : ((packCount[pk] || 0) > 1);   // venta en carrito
      // BONIFICACIÓN de ML: SOLO en Flex, en el ítem dueño del paquete. NO afecta la ganancia (va a la solapa FLEX).
      // Se calcula SIEMPRE en vivo (no del congelado) para corregir las ventas guardadas con bono viejo/0.
      const bono = (flex && packOwner[pk] === itemKey) ? (packBono[pk] || 0) : 0;
      let r;
      if (frozen) {
        // Venta ya registrada: usamos el costo/margen CONGELADO al momento de la venta.
        r = { revenue: frozen.revenue, fee: frozen.fee, envio: frozen.envio, envioReal: frozen.envioReal, tax: frozen.tax, taxReal: frozen.taxReal, factura: frozen.factura, queda: frozen.queda, cost: frozen.cost, net: frozen.net, marginPct: frozen.marginPct, known: frozen.known };
        savedCount++;
        // RELLENO de COSTO: si la venta se congeló SIN costo (el producto todavía no estaba en el
        // _COMPLETO al momento de registrarla) y ahora YA existe en la lista importada, recalculamos
        // el costo/margen/stock reales y actualizamos el congelado. Así, al reimportar la lista
        // actualizada, la venta del producto nuevo toma su costo real en vez de quedar "s/costo".
        if (!r.known && cr) {
          const fresh = saleNet(it, cr, cfg, shipPart, taxPart, flex);
          if (fresh.known) {
            r = fresh;
            stockFlag = !!(cr && cr.stock);
            sku = cr.sku || sku;
            proveedor = cr.proveedor || proveedor;
            if (sales && sales[key]) {
              Object.assign(sales[key], fresh, { stock: stockFlag, sku, proveedor });
              costFixedCount++;
            }
          }
        }
        // CORRECCIÓN de ENVÍO (carrito) e IMPUESTO (retención de MP) sobre lo congelado. Mantiene congelado el COSTO;
        // solo recalcula el envío del carrito (dueño = ítem de mayor valor) y el impuesto real (que no venía en la orden).
        let correctEnvio = r.envio;
        if (packOwner[pk] != null) correctEnvio = (packOwner[pk] === itemKey) ? ((packEnvio[pk] != null) ? packEnvio[pk] : r.envio) : 0;
        let correctTax = r.tax;
        const rt = (taxByOrder[o.order_id] != null) ? (taxByOrder[o.order_id] / n) : null;
        if (rt != null && rt > 0 && !(frozen.tax > 0)) correctTax = rt;
        const changedE = Math.abs((correctEnvio || 0) - (r.envio || 0)) > 0.5;
        const changedT = Math.abs((correctTax || 0) - (r.tax || 0)) > 0.5;
        if (changedE || changedT) {
          r.envio = correctEnvio; r.tax = correctTax; if (changedT) r.taxReal = true;
          r.queda = r.revenue - r.fee - (flex ? 0 : (r.envio || 0)) - (r.tax || 0);
          if (r.known) { r.net = r.revenue - r.fee - (r.envio || 0) - (r.tax || 0) - (r.cost || 0) - (r.factura || 0); r.marginPct = r.revenue > 0 ? (r.net / r.revenue) * 100 : null; }
          if (sales && sales[key]) { sales[key].envio = r.envio; sales[key].tax = r.tax; sales[key].taxReal = r.taxReal; sales[key].queda = r.queda; sales[key].net = r.net; sales[key].marginPct = r.marginPct; taxFixedCount++; }
        }
        // Corrección del BONO Flex (informativo, no toca la ganancia): actualizamos el congelado si cambió.
        if (sales && sales[key] && (Number(sales[key].bono) || 0) !== (bono || 0)) { sales[key].bono = bono; taxFixedCount++; }
      } else {
        r = saleNet(it, cr, cfg, shipPart, taxPart, flex);
        if (sales) {
          sales[key] = { account_id: account.id, seller_id: account.seller_id, order_id: o.order_id, pack_id: o.pack_id, date: o.date, item_id: it.item_id, title: it.title, stock: stockFlag, qty, sku, proveedor, cuotas, flex, pack, bono, savedAt: nowIso, ...r };
          freshCount++;
        }
      }
      // GANANCIA SIN FLEX = ganancia + el envío (flex) que absorbiste. COSTO STOCK = costo si salió de stock propio.
      const net_sin_flex = (r.net != null) ? r.net + (r.envio || 0) : null;
      const cost_stock = (r.known && stockFlag && r.cost != null) ? r.cost : 0;
      facturacion += r.revenue;
      unidades += qty; feeTotal += (r.fee || 0); envioTotal += (r.envio || 0); taxTotal += (r.tax || 0);
      facturaTotal += (r.factura || 0); quedaTotal += (r.queda || 0); bonoTotal += (bono || 0); if (cuotas > 1) cuotasCount++;
      if (r.known) { ganancia += r.net; factConocida += r.revenue; conocidas++; costTotal += (r.cost || 0); costStockTotal += cost_stock; gananciaSinFlex += (net_sin_flex || 0); if (r.net < 0) { perdida++; perdidaMonto += r.net; } } else sinCosto++;
      rows.push({ order_id: o.order_id, pack_id: (frozen && frozen.pack_id) || o.pack_id || o.order_id, date: o.date, item_id: it.item_id, title: it.title, status, stock: stockFlag, frozen: !!frozen, qty, sku, proveedor, cuotas, flex, pack, bono, net_sin_flex, cost_stock, ...r });
    }
  }
  return {
    from, to, days: daysBetween(from, to), count: rows.length, orders: keptOrders,
    facturacion, ganancia, margin: factConocida > 0 ? (ganancia / factConocida) * 100 : null,
    conocidas, sinCosto, perdida, shipFetched, hidden, savedCount, freshCount, taxRealCount, taxFixedCount, costFixedCount,
    unidades, feeTotal, envioTotal, taxTotal, facturaTotal, quedaTotal,
    costTotal, costStockTotal, gananciaSinFlex, perdidaMonto, cuotasCount, bonoTotal, factConocida, rows,
  };
}

// ===========================================================================
// ESTRATEGIA (el cerebro): segmentación estrella/promesa/vaca + cuenta líder
// por título (anti-canibalización) usando margen REAL cuando existe.
// Funciones PURAS (sin red) para poder testearlas con datos sintéticos.
// ===========================================================================

// MOTOR DE POSICIONAMIENTO: clasifica cada publicación cruzando margen × ventas × visitas
// (demanda) × conversión × exposición. Cada segmento tiene una jugada para convertirla en venta,
// sin esfuerzos en vano (no tirar ADS donde el problema es de conversión/precio).
//  it: { margin, sold, visits, ... }
function classifyItem(it, cfg) {
  cfg = cfg || {};
  const high = cfg.marginHigh != null ? cfg.marginHigh : 12;
  const minSales = cfg.minSales != null ? cfg.minSales : 1;
  const minVis = cfg.minVisits != null ? cfg.minVisits : 8;    // hay algo de demanda (catálogo de baja visita)
  const hotVis = cfg.hotVisits != null ? cfg.hotVisits : 30;   // mucha demanda
  const m = it.margin, sold = it.sold || 0, vis = it.visits || 0;
  const buen = (m != null) && m >= high;
  const vende = sold >= minSales;
  if (vende && buen) return 'estrella';         // vende y deja plata → escalar
  if (vende && !buen) return 'vaca';            // vende pero margen flaco → optimizar precio
  // No vende:
  if (vis >= hotVis) return 'ajustar';         // mucho tráfico y no convierte → precio/publicación, NO ADS
  if (buen && vis >= minVis) return 'promesa'; // buen margen + algo de demanda → ADS + promo (posicionar)
  return 'durmiente';                          // sin demanda en esta cuenta
}
// Score de POTENCIAL 0-100: qué tan valioso es empujar esta publicación (margen × demanda × conversión).
function potentialScore(it, cfg) {
  const high = (cfg && cfg.marginHigh != null) ? cfg.marginHigh : 12;
  const m = it.margin != null ? it.margin : 0, vis = it.visits || 0, sold = it.sold || 0;
  const marginN = Math.max(0, Math.min(1, m / (high * 2)));        // 0..1 (2×umbral = tope)
  const demandN = Math.max(0, Math.min(1, Math.log10(1 + vis) / 3)); // log de visitas (1000 vis ≈ 1)
  const conv = vis > 0 ? sold / vis : 0;
  const convN = Math.max(0, Math.min(1, conv / 0.05));             // 5% conversión = tope
  return Math.round((0.4 * marginN + 0.35 * demandN + 0.25 * convN) * 100);
}
function segmentAction(seg, isLeader, liderName, stock, it) {
  if (isLeader === false) return 'Solo orgánico — no anunciar acá (líder: ' + (liderName || '—') + '). Podés subir precio para margen alto.';
  const conv = (it && it.visits > 0) ? (it.sold / it.visits * 100) : null;
  const m = {
    estrella: 'ESCALAR ADS con ROAS alto (protegé margen) · sin promo · es tu caballito, dale presupuesto',
    promesa: 'ADS + promo para posicionar (ROAS bajo, ganás ranking) · empujá fuerte las primeras 48h',
    ajustar: 'Tiene tráfico y NO convierte' + (conv != null ? (' (' + conv.toFixed(1) + '%)') : '') + ' → NO gastes ADS: bajá/ajustá precio, poné promo, mejorá título y fotos',
    vaca: 'Optimizá precio / sacá promo innecesaria (recuperás margen) · ADS mínima o nula',
    durmiente: 'Sin demanda en esta cuenta → stock 0 (NO pausar, conserva ranking) o subí precio para margen alto',
  };
  if (stock && (seg === 'vaca' || seg === 'durmiente' || seg === 'ajustar')) return 'Stock propio (oferta): ideal para PROMO y rotarlo. ' + (m[seg] || '');
  return m[seg] || '—';
}

// MOTOR DE DECISIÓN: qué HACER con cada publicación (la tabla de acción). Prioridad = orden de impacto.
// Reglas clave: 1) título repetido → solo el líder recibe ADS (anti-canibalización); 2) muerta vieja → pausar.
function decideAction(it, cfg) {
  cfg = cfg || {};
  const high = cfg.marginHigh != null ? cfg.marginHigh : 12;
  const convGood = cfg.convGood != null ? cfg.convGood : 1.5;        // % conversión "buena"
  const strong = cfg.strongSales != null ? cfg.strongSales : 3;      // ventas 3m para estrella consolidada
  const minVis = cfg.minVisits != null ? cfg.minVisits : 8;
  const hotVis = cfg.hotVisits != null ? cfg.hotVisits : 30;
  const buen = it.margin != null && it.margin >= high;
  const sold = it.sold || 0, vis = it.visits || 0, conv = it.conv, age = it.ageDays;
  // 1) ANTI-CANIBALIZACIÓN: título repetido y NO es el líder → nunca ADS.
  if (it.duplicated && !it.isLeader) return { code: 'organico', label: '🌱 No anunciar — otra publicación del mismo título lidera (' + (it.leaderName || '—') + '). Dejala orgánica o subí precio para margen.', pri: 6 };
  // 2) MUERTA VIEJA: SIN ventas en 90d + 0 visitas + creada hace más de 1 año → pausar/limpiar.
  //    OJO: si vendió aunque sea 1 unidad, NO se pausa nunca (está viva) — cae a escalar/promover.
  if (sold === 0 && vis === 0 && age != null && age > 365) return { code: 'pausar', label: '⏸️ Pausar/limpiar — sin ventas, 0 visitas y +1 año publicada. No rankea; sacala del camino.', pri: 5 };
  // 3) ESTRELLA CONSOLIDADA: vende fuerte + buen margen → escalar ADS.
  if (buen && sold >= strong) return { code: 'escalar', label: '⭐ Escalar ADS — ROAS alto, protegé margen. Ya vende, dale presupuesto.', pri: 1 };
  // 4) PROMOVER YA (Caso A): buen margen + convierte (o tiene demanda) pero poca escala → invertir en ranking.
  if (buen && ((sold >= 1 && (conv == null || conv >= convGood)) || (sold === 0 && vis >= minVis))) {
    return { code: 'promover', label: '🎯 Promover YA — ADS + promo con ROAS bajo (inversión de ranking). Convierte / tiene demanda, solo le falta empuje.', pri: 2 };
  }
  // 5) AJUSTAR: mucho tráfico y no convierte → precio/publicación, NO ADS.
  if (vis >= hotVis && sold === 0) return { code: 'ajustar', label: '🔧 Ajustar precio/fotos/título — NO gastes ADS. Tiene tráfico y no convierte.', pri: 3 };
  // 6) VACA: vende con margen flaco → optimizar precio.
  if (!buen && sold >= 1) return { code: 'precio', label: '🐄 Optimizar precio / sacar promo — margen flaco. ADS mínima.', pri: 4 };
  // 7) RESTO (durmiente): sin demanda → stock 0 o subir precio.
  return { code: 'revisar', label: '💤 Sin demanda — stock 0 (conserva ranking) o subí precio para margen alto.', pri: 7 };
}
// Versión del enriquecimiento. Subir este número fuerza un refresco de TODO lo enriquecido antes
// (para propagar arreglos). v2 = fix visitas por ítem. v3 = precio real con promo desde /items/{id}/prices.
const ENRICH_VER = 3;
const ACTION_META = {
  escalar: { pri: 1, label: '⭐ Escalar ADS', hint: 'Estrellas consolidadas: dale presupuesto, protegé margen' },
  promover: { pri: 2, label: '🎯 Promover ya', hint: 'Convierten y les falta empuje: ADS + promo, ROAS bajo (invertís en ranking)' },
  ajustar: { pri: 3, label: '🔧 Ajustar precio', hint: 'Tráfico sin conversión: NO ADS, tocá precio/fotos/título' },
  precio: { pri: 4, label: '🐄 Optimizar precio', hint: 'Venden con margen flaco: subí precio / sacá promo' },
  pausar: { pri: 5, label: '⏸️ Pausar / limpiar', hint: '0 visitas y +1 año: no rankean, sacalas' },
  organico: { pri: 6, label: '🌱 No anunciar', hint: 'Título repetido: otra lidera. No las anuncies (evita competir con vos mismo)' },
  revisar: { pri: 7, label: '💤 Revisar', hint: 'Sin demanda: stock 0 o subí precio' },
};

// Reparte la cuenta LÍDER de cada título duplicado por rentabilidad real,
// con un balanceo suave hacia las cuentas de objetivo alto para no dejarlas huérfanas.
// groups: [ { title, items:[ {item_id, account_id, account_name, objetivo, margin, sales, segment} ] } ]
// Devuelve por cada item_id: { leader:bool, leaderAccountId, leaderName }.
function assignLeaders(groups, cfg) {
  const tieBand = (cfg && cfg.tieBand != null) ? cfg.tieBand : 2;   // puntos de margen dentro de los cuales "empatan"
  const assigned = {};   // account_id -> cuántos líderes lleva (para balancear)
  const out = {};
  // Ordenamos los grupos por su mejor margen desc para asignar primero los más jugosos.
  const ordered = groups.slice().sort((a, b) => bestMargin(b) - bestMargin(a));
  for (const g of ordered) {
    const cands = g.items.slice().sort((a, b) => (b.margin || -999) - (a.margin || -999));
    const top = cands[0];
    const topM = top.margin != null ? top.margin : -999;
    // Candidatos "empatados" con el mejor (dentro del tieBand).
    const near = cands.filter(c => (topM - (c.margin != null ? c.margin : -999)) <= tieBand);
    // Entre los empatados, elegimos: 1) mayor objetivo, 2) menos líderes ya asignados,
    // 3) más ventas (experiencia de la publicación), 4) mejor margen.
    near.sort((a, b) =>
      (b.objetivo || 0) - (a.objetivo || 0) ||
      (assigned[a.account_id] || 0) - (assigned[b.account_id] || 0) ||
      (b.sold || 0) - (a.sold || 0) ||
      (b.margin || -999) - (a.margin || -999)
    );
    const leader = near[0];
    assigned[leader.account_id] = (assigned[leader.account_id] || 0) + 1;
    for (const it of g.items) {
      // El líder es UNA publicación puntual (item_id), no toda la cuenta: así también
      // resolvemos duplicados dentro de la MISMA cuenta (solo una recibe ADS).
      out[it.item_id] = { leaderItemId: leader.item_id, leaderAccountId: leader.account_id, leaderName: leader.account_name };
    }
  }
  return out;
}
function bestMargin(g) { let m = -999; for (const i of g.items) if ((i.margin != null ? i.margin : -999) > m) m = (i.margin != null ? i.margin : -999); return m; }

// Replica el "simular costos" de ML: precio − cargo por vender − cuotas − envío − impuestos = RECIBÍS,
// y luego − costo del producto − factura (mensual) = ganancia. sim = objeto de simulateFee().
// cfg: { taxPct(factura%), cuotasPct, retencionPct, freeShipThreshold, cuotas(on/off) }.
function simNet(costRow, price, sim, cfg) {
  cfg = cfg || {};
  const p = Number(price) || 0; if (p <= 0) return null;
  const cost = Number(costRow.cost) || 0;
  // COSTO SIEMPRE DEL SIMULADOR DE ML: "cargo por vender" = comisión + cargo fijo (listing_prices).
  const cargoVender = sim ? (Number(sim.sale_fee) || 0) : 0;
  // COSTO DE CUOTAS: el simulador de ML lo incluye en "Recibís", pero la API (listing_prices) a veces
  // NO lo devuelve. Orden para completarlo, sin inventar nada, todo con datos de ML:
  //   1) sim.financing → si la API del simulador lo trae, se usa tal cual.
  //   2) tasa real de ML → lo que ML te cobró DE MÁS sobre la comisión en tus ventas reales de esa
  //      misma publicación (sale_fee de la orden). Es idéntico a lo que muestra el simulador.
  //   3) cuotasPct configurable → último recurso si nunca vendió y la API no informó cuotas.
  const realRate = (costRow.realTakeRate != null && Number(costRow.realTakeRate) > 0) ? Number(costRow.realTakeRate) : null;
  let cuotas;
  if (sim && sim.financing) cuotas = Number(sim.financing);
  else if (realRate != null) cuotas = Math.max(0, p * realRate - cargoVender);
  else cuotas = cfg.cuotasPct ? p * cfg.cuotasPct / 100 : 0;
  // Envío: 0 si lo paga el comprador (precio bajo el umbral de envío gratis); si no, estimación del _COMPLETO.
  const freeShip = cfg.freeShipThreshold != null ? cfg.freeShipThreshold : 33000;
  const envio = (p >= freeShip) ? Math.max(0, (Number(costRow.costShip) || cost) - cost) : 0;
  // Impuestos/retenciones estimadas (calibrable con el selftest contra el simulador real).
  const impuestos = p * ((cfg.retencionPct != null ? cfg.retencionPct : 0) / 100);
  const recibis = p - cargoVender - cuotas - envio - impuestos;              // = "Recibís" del simulador de ML
  const factura = p * ((cfg.taxPct != null ? cfg.taxPct : 5) / 100);         // factura mensual (parte del costo)
  const net = recibis - cost - factura;
  return { net, marginPct: p > 0 ? net / p * 100 : null, cargoVender, cuotas, envio, impuestos, recibis, cost, factura };
}

// Construye toda la foto estratégica a partir de: tabla de costos (todas las cuentas),
// ledger histórico de ventas (margen real), metadata de cuentas (objetivo), y el mapa de
// ventas de los últimos 90 días (item_id -> unidades) que define el "vende".
function buildStrategy(costsTable, hist, accountsMeta, cfg, sold90Map) {
  cfg = cfg || {};
  sold90Map = sold90Map || {};
  const nowMs = Date.now();
  const sales = (hist && hist.sales) || {};
  // 1) Agregado por item_id desde el ledger (margen real + velocidad).
  const perItem = {};
  let ledgerMinDate = null, ledgerMaxDate = null;
  for (const k in sales) {
    const s = sales[k];
    const p = perItem[s.item_id] || { sales: 0, rev: 0, net: 0, mSum: 0, mN: 0 };
    p.sales++; p.rev += (s.revenue || 0); p.net += (s.net || 0);
    if (s.known && s.marginPct != null) { p.mSum += s.marginPct; p.mN++; }
    perItem[s.item_id] = p;
    if (s.date) { if (!ledgerMinDate || s.date < ledgerMinDate) ledgerMinDate = s.date; if (!ledgerMaxDate || s.date > ledgerMaxDate) ledgerMaxDate = s.date; }
  }
  const objByAcc = {}; const nameByAcc = {}; const taxByAcc = {};
  for (const a of (accountsMeta || [])) { objByAcc[a.id] = a.objetivo || 0; nameByAcc[a.id] = a.name; taxByAcc[a.id] = a.factura != null ? a.factura : 5; }

  // 2) Clasificamos cada producto.
  const items = [];
  let pausadas = 0;
  for (const id in costsTable) {
    const c = costsTable[id];
    // Solo publicaciones ACTIVAS. Si ya está enriquecida y NO está activa (pausada/cerrada/etc.), la salteamos.
    const st = String(c.status || '').toLowerCase();
    if (st && st !== 'active') { pausadas++; continue; }
    const agg = perItem[id];
    // MARGEN: simulador de ML al precio real. Se RECALCULA con la factura ACTUAL de la cuenta
    // (usando los componentes de costo ya guardados), así cambiar la factura en Ajustes actualiza
    // el margen al instante SIN re-enriquecer. Fallback: simMargin viejo, y luego margen de lista.
    let simMargin = null;
    if (c.simFee != null && Number(c.price) > 0) {
      const f = priceFactors(c, taxByAcc[c.account_id]);
      simMargin = f ? marginAtPrice(f, Number(c.price)) : (c.simMargin != null ? Number(c.simMargin) : null);
    } else if (c.simMargin != null && !isNaN(c.simMargin)) { simMargin = Number(c.simMargin); }
    const listMargin = (Number(c.marginList) || 0) * 100;
    const marginPct = simMargin != null ? simMargin : (listMargin || null);
    const marginSrc = simMargin != null ? 'sim' : 'lista';
    // "VENDE" = unidades vendidas en los ÚLTIMOS 90 DÍAS (mapa de órdenes). Si no hay mapa aún,
    // cae al ledger. El acumulado histórico de ML (sold_quantity) queda como referencia (soldTotal).
    const sold90 = sold90Map[id] != null ? Number(sold90Map[id]) : (agg ? agg.sales : 0);
    const soldTotal = c.sold != null ? Number(c.sold) : null;
    const visits = Number(c.visits) || 0;
    const conv = visits > 0 ? (sold90 / visits * 100) : null;
    const ageDays = c.created ? Math.floor((nowMs - new Date(c.created).getTime()) / 86400000) : null;
    const it = {
      item_id: id, title: c.title || '', titleNorm: normTitle(c.title || ''),
      account_id: c.account_id, account_name: c.account_name, seller_id: c.seller_id,
      objetivo: objByAcc[c.account_id] || 0,
      margin: marginPct, marginSrc, sold: sold90, soldTotal, visits, conv, ageDays,
      visits90: c.visits90 != null ? Number(c.visits90) : null, visitsTotal: c.visitsTotal != null ? Number(c.visitsTotal) : null,
      realRate: c.realTakeRate != null ? +(Number(c.realTakeRate) * 100).toFixed(1) : null,
      price: c.price != null ? Number(c.price) : null, listPrice: c.listPrice != null ? Number(c.listPrice) : null, origPrice: c.origPrice != null ? Number(c.origPrice) : null, enPromo: !!c.enPromo,
      listingType: c.listingType || '', health: c.health != null ? Number(c.health) : null,
      enriched: !!c.enrichAt, revenue: agg ? agg.rev : 0, net: agg ? agg.net : 0,
      stock: !!c.stock,
    };
    it.segment = classifyItem(it, cfg);
    it.score = potentialScore(it, cfg);
    items.push(it);
  }

  // 3) Dedup por TÍTULO (cualquier repetición, entre cuentas O dentro de la misma cuenta).
  // Un título con 2+ publicaciones = competencia interna → solo una recibe ADS.
  const byTitle = {};
  for (const it of items) { if (!it.titleNorm) continue; (byTitle[it.titleNorm] = byTitle[it.titleNorm] || []).push(it); }
  const dupGroups = [];
  for (const t in byTitle) { const arr = byTitle[t]; if (arr.length >= 2) dupGroups.push({ title: arr[0].title, items: arr }); }

  // 4) Líder por grupo (una publicación puntual). El resto: no anunciar.
  const leaderMap = assignLeaders(dupGroups, cfg);
  const dupItemIds = new Set();
  for (const g of dupGroups) for (const it of g.items) dupItemIds.add(it.item_id);
  for (const it of items) {
    if (dupItemIds.has(it.item_id)) {
      const lead = leaderMap[it.item_id];
      it.duplicated = true;
      it.isLeader = lead ? (it.item_id === lead.leaderItemId) : true;
      it.leaderName = lead ? lead.leaderName : it.account_name;
    } else { it.duplicated = false; it.isLeader = true; it.leaderName = it.account_name; }
    // MOTOR DE DECISIÓN → qué hacer con esta publicación (la tabla de acción).
    const dec = decideAction(it, cfg);
    it.actionCode = dec.code; it.action = dec.label; it.priority = dec.pri;
    // MANTENER VIVO EL TÍTULO: si es el LÍDER de un grupo duplicado y quedó sin acción (durmiente),
    // pero deja margen, lo empujamos igual. Así, de cada título repetido, SIEMPRE queda al menos una
    // publicación (la líder) con ADS/promo — el resto orgánicas. Nunca se apaga el título entero.
    const high = cfg.marginHigh != null ? cfg.marginHigh : 12;
    if (it.duplicated && it.isLeader && it.actionCode === 'revisar' && it.margin != null && it.margin >= high) {
      it.actionCode = 'promover';
      it.action = '🎯 Promover (LÍDER del título) — mantené SOLO esta con ADS/promo del grupo repetido; las otras orgánicas.';
      it.priority = 2;
    }
  }

  // 5) Resúmenes: por segmento, por ACCIÓN (el plan) y por cuenta.
  const segCount = { estrella: 0, promesa: 0, ajustar: 0, vaca: 0, durmiente: 0 };
  const planCount = { escalar: 0, promover: 0, ajustar: 0, precio: 0, pausar: 0, organico: 0, revisar: 0 };
  const perAcc = {};
  const spanDays = (ledgerMinDate && ledgerMaxDate) ? Math.max(1, daysBetween(ledgerMinDate, ledgerMaxDate)) : 0;
  for (const it of items) {
    if (segCount[it.segment] != null) segCount[it.segment]++;
    if (planCount[it.actionCode] != null) planCount[it.actionCode]++;
    const a = perAcc[it.account_id] || { account_id: it.account_id, account_name: it.account_name, objetivo: it.objetivo, items: 0, estrella: 0, promesa: 0, ajustar: 0, vaca: 0, durmiente: 0, escalar: 0, promover: 0, pausar: 0, lider: 0, orgOnly: 0, dup: 0, enriched: 0, rev: 0, net: 0, rev90: 0 };
    a.items++; if (a[it.segment] != null) a[it.segment]++;
    if (a[it.actionCode] != null) a[it.actionCode]++;
    if (it.enriched) a.enriched++; a.rev += it.revenue; a.net += it.net;
    a.rev90 += (Number(it.sold) || 0) * (Number(it.price) || 0);   // facturación real estimada últimos 90d
    if (it.duplicated) { a.dup++; if (it.isLeader) a.lider++; else a.orgOnly++; }
    perAcc[it.account_id] = a;
  }
  const roas = cfg.roas != null ? cfg.roas : 5;   // ROAS objetivo para estimar la inversión en ADS
  const accounts = Object.values(perAcc).map(a => {
    // Proyección MES CORRIDO: run-rate de los últimos 90 días (rev90 / 3 meses).
    const proyMensual = a.rev90 / 3;
    const avance = a.objetivo > 0 ? proyMensual / a.objetivo * 100 : 0;
    const faltante = Math.max(0, (a.objetivo || 0) - proyMensual);
    const adsBudget = roas > 0 ? faltante / roas : 0;   // para cubrir el faltante con ADS a ese ROAS
    return { ...a, proy_mensual: proyMensual, avance, faltante, ads_budget: adsBudget, roas };
  }).sort((x, y) => (y.objetivo - x.objetivo) || (y.items - x.items));

  const dupItems = items.filter(i => i.duplicated).length;
  return {
    generated: new Date().toISOString(),
    totals: { productos: items.length, activas: items.length, pausadas, con_costo_cuentas: accounts.length, ledger_ventas: Object.keys(sales).length, span_dias: spanDays, ledger_desde: ledgerMinDate, ledger_hasta: ledgerMaxDate },
    segmentos: segCount,
    plan: planCount, planMeta: ACTION_META,
    duplicados: { grupos: dupGroups.length, items: dupItems, orgOnly: items.filter(i => i.duplicated && !i.isLeader).length },
    cuentas: accounts,
    items,
  };
}

// ---------------------------------------------------------------------------
// Semáforo. Usa el ACOS de equilibrio REAL de la campaña (de tus costos) si
// está disponible; si no, cae al margen global de la config.
// ---------------------------------------------------------------------------
function decide(row, cfg) {
  const { clicks, acos, revenue, breakevenAcos, netProfit } = row;
  const breakeven = (breakevenAcos != null) ? breakevenAcos : cfg.margin;
  const target = (breakevenAcos != null) ? breakevenAcos * 0.6 : cfg.acosTarget;
  if (clicks < cfg.minClicks) return { action: 'JUNTAR_DATOS', reason: `pocos clics (${clicks}/${cfg.minClicks})` };
  if (!revenue) return { action: 'PAUSAR', reason: 'sin ventas con clics suficientes' };
  // Señal más fuerte: si conocemos costo real y la ganancia neta después de ads es negativa.
  if (netProfit != null && netProfit < 0) return { action: 'PAUSAR', reason: `pierde ${Math.round(Math.abs(netProfit)).toLocaleString('es-AR')} después de ads (ACOS ${acos?.toFixed(1)}% > equilibrio ${breakeven.toFixed(1)}%)` };
  if (acos == null) return { action: 'PAUSAR', reason: 'sin ventas atribuibles' };
  if (acos <= target) return { action: 'ESCALAR', reason: `ACOS ${acos.toFixed(1)}% ≤ objetivo ${target.toFixed(1)}%` };
  if (acos <= breakeven) return { action: 'MANTENER', reason: `ACOS ${acos.toFixed(1)}% ≤ equilibrio ${breakeven.toFixed(1)}%` };
  return { action: 'PAUSAR', reason: `ACOS ${acos.toFixed(1)}% > equilibrio real ${breakeven.toFixed(1)}%` };
}

// ---------------------------------------------------------------------------
// Analiza una campaña cruzando sus ítems con la tabla de costos.
// Devuelve la campaña normalizada + margen/ganancia real cuando hay costos.
// ---------------------------------------------------------------------------
async function analyzeCampaign(engine, account, campaign, costs, from, to, freeShipThreshold) {
  const base = readMetrics(campaign);
  const out = {
    campaign_id: campaign.id || campaign.campaign_id,
    name: campaign.name || campaign.campaign_name || '(sin nombre)',
    status: campaign.status,
    metrics: base,
    breakevenAcos: null,   // % — equilibrio real de la campaña
    grossProfit: null,     // $ ganancia bruta (antes de ads) de ventas atribuidas
    netProfit: null,       // $ ganancia después de restar la inversión en ads
    costCoverage: 0,       // % de la venta con costo real conocido
  };

  // Si no hay costos cargados, dejamos la campaña a nivel global (margen de config).
  if (!costs || !Object.keys(costs).length) return out;

  const items = await engine.listCampaignItems(account, out.campaign_id, from, to);
  if (!items.length) return out;

  let sumRev = 0, sumProfit = 0, sumKnownRev = 0;
  for (const it of items) {
    const id = it.item_id || it.id || it.mcId || it.mla;
    const m = readMetrics(it);
    sumRev += m.revenue;
    const costRow = costs[String(id)];
    if (costRow && m.units > 0 && m.revenue > 0) {
      const price = m.revenue / m.units;                 // precio efectivo cobrado (promo incluida)
      const rm = realMarginAtPrice(costRow, price, freeShipThreshold);
      if (rm) {
        sumProfit += rm.profitPerUnit * m.units;         // ganancia bruta real del ítem
        sumKnownRev += m.revenue;
      }
    }
  }

  if (sumKnownRev > 0) {
    out.grossProfit = sumProfit;
    out.netProfit = sumProfit - base.cost;               // menos la inversión total en ads
    out.breakevenAcos = (sumProfit / sumKnownRev) * 100; // margen de contribución real % = ACOS de equilibrio
    out.costCoverage = sumRev > 0 ? (sumKnownRev / sumRev) * 100 : 100;
  }
  return out;
}

async function analyzeAccount(engine, account, cfg, costs) {
  const to = ymd(new Date());
  const from = ymd(daysAgo(cfg.windowDays));
  const campaigns = await engine.listCampaigns(account, from, to);
  const rows = [];
  for (const c of campaigns) {
    const a = await analyzeCampaign(engine, account, c, costs, from, to, cfg.freeShipThreshold);
    const d = decide({ ...a.metrics, breakevenAcos: a.breakevenAcos, netProfit: a.netProfit }, cfg);
    rows.push({ ...a, action: d.action, reason: d.reason });
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Job nocturno (DRY-RUN por defecto).
// ---------------------------------------------------------------------------
async function runNightlyJob(deps) {
  const { loadDB, saveDB } = deps;
  const engine = makeEngine(deps);
  const cfg = getAdsConfig(loadDB);
  const costs = loadCosts(loadDB);
  const accounts = loadDB().ml_accounts || [];
  const runLog = { at: new Date().toISOString(), dry_run: !cfg.autoPause, results: [] };

  for (const account of accounts) {
    try {
      const rows = await analyzeAccount(engine, account, cfg, costs);
      for (const r of rows) {
        const shouldPause = r.action === 'PAUSAR' && String(r.status).toLowerCase() === 'active';
        const entry = {
          account: account.name, campaign_id: r.campaign_id, name: r.name,
          acos: r.metrics.acos, clicks: r.metrics.clicks, cost: r.metrics.cost,
          net_profit: r.netProfit, breakeven: r.breakevenAcos,
          action: r.action, reason: r.reason, paused: false,
        };
        if (shouldPause) {
          if (cfg.autoPause) {
            try { await engine.setCampaignStatus(account, r.campaign_id, 'paused'); entry.paused = true; }
            catch (e) { entry.error = (e && e.response && e.response.data) || String(e.message || e); }
          } else { entry.would_pause = true; }
        }
        runLog.results.push(entry);
      }
    } catch (e) {
      runLog.results.push({ account: account.name, error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  }

  const db2 = loadDB();
  db2.ads_log = (db2.ads_log || []).slice(-19);
  db2.ads_log.push(runLog);
  db2.ads_last_run = runLog.at;
  saveDB(db2);
  console.log(`[ADS] Corrida ${runLog.dry_run ? 'DRY-RUN' : 'LIVE'} — pausadas: ${runLog.results.filter(r => r.paused).length}, a pausar (dry): ${runLog.results.filter(r => r.would_pause).length}`);
  return runLog;
}

// ---------------------------------------------------------------------------
// Scheduler diario (resiste reinicios de Render vía ads_last_run).
// ---------------------------------------------------------------------------
function startScheduler(deps) {
  const { loadDB } = deps;
  const HOUR = Number(process.env.ADS_RUN_HOUR || 13);
  async function tick() {
    try {
      const db = loadDB();
      const now = new Date();
      const last = db.ads_last_run ? new Date(db.ads_last_run) : null;
      const ranToday = last && last.toDateString() === now.toDateString();
      if (now.getHours() >= HOUR && !ranToday) await runNightlyJob(deps);
    } catch (e) { console.error('[ADS] scheduler error:', e.message || e); }
  }
  setInterval(tick, 60 * 60 * 1000);
  setTimeout(tick, 30 * 1000);
}

// ---------------------------------------------------------------------------
// Rutas HTTP.
// ---------------------------------------------------------------------------
function registerAds(deps) {
  const { route, sendJSON, requireAuth, loadDB, saveDB } = deps;
  const engine = makeEngine(deps);
  const isAdmin = (req) => { const s = requireAuth(req); return s && s.role === 'admin' ? s : null; };
  // Caché de la foto estratégica: buildStrategy sobre ~150k items + leer 6 archivos de costos es caro.
  // Los filtros se aplican DESPUÉS, así que reusamos la foto por unos segundos. Se invalida al
  // enriquecer o importar (bustStrat) para no mostrar datos viejos.
  let _stratCache = null, _stratVersion = 0;
  const bustStrat = () => { _stratVersion++; _stratCache = null; };
  // CANDADO de enriquecimiento por cuenta: evita que corran DOS refinar de la misma cuenta a la vez
  // (cada uno carga y reescribe el archivo de ~42k ítems → doble memoria → crash). Serializa el acceso.
  const _enrichLocks = {};

  const getAccount = (req) => {
    const q = new URL(req.url, 'http://localhost').searchParams;
    const id = parseInt(q.get('account_id'));
    const sid = q.get('seller_id');
    const accs = loadDB().ml_accounts || [];
    return accs.find(a => a.id === id) || (sid ? accs.find(a => String(a.seller_id) === String(sid)) : null) || null;
  };

  route('GET', '/api/ads/accounts', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
    sendJSON(res, 200, { accounts: (loadDB().ml_accounts || []).map(a => { const c = getAccountCfg(a); return { id: a.id, name: a.name, seller_id: a.seller_id, objetivo: c.objetivo, factura: c.taxPct }; }) });
  });

  route('GET', '/api/ads/selftest', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'Pasá ?account_id=<id>' });
    const out = { account: account.name };
    try {
      const adv = await engine.getAdvertiser(account);
      out.advertiser_id = adv.id; out.site = adv.site;
      const to = ymd(new Date()), from = ymd(daysAgo(14));
      const camps = await engine.listCampaigns(account, from, to);
      out.campaigns_found = camps.length;
      out.campaigns_endpoint = account.ads_campaigns_ep;
      out.sample = camps.slice(0, 2);
      out.ok = true;
    } catch (e) {
      out.ok = false;
      out.error = (e && e.response && e.response.data) || String(e.message || e);
      out.hint = 'Activá Product Ads en la cuenta, reconectá para token con permiso de publicidad, o confirmá los paths en EP{}.';
    }
    sendJSON(res, 200, out);
  });

  route('GET', '/api/ads/campaigns', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'account_id inválido' });
    const cfg = getAdsConfig(loadDB);
    const costs = loadCosts(loadDB);
    try {
      const rows = await analyzeAccount(engine, account, cfg, costs);
      sendJSON(res, 200, { config: cfg, costs_loaded: Object.keys(costs).length, campaigns: rows });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // Config por cuenta (objetivo mensual, % impuesto). Default objetivo 100M; taxPct 5.
  function getAccountCfg(account) {
    const g = getAdsConfig(loadDB);
    const per = (loadDB().ads_config && loadDB().ads_config.accounts) || {};
    const a = per[String(account.seller_id)] || {};
    // taxPct (FACTURA %) ahora es GLOBAL: una sola para todas las cuentas (default 5). objetivo sigue por cuenta (lo usa Estrategia).
    return { ...g, objetivo: a.objetivo != null ? a.objetivo : 100000000, taxPct: (g.facturaPct != null ? g.facturaPct : 5), cuotasPct: a.cuotasPct != null ? a.cuotasPct : (g.cuotasPct || 0) };
  }

  // RENTABILIDAD REAL: trae ventas de ML y calcula margen verdadero por cuenta.
  route('GET', '/api/ads/ventas', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'account_id inválido' });
    const u = new URL(req.url, 'http://x');
    let from = u.searchParams.get('from'), to = u.searchParams.get('to');
    if (!to) to = ymd(new Date());
    if (!from) from = ymd(daysAgo(30));
    const cfg = getAccountCfg(account);
    const costs = loadCosts(loadDB);
    const hist = loadHistFile();
    try {
      const v = await analyzeVentas(engine, account, cfg, costs, from, to, hist);
      if (v.freshCount > 0 || v.taxFixedCount > 0 || v.costFixedCount > 0) { hist.updated = new Date().toISOString(); saveHistFile(hist); }  // persistimos nuevas + correcciones de impuesto + costos rellenados
      const proyMensual = v.days > 0 ? v.facturacion / v.days * 30 : 0;
      sendJSON(res, 200, {
        account: account.name, objetivo: cfg.objetivo, taxPct: cfg.taxPct, from, to,
        proy_mensual: proyMensual, avance: cfg.objetivo > 0 ? proyMensual / cfg.objetivo * 100 : 0,
        resumen: { count: v.count, orders: v.orders, facturacion: v.facturacion, ganancia: v.ganancia, margin: v.margin, conocidas: v.conocidas, sinCosto: v.sinCosto, perdida: v.perdida, days: v.days, shipFetched: v.shipFetched, hidden: v.hidden, saved: v.savedCount, fresh: v.freshCount, taxReal: v.taxRealCount, costFixed: v.costFixedCount, unidades: v.unidades, feeTotal: v.feeTotal, envioTotal: v.envioTotal, taxTotal: v.taxTotal, facturaTotal: v.facturaTotal, quedaTotal: v.quedaTotal, costTotal: v.costTotal, costStockTotal: v.costStockTotal, gananciaSinFlex: v.gananciaSinFlex, perdidaMonto: v.perdidaMonto, cuotasCount: v.cuotasCount, bonoTotal: v.bonoTotal },
        ventas: v.rows.sort((a, b) => (a.net == null ? 1 : b.net == null ? -1 : a.net - b.net)).slice(0, 150),
      });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // RENTABILIDAD de TODAS las cuentas juntas, en un mismo rango de fechas.
  route('GET', '/api/ads/ventas-all', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const u = new URL(req.url, 'http://x');
    let from = u.searchParams.get('from'), to = u.searchParams.get('to');
    if (!to) to = ymd(new Date());
    if (!from) from = ymd(daysAgo(30));
    const accounts = loadDB().ml_accounts || [];
    const costs = loadCosts(loadDB);
    const hist = loadHistFile();
    try {
      const allRows = [];
      let facturacion = 0, ganancia = 0, factConocida = 0, conocidas = 0, perdida = 0, sinCosto = 0;
      let shipFetched = 0, hidden = 0, saved = 0, fresh = 0, taxReal = 0, taxFixed = 0, costFixed = 0, orders = 0, objetivoTotal = 0;
      let unidades = 0, feeTotal = 0, envioTotal = 0, taxTotal = 0, facturaTotal = 0, quedaTotal = 0;
      let costTotal = 0, costStockTotal = 0, gananciaSinFlex = 0, perdidaMonto = 0, cuotasCount = 0, bonoTotal = 0;
      const porCuenta = [];
      for (const account of accounts) {
        const cfg = getAccountCfg(account);
        objetivoTotal += cfg.objetivo || 0;
        const v = await analyzeVentas(engine, account, cfg, costs, from, to, hist);
        for (const r of v.rows) { r.account_name = account.name; allRows.push(r); if (r.known) factConocida += r.revenue; }
        facturacion += v.facturacion; ganancia += v.ganancia; orders += v.orders;
        conocidas += v.conocidas; perdida += v.perdida; sinCosto += v.sinCosto;
        shipFetched += v.shipFetched; hidden += v.hidden; saved += v.savedCount; fresh += v.freshCount; taxReal += v.taxRealCount; taxFixed += v.taxFixedCount; costFixed += (v.costFixedCount || 0);
        unidades += v.unidades; feeTotal += v.feeTotal; envioTotal += v.envioTotal; taxTotal += v.taxTotal;
        facturaTotal += v.facturaTotal; quedaTotal += v.quedaTotal; costTotal += v.costTotal; costStockTotal += v.costStockTotal;
        gananciaSinFlex += v.gananciaSinFlex; perdidaMonto += v.perdidaMonto; cuotasCount += v.cuotasCount; bonoTotal += v.bonoTotal;
        const proy = v.days > 0 ? v.facturacion / v.days * 30 : 0;
        porCuenta.push({ account_name: account.name, objetivo: cfg.objetivo, facturacion: v.facturacion, ganancia: v.ganancia, margin: v.margin, orders: v.orders, perdida: v.perdida, proy_mensual: proy });
      }
      if (fresh > 0 || taxFixed > 0 || costFixed > 0) { hist.updated = new Date().toISOString(); saveHistFile(hist); }
      const days = daysBetween(from, to);
      const proyMensual = days > 0 ? facturacion / days * 30 : 0;
      sendJSON(res, 200, {
        account: 'Todas las cuentas', all: true, objetivo: objetivoTotal, from, to,
        proy_mensual: proyMensual, avance: objetivoTotal > 0 ? proyMensual / objetivoTotal * 100 : 0,
        por_cuenta: porCuenta,
        resumen: { count: allRows.length, orders, facturacion, ganancia, margin: factConocida > 0 ? (ganancia / factConocida) * 100 : null, conocidas, sinCosto, perdida, days, shipFetched, hidden, saved, fresh, taxReal, costFixed, unidades, feeTotal, envioTotal, taxTotal, facturaTotal, quedaTotal, costTotal, costStockTotal, gananciaSinFlex, perdidaMonto, cuotasCount, bonoTotal },
        ventas: allRows.sort((a, b) => (a.net == null ? 1 : b.net == null ? -1 : a.net - b.net)).slice(0, 300),
      });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // Guardar objetivo/impuesto por cuenta.
  route('POST', '/api/ads/account-config', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const b = await deps.parseBody(req);
    const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(b.account_id));
    if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
    const db = loadDB();
    db.ads_config = db.ads_config || {}; db.ads_config.accounts = db.ads_config.accounts || {};
    const cur = db.ads_config.accounts[String(account.seller_id)] || {};
    if (b.objetivo != null && !isNaN(Number(b.objetivo))) cur.objetivo = Number(b.objetivo);
    if (b.taxPct != null && !isNaN(Number(b.taxPct))) cur.taxPct = Number(b.taxPct);
    db.ads_config.accounts[String(account.seller_id)] = cur;
    saveDB(db);
    sendJSON(res, 200, { ok: true });
  });

  // ======================= GESTIÓN · HISTÓRICO (snapshots diarios) =======================
  // Calcula las ventas de UN día (from=to=date), para una cuenta o todas, y devuelve filas + totales.
  // analyzeVentas congela el costo de las ventas nuevas en el ledger; acá lo persistimos.
  async function gestionComputeDay(date, accountId) {
    const costs = loadCosts(loadDB);
    const hist = loadHistFile();
    const accounts = loadDB().ml_accounts || [];
    let list = accounts;
    if (accountId && accountId !== 'all') { const a = accounts.find(x => x.id === parseInt(accountId)); list = a ? [a] : []; }
    const allRows = [];
    const T = { facturacion: 0, unidades: 0, feeTotal: 0, envioTotal: 0, taxTotal: 0, facturaTotal: 0, quedaTotal: 0, costTotal: 0, costStockTotal: 0, ganancia: 0, gananciaSinFlex: 0, perdida: 0, perdidaMonto: 0, cuotasCount: 0, bonoTotal: 0, conocidas: 0, sinCosto: 0, factConocida: 0, orders: 0, count: 0 };
    for (const account of list) {
      const cfg = getAccountCfg(account);
      const v = await analyzeVentas(engine, account, cfg, costs, date, date, hist);
      for (const r of v.rows) { r.account_name = account.name; r.account_id = account.id; allRows.push(r); }
      T.facturacion += v.facturacion; T.unidades += v.unidades; T.feeTotal += v.feeTotal; T.envioTotal += v.envioTotal; T.taxTotal += v.taxTotal;
      T.facturaTotal += v.facturaTotal; T.quedaTotal += v.quedaTotal; T.costTotal += v.costTotal; T.costStockTotal += v.costStockTotal;
      T.ganancia += v.ganancia; T.gananciaSinFlex += v.gananciaSinFlex; T.perdida += v.perdida; T.perdidaMonto += v.perdidaMonto;
      T.cuotasCount += v.cuotasCount; T.bonoTotal += v.bonoTotal; T.conocidas += v.conocidas; T.sinCosto += v.sinCosto; T.factConocida += v.factConocida; T.orders += v.orders; T.count += v.count;
    }
    hist.updated = new Date().toISOString(); saveHistFile(hist);   // guardamos costos congelados de las ventas nuevas
    T.margin = T.factConocida > 0 ? (T.ganancia / T.factConocida) * 100 : null;
    return { sales: allRows, totals: T };
  }

  // GUARDAR día: congela las ventas del día elegido. Re-guardar el MISMO día sobreescribe.
  route('POST', '/api/gestion/save-day', async (req, res) => {
    const sess = isAdmin(req);
    if (!sess) return sendJSON(res, 403, { error: 'Solo admin' });
    const b = await deps.parseBody(req);
    const date = String(b.date || '').trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return sendJSON(res, 400, { error: 'Fecha inválida (usá YYYY-MM-DD)' });
    const accountId = (b.account_id != null ? String(b.account_id) : 'all');
    try {
      const { sales, totals } = await gestionComputeDay(date, accountId);
      const store = loadGestionDays();
      const g = getAdsConfig(loadDB);
      const existed = !!(store.days && store.days[date]);
      store.days = store.days || {};
      store.days[date] = { date, savedAt: new Date().toISOString(), savedBy: (sess && sess.username) || 'admin', taxPct: (g.facturaPct != null ? g.facturaPct : 5), scope: accountId, totals, sales };
      store.updated = new Date().toISOString();
      saveGestionDays(store);
      sendJSON(res, 200, { ok: true, date, overwrote: existed, count: sales.length, totals });
    } catch (e) { sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) }); }
  });

  // LISTAR histórico. detail=1 incluye las filas de venta (para tabla/rankings/XLSX); si no, sólo totales.
  route('GET', '/api/gestion/history', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const u = new URL(req.url, 'http://x');
    const from = u.searchParams.get('from'), to = u.searchParams.get('to');
    const detail = u.searchParams.get('detail') === '1';
    const store = loadGestionDays();
    let days = Object.values(store.days || {});
    if (from) days = days.filter(d => d.date >= from);
    if (to) days = days.filter(d => d.date <= to);
    days.sort((a, b) => (a.date < b.date ? -1 : 1));
    const out = days.map(d => detail ? d : { date: d.date, savedAt: d.savedAt, savedBy: d.savedBy, taxPct: d.taxPct, scope: d.scope, totals: d.totals, count: (d.sales || []).length });
    sendJSON(res, 200, { days: out, saved_dates: Object.keys(store.days || {}).sort() });
  });

  // REVALIDAR días guardados: en este segmento NO trabajamos con ventas canceladas ni reclamos
  // cerrados con devolución al comprador. Si una venta ya guardada se canceló/devolvió DESPUÉS de
  // guardar, hay que sacarla del día (de las stats y del detalle). Re-corremos el cálculo del día
  // (mantiene el costo CONGELADO de las que siguen vivas y descarta las muertas vía isDeadOrder).
  route('POST', '/api/gestion/revalidate', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const b = await deps.parseBody(req);
    const from = b.from ? String(b.from) : null, to = b.to ? String(b.to) : null;
    const store = loadGestionDays();
    let dates = Object.keys(store.days || {}).sort();
    if (from) dates = dates.filter(d => d >= from);
    if (to) dates = dates.filter(d => d <= to);
    const changes = [];
    try {
      for (const date of dates) {
        const prev = store.days[date];
        const before = (prev.sales || []).length;
        const { sales, totals } = await gestionComputeDay(date, prev.scope || 'all');
        store.days[date] = { ...prev, totals, sales, revalidatedAt: new Date().toISOString() };
        changes.push({ date, before, after: sales.length, removed: Math.max(0, before - sales.length) });
      }
      store.updated = new Date().toISOString();
      saveGestionDays(store);
      const removedTotal = changes.reduce((a, c) => a + c.removed, 0);
      sendJSON(res, 200, { ok: true, days: dates.length, removed: removedTotal, changes });
    } catch (e) { sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) }); }
  });

  // DIAGNÓSTICO FLEX: trae los datos CRUDOS de ML (orden, envío, costos de envío y pagos) para una venta,
  // así vemos si la "bonificación por envío" viene en la API y con qué valor. Acepta N° de orden o de paquete (Venta #).
  route('GET', '/api/gestion/flex-diag', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const u = new URL(req.url, 'http://x');
    const num = (u.searchParams.get('order_id') || '').trim();
    const accId = u.searchParams.get('account_id');
    if (!num) return sendJSON(res, 400, { error: 'Pasá el N° de venta' });
    const accounts = loadDB().ml_accounts || [];
    const list = (accId && accId !== 'all') ? accounts.filter(a => a.id === parseInt(accId)) : accounts;
    const out = { num, tried: [] };
    for (const acc of list) {
      try {
        const token = await deps.getValidToken(acc);
        let order = null;
        try { const o = await deps.mlGet('https://api.mercadolibre.com/orders/' + num, token, {}); if (o && o.id) order = o; } catch (e) {}
        if (!order) {
          try { const pk = await deps.mlGet('https://api.mercadolibre.com/packs/' + num, token, {}); if (pk && Array.isArray(pk.orders) && pk.orders[0]) { const oid = pk.orders[0].id; const o = await deps.mlGet('https://api.mercadolibre.com/orders/' + oid, token, {}); if (o && o.id) { order = o; out.pack_id = num; } } } catch (e) {}
        }
        if (!order) { out.tried.push(acc.name); continue; }
        out.found_in = acc.name;
        out.order_id = order.id;
        out.pack_id = order.pack_id || out.pack_id || null;
        out.status = order.status;
        out.date_created = order.date_created;
        out.total_amount = order.total_amount;
        out.items = (order.order_items || []).map(it => ({ id: it.item && it.item.id, title: it.item && it.item.title, qty: it.quantity, unit_price: it.unit_price, sale_fee: it.sale_fee }));
        out.payments = (order.payments || []).map(p => ({ transaction_amount: p.transaction_amount, shipping_cost: p.shipping_cost, taxes_amount: p.taxes_amount, coupon_amount: p.coupon_amount, marketplace_fee: p.marketplace_fee, total_paid_amount: p.total_paid_amount, installments: p.installments, status: p.status }));
        out.order_taxes = order.taxes || null;
        // El "Impuestos" (retención) NO viene en la orden; vive en el detalle del PAGO de Mercado Pago.
        const errInfo = (e) => { try { return { status: e && e.response && e.response.status, data: e && e.response && e.response.data, message: e && e.message }; } catch (_) { return String(e); } };
        const payId = order.payments && order.payments[0] && order.payments[0].id;
        out.payment_id = payId || null;
        if (payId) {
          for (const host of ['https://api.mercadopago.com', 'https://api.mercadolibre.com']) {
            try {
              const mp = await deps.mlGet(host + '/v1/payments/' + payId, token, {});
              out.mp_payment = { host, taxes_amount: mp.taxes_amount, transaction_amount: mp.transaction_amount, net_received_amount: mp.transaction_details && mp.transaction_details.net_received_amount, charges_details: mp.charges_details, taxes: mp.taxes, fee_details: mp.fee_details };
              break;
            } catch (e) { (out.mp_errors = out.mp_errors || []).push({ host, err: errInfo(e) }); }
          }
        }
        const shipId = order.shipping && order.shipping.id;
        out.shipping_id = shipId || null;
        if (shipId) {
          try { const s = await deps.mlGet('https://api.mercadolibre.com/shipments/' + shipId, token, {}, { 'x-format-new': 'true' }); out.shipment = { status: s.status, logistic_type: s.logistic_type || (s.logistic && s.logistic.type), base_cost: s.base_cost, cost: s.cost, sender_id: s.sender_id }; } catch (e) { out.shipment_error = String(e && (e.message || e)); }
          try { out.shipment_costs = await deps.mlGet('https://api.mercadolibre.com/shipments/' + shipId + '/costs', token, {}, { 'x-format-new': 'true' }); } catch (e) { out.costs_error = String(e && (e.message || e)); }
        }
        break;
      } catch (e) { out.tried.push(acc.name + ': ' + String(e && (e.message || e))); }
    }
    sendJSON(res, 200, out);
  });

  // BORRAR un día guardado.
  route('POST', '/api/gestion/delete-day', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const b = await deps.parseBody(req);
    const date = String(b.date || '').trim();
    const store = loadGestionDays();
    if (store.days && store.days[date]) { delete store.days[date]; store.updated = new Date().toISOString(); saveGestionDays(store); return sendJSON(res, 200, { ok: true, date }); }
    sendJSON(res, 404, { error: 'No hay datos guardados para ese día' });
  });

  // Selftest de ventas: muestra una orden CRUDA de ML para calibrar comisión/envío.
  route('GET', '/api/ads/ventas/selftest', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'Pasá ?account_id=' });
    try {
      const token = await getValidToken(account);
      const data = await mlGet('https://api.mercadolibre.com/orders/search', token,
        { seller: account.seller_id, 'order.status': 'paid', sort: 'date_desc', limit: 2 });
      const out = { total: data.paging && data.paging.total, sample: (data.results || []).slice(0, 2) };
      // dump crudo del envío de la 1ª orden para calibrar el costo real
      const o0 = (data.results || [])[0];
      // Impuesto REAL: mostramos los pagos crudos de la 1ª orden para confirmar el campo de impuestos.
      if (o0) {
        out.impuesto_calibracion = {
          payments: (o0.payments || []).map(p => ({ taxes_amount: p.taxes_amount, marketplace_fee: p.marketplace_fee, transaction_amount: p.transaction_amount, total_paid_amount: p.total_paid_amount, coupon_amount: p.coupon_amount, shipping_cost: p.shipping_cost })),
          tax_real_sumado: (o0.payments || []).reduce((s, p) => s + (Number(p.taxes_amount) || 0), 0),
          sale_fee_items: (o0.order_items || []).map(it => it.sale_fee),
        };
      }
      const shipId = o0 && o0.shipping && o0.shipping.id;
      if (shipId) {
        out.shipment_id = shipId;
        out.shipping_computed = await engine.fetchShipping(account, shipId);
        try { out.raw_costs = await mlGet(`https://api.mercadolibre.com/shipments/${shipId}/costs`, token, {}, { 'x-format-new': 'true' }); } catch (e) { out.raw_costs_error = String(e && e.response && e.response.status); }
        try { const s = await mlGet(`https://api.mercadolibre.com/shipments/${shipId}`, token, {}, { 'x-format-new': 'true' }); out.raw_shipment = { base_cost: s.base_cost, cost: s.cost, status: s.status, logistic_type: s.logistic_type, shipping_option: s.shipping_option }; } catch (e) {}
      }
      sendJSON(res, 200, out);
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e), hint: 'La cuenta necesita permiso de lectura de órdenes (read).' });
    }
  });

  // Publicaciones GANADORAS para anunciar: cruza tu margen (Excel) con datos en vivo
  // de ML (estado, stock, ventas). Devuelve la lista lista para cargar en una campaña.
  route('GET', '/api/ads/winners', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'account_id inválido' });
    const u = new URL(req.url, 'http://localhost');
    const minMargin = Number(u.searchParams.get('minMargin')) || 12;   // % margen mínimo
    const minSales = Number(u.searchParams.get('minSales'));            // ventas mínimas (0 = no filtra)
    const minSalesN = isNaN(minSales) ? 1 : minSales;
    const limit = Math.min(Number(u.searchParams.get('limit')) || 40, 200);
    const costs = loadCosts(loadDB);
    if (!Object.keys(costs).length) return sendJSON(res, 200, { winners: [], note: 'Importá tu Excel de costos primero.' });
    // 1) candidatos por margen (de tu planilla), ordenados de mayor a menor margen
    const pool = Object.keys(costs)
      .filter(id => /^MLA/i.test(id) && (Number(costs[id].marginList) * 100) >= minMargin)
      .sort((a, b) => (Number(costs[b].marginList) || 0) - (Number(costs[a].marginList) || 0))
      .slice(0, Math.min(limit * 4, 240));
    if (!pool.length) return sendJSON(res, 200, { winners: [], scanned: 0, note: `Ningún producto con margen ≥ ${minMargin}%.` });
    // 2) datos en vivo de ML para filtrar por estado/stock/ventas
    const info = await engine.fetchItems(account, pool, 'id,title,price,available_quantity,sold_quantity,status,permalink');
    const winners = [];
    for (const id of pool) {
      const it = info[id]; if (!it) continue;
      if (String(it.status).toLowerCase() !== 'active') continue;
      if ((Number(it.available_quantity) || 0) <= 0) continue;
      if ((Number(it.sold_quantity) || 0) < minSalesN) continue;
      winners.push({
        item_id: id, title: it.title || '', price: Number(it.price) || 0,
        stock: Number(it.available_quantity) || 0, sold: Number(it.sold_quantity) || 0,
        margin: (Number(costs[id].marginList) || 0) * 100, permalink: it.permalink || '',
      });
      if (winners.length >= limit) break;
    }
    sendJSON(res, 200, { winners, scanned: pool.length, criteria: { minMargin, minSales: minSalesN, limit } });
  });

  // ESTRATEGIA: el cerebro. Cruza las 6 cuentas por título, segmenta estrella/promesa/vaca
  // con margen REAL (del ledger) y asigna la cuenta líder de cada duplicado. No pega a ML:
  // trabaja sobre lo que ya está en el panel (costos por cuenta + ledger de ventas).
  route('GET', '/api/ads/estrategia', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
    const u = new URL(req.url, 'http://localhost');
    // OJO: Number(null)=0 y isNaN(0)=false, así que un parámetro ausente NO debe pasar por Number()
    // sin chequear antes; si no, el default se pierde. Este helper respeta el default.
    const numP = (k, def) => { const v = u.searchParams.get(k); if (v == null || v === '') return def; const n = Number(v); return isNaN(n) ? def : n; };
    const cfg = { marginHigh: numP('marginHigh', 12), minSales: numP('minSales', 1),
      minVisits: numP('minVisits', 8), hotVisits: numP('hotVisits', 30), roas: numP('roas', 5), tieBand: 2 };
    // Mapa de ventas de los últimos 90 días, fusionado de todas las cuentas (item_ids únicos).
    const s90 = loadSold90File(); const sold90Map = {}; let s90At = null;
    for (const aid in (s90.accounts || {})) { const a = s90.accounts[aid]; if (a && a.map) { for (const k in a.map) sold90Map[k] = a.map[k]; if (a.computedAt && (!s90At || a.computedAt > s90At)) s90At = a.computedAt; } }
    // FILTROS DE VISTA (server-side, porque con 146k items el top-500 no alcanza para ver
    // pausar/durmiente/una cuenta puntual). viewAccount escala TODO (KPIs + tabla) a esa cuenta;
    // action/segs/dupOnly/enrichedOnly filtran SOLO la tabla.
    const viewAccount = u.searchParams.get('viewAccount') || '';
    const fAction = u.searchParams.get('action') || '';
    const segParam = u.searchParams.get('segs');
    const segSet = segParam != null ? new Set(String(segParam).split(',').filter(Boolean)) : null;
    const dupOnly = u.searchParams.get('dupOnly') === '1';
    const enrichedOnly = u.searchParams.get('enrichedOnly') === '1';
    const limit = Math.min(Number(u.searchParams.get('limit')) || 500, 20000);
    try {
      // Reusar la foto si es reciente (<20s) y no cambió la config ni hubo enriquecimiento/importación.
      // En cache-hit NO leemos los 6 archivos de costos (lo más caro) ni recalculamos.
      const cacheKey = JSON.stringify(cfg) + '|' + s90At;
      let strat;
      if (_stratCache && _stratCache.key === cacheKey && _stratCache.ver === _stratVersion && (Date.now() - _stratCache.at) < 20000) {
        strat = _stratCache.strat;
      } else {
        const costsTable = loadCostsFile().costs || {};
        if (!Object.keys(costsTable).length) return sendJSON(res, 200, { empty: true, note: 'Importá los _COMPLETO de tus cuentas primero (uno por cuenta).' });
        const hist = loadHistFile();
        const accountsMeta = (loadDB().ml_accounts || []).map(a => ({ id: a.id, name: a.name, seller_id: a.seller_id, objetivo: getAccountCfg(a).objetivo, factura: getAccountCfg(a).taxPct }));
        strat = buildStrategy(costsTable, hist, accountsMeta, cfg, sold90Map);
        strat.totals.sold90_desde = s90At;
        _stratCache = { key: cacheKey, ver: _stratVersion, at: Date.now(), strat };
      }
      // 1) SCOPE por cuenta (define KPIs y el universo de la tabla).
      const scoped = viewAccount ? strat.items.filter(i => String(i.account_id) === String(viewAccount)) : strat.items;
      // 2) Contadores del scope → tarjetas de segmento / plan / duplicados.
      const segmentos = { estrella: 0, promesa: 0, ajustar: 0, vaca: 0, durmiente: 0 };
      const plan = { escalar: 0, promover: 0, ajustar: 0, precio: 0, pausar: 0, organico: 0, revisar: 0 };
      let dupItems = 0; const dupG = new Set(); let enrCount = 0;
      for (const it of scoped) {
        if (segmentos[it.segment] != null) segmentos[it.segment]++;
        if (plan[it.actionCode] != null) plan[it.actionCode]++;
        if (it.enriched) enrCount++;
        if (it.duplicated) { dupItems++; if (it.titleNorm) dupG.add(it.titleNorm); }
      }
      const duplicados = viewAccount ? { items: dupItems, grupos: dupG.size } : strat.duplicados;
      const cuentas = viewAccount ? (strat.cuentas || []).filter(c => String(c.account_id) === String(viewAccount)) : strat.cuentas;
      const totals = viewAccount ? { ...strat.totals, productos: scoped.length, enriquecidos: enrCount, viewAccount } : strat.totals;
      // 3) FILTRO de la tabla (segmento + duplicados + enriquecidos + acción), luego orden e items.
      let tbl = scoped;
      if (segSet) tbl = tbl.filter(i => segSet.has(i.segment));
      if (dupOnly) tbl = tbl.filter(i => i.duplicated);
      if (enrichedOnly) tbl = tbl.filter(i => i.enriched);
      if (fAction) tbl = tbl.filter(i => i.actionCode === fAction);
      const matched = tbl.length;
      const items = tbl.slice().sort((a, b) =>
        ((a.priority || 9) - (b.priority || 9)) || ((b.score || 0) - (a.score || 0)) || ((b.margin || -999) - (a.margin || -999))
      ).slice(0, limit);
      sendJSON(res, 200, { config: cfg, totals, segmentos: viewAccount ? segmentos : strat.segmentos, plan: viewAccount ? plan : strat.plan, planMeta: strat.planMeta, duplicados, cuentas, items, matched, shown: items.length, viewAccount });
    } catch (e) {
      sendJSON(res, 500, { error: String(e && e.message || e) });
    }
  });

  // SELFTEST del simulador de costos: muestra la respuesta cruda de listing_prices para calibrar.
  route('GET', '/api/ads/costsim/selftest', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'Pasá ?account_id=' });
    const u = new URL(req.url, 'http://x');
    const itemId = u.searchParams.get('item_id');
    try {
      const out = { account: account.name };
      const token = await getValidToken(account);
      let categoryId = u.searchParams.get('category_id') || null, listingType = u.searchParams.get('listing_type') || null, price = Number(u.searchParams.get('price')) || null;
      let listP = null, salePriceAmt = null;
      if (itemId) {
        // ÍTEM COMPLETO (sin filtro de atributos) → vemos price, original_price, sale_price (precio del deal/promo), sale_terms.
        let full = null;
        try { full = await mlGet('https://api.mercadolibre.com/items/' + itemId, token); } catch (e) {}
        if (full) {
          listP = Number(full.price) || null;
          salePriceAmt = full.sale_price && full.sale_price.amount != null ? Number(full.sale_price.amount) : null;
          out.item = {
            id: itemId, title: full.title, price: full.price, original_price: full.original_price,
            sale_price: full.sale_price || null, category_id: full.category_id, listing_type_id: full.listing_type_id,
            precio_de_venta_usado: (salePriceAmt && salePriceAmt < listP) ? salePriceAmt : listP,
          };
          categoryId = categoryId || full.category_id; listingType = listingType || full.listing_type_id;
          price = price || ((salePriceAmt && salePriceAmt < listP) ? salePriceAmt : Number(full.price));
        }
        // ENDPOINT DE PRECIOS: expone standard vs promotion/deal (el precio real que paga el comprador).
        try { out.items_prices = await mlGet('https://api.mercadolibre.com/items/' + itemId + '/prices', token); } catch (e) { out.items_prices = { error: String(e.message || e) }; }
        // PRUEBA del multiget (la vía que usa el enriquecimiento masivo): ¿trae sale_price?
        try { const mg = await engine.fetchItems(account, [itemId], 'id,price,original_price,sale_price'); out.multiget_prueba = mg[itemId] ? { price: mg[itemId].price, original_price: mg[itemId].original_price, sale_price: mg[itemId].sale_price || null } : null; } catch (e) {}
      }
      const params = { price: Math.round(price || 10000) };
      if (categoryId) params.category_id = categoryId;
      if (listingType) params.listing_type_id = listingType;
      out.request = params;
      out.raw = await mlGet('https://api.mercadolibre.com/sites/MLA/listing_prices', token, params);
      const sim = await engine.simulateFee(account, params.price, categoryId, listingType);
      out.simulateFee = sim;
      // TASA REAL de ML (de ventas 90d): incluye comisión + cargo + CUOTAS. Es la que reproduce "Recibís".
      const cRow = itemId ? ((loadCostsFile().costs || {})[itemId] || { cost: 0, costShip: 0 }) : { cost: 0, costShip: 0 };
      if (itemId) {
        try {
          const r90 = await fetchSold90Map(engine, account, ymd(daysAgo(90)), ymd(new Date()));
          const tk = r90.take[itemId];
          if (tk && tk.rev > 0) { cRow.realTakeRate = tk.fee / tk.rev; out.tasa_real_ml = { pct: +(cRow.realTakeRate * 100).toFixed(2), ...tk }; }
          else out.tasa_real_ml = 'sin ventas 90d (usa simulador + cuotasPct)';
        } catch (e) {}
      }
      const cfgA = getAccountCfg(account);
      if (u.searchParams.get('cuotasPct') != null) cfgA.cuotasPct = Number(u.searchParams.get('cuotasPct')) || 0;
      if (u.searchParams.get('retencionPct') != null) cfgA.retencionPct = Number(u.searchParams.get('retencionPct')) || 0;
      // Desglose "Recibís" para comparar con la web de ML (usa tasa real si la publicación vendió).
      out.desglose_recibis = simNet(cRow, params.price, sim, cfgA);
      out.leyenda = 'Compará out.desglose_recibis.recibis contra el "Recibís" que muestra ML. precio_de_venta_usado debe coincidir con el precio en promoción.';
      sendJSON(res, 200, out);
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // SELFTEST de visitas: compara visitas de los últimos 90 días (rango) vs acumulado, para verificar que el rango anda.
  route('GET', '/api/ads/visits/selftest', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'Pasá ?account_id=' });
    const itemId = new URL(req.url, 'http://x').searchParams.get('item_id');
    if (!itemId) return sendJSON(res, 400, { error: 'Pasá ?item_id=MLAxxxx' });
    try {
      const token = await getValidToken(account);
      const from = ymd(daysAgo(90)), to = ymd(new Date());
      const out = { item_id: itemId, desde: from, hasta: to };
      // Respuestas CRUDAS de cada endpoint de ML para ver la forma exacta y por qué puede dar 0.
      try { out.raw_rango_items_visits = await mlGet('https://api.mercadolibre.com/items/visits', token, { ids: itemId, date_from: from, date_to: to }); } catch (e) { out.raw_rango_items_visits = { error: String((e && e.response && e.response.data) || e.message || e) }; }
      try { out.raw_acumulado_visits_items = await mlGet('https://api.mercadolibre.com/visits/items', token, { ids: itemId }); } catch (e) { out.raw_acumulado_visits_items = { error: String((e && e.response && e.response.data) || e.message || e) }; }
      try { out.raw_item_visits_single = await mlGet('https://api.mercadolibre.com/items/' + itemId + '/visits', token, { date_from: from, date_to: to }); } catch (e) { out.raw_item_visits_single = { error: String((e && e.response && e.response.data) || e.message || e) }; }
      const rango = await engine.fetchVisits(account, [itemId], from, to);
      const acumulado = await engine.fetchVisits(account, [itemId]);
      out.visitas_90d = rango[itemId] != null ? rango[itemId] : null;
      out.visitas_acumuladas = acumulado[itemId] != null ? acumulado[itemId] : null;
      out.visitas_usadas = (out.visitas_90d && out.visitas_90d > 0) ? out.visitas_90d : out.visitas_acumuladas;
      sendJSON(res, 200, out);
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // VENTAS 90 DÍAS (mapa unidades + tasa real de ML por publicación). Paso SEPARADO y liviano:
  // el front lo llama UNA vez por cuenta antes de enriquecer, así el enriquecimiento no arrastra
  // la lectura pesada de órdenes (era lo que hacía timeout / "Failed to fetch" en la cuenta grande).
  route('GET', '/api/ads/estrategia/sold90', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'account_id inválido' });
    try {
      const s90 = loadSold90File(); s90.accounts = s90.accounts || {};
      const cur = s90.accounts[account.id];
      const fresh = cur && cur.computedAt && cur.take && (Date.now() - new Date(cur.computedAt).getTime()) < 6 * 3600 * 1000;
      if (fresh) return sendJSON(res, 200, { ok: true, cached: true, items: Object.keys(cur.map || {}).length });
      const r90 = await fetchSold90Map(engine, account, ymd(daysAgo(90)), ymd(new Date()));
      s90.accounts[account.id] = { computedAt: new Date().toISOString(), days: 90, map: r90.units, take: r90.take };
      saveSold90File(s90);
      bustStrat();
      sendJSON(res, 200, { ok: true, cached: false, items: Object.keys(r90.units).length });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // ENRIQUECER (refinar) una cuenta con la DATA REAL de ML por publicación:
  // título real, precio CON promo, precio de lista, ventas, visitas, exposición (tipo), health,
  // y el margen simulado al precio real. Es el cimiento del motor inteligente. Tope por velocidad.
  route('GET', '/api/ads/estrategia/refinar', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const account = getAccount(req);
    if (!account) return sendJSON(res, 404, { error: 'account_id inválido' });
    // CANDADO: si ya hay un enriquecimiento en curso para esta cuenta, respondemos "ocupado" al toque
    // (sin tocar ML ni el archivo) para no duplicar la carga en memoria. El front espera y reintenta.
    if (_enrichLocks[account.id]) return sendJSON(res, 200, { refined: 0, busy: true, note: 'Ya hay un enriquecimiento en curso para esta cuenta; esperá que termine el lote.' });
    _enrichLocks[account.id] = true;
    const u = new URL(req.url, 'http://x');
    const cap = Math.min(Number(u.searchParams.get('cap')) || 12, 600);   // lote chico: ahora hay 2 llamadas por ítem (visitas + precios); concurrencia 6 + paracaídas + candado
    const cfg = getAccountCfg(account);
    if (u.searchParams.get('cuotasPct') != null) cfg.cuotasPct = Number(u.searchParams.get('cuotasPct')) || 0;
    if (u.searchParams.get('retencionPct') != null) cfg.retencionPct = Number(u.searchParams.get('retencionPct')) || 0;
    // Trabajamos SOLO con el archivo de esta cuenta (rápido, no toca las demás).
    const file = loadAccountCosts(account.seller_id);
    const table = file.costs || {};
    const allMLA = Object.keys(table).filter(id => /^MLA/i.test(id));   // todas las publicaciones del archivo
    // SOLO ACTIVAS: excluyo las que ya sabemos pausadas/cerradas (no vuelven a pasar por ningún proceso).
    const mine = allMLA.filter(id => {
      const st = String(table[id].status || '').toLowerCase();
      return !st || st === 'active';   // sin estado conocido (aún sin enriquecer) o activa
    });
    const pausadas = allMLA.filter(id => { const st = String(table[id].status || '').toLowerCase(); return st && st !== 'active'; }).length;
    // "Necesita refresco" = nunca enriquecida (sin enrichAt) O enriquecida con una versión ANTERIOR
    // del código (enrichVer < ENRICH_VER). ENRICH_VER=2 = arreglo de visitas (pedido de a una).
    // Así, al re-enriquecer, se refrescan las que quedaron con visitas viejas en 0 (aunque tengan visits90=0
    // guardado), primero las de mayor margen (tus estrellas).
    const needsRefresh = (id) => (!table[id].enrichAt || (Number(table[id].enrichVer) || 0) < ENRICH_VER) ? 0 : 1;
    // Unidades vendidas en 90d (del archivo ya calculado por el paso sold90). Las que VENDIERON van
    // primero — son las que importan (tus estrellas/vacas) y así se refrescan antes que el resto.
    const soldUnits = (() => { try { const c = (loadSold90File().accounts || {})[account.id]; return (c && c.map) || {}; } catch (e) { return {}; } })();
    const ids = mine
      .sort((a, b) =>
        needsRefresh(a) - needsRefresh(b) ||
        ((soldUnits[b] || 0) > 0 ? 1 : 0) - ((soldUnits[a] || 0) > 0 ? 1 : 0) ||   // vendió → primero
        (Number(soldUnits[b] || 0)) - (Number(soldUnits[a] || 0)) ||               // más ventas → primero
        (Number(table[b].marginList) || 0) - (Number(table[a].marginList) || 0))   // luego por margen de lista
      .slice(0, cap);
    if (!ids.length) { _enrichLocks[account.id] = false; return sendJSON(res, 200, { refined: 0, account_total: mine.length, file_total: allMLA.length, pausadas, note: `No hay publicaciones activas para enriquecer. En el archivo hay ${allMLA.length} (${pausadas} pausadas). Si esperabas más, puede que la importación del _COMPLETO de esta cuenta haya quedado incompleta.` }); }
    try {
      // Ventas de los últimos 90 días de la cuenta (se recalcula si está vieja, > 6h). Una sola vez por corrida.
      const s90 = loadSold90File(); s90.accounts = s90.accounts || {};
      let cur90 = s90.accounts[account.id];
      const fresh = cur90 && cur90.computedAt && (Date.now() - new Date(cur90.computedAt).getTime()) < 6 * 3600 * 1000;
      if (!fresh || !cur90 || !cur90.take) {
        try {
          const r90 = await fetchSold90Map(engine, account, ymd(daysAgo(90)), ymd(new Date()));
          cur90 = { computedAt: new Date().toISOString(), days: 90, map: r90.units, take: r90.take };
          s90.accounts[account.id] = cur90;
          saveSold90File(s90);
        } catch (e) { /* si falla, seguimos; buildStrategy cae al ledger */ }
      }
      const takeMap = (cur90 && cur90.take) || {};   // item_id -> {rev,fee} → tasa real de ML (incluye cuotas)
      // Data en vivo de ML: título, precio (con promo/deal via sale_price), precio original, stock, ventas, tipo, categoría, health.
      // fetchItems (multiget) + visitas de 90 días, en paralelo.
      const [info, visits90] = await Promise.all([
        engine.fetchItems(account, ids, 'id,title,price,original_price,sale_price,available_quantity,sold_quantity,listing_type_id,category_id,health,permalink,status,date_created,start_time'),
        engine.fetchVisits(account, ids, ymd(daysAgo(90)), ymd(new Date())),   // visitas de los últimos 90 días (misma ventana que ventas)
      ]);
      // Visitas ACUMULADAS (histórico) SOLO para las que dieron 0 en 90 días (respaldo, sin duplicar la carga).
      const zeroVisIds = ids.filter(id => !(visits90[id] > 0));
      let visitsAcc = {};
      try { if (zeroVisIds.length) visitsAcc = await engine.fetchVisits(account, zeroVisIds); } catch (e) {}
      // PRECIO REAL con promo (desde /items/{id}/prices). Es la fuente que expone la promoción vigente
      // cuando item.sale_price viene null (p.ej. "precio mayorista"). Por ítem, después de las visitas.
      let pricesMap = {};
      try { pricesMap = await engine.fetchItemPrices(account, ids); } catch (e) {}
      // Precio de VENTA real: 1) el de /prices (promo vigente), 2) sale_price, 3) el price del multiget.
      const sellPriceOf = (it, c) => {
        const base = Number(it.price) || Number(c.listPrice) || 0;
        const pm = pricesMap[it.id || c.item_id];
        if (pm && pm.sell != null && pm.sell > 0) return pm.sell;   // precio real con promo (autoridad)
        const sp = it.sale_price && it.sale_price.amount != null ? Number(it.sale_price.amount) : null;
        return (sp && sp > 0 && sp < base) ? sp : base;
      };
      // Precio de LISTA real (sin promo): el "standard" de /prices, si vino.
      const listPriceOf = (it, c) => { const pm = pricesMap[it.id || c.item_id]; return (pm && pm.list != null && pm.list > 0) ? pm.list : (Number(it.price) || Number(c.listPrice) || 0); };
      const simMap = {};
      const simJobs = ids.filter(id => info[id]).map(id => { const it = info[id], c = table[id]; return { id, price: sellPriceOf(it, c), catId: it.category_id, lt: it.listing_type_id || c.listingType }; });
      await mapLimit(simJobs, 6, async (job) => { if (job.price > 0) { try { simMap[job.id] = await engine.simulateFee(account, job.price, job.catId, job.lt); } catch (e) {} } });
      let refined = 0, failed = 0;
      const nowIso = new Date().toISOString();
      for (const id of ids) {
        const c = table[id]; const it = info[id];
        if (!it) { failed++; continue; }
        const price = sellPriceOf(it, c);                               // precio de VENTA (con promo/deal aplicado)
        const listP = listPriceOf(it, c);                               // precio de lista (sin deal)
        const orig = Number(it.original_price) || (price < listP ? listP : null); // precio tachado (antes de promo)
        const catId = it.category_id; const lt = it.listing_type_id || c.listingType;
        const sim = simMap[id];
        // TASA REAL de ML si la publicación vendió en 90 días (incluye comisión + cargo + CUOTAS). Fuente de verdad.
        const tk = takeMap[id];
        c.realTakeRate = (tk && tk.rev > 0) ? (tk.fee / tk.rev) : null;
        if (price > 0 && (sim || c.realTakeRate != null)) {
          const nm = simNet(c, price, sim, cfg);   // simNet ya usa c.realTakeRate cuando existe
          if (nm) {
            // Guardamos los componentes del SIMULADOR (comisión+cargo fijo) + el costo de cuotas ya resuelto,
            // de modo que priceFactors/marginAtPrice (recompute con la factura actual) den el MISMO margen.
            c.simFee = sim ? Number(sim.sale_fee) || 0 : (nm.cargoVender || 0);
            c.simFixed = sim ? Number(sim.fixed_fee) || 0 : 0;
            c.simCuotas = nm.cuotas;   // cuotas del simulador (o completadas con la tasa real de ML)
            c.simEnvio = nm.envio; c.simImp = nm.impuestos; c.simRecibis = nm.recibis; c.simMargin = nm.marginPct;
          }
        }
        // Data real de la publicación (título de ML = autoridad para el cruce por título).
        if (it.title) c.title = it.title;
        c.price = price; c.listPrice = listP; c.origPrice = orig; c.enPromo = !!(price < listP);
        c.sold = Number(it.sold_quantity) || 0;
        c.stockAvail = Number(it.available_quantity) || 0;
        // VISITAS: 90 días si las hay; si no, el histórico acumulado (así una publicación con visitas
        // viejas no queda en 0 y mal clasificada como muerta). Guardamos ambas para transparencia.
        const v90 = visits90[id] != null ? Number(visits90[id]) : 0;
        const vAcc = visitsAcc[id] != null ? Number(visitsAcc[id]) : 0;
        c.visits90 = v90; c.visitsTotal = vAcc;
        c.visits = v90 > 0 ? v90 : (vAcc > 0 ? vAcc : (c.visits || 0));
        c.listingType = lt || c.listingType; c.category_id = catId || c.category_id;
        c.health = it.health != null ? Number(it.health) : c.health;
        c.status = it.status || c.status; c.permalink = it.permalink || c.permalink;
        c.created = it.date_created || it.start_time || c.created;   // antigüedad (para pausar muertas viejas)
        c.enrichAt = nowIso;
        c.enrichVer = ENRICH_VER;   // marca la versión del enriquecimiento (para forzar refrescos futuros)
        refined++;
      }
      saveAccountCosts(account.seller_id, { costs: table, updated: new Date().toISOString() });
      bustStrat();   // datos nuevos → invalidar la foto cacheada
      // "Al día" = enriquecidas con la versión ACTUAL del código (enrichVer >= ENRICH_VER). Así el progreso
      // refleja el refresco real y el loop sigue hasta refrescar TODAS (no se corta con datos viejos).
      const enrichedTotal = mine.filter(id => table[id].enrichAt && (Number(table[id].enrichVer) || 0) >= ENRICH_VER).length;
      sendJSON(res, 200, { refined, failed, scanned: ids.length, cap, account: account.name, enriched_total: enrichedTotal, account_total: mine.length,
        file_total: allMLA.length, activas: mine.length, pausadas,
        note: enrichedTotal < mine.length ? `Enriquecí ${enrichedTotal} de ${mine.length} ACTIVAS. Volvé a tocar 🎯 para seguir con el resto.` : `Enriquecí TODAS las ACTIVAS (${mine.length}). En el archivo hay ${allMLA.length} en total${pausadas ? ` (${pausadas} pausadas quedan fuera a propósito)` : ''}.` });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    } finally {
      _enrichLocks[account.id] = false;   // liberar el candado siempre (éxito o error)
    }
  });

  // Helpers compartidos por el actualizador de precios.
  function strategyCfgFrom(u) {
    const numP = (k, def) => { const v = u.searchParams.get(k); if (v == null || v === '') return def; const n = Number(v); return isNaN(n) ? def : n; };
    return { marginHigh: numP('marginHigh', 12), minSales: numP('minSales', 1), minVisits: numP('minVisits', 8), hotVisits: numP('hotVisits', 30), roas: numP('roas', 5), tieBand: 2 };
  }
  function mergedSold90() { const s90 = loadSold90File(); const m = {}; for (const aid in (s90.accounts || {})) { const a = s90.accounts[aid]; if (a && a.map) for (const k in a.map) m[k] = a.map[k]; } return m; }
  function taxByAccount() { const m = {}; for (const a of (loadDB().ml_accounts || [])) m[a.id] = getAccountCfg(a).taxPct; return m; }

  // PLAN DE PRECIOS (vista previa): calcula el precio nuevo de cada publicación según reglas por acción.
  // body: { account_id?, rules: { <actionCode>: { mode:'margin'|'pct'|'none', value:number } }, limit? }
  route('POST', '/api/ads/precios/plan', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const body = await deps.parseBody(req);
    const rules = body.rules || {};
    const accountId = body.account_id && body.account_id !== 'all' ? String(body.account_id) : null;
    const limit = Math.min(Number(body.limit) || 1000, 5000);
    const costsTable = loadCostsFile().costs || {};
    if (!Object.keys(costsTable).length) return sendJSON(res, 200, { changes: [], count: 0, note: 'Importá y enriquecé productos primero.' });
    const cfg = strategyCfgFrom(new URL(req.url, 'http://x'));
    const accountsMeta = (loadDB().ml_accounts || []).map(a => ({ id: a.id, name: a.name, seller_id: a.seller_id, objetivo: getAccountCfg(a).objetivo, factura: getAccountCfg(a).taxPct }));
    const taxes = taxByAccount();
    try {
      const strat = buildStrategy(costsTable, loadHistFile(), accountsMeta, cfg, mergedSold90());
      let noEnrich = 0, imposible = 0;
      const changes = [];
      for (const it of strat.items) {
        if (accountId && String(it.account_id) !== accountId) continue;
        const rule = rules[it.actionCode];
        if (!rule || rule.mode === 'none' || rule.value == null) continue;
        const c = costsTable[it.item_id];
        const f = priceFactors(c, taxes[it.account_id]);
        let priceNew = null;
        if (rule.mode === 'margin') { if (!f) { noEnrich++; continue; } priceNew = priceForMargin(f, Number(rule.value)); if (priceNew == null) { imposible++; continue; } }
        else if (rule.mode === 'pct') { const base = Number(c.price) || it.price; if (!base) continue; priceNew = Math.round(base * (1 + Number(rule.value) / 100)); }
        if (!priceNew || priceNew <= 0) continue;
        const marginNew = f ? marginAtPrice(f, priceNew) : null;
        const priceNow = it.price != null ? it.price : (Number(c.price) || null);
        if (priceNow != null && priceNew === Math.round(priceNow)) continue;   // sin cambio real
        changes.push({ item_id: it.item_id, account_id: it.account_id, account_name: it.account_name, title: it.title,
          actionCode: it.actionCode, priceNow, priceNew, marginNow: it.margin, marginNew,
          deltaPct: priceNow ? ((priceNew - priceNow) / priceNow * 100) : null });
      }
      changes.sort((a, b) => Math.abs(b.deltaPct || 0) - Math.abs(a.deltaPct || 0));
      sendJSON(res, 200, { count: changes.length, changes: changes.slice(0, limit), skipped: { sin_enriquecer: noEnrich, margen_imposible: imposible } });
    } catch (e) { sendJSON(res, 500, { error: String(e && e.message || e) }); }
  });

  // APLICAR precios: manda los cambios a ML (PUT /items). body: { changes:[{item_id,account_id,price}] }
  route('POST', '/api/ads/precios/aplicar', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const body = await deps.parseBody(req);
    const changes = Array.isArray(body.changes) ? body.changes.slice(0, 500) : [];
    if (!changes.length) return sendJSON(res, 400, { error: 'No hay cambios para aplicar.' });
    const accById = {}; for (const a of (loadDB().ml_accounts || [])) accById[a.id] = a;
    // Cargamos solo los archivos de las cuentas afectadas (y los guardamos una vez al final).
    const touched = {};   // sellerId -> { costs }
    const loadT = (sid) => { if (!touched[sid]) touched[sid] = loadAccountCosts(sid); return touched[sid]; };
    const results = []; let ok = 0, err = 0;
    for (const ch of changes) {
      const acc = accById[ch.account_id]; const price = Math.round(Number(ch.price));
      if (!acc || !ch.item_id || !price || price <= 0) { results.push({ item_id: ch.item_id, ok: false, error: 'datos inválidos' }); err++; continue; }
      try {
        await engine.setItemPrice(acc, ch.item_id, price);
        const f = loadT(acc.seller_id); if (f.costs && f.costs[ch.item_id]) { f.costs[ch.item_id].price = price; f.costs[ch.item_id].priceUpdatedAt = new Date().toISOString(); }
        results.push({ item_id: ch.item_id, ok: true, price }); ok++;
      } catch (e) { results.push({ item_id: ch.item_id, ok: false, error: (e && e.response && e.response.data && (e.response.data.message || JSON.stringify(e.response.data))) || String(e.message || e) }); err++; }
    }
    for (const sid in touched) { touched[sid].updated = new Date().toISOString(); saveAccountCosts(sid, touched[sid]); }
    sendJSON(res, 200, { applied: ok, failed: err, results });
  });

  route('POST', '/api/ads/campaign-status', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const { account_id, campaign_id, status } = await deps.parseBody(req);
    if (!['active', 'paused'].includes(status)) return sendJSON(res, 400, { error: 'status debe ser active|paused' });
    const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(account_id));
    if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });
    try { sendJSON(res, 200, { ok: true, result: await engine.setCampaignStatus(account, campaign_id, status) }); }
    catch (e) { sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) }); }
  });

  // Comisión de respaldo por tipo de publicación cuando la fila no trae el rate.
  const COMMISSION_BY_TYPE = { gold_pro: 0.32, silver_pro: 0.24, gold_special: 0.18, gold: 0.18, silver: 0.18, bronze: 0.18, free: 0.18 };
  function commissionFor(rate, listingType) {
    const r = Number(rate);
    if (r > 0) return r;
    const t = String(listingType || '').trim().toLowerCase();
    return COMMISSION_BY_TYPE[t] ?? 0.18; // sin cuotas por defecto
  }
  const normShip = (d) => /mercado\s*env/i.test(String(d || '')) ? 'ME' : 'NO';

  // Importar tabla de costos por item_id (el panel manda el Excel ya parseado a JSON).
  // body: { costs: [ { item_id, cost(P), costShip(T), ship(D), commission(V), listingType(AB), listPrice(U), marginList(Y) } ], replace: bool }
  route('POST', '/api/ads/costs', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const body = await deps.parseBody(req);
    // Acepta formato COLUMNAR v2 (items = arrays por posición, más liviano) o el viejo (costs = objetos).
    let arr;
    if (Array.isArray(body.items)) {
      arr = body.items.map(a => ({ item_id: a[0], cost: a[1], costShip: a[2], ship: a[3], commission: a[4], listingType: a[5], listPrice: a[6], marginList: a[7], oferta: a[8], title: a[9], sku: a[10], proveedor: a[11] }));
    } else {
      arr = Array.isArray(body.costs) ? body.costs : [];
    }
    // Cuenta a la que pertenece este _COMPLETO (para que las 6 cuentas coexistan y se pueda cruzar por título).
    const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(body.account_id));
    const sellerId = account ? account.seller_id : null;
    const accName = account ? account.name : null;
    if (sellerId == null) return sendJSON(res, 400, { error: 'account_id inválido: elegí la cuenta del casillero.' });
    // Escribimos SOLO el archivo de esta cuenta (no toca las otras, no hay carrera entre imports simultáneos).
    // IMPORTANTE: cargamos SIEMPRE la tabla previa (aunque replace=true) para PRESERVAR los
    // campos del ENRIQUECIMIENTO (simFee, simEnvio, simCuotas, simImp, price, enrichAt, ...).
    // Antes el import pisaba el registro entero y borraba el enriquecimiento de toda la cuenta.
    const prior = (loadAccountCosts(sellerId).costs) || {};
    const table = body.replace ? {} : { ...prior };
    let n = 0;
    for (const r of arr) {
      const id = String(r.item_id || r.id || '').trim();
      if (!id) continue;
      const p = prior[id] || {};   // registro previo (para no perder el enriquecimiento)
      table[id] = {
        ...p,                                            // conserva simFee/simEnvio/simCuotas/simImp/price/enrichAt/... si existían
        cost: Number(r.cost) || 0,                       // col P
        costShip: Number(r.costShip) || Number(r.cost) || 0, // col T
        ship: normShip(r.ship),                          // col D → 'ME' | 'NO'
        commission: commissionFor(r.commission, r.listingType), // col V (con respaldo por tipo)
        listingType: String(r.listingType || '').toLowerCase(),
        listPrice: Number(r.listPrice) || 0,             // col U
        marginList: Number(r.marginList) || 0,           // col Y
        stock: /^(si|s[ií]|oferta|x|1|true)$/i.test(String(r.oferta != null ? r.oferta : (r.stock || '')).trim()), // col AA (oferta) → stock propio
        title: String(r.title || '').trim(),             // título (para cruce entre cuentas)
        sku: String(r.sku || '').trim(),                 // código de proveedor/SKU (referencia)
        proveedor: String(r.proveedor || '').trim(),     // PROVEEDOR (del _COMPLETO)
        seller_id: sellerId,                             // cuenta dueña de esta publicación
        account_id: account ? account.id : null,
        account_name: accName,
      };
      n++;
    }
    saveAccountCosts(sellerId, { costs: table, updated: new Date().toISOString() });
    bustStrat();   // nueva importación → invalidar la foto cacheada
    sendJSON(res, 200, { ok: true, imported: n, total: Object.keys(table).length, account: accName });
  });
  route('GET', '/api/ads/costs', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const f = loadCostsFile();
    const table = f.costs || {};
    sendJSON(res, 200, { total: Object.keys(table).length, updated: f.updated || null, by_account: countByAccount(table), persistent: DATA_DIR !== __dirname });
  });
  // Conteo de productos por cuenta (para los casilleros del panel).
  function countByAccount(table) {
    const m = {};
    for (const id in table) {
      const c = table[id]; const aid = c.account_id != null ? c.account_id : 'null';
      if (!m[aid]) m[aid] = { account_id: c.account_id != null ? c.account_id : null, account_name: c.account_name || 'sin cuenta', count: 0 };
      m[aid].count++;
    }
    return Object.values(m);
  }

  route('GET', '/api/ads/config', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    sendJSON(res, 200, getAdsConfig(loadDB));
  });
  route('POST', '/api/ads/config', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const body = await deps.parseBody(req);
    const db = loadDB();
    db.ads_config = { ...(db.ads_config || {}) };
    for (const k of ['margin', 'acosTarget', 'minClicks', 'windowDays', 'freeShipThreshold', 'facturaPct']) {
      if (body[k] !== undefined && body[k] !== '' && !isNaN(Number(body[k]))) db.ads_config[k] = Number(body[k]);
    }
    if (body.autoPause !== undefined) db.ads_config.autoPause = !!body.autoPause;
    saveDB(db);
    sendJSON(res, 200, { ok: true, config: getAdsConfig(loadDB) });
  });

  route('GET', '/api/ads/log', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const db = loadDB();
    sendJSON(res, 200, { last_run: db.ads_last_run || null, runs: (db.ads_log || []).slice(-5).reverse() });
  });

  route('POST', '/api/ads/run-now', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    try { const log = await runNightlyJob(deps); sendJSON(res, 200, { ok: true, dry_run: log.dry_run, results: log.results }); }
    catch (e) { sendJSON(res, 500, { error: String(e.message || e) }); }
  });

  startScheduler(deps);
  console.log('[ADS] Módulo Product Ads v2 (costo real) registrado. Auto-pausa: ' + (getAdsConfig(loadDB).autoPause ? 'ACTIVA' : 'DRY-RUN'));
}


const ADS_PANEL_HTML = Buffer.from("PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVzIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+UGFuZWwgRXN0cmF0w6lnaWNvIMK3IEF1dG9jaGFwPC90aXRsZT4KPHNjcmlwdD53aW5kb3cuX19QQU5FTF9NT0RFX189JyUlTU9ERSUlJzs8L3NjcmlwdD4KPHNjcmlwdCBzcmM9Ii92ZW5kb3IveGxzeC5qcyI+PC9zY3JpcHQ+CjxzY3JpcHQgc3JjPSIvdmVuZG9yL2NoYXJ0LmpzIj48L3NjcmlwdD4KPHNjcmlwdD4KLy8gUmVzcGFsZG86IHNpIHBvciBsbyBxdWUgc2VhIGxhIGxpYnJlcsOtYSBubyBjYXJnw7MgZGVzZGUgZWwgc2VydmVyLCBsYSByZWludGVudGFtb3MgZGVzZGUgbG9zIENETi4KKGZ1bmN0aW9uKCl7CiAgZnVuY3Rpb24gbG9hZENoYWluKHVybHMsIGNoZWNrKXsgdmFyIGk9MDsgKGZ1bmN0aW9uIG5leHQoKXsgaWYoY2hlY2soKXx8aT49dXJscy5sZW5ndGgpcmV0dXJuOyB2YXIgcz1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTsgcy5zcmM9dXJsc1tpKytdOyBzLm9uZXJyb3I9bmV4dDsgcy5vbmxvYWQ9ZnVuY3Rpb24oKXsgaWYoIWNoZWNrKCkpbmV4dCgpOyB9OyBkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKHMpOyB9KSgpOyB9CiAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ0RPTUNvbnRlbnRMb2FkZWQnLGZ1bmN0aW9uKCl7CiAgICBpZih0eXBlb2YgWExTWD09PSd1bmRlZmluZWQnKSBsb2FkQ2hhaW4oWydodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy94bHN4LzAuMTguNS94bHN4LmZ1bGwubWluLmpzJywnaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS94bHN4QDAuMTguNS9kaXN0L3hsc3guZnVsbC5taW4uanMnLCdodHRwczovL3VucGtnLmNvbS94bHN4QDAuMTguNS9kaXN0L3hsc3guZnVsbC5taW4uanMnXSxmdW5jdGlvbigpe3JldHVybiB0eXBlb2YgWExTWCE9PSd1bmRlZmluZWQnO30pOwogICAgaWYodHlwZW9mIENoYXJ0PT09J3VuZGVmaW5lZCcpIGxvYWRDaGFpbihbJ2h0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL0NoYXJ0LmpzLzQuNC4xL2NoYXJ0LnVtZC5taW4uanMnLCdodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2NoYXJ0LmpzQDQuNC4xL2Rpc3QvY2hhcnQudW1kLm1pbi5qcyddLGZ1bmN0aW9uKCl7cmV0dXJuIHR5cGVvZiBDaGFydCE9PSd1bmRlZmluZWQnO30pOwogIH0pOwp9KSgpOwo8L3NjcmlwdD4KPHN0eWxlPgogIDpyb290ey0tbmF2eTojMWYzODY0Oy0tYmx1ZTojMmU1NDk2Oy0tYmc6I2Y0ZjZmYjstLWNhcmQ6I2ZmZjstLWxpbmU6I2UyZThmMDstLWluazojMWUyOTNiOy0tbXV0OiM2NDc0OGI7CiAgLS1ncmVlbjojMTZhMzRhOy0tZ3JlZW5iZzojZGNmY2U3Oy0tYW1iZXI6I2Q5NzcwNjstLWFtYmVyYmc6I2ZlZjNjNzstLXJlZDojZGMyNjI2Oy0tcmVkYmc6I2ZlZTJlMjstLWJsdWViZzojZGJlYWZlO30KICAqe2JveC1zaXppbmc6Ym9yZGVyLWJveH0KICBib2R5e21hcmdpbjowO2ZvbnQtZmFtaWx5Oi1hcHBsZS1zeXN0ZW0sQmxpbmtNYWNTeXN0ZW1Gb250LCJTZWdvZSBVSSIsUm9ib3RvLEFyaWFsLHNhbnMtc2VyaWY7YmFja2dyb3VuZDp2YXIoLS1iZyk7Y29sb3I6dmFyKC0taW5rKTtmb250LXNpemU6MTRweH0KICAud3JhcHttYXgtd2lkdGg6bWluKDk4dncsMjQwMHB4KTttYXJnaW46MCBhdXRvO3BhZGRpbmc6MThweH0KICBoZWFkZXIudG9we2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEycHg7bWFyZ2luLWJvdHRvbToxNHB4fQogIGhlYWRlci50b3AgaDF7Zm9udC1zaXplOjIwcHg7bWFyZ2luOjA7Y29sb3I6dmFyKC0tbmF2eSk7Zm9udC13ZWlnaHQ6ODAwfQogIGhlYWRlci50b3AgLnN1Yntjb2xvcjp2YXIoLS1tdXQpO2ZvbnQtc2l6ZToxMnB4fQogIC5zcGFjZXJ7ZmxleDoxfQogIHNlbGVjdCxpbnB1dCxidXR0b257Zm9udDppbmhlcml0O2NvbG9yOnZhcigtLWluayl9CiAgc2VsZWN0LGlucHV0W3R5cGU9dGV4dF0saW5wdXRbdHlwZT1udW1iZXJde2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo5cHg7cGFkZGluZzo4cHggMTBweDtiYWNrZ3JvdW5kOiNmZmZ9CiAgYnV0dG9ue2N1cnNvcjpwb2ludGVyO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo5cHg7cGFkZGluZzo4cHggMTNweDtiYWNrZ3JvdW5kOiNmZmY7Zm9udC13ZWlnaHQ6NjAwO3RyYW5zaXRpb246LjEyc30KICBidXR0b246aG92ZXJ7YmFja2dyb3VuZDojZjFmNWY5fQogIGJ1dHRvbi5wcmltYXJ5e2JhY2tncm91bmQ6dmFyKC0tbmF2eSk7Y29sb3I6I2ZmZjtib3JkZXItY29sb3I6dmFyKC0tbmF2eSl9IGJ1dHRvbi5wcmltYXJ5OmhvdmVye2JhY2tncm91bmQ6IzE2MmE0ZH0KICAucGlsbHtkaXNwbGF5OmlubGluZS1mbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NnB4O2JvcmRlci1yYWRpdXM6OTk5cHg7cGFkZGluZzo0cHggMTFweDtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Ym9yZGVyOjFweCBzb2xpZCB0cmFuc3BhcmVudH0KICAucC1ncmVlbntiYWNrZ3JvdW5kOnZhcigtLWdyZWVuYmcpO2NvbG9yOiMxNjY1MzR9IC5wLWFtYmVye2JhY2tncm91bmQ6dmFyKC0tYW1iZXJiZyk7Y29sb3I6IzkyNDAwZX0KICAucC1yZWR7YmFja2dyb3VuZDp2YXIoLS1yZWRiZyk7Y29sb3I6Izk5MWIxYn0gLnAtYmx1ZXtiYWNrZ3JvdW5kOnZhcigtLWJsdWViZyk7Y29sb3I6IzFlNDBhZn0gLnAtZ3JleXtiYWNrZ3JvdW5kOiNmMWY1Zjk7Y29sb3I6IzQ3NTU2OX0KICAvKiBUYWJzICovCiAgLnRhYnN7ZGlzcGxheTpmbGV4O2dhcDo2cHg7Ym9yZGVyLWJvdHRvbToycHggc29saWQgdmFyKC0tbGluZSk7bWFyZ2luLWJvdHRvbToxNnB4O2ZsZXgtd3JhcDp3cmFwO3Bvc2l0aW9uOnN0aWNreTt0b3A6MDt6LWluZGV4OjMwO2JhY2tncm91bmQ6dmFyKC0tYmcpO3BhZGRpbmctdG9wOjZweH0KICAvKiBTY3JvbGwgaW50ZXJubyBjb24gaGVhZGVycyBmaWpvczogbGEgdGFibGEgc2Nyb2xsZWEgc29sYSB5IHN1IGVuY2FiZXphZG8gcXVlZGEgcGVnYWRvIGFycmliYS4gKi8KICAudnNjcm9sbHttYXgtaGVpZ2h0OmNhbGMoMTAwdmggLSAzMDBweCk7bWluLWhlaWdodDoyODBweDtvdmVyZmxvdzphdXRvfQogIC52c2Nyb2xsIHRoZWFkIHRoe3RvcDowO3otaW5kZXg6NH0KICAudGFie3BhZGRpbmc6MTBweCAxOHB4O2JvcmRlcjowO2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Ym9yZGVyLXJhZGl1czoxMHB4IDEwcHggMCAwO2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS1tdXQpO2N1cnNvcjpwb2ludGVyO2JvcmRlci1ib3R0b206M3B4IHNvbGlkIHRyYW5zcGFyZW50O21hcmdpbi1ib3R0b206LTJweH0KICAudGFiLmFjdGl2ZXtjb2xvcjp2YXIoLS1uYXZ5KTtib3JkZXItYm90dG9tLWNvbG9yOnZhcigtLW5hdnkpfQogIC50YWI6aG92ZXJ7YmFja2dyb3VuZDojZWVmMmY3fQogIC5wYW5lbHtkaXNwbGF5Om5vbmV9IC5wYW5lbC5hY3RpdmV7ZGlzcGxheTpibG9ja30KICAvKiBDb3N0IGJhciAqLwogIC5jb3N0YmFye2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxMnB4IDE2cHg7bWFyZ2luLWJvdHRvbToxNHB4O2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDtnYXA6MTJweDthbGlnbi1pdGVtczpjZW50ZXJ9CiAgLmJhbm5lcntiYWNrZ3JvdW5kOiNmZmY3ZWQ7Ym9yZGVyOjFweCBzb2xpZCAjZmVkN2FhO2NvbG9yOiM5YTM0MTI7Ym9yZGVyLXJhZGl1czoxMnB4O3BhZGRpbmc6MTRweCAxNnB4O21hcmdpbi1ib3R0b206MTRweDtkaXNwbGF5Om5vbmV9CiAgLmJhbm5lci5zaG93e2Rpc3BsYXk6YmxvY2t9IC5iYW5uZXIgYntjb2xvcjojN2MyZDEyfSAuYmFubmVyIG9se21hcmdpbjo4cHggMCAwO3BhZGRpbmctbGVmdDoyMHB4fQogIC5jYXJke2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxNHB4IDE2cHg7bWFyZ2luLWJvdHRvbToxNHB4fQogIC5jYXJkIGgze21hcmdpbjowIDAgMTBweDtmb250LXNpemU6MTNweDtjb2xvcjp2YXIoLS1tdXQpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouNnB4fQogIC5jZmdyaWR7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDoxNHB4O2FsaWduLWl0ZW1zOmZsZXgtZW5kfQogIC5maWVsZHtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDo0cHh9CiAgLmZpZWxkIGxhYmVse2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7Zm9udC13ZWlnaHQ6NjAwfQogIC5maWVsZCBpbnB1dHt3aWR0aDoxMTBweH0gLmZpZWxkIC5oaW50e2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLW11dCl9CiAgLmF1dG90YWd7bWFyZ2luLWxlZnQ6YXV0bztmb250LXNpemU6MTJweH0KICAua3Bpc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCg2LDFmcik7Z2FwOjEycHg7bWFyZ2luLWJvdHRvbToxNHB4fQogIC5rcGl7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEzcHggMTRweH0KICAua3BpIC5re2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7Zm9udC13ZWlnaHQ6NjAwO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouNHB4fQogIC5rcGkgLnZ7Zm9udC1zaXplOjIxcHg7Zm9udC13ZWlnaHQ6ODAwO21hcmdpbi10b3A6NXB4O2NvbG9yOnZhcigtLW5hdnkpfSAua3BpIC52LnNtYWxse2ZvbnQtc2l6ZToxNnB4fQogIC5rcGkuZ29vZCAudntjb2xvcjp2YXIoLS1ncmVlbil9IC5rcGkud2FybiAudntjb2xvcjp2YXIoLS1hbWJlcil9IC5rcGkuYmFkIC52e2NvbG9yOnZhcigtLXJlZCl9CiAgQG1lZGlhKG1heC13aWR0aDo5ODBweCl7LmtwaXN7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcil9fQogIEBtZWRpYShtYXgtd2lkdGg6NTYwcHgpey5rcGlze2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfS5maWVsZCBpbnB1dHt3aWR0aDo5MHB4fX0KICAubGVnZW5ke2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7ZGlzcGxheTpmbGV4O2dhcDoxMnB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbjoycHggMnB4IDEycHh9CiAgLmxlZ2VuZCBzcGFue2Rpc3BsYXk6aW5saW5lLWZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo1cHh9IC5kb3R7d2lkdGg6OXB4O2hlaWdodDo5cHg7Ym9yZGVyLXJhZGl1czo1MCV9CiAgLmZpbHRlcnN7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEycHggMTRweDttYXJnaW4tYm90dG9tOjEycHg7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDoxMHB4O2FsaWduLWl0ZW1zOmNlbnRlcn0KICAuZmlsdGVycyAuY2hpcHtjdXJzb3I6cG9pbnRlcjt1c2VyLXNlbGVjdDpub25lO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo5OTlweDtwYWRkaW5nOjVweCAxMnB4O2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjYwMDtiYWNrZ3JvdW5kOiNmZmY7Y29sb3I6dmFyKC0tbXV0KX0KICAuZmlsdGVycyAuY2hpcC5vbntiYWNrZ3JvdW5kOnZhcigtLW5hdnkpO2NvbG9yOiNmZmY7Ym9yZGVyLWNvbG9yOnZhcigtLW5hdnkpfQogIC5maWx0ZXJzIGlucHV0W3R5cGU9dGV4dF17ZmxleDoxO21pbi13aWR0aDoxODBweH0KICAudGFibGVjYXJke2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7b3ZlcmZsb3c6aGlkZGVufQogIC50YWJsZXNjcm9sbHtvdmVyZmxvdy14OmF1dG99CiAgdGFibGV7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO3dpZHRoOjEwMCU7bWluLXdpZHRoOjkwMHB4fQogIHRoLHRke3BhZGRpbmc6MTFweCAxOHB4O3RleHQtYWxpZ246bGVmdDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTt3aGl0ZS1zcGFjZTpub3dyYXB9CiAgdGh7YmFja2dyb3VuZDojZjhmYWZjO2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOi40cHg7Y3Vyc29yOnBvaW50ZXI7cG9zaXRpb246c3RpY2t5O3RvcDowfQogIHRoLm51bSx0ZC5udW17dGV4dC1hbGlnbjpyaWdodH0KICB0Ym9keSB0cjpob3ZlcntiYWNrZ3JvdW5kOiNmOGZhZmN9CiAgdGQubmFtZXt3aGl0ZS1zcGFjZTpub3JtYWw7bWluLXdpZHRoOjIyMHB4O2ZvbnQtd2VpZ2h0OjYwMH0KICB0ZC5uYW1lIC5pZHtkaXNwbGF5OmJsb2NrO2ZvbnQtd2VpZ2h0OjQwMDtjb2xvcjp2YXIoLS1tdXQpO2ZvbnQtc2l6ZToxMXB4fQogIC5hY29zY2VsbHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7anVzdGlmeS1jb250ZW50OmZsZXgtZW5kfQogIC5hY29zYmFye3dpZHRoOjU0cHg7aGVpZ2h0OjdweDtib3JkZXItcmFkaXVzOjRweDtiYWNrZ3JvdW5kOiNlZWYyZjc7b3ZlcmZsb3c6aGlkZGVuO2ZsZXg6bm9uZX0gLmFjb3NiYXI+aXtkaXNwbGF5OmJsb2NrO2hlaWdodDoxMDAlfQogIC5yb3didG57cGFkZGluZzo1cHggMTBweDtmb250LXNpemU6MTJweDtib3JkZXItcmFkaXVzOjdweH0KICAucm93YnRuLnBhdXNle2NvbG9yOiM5OTFiMWI7Ym9yZGVyLWNvbG9yOiNmY2E1YTV9IC5yb3didG4ucGF1c2U6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1yZWRiZyl9CiAgLnJvd2J0bi5wbGF5e2NvbG9yOiMxNjY1MzQ7Ym9yZGVyLWNvbG9yOiM4NmVmYWN9IC5yb3didG4ucGxheTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWdyZWVuYmcpfQogIC5lbXB0eSwubG9hZGluZ3twYWRkaW5nOjM4cHg7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tbXV0KX0KICAuYWN0aW9uc3tkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjEwcHg7YWxpZ24taXRlbXM6Y2VudGVyO21hcmdpbjoxNHB4IDB9CiAgLmJhcntiYWNrZ3JvdW5kOiNlZWYyZjc7Ym9yZGVyLXJhZGl1czo2cHg7aGVpZ2h0OjE0cHg7b3ZlcmZsb3c6aGlkZGVufS5iYXI+aXtkaXNwbGF5OmJsb2NrO2hlaWdodDoxMDAlO2JhY2tncm91bmQ6dmFyKC0tYmx1ZSl9CiAgLmxvZ2NhcmR7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjE0cHggMTZweDttYXJnaW4tdG9wOjZweDtkaXNwbGF5Om5vbmV9CiAgLmxvZ2NhcmQuc2hvd3tkaXNwbGF5OmJsb2NrfQogIC5sb2dyb3d7Zm9udC1zaXplOjEycHg7Ym9yZGVyLWJvdHRvbToxcHggZGFzaGVkIHZhcigtLWxpbmUpO3BhZGRpbmc6N3B4IDA7ZGlzcGxheTpmbGV4O2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwfQogIC50b2FzdHtwb3NpdGlvbjpmaXhlZDtib3R0b206MjBweDtsZWZ0OjUwJTt0cmFuc2Zvcm06dHJhbnNsYXRlWCgtNTAlKTtiYWNrZ3JvdW5kOnZhcigtLW5hdnkpO2NvbG9yOiNmZmY7cGFkZGluZzoxMXB4IDE4cHg7Ym9yZGVyLXJhZGl1czoxMHB4O2ZvbnQtc2l6ZToxM3B4O29wYWNpdHk6MDtwb2ludGVyLWV2ZW50czpub25lO3RyYW5zaXRpb246LjI1czt6LWluZGV4OjUwfQogIC50b2FzdC5zaG93e29wYWNpdHk6MX0KICAubXV0ZWR7Y29sb3I6dmFyKC0tbXV0KX0gLmJ7Zm9udC13ZWlnaHQ6NzAwfQogICN2ZW5UYWJsZS5oaWRlLWFjYyAuYWNjb2x7ZGlzcGxheTpub25lfQogIC8qID09PT09IEhpc3TDs3JpY28gKGdlc3Rpw7NuKSA9PT09PSAqLwogIC5ncmlkMntkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmciAxZnI7Z2FwOjEycHg7bWFyZ2luLWJvdHRvbToxMnB4fQogIEBtZWRpYShtYXgtd2lkdGg6OTAwcHgpey5ncmlkMntncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfX0KICAudHRse2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS1uYXZ5KTtmb250LXNpemU6MTNweDttYXJnaW4tYm90dG9tOjhweH0KICAjcGFuZWwtaGlzdCBjYW52YXN7bWF4LWhlaWdodDoyMjBweH0KICAjcGFuZWwtaGlzdCAudGFibGVjYXJke21hcmdpbi1ib3R0b206MTJweH0KICAuaGlzdC1oaXtiYWNrZ3JvdW5kOnZhcigtLWdyZWVuYmcpfSAuaGlzdC1sb3tiYWNrZ3JvdW5kOnZhcigtLXJlZGJnKX0KICBidXR0b24ubWluaXtwYWRkaW5nOjJweCA2cHg7Zm9udC1zaXplOjEycHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtiYWNrZ3JvdW5kOiNmZmY7Ym9yZGVyLXJhZGl1czo2cHg7Y3Vyc29yOnBvaW50ZXJ9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CjxkaXYgY2xhc3M9IndyYXAiPgoKICA8aGVhZGVyIGNsYXNzPSJ0b3AiPgogICAgPGRpdj4KICAgICAgPGgxPvCfk4ogUGFuZWwgRXN0cmF0w6lnaWNvIMK3IEF1dG9jaGFwPC9oMT4KICAgICAgPGRpdiBjbGFzcz0ic3ViIj5SZW50YWJpbGlkYWQgcmVhbCwgcHVibGljaWRhZCB5IGNyZWNpbWllbnRvIOKAlCBtdWx0aWN1ZW50YTwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzcGFjZXIiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZmllbGQiIHN0eWxlPSJtaW4td2lkdGg6MjEwcHgiPjxsYWJlbD5DdWVudGE8L2xhYmVsPgogICAgICA8c2VsZWN0IGlkPSJhY2NvdW50IiBvbmNoYW5nZT0ib25BY2NvdW50Q2hhbmdlKCkiPjwvc2VsZWN0PgogICAgPC9kaXY+CiAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJyZWZyZXNoVGFiKCkiPuKGuyBBY3R1YWxpemFyPC9idXR0b24+CiAgPC9oZWFkZXI+CgogIDwhLS0gQmFycmEgZGUgY29zdG9zOiB1biBjYXNpbGxlcm8gcG9yIGN1ZW50YSAoY2FkYSBfQ09NUExFVE8gbGlua2VhZG8gYSBzdSBjdWVudGEpIC0tPgogIDxkaXYgY2xhc3M9ImNvc3RiYXIiIHN0eWxlPSJmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6c3RyZXRjaDtnYXA6OHB4Ij4KICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7ZmxleC13cmFwOndyYXAiPgogICAgICA8ZGl2IGNsYXNzPSJiIiBzdHlsZT0iZm9udC1zaXplOjEzcHgiPvCfkrAgQ29zdG9zIHBvciBwcm9kdWN0byAoX0NPTVBMRVRPKSDigJQgdW4gYXJjaGl2byBwb3IgY3VlbnRhPC9kaXY+CiAgICAgIDxzcGFuIGlkPSJjb3N0c3RhdHVzIiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tbGVmdDphdXRvIj48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPkNhZGEgY3VlbnRhIHRpZW5lIHN1IGNhc2lsbGVyby4gSW1wb3J0w6EgZWwgX0NPTVBMRVRPIGRlIGNhZGEgdW5hOiBxdWVkYW4gbGFzIDYgZ3VhcmRhZGFzIHkgbGlua2VhZGFzIHBhcmEgZWwgY3J1Y2UgcG9yIHTDrXR1bG8gZGUgRXN0cmF0ZWdpYS4gUmVpbXBvcnRhciB1bmEgY3VlbnRhIHNvbG8gYWN0dWFsaXphIGVzYS48L2Rpdj4KICAgIDxkaXYgaWQ9ImNvc3RzbG90cyIgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMjMwcHgsMWZyKSk7Z2FwOjhweCI+PC9kaXY+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9ImJhbm5lciIgaWQ9ImJhbm5lciI+CiAgICA8Yj7impnvuI8gRmFsdGEgYWN0aXZhciBlbCBhY2Nlc28gYSBQdWJsaWNpZGFkIHBvciBBUEkuPC9iPgogICAgPGRpdiBpZD0iYmFubmVyTXNnIiBzdHlsZT0ibWFyZ2luLXRvcDo0cHgiPjwvZGl2PgogICAgPG9sPgogICAgICA8bGk+QWN0aXbDoSA8Yj5Qcm9kdWN0IEFkczwvYj4gZW4gbGEgY3VlbnRhIChHZXN0acOzbiBkZSBwdWJsaWNhY2lvbmVzIOKAuiBQdWJsaWNpZGFkKS48L2xpPgogICAgICA8bGk+RW4gdHUgYXBwIGRlIE1lcmNhZG8gTGlicmUgRGV2ZWxvcGVycywgaGFiaWxpdMOhIGVsIHBlcm1pc28gZGUgPGI+cHVibGljaWRhZCAoYWR2ZXJ0aXNpbmcpPC9iPi48L2xpPgogICAgICA8bGk+PGI+UmVjb25lY3TDoSBsYSBjdWVudGE8L2I+IGRlc2RlIENvbmZpZ3VyYWNpw7NuIOKGkiBDdWVudGFzLjwvbGk+CiAgICA8L29sPgogIDwvZGl2PgoKICA8IS0tIFBFU1RBw5FBUyAtLT4KICA8ZGl2IGNsYXNzPSJ0YWJzIj4KICAgIDxidXR0b24gY2xhc3M9InRhYiBhY3RpdmUiIGlkPSJ0YWItcmVudCIgb25jbGljaz0ic2hvd1RhYigncmVudCcpIj7wn5eC77iPIEdlc3Rpw7NuPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItaGlzdCIgb25jbGljaz0ic2hvd1RhYignaGlzdCcpIj7wn5OGIEhpc3TDs3JpY288L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYiIgaWQ9InRhYi1mbGV4IiBvbmNsaWNrPSJzaG93VGFiKCdmbGV4JykiPuKciO+4jyBGTEVYPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItZXN0ciIgb25jbGljaz0ic2hvd1RhYignZXN0cicpIj7wn6egIEVzdHJhdGVnaWE8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYiIgaWQ9InRhYi1wcmVjaW9zIiBvbmNsaWNrPSJzaG93VGFiKCdwcmVjaW9zJykiPvCfkrIgUHJlY2lvczwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiIiBpZD0idGFiLWFqdXN0ZXMiIG9uY2xpY2s9InNob3dUYWIoJ2FqdXN0ZXMnKSI+4pqZ77iPIEFqdXN0ZXM8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYiIgaWQ9InRhYi1wdWIiIG9uY2xpY2s9InNob3dUYWIoJ3B1YicpIj7wn5OiIFB1YmxpY2lkYWQgKEFEUyk8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYiIgaWQ9InRhYi13aW4iIG9uY2xpY2s9InNob3dUYWIoJ3dpbicpIj7wn4+GIEdhbmFkb3JhczwvYnV0dG9uPgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBSRU5UQUJJTElEQUQgPT09PT0gLS0+CiAgPGRpdiBjbGFzcz0icGFuZWwgYWN0aXZlIiBpZD0icGFuZWwtcmVudCI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2ZncmlkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkRlc2RlPC9sYWJlbD48aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InZlbl9mcm9tIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+SGFzdGE8L2xhYmVsPjxpbnB1dCB0eXBlPSJkYXRlIiBpZD0idmVuX3RvIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+QXRham9zPC9sYWJlbD48ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjZweCI+PGJ1dHRvbiB0eXBlPSJidXR0b24iIG9uY2xpY2s9InNldFZlblJhbmdvKDApIiB0aXRsZT0iVmVyIHNvbG8gbGFzIHZlbnRhcyBkZSBob3kiPkhveTwvYnV0dG9uPjxidXR0b24gdHlwZT0iYnV0dG9uIiBvbmNsaWNrPSJzZXRWZW5SYW5nbygxKSIgdGl0bGU9IlZlciBzb2xvIGxhcyB2ZW50YXMgZGUgYXllciI+QXllcjwvYnV0dG9uPjwvZGl2PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RmFjdHVyYSAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0idmVuX3RheCIgc3RlcD0iMC41IiBzdHlsZT0id2lkdGg6NzBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPmdsb2JhbCDCtyBkZWZhdWx0IDUlPC9zcGFuPjwvZGl2PgogICAgICAgIDxidXR0b24gb25jbGljaz0ic2F2ZUZhY3R1cmFDZmcoKSIgdGl0bGU9Ikd1YXJkYXIgbGEgZmFjdHVyYSAlIGdsb2JhbCAoYXBsaWNhIGEgdG9kYXMgbGFzIGN1ZW50YXMpIj7wn5K+IEd1YXJkYXIgJTwvYnV0dG9uPgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+Q3VlbnRhPC9sYWJlbD48c2VsZWN0IGlkPSJ2ZW5fYWNjdF9maWx0ZXIiIG9uY2hhbmdlPSJyZW5kZXJWZW50YXMoVkVOKSIgc3R5bGU9IndpZHRoOjE1MHB4IiB0aXRsZT0iRmlsdHLDoSBsYXMgdmVudGFzIHlhIHRyYcOtZGFzIHBvciBjdWVudGEgKHNpbiB2b2x2ZXIgYSBidXNjYXIpIj48b3B0aW9uIHZhbHVlPSIiPlRvZGFzPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5OwrAgZGUgdmVudGE8L2xhYmVsPjxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0idmVuX29yZGVyIiBwbGFjZWhvbGRlcj0iZmlsdHJhcuKApiIgb25pbnB1dD0icmVuZGVyVmVudGFzKFZFTikiIHN0eWxlPSJ3aWR0aDoxNTBweCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5TaW4gY29zdG88L2xhYmVsPjxsYWJlbCBjbGFzcz0ic2lnLWxpbmUiIHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo1cHg7Zm9udC1zaXplOjEycHg7d2hpdGUtc3BhY2U6bm93cmFwIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJ2ZW5fb25seV9zaW5jb3N0byIgb25jaGFuZ2U9InJlbmRlclZlbnRhcyhWRU4pIj4gc29sbyBzaW4gY29zdG88L2xhYmVsPjwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImxvYWRWZW50YXMoKSIgdGl0bGU9IkFwbGljYXIgZWwgZmlsdHJvIHkgdHJhZXIgbGFzIHZlbnRhcyI+8J+UjSBCdXNjYXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InNhdmVEaWEoKSIgdGl0bGU9IkNvbmdlbGEgbGFzIHZlbnRhcyBkZWwgZMOtYSAoZmVjaGEgRGVzZGUpIGNvbiBsYSBsaXN0YSBkZSBwcmVjaW9zIGRlIGhveS4gUmUtZ3VhcmRhciBlbCBtaXNtbyBkw61hIGxvIHNvYnJlZXNjcmliZS4iPvCfkr4gR3VhcmRhciBkw61hPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJkZWxldGVEaWEoKSIgdGl0bGU9IkVsaW1pbmEgZGVsIEhpc3TDs3JpY28gZWwgZMOtYSBndWFyZGFkbyAoZmVjaGEgRGVzZGUpLCBwYXJhIHBvZGVyIHZvbHZlciBhIHN1YmlybG8gY29uIEd1YXJkYXIgZMOtYSI+8J+Xke+4jyBFbGltaW5hciBkw61hPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJkb3dubG9hZFZlbnRhc1hsc3goKSI+4qyHIFhMU1g8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLXRvcDo4cHgiPkVsZWfDrSBlbCBwZXLDrW9kbyB5IHRvY8OhIDxiPvCflI0gQnVzY2FyPC9iPiAobm8gYnVzY2Egc29sbykuIEdhbmFuY2lhID0gcHJlY2lvIOKIkiBjb21pc2nDs24gcmVhbCDiiJIgZW52w61vIHJlYWwg4oiSIDxiPmltcHVlc3RvIHJlYWwgZGUgTUw8L2I+IOKIkiBjb3N0byDiiJIgPGI+ZmFjdHVyYTwvYj4uIExhIDxiPmZhY3R1cmE8L2I+ICglIGdsb2JhbCkgZXMgZWwgY2FyZ28gbWVuc3VhbCBkZSBNTCB5IGN1ZW50YSBjb21vIHBhcnRlIGRlbCBjb3N0by4gPGI+8J+SviBHdWFyZGFyIGTDrWE8L2I+IGNvbmdlbGEgZXNlIGTDrWEgY29uIHN1IGxpc3RhIGRlIHByZWNpb3MgeSBsbyBtYW5kYSBhbCA8Yj5IaXN0w7NyaWNvPC9iPi4gTm8gZW50cmFuIGNhbmNlbGFkYXMgbmkgcmVjbGFtb3MgY29uIGRldm9sdWNpw7NuIGFsIGNvbXByYWRvcjsgc2kgdW5hIHZlbnRhIHNlIGNhZSBkZXNwdcOpcyBkZSBndWFyZGFyLCByZXZhbGlkw6EgZW4gZWwgSGlzdMOzcmljby4gRWwgY29zdG8gcXVlZGEgPGI+Y29uZ2VsYWRvPC9iPiBhbCBtb21lbnRvIGRlIGxhIHZlbnRhLiA8Yj5RdWVkw7MgZW4gY3VlbnRhPC9iPiBlcyBlbCBkZXDDs3NpdG8gUkVBTCBkZSBNTDogZW4gRmxleCBlbCBlbnbDrW8gbm8gc2UgZGVzY3VlbnRhIGFow60gKHNlIGNvYnJhIGFwYXJ0ZSkuIEVuIHZlbnRhcyBlbiA8Yj7wn5uSIGNhcnJpdG88L2I+ICh2YXJpb3MgcHJvZHVjdG9zLCB1biBtaXNtbyBlbnbDrW8pIGVsIGVudsOtbyBzZSBjdWVudGEgPGI+dW5hIHNvbGEgdmV6PC9iPiB5IHNlIGNhcmdhIGFsIHByb2R1Y3RvIGRlIG1heW9yIHZhbG9yLjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJrcGlzIiBpZD0idmVuX2twaXMiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9InZlbl9wcm9ncmVzc19jYXJkIiBzdHlsZT0iZGlzcGxheTpub25lIj48ZGl2IGlkPSJ2ZW5fcHJvZ3Jlc3MiPjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCB2c2Nyb2xsIj4KICAgICAgPHRhYmxlIGlkPSJ2ZW5UYWJsZSIgY2xhc3M9ImhpZGUtYWNjIiBzdHlsZT0ibWluLXdpZHRoOjE1MDBweCI+CiAgICAgICAgPHRoZWFkPjx0cj4KICAgICAgICAgIDx0aCBkYXRhLWs9InRpdGxlIiBvbmNsaWNrPSJzb3J0VmVuKCd0aXRsZScpIj5WZW50YTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9ImFjY29sIiBkYXRhLWs9ImFjY291bnRfbmFtZSIgb25jbGljaz0ic29ydFZlbignYWNjb3VudF9uYW1lJykiPkN1ZW50YTwvdGg+CiAgICAgICAgICA8dGggZGF0YS1rPSJzdGF0dXMiIG9uY2xpY2s9InNvcnRWZW4oJ3N0YXR1cycpIj5Fc3RhZG8gZW52w61vPC90aD4KICAgICAgICAgIDx0aCBkYXRhLWs9InN0b2NrIiBvbmNsaWNrPSJzb3J0VmVuKCdzdG9jaycpIj5TdG9jazwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJxdHkiIG9uY2xpY2s9InNvcnRWZW4oJ3F0eScpIj5DYW50PC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9InJldmVudWUiIG9uY2xpY2s9InNvcnRWZW4oJ3JldmVudWUnKSI+UHJlY2lvPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImZlZSIgb25jbGljaz0ic29ydFZlbignZmVlJykiPkNvbWlzacOzbjwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJlbnZpbyIgb25jbGljaz0ic29ydFZlbignZW52aW8nKSI+RW52w61vPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9InRheCIgb25jbGljaz0ic29ydFZlbigndGF4JykiIHRpdGxlPSJJbXB1ZXN0byByZWFsIHF1ZSBNTCByZXRpZW5lIGVuIGxhIHZlbnRhIChyZXNwYWxkbzogJSBzaSBubyB2aWVuZSkiPkltcHVlc3RvczwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJxdWVkYSIgb25jbGljaz0ic29ydFZlbigncXVlZGEnKSIgdGl0bGU9IlF1ZWTDsyBlbiBjdWVudGEgUkVBTCBkZSBNTC4gRW4gQ29ycmVvIE1MIGRlc2N1ZW50YSBlbCBlbnbDrW8gZGVsIGRlcMOzc2l0bzsgZW4gRmxleCBOTyAoZWwgZmxleCBzZSBjb2JyYSBhcGFydGUgeSBzZSBkZXNjdWVudGEgZW4gbGEgR2FuYW5jaWEgY29tbyBjb3N0bykuIj5RdWVkw7MgZW4gY3VlbnRhPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImNvc3QiIG9uY2xpY2s9InNvcnRWZW4oJ2Nvc3QnKSI+Q29zdG88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iZmFjdHVyYSIgb25jbGljaz0ic29ydFZlbignZmFjdHVyYScpIiB0aXRsZT0iQ2FyZ28gbWVuc3VhbCBkZSBNTCAocGFydGUgZGVsIGNvc3RvKSI+RmFjdHVyYTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJuZXQiIG9uY2xpY2s9InNvcnRWZW4oJ25ldCcpIj5HYW5hbmNpYTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJuZXRfc2luX2ZsZXgiIG9uY2xpY2s9InNvcnRWZW4oJ25ldF9zaW5fZmxleCcpIiB0aXRsZT0iR2FuYW5jaWEgc2luIGNvbnRhciBlbCBlbnbDrW8vZmxleCI+R2FuIHMvZmxleDwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJtYXJnaW5QY3QiIG9uY2xpY2s9InNvcnRWZW4oJ21hcmdpblBjdCcpIj5NYXJnZW48L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iY3VvdGFzIiBvbmNsaWNrPSJzb3J0VmVuKCdjdW90YXMnKSIgdGl0bGU9IkN1b3RhcyBkZWwgcGFnbyAoMCDDsyAxID0gc2luIGN1b3RhcykiPkN1b3RhczwvdGg+CiAgICAgICAgICA8dGggZGF0YS1rPSJza3UiIG9uY2xpY2s9InNvcnRWZW4oJ3NrdScpIj5Dw7NkL1NLVTwvdGg+CiAgICAgICAgPC90cj48L3RoZWFkPgogICAgICAgIDx0Ym9keSBpZD0idmVuX2JvZHkiPjx0cj48dGQgY29sc3Bhbj0iMTciIGNsYXNzPSJsb2FkaW5nIj5FbGVnw60gZWwgcGVyw61vZG8geSB0b2PDoSDwn5SNIEJ1c2NhciBwYXJhIHRyYWVyIGxhcyB2ZW50YXMuPC90ZD48L3RyPjwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICA8L2Rpdj4KCiAgPCEtLSA9PT09PSBUQUIgSElTVMOTUklDTyAoZMOtYXMgZ3VhcmRhZG9zKSA9PT09PSAtLT4KICA8ZGl2IGNsYXNzPSJwYW5lbCIgaWQ9InBhbmVsLWhpc3QiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5EZXNkZTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJoX2Zyb20iIHN0eWxlPSJ3aWR0aDoxNTBweCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5IYXN0YTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJoX3RvIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+Q3VlbnRhPC9sYWJlbD48c2VsZWN0IGlkPSJoX2FjY291bnQiIHN0eWxlPSJ3aWR0aDoxNzBweCI+PG9wdGlvbiB2YWx1ZT0iIj5Ub2Rhczwvb3B0aW9uPjwvc2VsZWN0PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RXN0YWRvIGVudsOtbzwvbGFiZWw+PHNlbGVjdCBpZD0iaF9zdGF0dXMiIHN0eWxlPSJ3aWR0aDoxNTBweCI+PG9wdGlvbiB2YWx1ZT0iIj5Ub2Rvczwvb3B0aW9uPjwvc2VsZWN0PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RmxleDwvbGFiZWw+PHNlbGVjdCBpZD0iaF9mbGV4Ij48b3B0aW9uIHZhbHVlPSIiPlRvZG9zPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iMSI+U29sbyBGbGV4PC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iMCI+U2luIEZsZXg8L29wdGlvbj48L3NlbGVjdD48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkNvc3RvPC9sYWJlbD48c2VsZWN0IGlkPSJoX2Nvc3RvIj48b3B0aW9uIHZhbHVlPSIiPlRvZG9zPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iMSI+Q29uIGNvc3RvPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iMCI+U2luIGNvc3RvPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5SZXN1bHRhZG88L2xhYmVsPjxzZWxlY3QgaWQ9ImhfcmVzIj48b3B0aW9uIHZhbHVlPSIiPlRvZG9zPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0ibG9zcyI+QSBww6lyZGlkYTwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IndpbiI+Q29uIGdhbmFuY2lhPC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5OwrAgZGUgdmVudGE8L2xhYmVsPjxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaF9vcmRlciIgcGxhY2Vob2xkZXI9Im7Dum1lcm/igKYiIHN0eWxlPSJ3aWR0aDoxNDBweCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5CdXNjYXIgdGV4dG88L2xhYmVsPjxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaF90ZXh0IiBwbGFjZWhvbGRlcj0idMOtdHVsbyAvIFNLVSAvIHByb3ZlZWRvcuKApiIgc3R5bGU9IndpZHRoOjE5MHB4Ij48L2Rpdj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJoaXN0QXBwbHlGaWx0ZXJzKCkiPvCflI4gQXBsaWNhciBmaWx0cm9zPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJoaXN0UmV2YWxpZGF0ZSgpIiB0aXRsZT0iUmV2aXNhIGNhZGEgZMOtYSBndWFyZGFkbyBjb250cmEgTUwgeSBzYWNhIHZlbnRhcyBjYW5jZWxhZGFzIG8gY29uIGRldm9sdWNpw7NuIGFsIGNvbXByYWRvciI+8J+UhCBSZXZhbGlkYXIgZMOtYXM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9Imhpc3REb3dubG9hZFhsc3goKSIgdGl0bGU9IkRlc2NhcmdhIGZvcm1hdG8gUkVTVU1FTiBESUFSSU8gKyB1bmEgaG9qYSBwb3IgZMOtYSI+4qyHIERlc2NhcmdhciBYTFNYPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJoaXN0TG9hZCgpIiB0aXRsZT0iUmVjYXJnYXIgZGVsIHNlcnZpZG9yIj7ihrsgUmVjYXJnYXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBpZD0iaF9tZXRhIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLXRvcDo4cHgiPkNhcmdhbmRvIGhpc3TDs3JpY2/igKY8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ia3BpcyIgaWQ9Imhfa3BpcyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0iaF9jb21wYXJlIiBzdHlsZT0iZGlzcGxheTpub25lIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImdyaWQyIj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0idHRsIj5GYWN0dXJhY2nDs24geSBnYW5hbmNpYSBwb3IgZMOtYTwvZGl2PjxjYW52YXMgaWQ9ImhfY19kYWlseSIgaGVpZ2h0PSIxMjAiPjwvY2FudmFzPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJ0dGwiPk1hcmdlbiAlIHBvciBkw61hPC9kaXY+PGNhbnZhcyBpZD0iaF9jX21hcmdpbiIgaGVpZ2h0PSIxMjAiPjwvY2FudmFzPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJ0dGwiPlZlbnRhcyBwb3IgZMOtYSBkZSBsYSBzZW1hbmE8L2Rpdj48Y2FudmFzIGlkPSJoX2NfZG93IiBoZWlnaHQ9IjEyMCI+PC9jYW52YXM+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9InR0bCI+R2FuYW5jaWEgYWN1bXVsYWRhPC9kaXY+PGNhbnZhcyBpZD0iaF9jX2N1bSIgaGVpZ2h0PSIxMjAiPjwvY2FudmFzPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206NnB4Ij7wn5OKIFJhbmtpbmdzIGRlIGxvcyA8Yj7Dumx0aW1vcyA2MCBkw61hczwvYj4gKGZpam9zIOKAlCBubyBkZXBlbmRlbiBkZWwgZmlsdHJvIGRlIGZlY2hhcyBkZSBhcnJpYmEpLiBUb2PDoSBjdWFscXVpZXIgcmVjdWFkcm8gcGFyYSB2ZXIgZWwgZGV0YWxsZSBkZSB0b2RhcyBsYXMgdmVudGFzIGRlIGVzb3MgNjAgZMOtYXMuPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJncmlkMiI+CiAgICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCIgc3R5bGU9ImN1cnNvcjpwb2ludGVyIiBvbmNsaWNrPSJoaXN0U2hvd0FsbDYwKCdzb2xkJykiPjxkaXYgY2xhc3M9InR0bCIgc3R5bGU9InBhZGRpbmc6MTBweCAxMnB4IDAiPvCfj4YgTcOhcyB2ZW5kaWRvcyA8c3BhbiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXdlaWdodDo0MDAiPsK3IMO6bHRpbW9zIDYwIGTDrWFzPC9zcGFuPjwvZGl2PjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj48dGFibGU+PHRoZWFkPjx0cj48dGg+UHJvZHVjdG88L3RoPjx0aCBjbGFzcz0ibnVtIj5VbmlkLjwvdGg+PHRoIGNsYXNzPSJudW0iPkZhY3R1cmFjacOzbjwvdGg+PC90cj48L3RoZWFkPjx0Ym9keSBpZD0iaF90b3Bfc29sZCI+PC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiIHN0eWxlPSJjdXJzb3I6cG9pbnRlciIgb25jbGljaz0iaGlzdFNob3dBbGw2MCgncHJvZml0JykiPjxkaXYgY2xhc3M9InR0bCIgc3R5bGU9InBhZGRpbmc6MTBweCAxMnB4IDAiPvCfkrAgTcOhcyByZW50YWJsZXMgPHNwYW4gY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC13ZWlnaHQ6NDAwIj7CtyDDumx0aW1vcyA2MCBkw61hczwvc3Bhbj48L2Rpdj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+PHRhYmxlPjx0aGVhZD48dHI+PHRoPlByb2R1Y3RvPC90aD48dGggY2xhc3M9Im51bSI+R2FuYW5jaWE8L3RoPjx0aCBjbGFzcz0ibnVtIj5NYXJnZW48L3RoPjwvdHI+PC90aGVhZD48dGJvZHkgaWQ9ImhfdG9wX3Byb2ZpdCI+PC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiIHN0eWxlPSJjdXJzb3I6cG9pbnRlciIgb25jbGljaz0iaGlzdFNob3dBbGw2MCgnbG9zcycpIj48ZGl2IGNsYXNzPSJ0dGwiIHN0eWxlPSJwYWRkaW5nOjEwcHggMTJweCAwIj7imqDvuI8gQSBww6lyZGlkYSAvIG1hcmdlbiBmbGFjbyA8c3BhbiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXdlaWdodDo0MDAiPsK3ICZsdDsxMCUgwrcgw7psdGltb3MgNjAgZMOtYXM8L3NwYW4+PC9kaXY+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5Qcm9kdWN0bzwvdGg+PHRoIGNsYXNzPSJudW0iPkdhbmFuY2lhPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5IGlkPSJoX3RvcF9sb3NzIj48L3Rib2R5PjwvdGFibGU+PC9kaXY+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCIgc3R5bGU9ImN1cnNvcjpwb2ludGVyIiBvbmNsaWNrPSJoaXN0U2hvd0FsbDYwKCdwcm92JykiPjxkaXYgY2xhc3M9InR0bCIgc3R5bGU9InBhZGRpbmc6MTBweCAxMnB4IDAiPvCfk4cgUG9yIHByb3ZlZWRvciA8c3BhbiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXdlaWdodDo0MDAiPsK3IMO6bHRpbW9zIDYwIGTDrWFzPC9zcGFuPjwvZGl2PjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj48dGFibGU+PHRoZWFkPjx0cj48dGg+UHJvdmVlZG9yPC90aD48dGggY2xhc3M9Im51bSI+VW5pZC48L3RoPjx0aCBjbGFzcz0ibnVtIj5HYW5hbmNpYTwvdGg+PC90cj48L3RoZWFkPjx0Ym9keSBpZD0iaF9ieV9wcm92Ij48L3Rib2R5PjwvdGFibGU+PC9kaXY+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgaWQ9ImhfbW9kYWw2MCIgc3R5bGU9ImRpc3BsYXk6bm9uZTtwb3NpdGlvbjpmaXhlZDtpbnNldDowO2JhY2tncm91bmQ6cmdiYSgxNSwyMyw0MiwuNTUpO3otaW5kZXg6MTAwMDtwYWRkaW5nOjI0cHgiIG9uY2xpY2s9ImlmKGV2ZW50LnRhcmdldD09PXRoaXMpdGhpcy5zdHlsZS5kaXNwbGF5PSdub25lJyI+CiAgICAgIDxkaXYgc3R5bGU9ImJhY2tncm91bmQ6I2ZmZjtib3JkZXItcmFkaXVzOjEycHg7bWF4LXdpZHRoOjE0MDBweDttYXJnaW46MCBhdXRvO21heC1oZWlnaHQ6OTB2aDtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO292ZXJmbG93OmhpZGRlbiI+CiAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtwYWRkaW5nOjEycHggMTZweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0dGwiIGlkPSJoX21vZGFsNjBfdHRsIiBzdHlsZT0ibWFyZ2luOjAiPkRldGFsbGUgwrcgw7psdGltb3MgNjAgZMOtYXM8L2Rpdj4KICAgICAgICAgIDxidXR0b24gb25jbGljaz0iJCgnaF9tb2RhbDYwJykuc3R5bGUuZGlzcGxheT0nbm9uZSciPuKclSBDZXJyYXI8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCIgc3R5bGU9Im92ZXJmbG93OmF1dG87cGFkZGluZzowIDRweCA4cHgiPgogICAgICAgICAgPHRhYmxlIHN0eWxlPSJtaW4td2lkdGg6MTIwMHB4Ij48dGhlYWQ+PHRyPjx0aD5GZWNoYTwvdGg+PHRoPlByb2R1Y3RvPC90aD48dGg+Q3VlbnRhPC90aD48dGggY2xhc3M9Im51bSI+Q2FudDwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbzwvdGg+PHRoIGNsYXNzPSJudW0iPlF1ZWTDszwvdGg+PHRoIGNsYXNzPSJudW0iPkNvc3RvPC90aD48dGggY2xhc3M9Im51bSI+R2FuYW5jaWE8L3RoPjx0aCBjbGFzcz0ibnVtIj5NYXJnZW48L3RoPjx0aD5Qcm92ZWVkb3I8L3RoPjx0aCBjbGFzcz0ibnVtIj5OwrAgdmVudGE8L3RoPjwvdHI+PC90aGVhZD48dGJvZHkgaWQ9ImhfbW9kYWw2MF9ib2R5Ij48L3Rib2R5PjwvdGFibGU+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiPjxkaXYgY2xhc3M9InR0bCIgc3R5bGU9InBhZGRpbmc6MTBweCAxMnB4IDAiPvCfk4YgUmVzdW1lbiBkaWFyaW8g4oCUIGNhZGEgZMOtYSBndWFyZGFkbyAoZm9ybWF0byBFeGNlbCk8L2Rpdj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+CiAgICAgIDx0YWJsZSBzdHlsZT0ibWluLXdpZHRoOjExNTBweCI+PHRoZWFkPjx0cj4KICAgICAgICA8dGg+RmVjaGE8L3RoPjx0aD5Ew61hPC90aD48dGggY2xhc3M9Im51bSI+VmVudGFzIGJydXRhczwvdGg+PHRoIGNsYXNzPSJudW0iPlF1ZWTDsyBlbiBjdWVudGE8L3RoPjx0aCBjbGFzcz0ibnVtIj5Db3N0byBmYWN0dXJhPC90aD48dGggY2xhc3M9Im51bSI+Q29zdG8gYy9mbGV4PC90aD48dGggY2xhc3M9Im51bSI+RmFjdHVyYTwvdGg+PHRoIGNsYXNzPSJudW0iPkdhbmFuY2lhIGMvZmxleDwvdGg+PHRoIGNsYXNzPSJudW0iPiU8L3RoPjx0aCBjbGFzcz0ibnVtIj5HYW5hbmNpYSBzL2ZsZXg8L3RoPjx0aCBjbGFzcz0ibnVtIj5RdWVkw7MgdmVudGEgc3RvY2s8L3RoPjx0aCBjbGFzcz0ibnVtIj5DdW90YXM8L3RoPjx0aD48L3RoPgogICAgICA8L3RyPjwvdGhlYWQ+PHRib2R5IGlkPSJoX2RhaWx5X3Jvd3MiPjwvdGJvZHk+PC90YWJsZT4KICAgIDwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIj48ZGl2IGNsYXNzPSJ0dGwiIHN0eWxlPSJwYWRkaW5nOjEwcHggMTJweCAwIj5EZXRhbGxlIGRlIHZlbnRhcyAoc2Vnw7puIGZpbHRyb3MpPC9kaXY+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwgdnNjcm9sbCI+CiAgICAgIDx0YWJsZSBzdHlsZT0ibWluLXdpZHRoOjE0NTBweCI+PHRoZWFkPjx0cj4KICAgICAgICA8dGg+RmVjaGE8L3RoPjx0aD5WZW50YTwvdGg+PHRoPkN1ZW50YTwvdGg+PHRoPkVzdGFkbzwvdGg+PHRoPlN0b2NrPC90aD48dGggY2xhc3M9Im51bSI+UHJlY2lvPC90aD48dGggY2xhc3M9Im51bSI+Q29taXNpw7NuPC90aD48dGggY2xhc3M9Im51bSI+RW52w61vPC90aD48dGggY2xhc3M9Im51bSI+SW1wdWVzdG9zPC90aD48dGggY2xhc3M9Im51bSI+UXVlZMOzPC90aD48dGggY2xhc3M9Im51bSI+Q29zdG88L3RoPjx0aCBjbGFzcz0ibnVtIj5GYWN0dXJhPC90aD48dGggY2xhc3M9Im51bSI+R2FuYW5jaWE8L3RoPjx0aCBjbGFzcz0ibnVtIj5NYXJnZW48L3RoPjx0aCBjbGFzcz0ibnVtIj5DdW90YXM8L3RoPjx0aD5Dw7NkL1NLVTwvdGg+PHRoPk7CsCB2ZW50YTwvdGg+CiAgICAgIDwvdHI+PC90aGVhZD48dGJvZHkgaWQ9ImhfZGV0YWlsX3Jvd3MiPjwvdGJvZHk+PC90YWJsZT4KICAgIDwvZGl2PjwvZGl2PgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBGTEVYIChjb250cm9sIGRlIGJvbmlmaWNhY2lvbmVzKSA9PT09PSAtLT4KICA8ZGl2IGNsYXNzPSJwYW5lbCIgaWQ9InBhbmVsLWZsZXgiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5EZXNkZTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmX2Zyb20iIHN0eWxlPSJ3aWR0aDoxNTBweCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5IYXN0YTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJmX3RvIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+TsKwIGRlIHZlbnRhPC9sYWJlbD48aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImZfb3JkZXIiIHBsYWNlaG9sZGVyPSJmaWx0cmFy4oCmIiBvbmlucHV0PSJmbGV4UmVuZGVyKCkiIHN0eWxlPSJ3aWR0aDoxNTBweCI+PC9kaXY+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0iZmxleExvYWQoKSI+8J+UjSBCdXNjYXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImZsZXhEb3dubG9hZFhsc3goKSI+4qyHIERlc2NhcmdhciBYTFNYPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgaWQ9ImZfbWV0YSIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi10b3A6OHB4Ij5Db250cm9sIGRlIDxiPmJvbmlmaWNhY2lvbmVzIEZsZXg8L2I+IGRlIE1lcmNhZG8gTGlicmUgKHNvbG8gdmVudGFzIEZsZXgpLiBVc2EgbGEgPGI+Y3VlbnRhIGVsZWdpZGEgYXJyaWJhPC9iPi4gRWxlZ8OtIGVsIHBlcsOtb2RvIHkgdG9jw6Eg8J+UjSBCdXNjYXIuIExhIGJvbmlmaWNhY2nDs24gZXMgbGEgcXVlIE1MIHRlIGRhIHBvciBoYWNlciBlbCBlbnbDrW8gRmxleDsgbm8gYWZlY3RhIGxhIGdhbmFuY2lhLCBlcyBwbGF0YSBxdWUgTUwgdGUgcmVpbnRlZ3JhIHBvciBlbCBlbnbDrW8uPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImtwaXMiIGlkPSJmX2twaXMiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCB2c2Nyb2xsIj4KICAgICAgPHRhYmxlIGlkPSJmbGV4VGFibGUiIGNsYXNzPSJoaWRlLWFjYyIgc3R5bGU9Im1pbi13aWR0aDoxMTAwcHgiPjx0aGVhZD48dHI+CiAgICAgICAgPHRoPlZlbnRhPC90aD48dGggY2xhc3M9ImFjY29sIj5DdWVudGE8L3RoPjx0aD5Fc3RhZG8gZW52w61vPC90aD48dGggY2xhc3M9Im51bSI+UHJlY2lvPC90aD48dGggY2xhc3M9Im51bSI+RW52w61vPC90aD48dGggY2xhc3M9Im51bSI+Qm9uaWZpY2FjacOzbiBNTDwvdGg+PHRoIGNsYXNzPSJudW0iPkN1b3RhczwvdGg+PHRoPkPDs2QvU0tVPC90aD48dGggY2xhc3M9Im51bSI+TsKwIHZlbnRhPC90aD4KICAgICAgPC90cj48L3RoZWFkPjx0Ym9keSBpZD0iZl9ib2R5Ij48dHI+PHRkIGNvbHNwYW49IjkiIGNsYXNzPSJsb2FkaW5nIj5Ub2PDoSDwn5SNIEJ1c2NhciBwYXJhIHRyYWVyIGxhcyB2ZW50YXMgRmxleCBkZWwgcGVyw61vZG8uPC90ZD48L3RyPjwvdGJvZHk+PC90YWJsZT4KICAgIDwvZGl2PjwvZGl2PgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBFU1RSQVRFR0lBIChlbCBjZXJlYnJvKSA9PT09PSAtLT4KICA8ZGl2IGNsYXNzPSJwYW5lbCIgaWQ9InBhbmVsLWVzdHIiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5NYXJnZW4gImJ1ZW5vIiDiiaUgJTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImVzdHJfaGlnaCIgc3RlcD0iMC41IiB2YWx1ZT0iMTIiIHN0eWxlPSJ3aWR0aDo5MHB4Ij48c3BhbiBjbGFzcz0iaGludCI+YnVlbiBtYXJnZW48L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5WZW5kZSBzaSB2ZW50YXMg4omlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZXN0cl9taW5zYWxlcyIgc3RlcD0iMSIgdmFsdWU9IjEiIHN0eWxlPSJ3aWR0aDo4MHB4Ij48c3BhbiBjbGFzcz0iaGludCI+dmVsb2NpZGFkPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RGVtYW5kYSBzaSB2aXNpdGFzIOKJpTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImVzdHJfbWludmlzIiBzdGVwPSIxIiB2YWx1ZT0iOCIgc3R5bGU9IndpZHRoOjkwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij5oYXkgaW50ZXLDqXM8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5NdWNobyB0csOhZmljbyDiiaU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJlc3RyX2hvdHZpcyIgc3RlcD0iNSIgdmFsdWU9IjMwIiBzdHlsZT0id2lkdGg6OTBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPm5vIGNvbnZpZXJ0ZeKGkmFqdXN0YXI8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5ST0FTIG9iamV0aXZvPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZXN0cl9yb2FzIiBzdGVwPSIwLjUiIHZhbHVlPSI1IiBzdHlsZT0id2lkdGg6ODBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPnBhcmEgY2FsY3VsYXIgQURTPC9zcGFuPjwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImxvYWRFc3RyYXRlZ2lhKCkiPvCfp6AgQ2FsY3VsYXIgZXN0cmF0ZWdpYTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0icmVmaW5hck1hcmdlbmVzKCkiIHRpdGxlPSJUcmFlIGxhIGRhdGEgcmVhbCBkZSBjYWRhIHB1YmxpY2FjacOzbiBkZXNkZSBNTDogdMOtdHVsbywgcHJlY2lvIGNvbiBwcm9tbywgdmVudGFzLCB2aXNpdGFzLCBleHBvc2ljacOzbiB5IGVsIGNvc3RvIGV4YWN0byAoc2ltdWxhciBjb3N0b3MpIj7wn46vIEVucmlxdWVjZXIgY29uIGRhdG9zIGRlIE1MPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJkb3dubG9hZEVzdHJhdGVnaWFYbHN4KCkiPuKshyBEZXNjYXJnYXIgWExTWDwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tdG9wOjhweCI+TW90b3IgZGUgcG9zaWNpb25hbWllbnRvOiBjcnV6YSA8Yj50b2RhcyBsYXMgY3VlbnRhczwvYj4gcG9yIHTDrXR1bG8geSBjbGFzaWZpY2EgY2FkYSBwdWJsaWNhY2nDs24gcG9yIDxiPm1hcmdlbiDDlyB2ZW50YXMgw5cgdmlzaXRhcyDDlyBjb252ZXJzacOzbjwvYj4sIGNvbiBsYSBqdWdhZGEgcGFyYSBjb252ZXJ0aXJsYSBlbiB2ZW50YS4gRWwgbWFyZ2VuIHNhbGUgZGVsIDxiPnNpbXVsYWRvciBkZSBNTDwvYj4gYWwgPGI+cHJlY2lvIHJlYWwgY29uIHByb21vPC9iPiAo8J+UtSksIGZhbGxiYWNrIGRlIGxpc3RhICjwn5+gKS4gPGI+SW1wb3J0YW50ZTo8L2I+IGxvcyBkYXRvcyByZWFsZXMgKHTDrXR1bG8sIHZlbnRhcywgdmlzaXRhcywgcHJlY2lvIGNvbiBwcm9tbykgc2FsZW4gZGUgTUwgc8OzbG8gY3VhbmRvIHRvY8OhcyA8Yj7wn46vIEVucmlxdWVjZXI8L2I+IOKAlCBoYWNlbG8gcG9yIGN1ZW50YS4gRWwgPGI+InZlbmRlIjwvYj4gbWlyYSBsYXMgPGI+dmVudGFzIGRlIGxvcyDDumx0aW1vcyAzIG1lc2VzPC9iPi48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9ImVzdHJfcHJvZ3Jlc3NfY2FyZCIgc3R5bGU9ImRpc3BsYXk6bm9uZTtib3JkZXItY29sb3I6dmFyKC0tbmF2eSkiPgogICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwIj4KICAgICAgICA8YiBzdHlsZT0iZm9udC1zaXplOjEzcHg7Y29sb3I6dmFyKC0tbmF2eSkiIGlkPSJlc3RyX3Byb2dfdHh0Ij5FbnJpcXVlY2llbmRv4oCmPC9iPgogICAgICAgIDxzcGFuIGNsYXNzPSJtdXRlZCIgaWQ9ImVzdHJfcHJvZ19zdWIiIHN0eWxlPSJmb250LXNpemU6MTFweCI+PC9zcGFuPgogICAgICAgIDxidXR0b24gb25jbGljaz0ic3RvcEVucmlxdWVjZXIoKSIgc3R5bGU9Im1hcmdpbi1sZWZ0OmF1dG8iIGlkPSJlc3RyX3N0b3BfYnRuIj7ij7kgRGV0ZW5lcjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iYmFyIiBzdHlsZT0ibWFyZ2luLXRvcDo4cHgiPjxpIGlkPSJlc3RyX3Byb2dfYmFyIiBzdHlsZT0id2lkdGg6MCU7YmFja2dyb3VuZDp2YXIoLS1uYXZ5KSI+PC9pPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJrcGlzIiBpZD0iZXN0cl9rcGlzIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiIGlkPSJlc3RyX3BsYW5fY2FyZCIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+CiAgICAgIDxoMz7wn5OLIFBsYW4gZGUgYWNjacOzbiDigJQgcXXDqSBoYWNlciwgcG9yIHByaW9yaWRhZDwvaDM+CiAgICAgIDxkaXYgaWQ9ImVzdHJfcGxhbiIgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMjIwcHgsMWZyKSk7Z2FwOjEwcHgiPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6OHB4Ij5Ub2PDoSB1bmEgYWNjacOzbiBwYXJhIGZpbHRyYXIgbGEgdGFibGEgZGUgYWJham8uIEVsIG9yZGVuIGVzIHBvciBpbXBhY3RvOiBwcmltZXJvIGVzY2FsYXIgeSBwcm9tb3Zlci48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9ImVzdHJfYWNjdHNfY2FyZCIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+CiAgICAgIDxoMz5DdWVudGFzIGhhY2lhIHN1IG9iamV0aXZvPC9oMz4KICAgICAgPGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPjx0YWJsZSBzdHlsZT0ibWluLXdpZHRoOjEwMDBweCIgaWQ9ImVzdHJBY2N0VGFibGUiPgogICAgICAgIDx0aGVhZD48dHI+PHRoPkN1ZW50YTwvdGg+PHRoIGNsYXNzPSJudW0iPk9iamV0aXZvL21lczwvdGg+PHRoIGNsYXNzPSJudW0iPlByb3kuIG1lcyBjb3JyaWRvPC90aD48dGggY2xhc3M9Im51bSI+QXZhbmNlPC90aD48dGggY2xhc3M9Im51bSI+RmFsdGFudGU8L3RoPjx0aCBjbGFzcz0ibnVtIj7wn5KwIEFEUyBzdWdlcmlkby9tZXM8L3RoPjx0aCBjbGFzcz0ibnVtIj5FbnJpcXVlYy48L3RoPjx0aCBjbGFzcz0ibnVtIj7irZA8L3RoPjx0aCBjbGFzcz0ibnVtIj7wn46vPC90aD48dGggY2xhc3M9Im51bSI+8J+RkTwvdGg+PC90cj48L3RoZWFkPgogICAgICAgIDx0Ym9keSBpZD0iZXN0cl9hY2N0cyI+PC90Ym9keT4KICAgICAgPC90YWJsZT48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibGVnZW5kIiBpZD0iZXN0cl9sZWdlbmQiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogICAgICA8c3Bhbj48Yj7irZAgRXN0cmVsbGE6PC9iPiB2ZW5kacOzICjDumx0aW1vcyAzIG1lc2VzKSArIGJ1ZW4gbWFyZ2VuIOKGkiBlc2NhbGFyIEFEUzwvc3Bhbj4KICAgICAgPHNwYW4+PGI+8J+agCBQcm9tZXNhOjwvYj4gYnVlbiBtYXJnZW4gKyBkZW1hbmRhLCBubyB2ZW5kZSDihpIgQURTICsgcHJvbW88L3NwYW4+CiAgICAgIDxzcGFuPjxiPvCflKcgQWp1c3Rhcjo8L2I+IG11Y2hvIHRyw6FmaWNvLCBubyBjb252aWVydGUg4oaSIHByZWNpby9wdWJsaWNhY2nDs24gKE5PIEFEUyk8L3NwYW4+CiAgICAgIDxzcGFuPjxiPvCfkIQgVmFjYTo8L2I+IHZlbmRlICsgbWFyZ2VuIGZsYWNvIOKGkiBvcHRpbWl6YXIgcHJlY2lvPC9zcGFuPgogICAgICA8c3Bhbj48Yj7wn5KkIER1cm1pZW50ZTo8L2I+IHNpbiBkZW1hbmRhIOKGkiBzdG9jayAwIG8gc3ViaXIgcHJlY2lvPC9zcGFuPgogICAgICA8c3Bhbj48Yj7wn4yxIE9yZ8Ohbmljbzo8L2I+IGR1cGxpY2Fkbywgb3RyYSBjdWVudGEgbGlkZXJhPC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmaWx0ZXJzIiBpZD0iZXN0cl9maWx0ZXJzIiBzdHlsZT0iZGlzcGxheTpub25lO21hcmdpbi1ib3R0b206MTBweCI+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLXNlZz0iZXN0cmVsbGEiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSI+4q2QIEVzdHJlbGxhPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1zZWc9InByb21lc2EiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSI+8J+agCBQcm9tZXNhPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1zZWc9ImFqdXN0YXIiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSI+8J+UpyBBanVzdGFyPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1zZWc9InZhY2EiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSI+8J+QhCBWYWNhPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1zZWc9ImR1cm1pZW50ZSIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIj7wn5KkIER1cm1pZW50ZTwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAiIGRhdGEtc2VnPSJlbnJpY2hlZE9ubHkiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSIgdGl0bGU9IlNvbG8gbG9zIGVucmlxdWVjaWRvcyBjb24gZGF0YSByZWFsIGRlIE1MIj7inIUgU29sbyBlbnJpcXVlY2lkb3M8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIiBkYXRhLXNlZz0iZHVwT25seSIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIiB0aXRsZT0iU29sbyBwcm9kdWN0b3MgcmVwZXRpZG9zIGVudHJlIGN1ZW50YXMiPvCflIEgU29sbyBkdXBsaWNhZG9zPC9zcGFuPgogICAgICA8c2VsZWN0IGlkPSJlc3RyX2FjY3QiIG9uY2hhbmdlPSJmaWx0ZXJBY2N0KHRoaXMudmFsdWUpIiB0aXRsZT0iTW9zdHJhciBzb2xvIHVuYSBjdWVudGEgKGVsIGNydWNlIHBvciB0w610dWxvIHNpZ3VlIHZpZW5kbyB0b2RhcykiIHN0eWxlPSJtYXJnaW4tbGVmdDo4cHg7cGFkZGluZzo0cHggOHB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtib3JkZXItcmFkaXVzOjhweDtmb250LXNpemU6MTJweCI+CiAgICAgICAgPG9wdGlvbiB2YWx1ZT0iIj7wn4+iIFRvZGFzIGxhcyBjdWVudGFzPC9vcHRpb24+CiAgICAgIDwvc2VsZWN0PgogICAgICA8YnV0dG9uIG9uY2xpY2s9ImRvd25sb2FkRXN0cmF0ZWdpYVZpc2libGVYbHN4KCkiIHN0eWxlPSJtYXJnaW4tbGVmdDphdXRvIiB0aXRsZT0iQmFqYSBhIEV4Y2VsIGV4YWN0YW1lbnRlIGxvIHF1ZSBlc3TDoXMgdmllbmRvLCBjb24gbG9zIGZpbHRyb3MgYXBsaWNhZG9zIj7irIcgRGVzY2FyZ2FyIGxvIGZpbHRyYWRvIChYTFNYKTwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGlkPSJlc3RyX2NvdW50IiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjZweDtkaXNwbGF5Om5vbmUiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+CiAgICAgIDx0YWJsZSBpZD0iZXN0clRhYmxlIiBzdHlsZT0ibWluLXdpZHRoOjEyODBweCI+CiAgICAgICAgPHRoZWFkPjx0cj4KICAgICAgICAgIDx0aCBkYXRhLWs9InRpdGxlIiBvbmNsaWNrPSJzb3J0RXN0cigndGl0bGUnKSI+UHJvZHVjdG88L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0iYWNjb3VudF9uYW1lIiBvbmNsaWNrPSJzb3J0RXN0cignYWNjb3VudF9uYW1lJykiPkN1ZW50YTwvdGg+CiAgICAgICAgICA8dGggZGF0YS1rPSJzZWdtZW50IiBvbmNsaWNrPSJzb3J0RXN0cignc2VnbWVudCcpIj5TZWdtZW50bzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJzY29yZSIgb25jbGljaz0ic29ydEVzdHIoJ3Njb3JlJykiIHRpdGxlPSJQb3RlbmNpYWwgZGUgYWNjacOzbiAobWFyZ2VuIMOXIGRlbWFuZGEgw5cgY29udmVyc2nDs24pIj5Qb3RlbmNpYWw8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ibWFyZ2luIiBvbmNsaWNrPSJzb3J0RXN0cignbWFyZ2luJykiPk1hcmdlbjwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJwcmljZSIgb25jbGljaz0ic29ydEVzdHIoJ3ByaWNlJykiPlByZWNpbzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJzb2xkIiBvbmNsaWNrPSJzb3J0RXN0cignc29sZCcpIiB0aXRsZT0iVW5pZGFkZXMgdmVuZGlkYXMgZW4gbG9zIMO6bHRpbW9zIDMgbWVzZXMgKGRlZmluZSBzaSAndmVuZGUnKSI+VmVudGFzIDNtPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9InZpc2l0cyIgb25jbGljaz0ic29ydEVzdHIoJ3Zpc2l0cycpIiB0aXRsZT0iVmlzaXRhcyBkZSBsb3Mgw7psdGltb3MgMyBtZXNlcyAobWlzbWEgdmVudGFuYSBxdWUgbGFzIHZlbnRhcykiPlZpc2l0YXMgM208L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iY29udiIgb25jbGljaz0ic29ydEVzdHIoJ2NvbnYnKSIgdGl0bGU9IkNvbnZlcnNpw7NuID0gdmVudGFzIC8gdmlzaXRhcyI+Q29udi48L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0iaXNMZWFkZXIiIG9uY2xpY2s9InNvcnRFc3RyKCdpc0xlYWRlcicpIj5Mw61kZXI8L3RoPgogICAgICAgICAgPHRoPkFjY2nDs248L3RoPgogICAgICAgIDwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9ImVzdHJfYm9keSI+PHRyPjx0ZCBjb2xzcGFuPSIxMSIgY2xhc3M9ImxvYWRpbmciPlRvY8OhICLwn6egIENhbGN1bGFyIGVzdHJhdGVnaWEiIHBhcmEgY3J1emFyIGxhcyBjdWVudGFzLjwvdGQ+PC90cj48L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+PC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIEFKVVNURVMgPT09PT0gLS0+CiAgPGRpdiBjbGFzcz0icGFuZWwiIGlkPSJwYW5lbC1hanVzdGVzIj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8aDM+4pqZ77iPIE9iamV0aXZvIHkgZmFjdHVyYSBwb3IgY3VlbnRhPC9oMz4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjEwcHgiPkVsIDxiPm9iamV0aXZvIG1lbnN1YWw8L2I+IGRlIGNhZGEgY3VlbnRhIHkgc3UgPGI+JSBkZSBmYWN0dXJhPC9iPiAoY2FyZ28gbWVuc3VhbCBkZSBNTCBxdWUgY3VlbnRhIGNvbW8gY29zdG8pLiBDb24gZXN0byBlbCBzaXN0ZW1hIGNhbGN1bGEgZWwgbWFyZ2VuIHJlYWwsIGVsIGF2YW5jZSBtZXMgY29ycmlkbyB5IGN1w6FudG8gaW52ZXJ0aXIgZW4gQURTLiA8Yj5BbCBjYW1iaWFyIGxhIGZhY3R1cmEsIGVsIG1hcmdlbiBzZSByZWNhbGN1bGEgc29sbzwvYj4gY3VhbmRvIHZvbHbDqXMgYSBDYWxjdWxhciBlc3RyYXRlZ2lhIOKAlCBubyBoYWNlIGZhbHRhIHJlLWVucmlxdWVjZXIuPC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVzdHJfYWNjdGNmZyIgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMzAwcHgsMWZyKSk7Z2FwOjEwcHgiPjwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIFBSRUNJT1MgKGFjdHVhbGl6YWRvciBtYXNpdm8pID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIiBpZD0icGFuZWwtcHJlY2lvcyI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0iZXN0cl9wcmVjaW9zX2NhcmQiIHN0eWxlPSJib3JkZXI6MnB4IHNvbGlkIHZhcigtLW5hdnkpIj4KICAgICAgPGgzPvCfkrIgQWN0dWFsaXphZG9yIGRlIHByZWNpb3MgbWFzaXZvIOKAlCBwb3IgZXN0cmF0ZWdpYTwvaDM+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLWJvdHRvbToxMHB4Ij5EZWZpbsOtIHVuYSByZWdsYSBwb3IgYWNjacOzbi4gPGI+TWFyZ2VuIG9iamV0aXZvPC9iPjogZWwgc2lzdGVtYSBjYWxjdWxhIGVsIHByZWNpbyBjb24gZWwgY29zdG8gZXhhY3RvIGRlIE1MLiA8Yj5BanVzdGUgJTwvYj46IHN1YmUvYmFqYSBlbCBwcmVjaW8gYWN0dWFsIGVzZSBwb3JjZW50YWplLiBEZXNwdcOpcyB2ZXMgbGEgPGI+dmlzdGEgcHJldmlhPC9iPiB5IGFwcm9iw6FzIGFudGVzIGRlIG1hbmRhciBhIE1MLiBTb2xvIGZ1bmNpb25hIGNvbiBwcm9kdWN0b3MgPGI+ZW5yaXF1ZWNpZG9zPC9iPi48L2Rpdj4KICAgICAgPGRpdiBpZD0icHJlY2lvX3J1bGVzIiBzdHlsZT0iZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoYXV0by1maWxsLG1pbm1heCgzMjBweCwxZnIpKTtnYXA6MTBweCI+PC9kaXY+CiAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6MTBweDtmbGV4LXdyYXA6d3JhcDttYXJnaW4tdG9wOjEycHg7YWxpZ24taXRlbXM6Y2VudGVyIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJwcmV2aWV3UHJlY2lvcygpIj7wn5GBIFZpc3RhIHByZXZpYTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iYXBsaWNhclByZWNpb3MoKSIgaWQ9InByZWNpb19hcHBseV9idG4iIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ym9yZGVyLWNvbG9yOnZhcigtLWdyZWVuKTtjb2xvcjojMTY2NTM0Ij7inIUgQXBsaWNhciBhIE1MICg8c3BhbiBpZD0icHJlY2lvX2FwcGx5X24iPjA8L3NwYW4+KTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iZG93bmxvYWRQcmVjaW9zWGxzeCgpIiBpZD0icHJlY2lvX3hsc3hfYnRuIiBzdHlsZT0iZGlzcGxheTpub25lIj7irIcgWExTWDwvYnV0dG9uPgogICAgICAgIDxzcGFuIGNsYXNzPSJtdXRlZCIgaWQ9InByZWNpb19wcmV2X2luZm8iIHN0eWxlPSJmb250LXNpemU6MTJweCI+PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0idGFibGVzY3JvbGwiIHN0eWxlPSJtYXJnaW4tdG9wOjEycHgiPjx0YWJsZSBpZD0icHJlY2lvVGFibGUiIHN0eWxlPSJtaW4td2lkdGg6OTAwcHg7ZGlzcGxheTpub25lIj4KICAgICAgICA8dGhlYWQ+PHRyPjx0aD48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJwcmVjaW9fYWxsIiBjaGVja2VkIG9uY2xpY2s9InRvZ2dsZVByZWNpb0FsbCh0aGlzKSI+PC90aD48dGg+UHJvZHVjdG88L3RoPjx0aD5DdWVudGE8L3RoPjx0aD5BY2Npw7NuPC90aD48dGggY2xhc3M9Im51bSI+UHJlY2lvIGFjdHVhbDwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbyBudWV2bzwvdGg+PHRoIGNsYXNzPSJudW0iPs6UJTwvdGg+PHRoIGNsYXNzPSJudW0iPk1hcmdlbiBhY3R1YWw8L3RoPjx0aCBjbGFzcz0ibnVtIj5NYXJnZW4gbnVldm88L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9InByZWNpb19ib2R5Ij48L3Rib2R5PgogICAgICA8L3RhYmxlPjwvZGl2PgogICAgPC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIFBVQkxJQ0lEQUQgPT09PT0gLS0+CiAgPGRpdiBjbGFzcz0icGFuZWwiIGlkPSJwYW5lbC1wdWIiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxoMz5Db25maWd1cmFjacOzbiBkZSBkZWNpc2nDs24gKHR1IG1hcmdlbiBtYW5kYSk8L2gzPgogICAgICA8ZGl2IGNsYXNzPSJjZmdyaWQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+TWFyZ2VuIG5ldG8gJTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImNmZ19tYXJnaW4iIHN0ZXA9IjAuNSIgbWluPSIwIj48c3BhbiBjbGFzcz0iaGludCI+ZXF1aWxpYnJpbyBkZSBBQ09TPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+QUNPUyBvYmpldGl2byAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iY2ZnX3RhcmdldCIgc3RlcD0iMC41IiBtaW49IjAiPjxzcGFuIGNsYXNzPSJoaW50Ij5tZXRhIHJlbnRhYmxlPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+TcOtbi4gY2xpY3M8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJjZmdfY2xpY2tzIiBzdGVwPSIxIiBtaW49IjAiPjxzcGFuIGNsYXNzPSJoaW50Ij5wYXJhIGRlY2lkaXI8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5WZW50YW5hIChkw61hcyk8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJjZmdfd2luZG93IiBzdGVwPSIxIiBtaW49IjEiIG1heD0iOTAiPjxzcGFuIGNsYXNzPSJoaW50Ij5tw6F4IDkwPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RW52w61vIGdyYXRpcyBkZXNkZSAkPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iY2ZnX3NoaXAiIHN0ZXA9IjEwMDAiIG1pbj0iMCI+PHNwYW4gY2xhc3M9ImhpbnQiPnVtYnJhbDwvc3Bhbj48L2Rpdj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InNhdmVDb25maWcoKSI+R3VhcmRhcjwvYnV0dG9uPgogICAgICAgIDxkaXYgY2xhc3M9ImF1dG90YWcgcGlsbCBwLWdyZXkiIGlkPSJhdXRvdGFnIj5BdXRvLXBhdXNhOiDigJQ8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImtwaXMiIGlkPSJrcGlzIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImxlZ2VuZCI+CiAgICAgIDxzcGFuPjxpIGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLWdyZWVuKSI+PC9pPiA8Yj5Fc2NhbGFyPC9iPjwvc3Bhbj4KICAgICAgPHNwYW4+PGkgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tYW1iZXIpIj48L2k+IDxiPk1hbnRlbmVyPC9iPjwvc3Bhbj4KICAgICAgPHNwYW4+PGkgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6IzNiODJmNiI+PC9pPiA8Yj5KdW50YXIgZGF0b3M8L2I+PC9zcGFuPgogICAgICA8c3Bhbj48aSBjbGFzcz0iZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1yZWQpIj48L2k+IDxiPlBhdXNhcjwvYj48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZpbHRlcnMiPgogICAgICA8c3BhbiBjbGFzcz0iYiIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLW11dCkiPkZpbHRyYXI6PC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1hY3Q9IkVTQ0FMQVIiIG9uY2xpY2s9InRvZ2dsZUNoaXAodGhpcykiPvCfn6IgRXNjYWxhcjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtYWN0PSJNQU5URU5FUiIgb25jbGljaz0idG9nZ2xlQ2hpcCh0aGlzKSI+8J+foSBNYW50ZW5lcjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtYWN0PSJKVU5UQVJfREFUT1MiIG9uY2xpY2s9InRvZ2dsZUNoaXAodGhpcykiPvCflLUgSnVudGFyIGRhdG9zPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1hY3Q9IlBBVVNBUiIgb25jbGljaz0idG9nZ2xlQ2hpcCh0aGlzKSI+8J+UtCBQYXVzYXI8L3NwYW4+CiAgICAgIDxzZWxlY3QgaWQ9InN0YXR1c0ZpbHRlciIgb25jaGFuZ2U9InJlbmRlcigpIj48b3B0aW9uIHZhbHVlPSJhbGwiPlRvZG9zIGxvcyBlc3RhZG9zPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iYWN0aXZlIj5Tb2xvIGFjdGl2YXM8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJwYXVzZWQiPlNvbG8gcGF1c2FkYXM8L29wdGlvbj48L3NlbGVjdD4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJzZWFyY2giIHBsYWNlaG9sZGVyPSJCdXNjYXIgcG9yIG5vbWJyZSBvIElEIGRlIGNhbXBhw7Fh4oCmIiBvbmlucHV0PSJyZW5kZXIoKSI+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPgogICAgICA8dGFibGU+CiAgICAgICAgPHRoZWFkPjx0cj4KICAgICAgICAgIDx0aCBvbmNsaWNrPSJzb3J0QnkoJ25hbWUnKSI+Q2FtcGHDsWE8L3RoPjx0aCBvbmNsaWNrPSJzb3J0QnkoJ3N0YXR1cycpIj5Fc3RhZG88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIG9uY2xpY2s9InNvcnRCeSgnY29zdCcpIj5JbnZlcnNpw7NuPC90aD48dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCdyZXZlbnVlJykiPlZlbnRhcyBwdWIuPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ2Fjb3MnKSI+QUNPUzwvdGg+PHRoIGNsYXNzPSJudW0iIG9uY2xpY2s9InNvcnRCeSgnYnJlYWtldmVuQWNvcycpIj5FcXVpbGlicmlvPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ25ldFByb2ZpdCcpIj5HYW5hbmNpYTwvdGg+PHRoIGNsYXNzPSJudW0iIG9uY2xpY2s9InNvcnRCeSgncm9hcycpIj5ST0FTPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ2NsaWNrcycpIj5DbGljczwvdGg+PHRoIG9uY2xpY2s9InNvcnRCeSgnYWN0aW9uJykiPkFjY2nDs248L3RoPjx0aD5Nb3Rpdm88L3RoPjx0aD48L3RoPgogICAgICAgIDwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9InRib2R5Ij48dHI+PHRkIGNvbHNwYW49IjEyIiBjbGFzcz0ibG9hZGluZyI+RWxlZ8OtIHVuYSBjdWVudGHigKY8L3RkPjwvdHI+PC90Ym9keT4KICAgICAgPC90YWJsZT4KICAgIDwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0iYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9InJ1bk5vdygpIj7ilrYgQ29ycmVyIGFuw6FsaXNpcyBBRFM8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJ0b2dnbGVMb2coKSI+8J+TnCDDmmx0aW1hcyBjb3JyaWRhczwvYnV0dG9uPgogICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiIGlkPSJsYXN0UnVuIj48L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImxvZ2NhcmQiIGlkPSJsb2djYXJkIj48L2Rpdj4KICA8L2Rpdj4KCiAgPCEtLSA9PT09PSBUQUIgR0FOQURPUkFTID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIiBpZD0icGFuZWwtd2luIj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206MTBweCI+Q3J1emEgdHUgbWFyZ2VuIChkZWwgRXhjZWwpIGNvbiBkYXRvcyBlbiB2aXZvIGRlIE1MOiBzb2xvIGFjdGl2YXMsIGNvbiBzdG9jayB5IGNvbiB2ZW50YXMuIENvcGnDoXMgbG9zIElEcyB5IGxvcyBwZWfDoXMgYWwgY3JlYXIgbGEgY2FtcGHDsWEgZW4gTWVyY2FkbyBMaWJyZS48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2ZncmlkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk1hcmdlbiBtw61uaW1vICU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJ3aW5fbWFyZ2luIiB2YWx1ZT0iMTIiIHN0ZXA9IjEiIHN0eWxlPSJ3aWR0aDoxMDBweCI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5WZW50YXMgbcOtbmltYXM8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJ3aW5fc2FsZXMiIHZhbHVlPSIxIiBzdGVwPSIxIiBzdHlsZT0id2lkdGg6MTAwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+Q2FudGlkYWQ8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJ3aW5fbGltaXQiIHZhbHVlPSI0MCIgc3RlcD0iMTAiIHN0eWxlPSJ3aWR0aDoxMDBweCI+PC9kaXY+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0ibG9hZFdpbm5lcnMoKSI+QnVzY2FyIGdhbmFkb3JhczwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iY29weVdpbm5lcnMoKSI+8J+TiyBDb3BpYXIgSURzPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJjc3ZXaW5uZXJzKCkiPuKshyBDU1Y8L2J1dHRvbj4KICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiIGlkPSJ3aW5TdGF0dXMiPjwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPgogICAgICA8dGFibGUgc3R5bGU9Im1pbi13aWR0aDo2NDBweCI+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+UHVibGljYWNpw7NuPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuPC90aD48dGggY2xhc3M9Im51bSI+UHJlY2lvPC90aD48dGggY2xhc3M9Im51bSI+U3RvY2s8L3RoPjx0aCBjbGFzcz0ibnVtIj5WZW50YXM8L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9IndpbkJvZHkiPjx0cj48dGQgY29sc3Bhbj0iNSIgY2xhc3M9ImxvYWRpbmciPkVsZWfDrSBjcml0ZXJpb3MgeSB0b2PDoSAiQnVzY2FyIGdhbmFkb3JhcyIuPC90ZD48L3RyPjwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICA8L2Rpdj4KCjwvZGl2Pgo8ZGl2IGNsYXNzPSJ0b2FzdCIgaWQ9InRvYXN0Ij48L2Rpdj4KCjxzY3JpcHQ+Cid1c2Ugc3RyaWN0JzsKbGV0IFNUQVRFPXtyb3dzOltdLGNmZzp7fSxzb3J0S2V5Oidjb3N0Jyxzb3J0RGlyOi0xLGFjdHM6e0VTQ0FMQVI6MSxNQU5URU5FUjoxLEpVTlRBUl9EQVRPUzoxLFBBVVNBUjoxfX07CmxldCBWRU49bnVsbCwgV0lOTkVSUz1bXSwgU1RSQVQ9bnVsbCwgQ1VSVEFCPSdyZW50JzsKY29uc3QgJD1pZD0+ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpOwpjb25zdCBmbXRNb25leT1uPT4obj09bnVsbHx8aXNOYU4obikpPyfigJQnOickJytNYXRoLnJvdW5kKG4pLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpOwpjb25zdCBmbXRQY3Q9bj0+KG49PW51bGx8fGlzTmFOKG4pKT8n4oCUJzpuLnRvRml4ZWQoMSkrJyUnOwpjb25zdCBmbXRYPW49PihuPT1udWxsfHxpc05hTihuKSk/J+KAlCc6bi50b0ZpeGVkKDEpKyd4JzsKZnVuY3Rpb24gdG9hc3QobSl7Y29uc3QgdD0kKCd0b2FzdCcpO3QudGV4dENvbnRlbnQ9bTt0LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTtzZXRUaW1lb3V0KCgpPT50LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKSwyNjAwKTt9CmZ1bmN0aW9uIGVzYyhzKXtyZXR1cm4gU3RyaW5nKHM9PW51bGw/Jyc6cykucmVwbGFjZSgvWyY8PiJdL2csYz0+KHsnJic6JyZhbXA7JywnPCc6JyZsdDsnLCc+JzonJmd0OycsJyInOicmcXVvdDsnfVtjXSkpO30KYXN5bmMgZnVuY3Rpb24gYXBpKHBhdGgsb3B0cyl7CiAgY29uc3Qgcj1hd2FpdCBmZXRjaChwYXRoLE9iamVjdC5hc3NpZ24oe2hlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ319LG9wdHMpKTsKICBpZihyLnN0YXR1cz09PTQwMSl7bG9jYXRpb24uaHJlZj0nLyc7cmV0dXJuIG5ldyBQcm9taXNlKCgpPT57fSk7fQogIGNvbnN0IGQ9YXdhaXQgci5qc29uKCkuY2F0Y2goKCk9Pih7fSkpOwogIGlmKCFyLm9rKSB0aHJvdyAoZC5lcnJvcj9kOntlcnJvcjonSFRUUCAnK3Iuc3RhdHVzfSk7CiAgcmV0dXJuIGQ7Cn0KCmZ1bmN0aW9uIHNob3dUYWIodCl7CiAgQ1VSVEFCPXQ7CiAgWydyZW50JywnaGlzdCcsJ2ZsZXgnLCdwdWInLCd3aW4nLCdlc3RyJywncHJlY2lvcycsJ2FqdXN0ZXMnXS5mb3JFYWNoKHg9Pntjb25zdCB0Yj0kKCd0YWItJyt4KSxwbj0kKCdwYW5lbC0nK3gpO2lmKHRiKXRiLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScseD09PXQpO2lmKHBuKXBuLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScseD09PXQpO30pOwogIGlmKHQhPT0ncHViJyl7Y29uc3QgYj0kKCdiYW5uZXInKTtpZihiKWIuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpO30gIC8vIGVsIGJhbm5lciBkZSBBRFMgc29sbyB2YSBlbiBQdWJsaWNpZGFkCiAgaWYodD09PSdoaXN0Jyl7IGlmKCFISVNUX0xPQURFRCl7IGhpc3RMb2FkKCk7IH0gfQogIGlmKHQ9PT0nZmxleCcpeyBpZighRkxFWF9MT0FERUQpeyBmbGV4TG9hZCgpOyB9IH0KICByZWZyZXNoVGFiKCk7Cn0KZnVuY3Rpb24gcmVmcmVzaFRhYigpewogIGlmKCEkKCdhY2NvdW50JykudmFsdWUpIHJldHVybjsKICBpZihDVVJUQUI9PT0ncmVudCcpeyAvKiBSZW50YWJpbGlkYWQgTk8gYnVzY2Egc29sYTogZWwgdXN1YXJpbyB0b2NhIPCflI0gQnVzY2FyICovIH0KICBlbHNlIGlmKENVUlRBQj09PSdwdWInKXsgbG9hZENhbXBhaWducygpOyB9CiAgZWxzZSBpZihDVVJUQUI9PT0nd2luJyl7IC8qIG9uIGRlbWFuZCAqLyB9CiAgZWxzZSBpZihDVVJUQUI9PT0nZXN0cicpeyBpZighU1RSQVQpIGxvYWRFc3RyYXRlZ2lhKCk7IH0KICBlbHNlIGlmKENVUlRBQj09PSdwcmVjaW9zJyl7IHJlbmRlclByZWNpb1J1bGVzKCk7IH0KICBlbHNlIGlmKENVUlRBQj09PSdhanVzdGVzJyl7IHJlbmRlckFjY3RDZmcoU1RSQVQ/U1RSQVQuY3VlbnRhczpbXSk7IH0KfQpmdW5jdGlvbiBvbkFjY291bnRDaGFuZ2UoKXsgVkVOPW51bGw7IFdJTk5FUlM9W107IGlmKENVUlRBQiE9PSdlc3RyJylTVFJBVD1udWxsOyByZWZyZXNoVGFiKCk7IH0KCmxldCBBQ0NPVU5UUz1bXTsKZnVuY3Rpb24gcmVuZGVyQ29zdFNsb3RzKCl7CiAgY29uc3QgYm94PSQoJ2Nvc3RzbG90cycpO2lmKCFib3gpcmV0dXJuOwogIGJveC5pbm5lckhUTUw9QUNDT1VOVFMubWFwKGE9PgogICAgJzxkaXYgc3R5bGU9ImJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6OHB4IDEwcHg7YmFja2dyb3VuZDojZmZmIj4nKwogICAgICAnPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4Ij4nKwogICAgICAgICc8ZGl2IHN0eWxlPSJtaW4td2lkdGg6MDtmbGV4OjEiPjxkaXYgY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweDt3aGl0ZS1zcGFjZTpub3dyYXA7b3ZlcmZsb3c6aGlkZGVuO3RleHQtb3ZlcmZsb3c6ZWxsaXBzaXMiPicrZXNjKGEubmFtZSkrJzwvZGl2PicrCiAgICAgICAgJzxkaXYgY2xhc3M9Im11dGVkIiBpZD0ic2xvdGNvdW50LScrYS5pZCsnIiBzdHlsZT0iZm9udC1zaXplOjExcHgiPuKAlCBzaW4gY29zdG9zPC9kaXY+PC9kaXY+JysKICAgICAgICAnPGxhYmVsIGNsYXNzPSJwaWxsIHAtYmx1ZSIgc3R5bGU9ImN1cnNvcjpwb2ludGVyO3doaXRlLXNwYWNlOm5vd3JhcCI+8J+TpSBJbXBvcnRhcicrCiAgICAgICAgICAnPGlucHV0IHR5cGU9ImZpbGUiIGFjY2VwdD0iLnhsc3gsLnhscyIgc3R5bGU9ImRpc3BsYXk6bm9uZSIgb25jaGFuZ2U9ImltcG9ydENvc3RzKHRoaXMsJythLmlkKycsXCcnK2VzYyhhLm5hbWUpLnJlcGxhY2UoLycvZywiXFwnIikrJ1wnKSI+PC9sYWJlbD4nKwogICAgICAnPC9kaXY+JysKICAgICAgJzxkaXYgY2xhc3M9ImJhciIgaWQ9InNsb3RiYXItJythLmlkKyciIHN0eWxlPSJkaXNwbGF5Om5vbmU7aGVpZ2h0OjZweDttYXJnaW4tdG9wOjZweCI+PGkgc3R5bGU9IndpZHRoOjAlO2JhY2tncm91bmQ6dmFyKC0tYmx1ZSkiPjwvaT48L2Rpdj4nKwogICAgJzwvZGl2PicpLmpvaW4oJycpOwp9Ci8vIE1vZG8gZGVsIHBhbmVsOiAnZ2VzdGlvbicgKHNvbG8gR2VzdGnDs24pIG8gJ2VzdHJhdGVnaWEnIChFc3RyYXRlZ2lhK1B1YmxpY2lkYWQrR2FuYWRvcmFzKS4KY29uc3QgUEFORUxfTU9ERT0od2luZG93Ll9fUEFORUxfTU9ERV9fPT09J2dlc3Rpb24nKT8nZ2VzdGlvbic6J2VzdHJhdGVnaWEnOwpmdW5jdGlvbiBhcHBseU1vZGUoKXsKICBjb25zdCBzaG93UmVudD0oUEFORUxfTU9ERT09PSdnZXN0aW9uJyk7CiAgY29uc3QgZXN0clRhYnM9Wydlc3RyJywncHJlY2lvcycsJ2FqdXN0ZXMnLCdwdWInLCd3aW4nXTsKICAkKCd0YWItcmVudCcpLnN0eWxlLmRpc3BsYXk9c2hvd1JlbnQ/Jyc6J25vbmUnOwogIGNvbnN0IGhiPSQoJ3RhYi1oaXN0Jyk7IGlmKGhiKSBoYi5zdHlsZS5kaXNwbGF5PXNob3dSZW50PycnOidub25lJzsKICBjb25zdCBmYj0kKCd0YWItZmxleCcpOyBpZihmYikgZmIuc3R5bGUuZGlzcGxheT1zaG93UmVudD8nJzonbm9uZSc7CiAgZXN0clRhYnMuZm9yRWFjaCh0PT57Y29uc3QgYj0kKCd0YWItJyt0KTtpZihiKWIuc3R5bGUuZGlzcGxheT1zaG93UmVudD8nbm9uZSc6Jyc7fSk7CiAgLy8gVMOtdHVsbyBzZWfDum4gbW9kbwogIGNvbnN0IGgxPWRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ2hlYWRlci50b3AgaDEnKSwgc3ViPWRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ2hlYWRlci50b3AgLnN1YicpOwogIGlmKHNob3dSZW50KXsgaWYoaDEpaDEudGV4dENvbnRlbnQ9J/Cfl4LvuI8gR2VzdGnDs24gwrcgQXV0b2NoYXAnOyBpZihzdWIpc3ViLnRleHRDb250ZW50PSdSZW50YWJpbGlkYWQgZGlhcmlhIHBvciBjdWVudGEg4oCUIGN1w6FudG8gZ2Fuw6FzIHBvciBkw61hJzsgfQogIGVsc2UgeyBpZihoMSloMS50ZXh0Q29udGVudD0n8J+noCBFc3RyYXRlZ2lhIMK3IEF1dG9jaGFwJzsgaWYoc3ViKXN1Yi50ZXh0Q29udGVudD0nU2VnbWVudGFjacOzbiwgY3VlbnRhIGzDrWRlciB5IGNyZWNpbWllbnRvIHBvciBjdWVudGEnOyB9CiAgc2hvd1RhYihzaG93UmVudD8ncmVudCc6J2VzdHInKTsKfQphc3luYyBmdW5jdGlvbiBpbml0KCl7CiAgdHJ5ewogICAgY29uc3QgYWNjcz1hd2FpdCBhcGkoJy9hcGkvYWRzL2FjY291bnRzJyk7CiAgICBBQ0NPVU5UUz1hY2NzLmFjY291bnRzfHxbXTsKICAgIGNvbnN0IHNlbD0kKCdhY2NvdW50Jyk7IHNlbC5pbm5lckhUTUw9Jyc7CiAgICBjb25zdCBvQWxsPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpO29BbGwudmFsdWU9J2FsbCc7b0FsbC50ZXh0Q29udGVudD0n8J+Xgu+4jyBUb2RhcyBsYXMgY3VlbnRhcyc7c2VsLmFwcGVuZENoaWxkKG9BbGwpOwogICAgQUNDT1VOVFMuZm9yRWFjaChhPT57Y29uc3Qgbz1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdvcHRpb24nKTtvLnZhbHVlPWEuaWQ7by50ZXh0Q29udGVudD1hLm5hbWUrJyAoJythLnNlbGxlcl9pZCsnKSc7c2VsLmFwcGVuZENoaWxkKG8pO30pOwogICAgcmVuZGVyQ29zdFNsb3RzKCk7CiAgfWNhdGNoKGUpe30KICBhd2FpdCBsb2FkQ29uZmlnKCk7IGxvYWRDb3N0U3RhdHVzKCk7CiAgLy8gRmVjaGFzIHBvciBkZWZlY3RvIGVuIGhvcmEgYXJnZW50aW5hIChVVEMtMyksIGNvbnNpc3RlbnRlIGNvbiBlbCBEYXNoYm9hcmQuCiAgY29uc3QgYXJnVG9kYXk9bmV3IERhdGUoRGF0ZS5ub3coKS0zKjM2MDAqMTAwMCksIGFyZ0Fnbz1uZXcgRGF0ZShEYXRlLm5vdygpLTMqMzYwMCoxMDAwLTMwKjg2NDAwMDAwKTsKICAkKCd2ZW5fdG8nKS52YWx1ZT1hcmdUb2RheS50b0lTT1N0cmluZygpLnNsaWNlKDAsMTApOwogICQoJ3Zlbl9mcm9tJykudmFsdWU9YXJnQWdvLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCk7CiAgaWYoJCgnZl90bycpKSAkKCdmX3RvJykudmFsdWU9YXJnVG9kYXkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTsgICAvLyBzb2xhcGEgRkxFWAogIGlmKCQoJ2ZfZnJvbScpKSAkKCdmX2Zyb20nKS52YWx1ZT1hcmdBZ28udG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTsKICByZW5kZXJBY2N0Q2ZnKFtdKTsgICAgICAvLyBvYmpldGl2by9mYWN0dXJhIHBvciBjdWVudGEgdmlzaWJsZXMgZGVzZGUgZWwgaW5pY2lvIChjb24gbG8gZ3VhcmRhZG8pCiAgcmVuZGVyUHJlY2lvUnVsZXMoKTsgICAgLy8gcmVnbGFzIGRlbCBhY3R1YWxpemFkb3IgZGUgcHJlY2lvcyBsaXN0YXMKICBhcHBseU1vZGUoKTsgLy8gbXVlc3RyYSBsYXMgcGVzdGHDsWFzIHNlZ8O6biAvZ2VzdGlvbiBvIC9wdWJsaWNpZGFkCn0KYXN5bmMgZnVuY3Rpb24gbG9hZENvbmZpZygpewogIHRyeXsKICAgIGNvbnN0IGM9YXdhaXQgYXBpKCcvYXBpL2Fkcy9jb25maWcnKTsgU1RBVEUuY2ZnPWM7CiAgICBpZigkKCdjZmdfbWFyZ2luJykpeyQoJ2NmZ19tYXJnaW4nKS52YWx1ZT1jLm1hcmdpbjskKCdjZmdfdGFyZ2V0JykudmFsdWU9Yy5hY29zVGFyZ2V0OyQoJ2NmZ19jbGlja3MnKS52YWx1ZT1jLm1pbkNsaWNrczskKCdjZmdfd2luZG93JykudmFsdWU9Yy53aW5kb3dEYXlzOwogICAgJCgnY2ZnX3NoaXAnKS52YWx1ZT1jLmZyZWVTaGlwVGhyZXNob2xkIT1udWxsP2MuZnJlZVNoaXBUaHJlc2hvbGQ6MzMwMDA7fQogICAgaWYoJCgndmVuX3RheCcpJiYhJCgndmVuX3RheCcpLnZhbHVlKSQoJ3Zlbl90YXgnKS52YWx1ZT0oYy5mYWN0dXJhUGN0IT1udWxsP2MuZmFjdHVyYVBjdDo1KTsgIC8vIGZhY3R1cmEgJSBnbG9iYWwKICAgIGNvbnN0IHRhZz0kKCdhdXRvdGFnJyk7dGFnLnRleHRDb250ZW50PSdBdXRvLXBhdXNhOiAnKyhjLmF1dG9QYXVzZT8nQUNUSVZBJzonRFJZLVJVTiAobm8gcGF1c2EpJyk7dGFnLmNsYXNzTmFtZT0nYXV0b3RhZyBwaWxsICcrKGMuYXV0b1BhdXNlPydwLXJlZCc6J3AtZ3JleScpOwogIH1jYXRjaChlKXt9Cn0KYXN5bmMgZnVuY3Rpb24gc2F2ZUNvbmZpZygpewogIHRyeXtjb25zdCBib2R5PXttYXJnaW46KyQoJ2NmZ19tYXJnaW4nKS52YWx1ZSxhY29zVGFyZ2V0OiskKCdjZmdfdGFyZ2V0JykudmFsdWUsbWluQ2xpY2tzOiskKCdjZmdfY2xpY2tzJykudmFsdWUsd2luZG93RGF5czorJCgnY2ZnX3dpbmRvdycpLnZhbHVlLGZyZWVTaGlwVGhyZXNob2xkOiskKCdjZmdfc2hpcCcpLnZhbHVlfTsKICBjb25zdCByPWF3YWl0IGFwaSgnL2FwaS9hZHMvY29uZmlnJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KGJvZHkpfSk7U1RBVEUuY2ZnPXIuY29uZmlnO3RvYXN0KCdDb25maWd1cmFjacOzbiBndWFyZGFkYScpO2xvYWRDYW1wYWlnbnMoKTt9CiAgY2F0Y2goZSl7dG9hc3QoJ0Vycm9yOiAnKyhlLmVycm9yfHxlKSk7fQp9CgovLyAtLS0tIENvc3RvcyAtLS0tCmZ1bmN0aW9uIHBpY2socm93LG5hbWVzKXtmb3IoY29uc3QgbiBvZiBuYW1lcyl7Zm9yKGNvbnN0IGsgaW4gcm93KXtpZihTdHJpbmcoaykudHJpbSgpLnRvTG93ZXJDYXNlKCk9PT1uKXJldHVybiByb3dba107fX1yZXR1cm4gdW5kZWZpbmVkO30KZnVuY3Rpb24gaW1wb3J0Q29zdHMoaW5wdXQsYWNjSWQsYWNjTmFtZSl7CiAgY29uc3QgZmlsZT1pbnB1dC5maWxlcyYmaW5wdXQuZmlsZXNbMF07aWYoIWZpbGUpcmV0dXJuOwogIGlmKHR5cGVvZiBYTFNYPT09J3VuZGVmaW5lZCcpe3RvYXN0KCdObyBjYXJnw7MgbGEgbGlicmVyw61hIGRlIEV4Y2VsJyk7cmV0dXJuO30KICBpZighYWNjSWQpe3RvYXN0KCdDYXNpbGxlcm8gc2luIGN1ZW50YScpO2lucHV0LnZhbHVlPScnO3JldHVybjt9CiAgY29uc3QgY250PSQoJ3Nsb3Rjb3VudC0nK2FjY0lkKTtpZihjbnQpY250LnRleHRDb250ZW50PSdsZXllbmRvIEV4Y2Vs4oCmJzsKICBjb25zdCByZWFkZXI9bmV3IEZpbGVSZWFkZXIoKTsKICByZWFkZXIub25sb2FkPWFzeW5jIGU9PnsKICAgIHRyeXsKICAgICAgY29uc3Qgd2I9WExTWC5yZWFkKGUudGFyZ2V0LnJlc3VsdCx7dHlwZTonYXJyYXknfSk7Y29uc3Qgd3M9d2IuU2hlZXRzWydTaGVldDEnXXx8d2IuU2hlZXRzW3diLlNoZWV0TmFtZXNbMF1dOwogICAgICAvLyBGaWxhcyBjb21vIEFSUkFZUyAocsOhcGlkbykgeSBtYXBlbyBkZSBjb2x1bW5hcyBVTkEgU09MQSBWRVogKGV2aXRhIHJlY29ycmVyIGNvbHVtbmFzIHBvciBjYWRhIGZpbGEpLgogICAgICBjb25zdCByb3dzPVhMU1gudXRpbHMuc2hlZXRfdG9fanNvbih3cyx7aGVhZGVyOjEsZGVmdmFsOicnfSk7CiAgICAgIGNvbnN0IEg9KHJvd3NbMF18fFtdKS5tYXAoeD0+U3RyaW5nKHg9PW51bGw/Jyc6eCkudHJpbSgpLnRvTG93ZXJDYXNlKCkpOwogICAgICBjb25zdCBpZHg9bmFtZXM9Pntmb3IoY29uc3QgbiBvZiBuYW1lcyl7Y29uc3QgaT1ILmluZGV4T2Yobik7aWYoaT49MClyZXR1cm4gaTt9cmV0dXJuIC0xO307CiAgICAgIGNvbnN0IGNJZD1pZHgoWydpdGVtX2lkJ10pLGNDb3N0PWlkeChbJ3ByZWNpbyBjb3N0byddKSxjQ1M9aWR4KFsnY29zdG8vZ2FzdG9zJ10pLGNTaD1pZHgoWydzaGlwcGluZyddKSxjQ29tPWlkeChbJ2Nvc3RvIHBvciB2ZW5kZXInXSksY0xUPWlkeChbJ2xpc3RpbmdfdHlwZV9pZCddKSxjTFA9aWR4KFsncHJlY2lvIGZpbmFsJ10pLGNNZz1pZHgoWydtYXJnZW4gZGUgZ2FuYW5jaWEnXSksY09mPWlkeChbJ29mZXJ0YSddKSxjVGk9aWR4KFsndGl0dWxvJywndMOtdHVsbycsJ3RpdGxlJywncHVibGljYWNpb24nLCdwdWJsaWNhY2nDs24nLCdub21icmUnXSksY1NrPWlkeChbJ2NvZGlnbyB1dGlsaXphZG8nLCdjw7NkaWdvIHV0aWxpemFkbycsJ2NvZGlnb191dGlsaXphZG8nLCdza3UnLCdjb2RpZ28nLCdjw7NkaWdvJywnY29kaWdvIHByb3ZlZWRvcicsJ2PDs2RpZ28gcHJvdmVlZG9yJywnc2t1IHByb3ZlZWRvciddKSxjUHI9aWR4KFsncHJvdmVlZG9yIHV0aWxpemFkbycsJ3Byb3ZlZWRvcl91dGlsaXphZG8nLCdwcm92ZWVkb3InLCdwcm92JywncHJvdmVlZG9yOiddKTsKICAgICAgaWYoY0lkPDApe3RvYXN0KCdObyBlbmNvbnRyw6kgbGEgY29sdW1uYSBpdGVtX2lkIGVuIGVsIEV4Y2VsJyk7aWYoY250KWNudC50ZXh0Q29udGVudD0n4oCUIGZhbHRhIGNvbHVtbmEgaXRlbV9pZCc7cmV0dXJuO30KICAgICAgLy8gRm9ybWF0byBDT0xVTU5BUiAoYXJyYXlzLCBzaW4gcmVwZXRpciBsb3Mgbm9tYnJlcyBkZSBjb2x1bW5hIGVuIGNhZGEgZmlsYSkg4oaSIHBheWxvYWQgfm1pdGFkLCBzdWJlIG3DoXMgcsOhcGlkby4KICAgICAgLy8gT3JkZW4gZmlqbzogW2l0ZW1faWQsIGNvc3QsIGNvc3RTaGlwLCBzaGlwLCBjb21taXNzaW9uLCBsaXN0aW5nVHlwZSwgbGlzdFByaWNlLCBtYXJnaW5MaXN0LCBvZmVydGEsIHRpdGxlLCBza3UsIHByb3ZlZWRvcl0KICAgICAgY29uc3QgcmU9L15NTEFcZCsvaTtjb25zdCBpdGVtcz1bXTsKICAgICAgZm9yKGxldCByPTE7cjxyb3dzLmxlbmd0aDtyKyspe2NvbnN0IHJvdz1yb3dzW3JdO2lmKCFyb3cpY29udGludWU7Y29uc3QgaXRlbV9pZD1TdHJpbmcocm93W2NJZF09PW51bGw/Jyc6cm93W2NJZF0pLnRyaW0oKTtpZighcmUudGVzdChpdGVtX2lkKSljb250aW51ZTsKICAgICAgICBpdGVtcy5wdXNoKFtpdGVtX2lkLHJvd1tjQ29zdF0scm93W2NDU10scm93W2NTaF0scm93W2NDb21dLHJvd1tjTFRdLHJvd1tjTFBdLHJvd1tjTWddLGNPZj49MD9yb3dbY09mXTonJyxjVGk+PTA/cm93W2NUaV06JycsY1NrPj0wP3Jvd1tjU2tdOicnLGNQcj49MD9yb3dbY1ByXTonJ10pO30KICAgICAgaWYoIWl0ZW1zLmxlbmd0aCl7dG9hc3QoJ05vIGVuY29udHLDqSBmaWxhcyBjb24gaXRlbV9pZCB2w6FsaWRvJyk7aWYoY250KWNudC50ZXh0Q29udGVudD0n4oCUIHNpbiBmaWxhcyB2w6FsaWRhcyc7cmV0dXJuO30KICAgICAgLy8gU3ViaWRhIGNvbiBiYXJyYSBkZSBwcm9ncmVzbyByZWFsIChYSFIgcmVwb3J0YSBlbCAlIGRlbCB1cGxvYWQ7IGZldGNoIG5vIHB1ZWRlKS4KICAgICAgY29uc3QgcGF5bG9hZD1KU09OLnN0cmluZ2lmeSh7aXRlbXMsdjoyLGFjY291bnRfaWQ6YWNjSWQscmVwbGFjZTp0cnVlfSk7CiAgICAgIGNvbnN0IGJhcj0kKCdzbG90YmFyLScrYWNjSWQpLCBiYXJJPWJhcj9iYXIucXVlcnlTZWxlY3RvcignaScpOm51bGw7CiAgICAgIGlmKGJhciliYXIuc3R5bGUuZGlzcGxheT0nYmxvY2snOyBpZihiYXJJKWJhckkuc3R5bGUud2lkdGg9JzAlJzsKICAgICAgY29uc3QgdG90YWw9aXRlbXMubGVuZ3RoOwogICAgICB1cGxvYWRDb3N0cyhwYXlsb2FkLHsKICAgICAgICBvbnByb2dyZXNzOihwY3QpPT57IGlmKGJhckkpYmFySS5zdHlsZS53aWR0aD1wY3QrJyUnOyBpZihjbnQpY250LnRleHRDb250ZW50PSdzdWJpZW5kbyAnK3BjdCsnJSAoJyt0b3RhbC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnKSc7IH0sCiAgICAgICAgb251cGxvYWQ6KCk9PnsgaWYoYmFySSliYXJJLnN0eWxlLndpZHRoPScxMDAlJzsgaWYoY250KWNudC50ZXh0Q29udGVudD0ncHJvY2VzYW5kbyBlbiBlbCBzZXJ2aWRvcuKApic7IH0sCiAgICAgICAgb25kb25lOihyZXMpPT57IGlmKGJhciliYXIuc3R5bGUuZGlzcGxheT0nbm9uZSc7IHRvYXN0KCdDb3N0b3MgaW1wb3J0YWRvcyAoJysoYWNjTmFtZXx8KHJlcyYmcmVzLmFjY291bnQpfHwnY3VlbnRhJykrJyk6ICcrKChyZXMmJnJlcy5pbXBvcnRlZCl8fDApKTsgbG9hZENvc3RTdGF0dXMoKTsgfSwKICAgICAgICBvbmVycm9yOihtc2cpPT57IGlmKGJhciliYXIuc3R5bGUuZGlzcGxheT0nbm9uZSc7IGlmKGNudCljbnQudGV4dENvbnRlbnQ9J+KAlCBlcnJvcic7IHRvYXN0KCdFcnJvciBpbXBvcnRhbmRvOiAnK21zZyk7IH0sCiAgICAgIH0pOwogICAgfWNhdGNoKGVycil7dG9hc3QoJ0Vycm9yIGltcG9ydGFuZG86ICcrKGVyci5lcnJvcnx8ZXJyLm1lc3NhZ2V8fGVycikpO2lmKGNudCljbnQudGV4dENvbnRlbnQ9J+KAlCBlcnJvcic7fQogICAgaW5wdXQudmFsdWU9Jyc7CiAgfTsKICByZWFkZXIucmVhZEFzQXJyYXlCdWZmZXIoZmlsZSk7Cn0KLy8gU3ViZSBlbCBwYXlsb2FkIGNvbiBYSFIgcGFyYSByZXBvcnRhciBlbCAlIGRlIGF2YW5jZSBkZWwgdXBsb2FkIGVuIGxhIGJhcnJhLgpmdW5jdGlvbiB1cGxvYWRDb3N0cyhwYXlsb2FkLGNiKXsKICBjb25zdCB4aHI9bmV3IFhNTEh0dHBSZXF1ZXN0KCk7CiAgeGhyLm9wZW4oJ1BPU1QnLCcvYXBpL2Fkcy9jb3N0cycpOwogIHhoci5zZXRSZXF1ZXN0SGVhZGVyKCdDb250ZW50LVR5cGUnLCdhcHBsaWNhdGlvbi9qc29uJyk7CiAgeGhyLnVwbG9hZC5vbnByb2dyZXNzPWV2PT57IGlmKGV2Lmxlbmd0aENvbXB1dGFibGUmJmNiLm9ucHJvZ3Jlc3MpeyBjYi5vbnByb2dyZXNzKE1hdGgucm91bmQoZXYubG9hZGVkL2V2LnRvdGFsKjEwMCkpOyB9IH07CiAgeGhyLnVwbG9hZC5vbmxvYWQ9KCk9PnsgaWYoY2Iub251cGxvYWQpY2Iub251cGxvYWQoKTsgfTsKICB4aHIub25sb2FkPSgpPT57CiAgICBpZih4aHIuc3RhdHVzPT09NDAxKXsgbG9jYXRpb24uaHJlZj0nLyc7IHJldHVybjsgfQogICAgbGV0IGQ9e307IHRyeXsgZD1KU09OLnBhcnNlKHhoci5yZXNwb25zZVRleHR8fCd7fScpOyB9Y2F0Y2goZSl7fQogICAgaWYoeGhyLnN0YXR1cz49MjAwJiZ4aHIuc3RhdHVzPDMwMCl7IGlmKGNiLm9uZG9uZSljYi5vbmRvbmUoZCk7IH0KICAgIGVsc2UgeyBpZihjYi5vbmVycm9yKWNiLm9uZXJyb3IoZC5lcnJvcj8odHlwZW9mIGQuZXJyb3I9PT0nc3RyaW5nJz9kLmVycm9yOkpTT04uc3RyaW5naWZ5KGQuZXJyb3IpKTooJ0hUVFAgJyt4aHIuc3RhdHVzKSk7IH0KICB9OwogIHhoci5vbmVycm9yPSgpPT57IGlmKGNiLm9uZXJyb3IpY2Iub25lcnJvcignZXJyb3IgZGUgcmVkJyk7IH07CiAgeGhyLnNlbmQocGF5bG9hZCk7Cn0KYXN5bmMgZnVuY3Rpb24gbG9hZENvc3RTdGF0dXMoKXsKICB0cnl7Y29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL2Nvc3RzJyk7CiAgICBjb25zdCBieT1BcnJheS5pc0FycmF5KGQuYnlfYWNjb3VudCk/ZC5ieV9hY2NvdW50OltdOwogICAgY29uc3QgbkFjYz1ieS5maWx0ZXIoeD0+eC5jb3VudD4wKS5sZW5ndGg7CiAgICBjb25zdCBwZXJzVGFnPWQucGVyc2lzdGVudD8nIMK3IDxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1ncmVlbikiPvCfkr4gcGVyc2lzdGVudGU8L3NwYW4+JzonIMK3IDxzcGFuIHN0eWxlPSJjb2xvcjp2YXIoLS1hbWJlcikiIHRpdGxlPSJDb25maWd1csOhIERBVEFfRElSIGEgdW4gZGlzY28gZGUgUmVuZGVyIHBhcmEgbm8gcGVyZGVyIGxvcyBkYXRvcyBlbiBjYWRhIGRlcGxveSI+4pqg77iPIGRhdG9zIHRlbXBvcmFsZXM8L3NwYW4+JzsKICAgICQoJ2Nvc3RzdGF0dXMnKS5pbm5lckhUTUw9KGQudG90YWw/KCfinIUgPGI+JytkLnRvdGFsLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2I+IHByb2R1Y3RvcyDCtyAnK25BY2MrJyBkZSAnKyhBQ0NPVU5UUy5sZW5ndGh8fDYpKycgY3VlbnRhcyBjYXJnYWRhcycpOifimqDvuI8gU2luIGNvc3RvczogaW1wb3J0w6EgZWwgX0NPTVBMRVRPIGRlIGNhZGEgY3VlbnRhLicpK3BlcnNUYWc7CiAgICAvLyBSZXNldGVvIGxvcyBjb250YWRvcmVzIGRlIGNhZGEgY2FzaWxsZXJvIHkgbHVlZ28gbG9zIGxsZW5vLgogICAgQUNDT1VOVFMuZm9yRWFjaChhPT57Y29uc3QgYz0kKCdzbG90Y291bnQtJythLmlkKTtpZihjKWMudGV4dENvbnRlbnQ9J+KAlCBzaW4gY29zdG9zJzt9KTsKICAgIGJ5LmZvckVhY2goeD0+e2NvbnN0IGM9JCgnc2xvdGNvdW50LScreC5hY2NvdW50X2lkKTtpZihjKWMuaW5uZXJIVE1MPSfinIUgPGI+Jyt4LmNvdW50LnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2I+IHByb2R1Y3Rvcyc7fSk7CiAgfWNhdGNoKGUpe30KfQoKLy8gLS0tLSBSRU5UQUJJTElEQUQgLS0tLQpsZXQgVlNPUlQ9e2tleTonbmV0JyxkaXI6MX07CmZ1bmN0aW9uIHN0YXR1c0xhYmVsKHMpe2NvbnN0IG09e3BlbmRpbmc6J1BlbmRpZW50ZScsaGFuZGxpbmc6J1ByZXBhcmFuZG8nLHJlYWR5X3RvX3NoaXA6J0xpc3RvIHAvZW52aWFyJyxyZWFkeV90b19wcmludDonTGlzdG8gcC9pbXByaW1pcicsc2hpcHBlZDonRW52aWFkbycsZGVsaXZlcmVkOidFbnRyZWdhZG8nLG5vdF9kZWxpdmVyZWQ6J05vIGVudHJlZ2FkbycsY2FuY2VsbGVkOidDYW5jZWxhZG8nLHRvX2JlX2FncmVlZDonQSBjb252ZW5pcid9O3JldHVybiBtW3NdfHwoc3x8J+KAlCcpO30KZnVuY3Rpb24gc3RhdHVzUGlsbChzKXtjb25zdCBjbHM9KHtkZWxpdmVyZWQ6J3AtZ3JlZW4nLHNoaXBwZWQ6J3AtYmx1ZScscmVhZHlfdG9fc2hpcDoncC1hbWJlcicscmVhZHlfdG9fcHJpbnQ6J3AtYW1iZXInLGhhbmRsaW5nOidwLWFtYmVyJyxwZW5kaW5nOidwLWdyZXknLGNhbmNlbGxlZDoncC1yZWQnLG5vdF9kZWxpdmVyZWQ6J3AtcmVkJ30pW3NdfHwncC1ncmV5JztyZXR1cm4gJzxzcGFuIGNsYXNzPSJwaWxsICcrY2xzKyciPicrc3RhdHVzTGFiZWwocykrJzwvc3Bhbj4nO30KZnVuY3Rpb24gc29ydFZlbihrKXsgaWYoVlNPUlQua2V5PT09aylWU09SVC5kaXIqPS0xOyBlbHNle1ZTT1JULmtleT1rO1ZTT1JULmRpcj0oaz09PSd0aXRsZSd8fGs9PT0nc3RhdHVzJ3x8az09PSdzdG9jaycpPzE6LTE7fSBpZihWRU4pcmVuZGVyVmVudGFzKFZFTik7IH0KZnVuY3Rpb24gdXBkYXRlVmVuQXJyb3dzKCl7ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnI3ZlblRhYmxlIHRoZWFkIHRoJykuZm9yRWFjaCh0aD0+e2NvbnN0IGE9dGgucXVlcnlTZWxlY3RvcignLmFycicpO2lmKGEpYS5yZW1vdmUoKTtpZih0aC5kYXRhc2V0Lms9PT1WU09SVC5rZXkpe2NvbnN0IHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpO3MuY2xhc3NOYW1lPSdhcnInO3MudGV4dENvbnRlbnQ9VlNPUlQuZGlyPjA/JyDilrInOicg4pa8Jzt0aC5hcHBlbmRDaGlsZChzKTt9fSk7fQpmdW5jdGlvbiBkb3dubG9hZFZlbnRhc1hsc3goKXsKICBpZighVkVOfHwhVkVOLnZlbnRhc3x8IVZFTi52ZW50YXMubGVuZ3RoKXt0b2FzdCgnQW5hbGl6w6EgdmVudGFzIHByaW1lcm8nKTtyZXR1cm47fQogIGNvbnN0IGRhdGE9VkVOLnZlbnRhcy5tYXAodj0+e2NvbnN0IG89e0ZlY2hhOnYuZGF0ZSxOX3ZlbnRhOnYucGFja19pZHx8di5vcmRlcl9pZHx8Jyd9O2lmKFZFTi5hbGwpby5DdWVudGE9di5hY2NvdW50X25hbWV8fCcnO3JldHVybiBPYmplY3QuYXNzaWduKG8se1B1YmxpY2FjaW9uOnYudGl0bGUsSXRlbUlEOnYuaXRlbV9pZCxDb2RfU0tVOnYuc2t1fHwnJyxFc3RhZG9fZW52aW86c3RhdHVzTGFiZWwodi5zdGF0dXMpLFN0b2NrOnYuc3RvY2s/J1PDrSc6JycsQ2FudGlkYWQ6di5xdHl8fDEsUHJlY2lvOnYucmV2ZW51ZSxDb21pc2lvbjp2LmZlZSxFbnZpbzp2LmVudmlvLEltcHVlc3RvczpNYXRoLnJvdW5kKHYudGF4fHwwKSxRdWVkb19lbl9jdWVudGE6TWF0aC5yb3VuZCh2LnF1ZWRhKSxDb3N0bzp2LmNvc3QsRmFjdHVyYTpNYXRoLnJvdW5kKHYuZmFjdHVyYXx8MCksR2FuYW5jaWE6di5uZXQ9PW51bGw/Jyc6TWF0aC5yb3VuZCh2Lm5ldCksR2FuYW5jaWFfc2luX2ZsZXg6di5uZXRfc2luX2ZsZXg9PW51bGw/Jyc6TWF0aC5yb3VuZCh2Lm5ldF9zaW5fZmxleCksTWFyZ2VuX3BjdDp2Lm1hcmdpblBjdD09bnVsbD8nJzordi5tYXJnaW5QY3QudG9GaXhlZCgxKSxDdW90YXM6di5jdW90YXN8fDB9KTt9KTsKICBjb25zdCB3cz1YTFNYLnV0aWxzLmpzb25fdG9fc2hlZXQoZGF0YSk7Y29uc3Qgd2I9WExTWC51dGlscy5ib29rX25ldygpO1hMU1gudXRpbHMuYm9va19hcHBlbmRfc2hlZXQod2Isd3MsJ1ZlbnRhcycpOwogIFhMU1gud3JpdGVGaWxlKHdiLCd2ZW50YXNfJysoVkVOLmFsbD8nVE9EQVMnOigkKCdhY2NvdW50Jykuc2VsZWN0ZWRPcHRpb25zWzBdPyQoJ2FjY291bnQnKS5zZWxlY3RlZE9wdGlvbnNbMF0udGV4dENvbnRlbnQuc3BsaXQoJyAnKVswXTonY3VlbnRhJykpKydfJysoVkVOLmZyb218fCcnKSsnXycrKFZFTi50b3x8JycpKycueGxzeCcpOwp9Ci8vIEF0YWpvcyBkZSBmZWNoYTogMCA9IGhveSwgMSA9IGF5ZXIgKGhvcmEgYXJnZW50aW5hIFVUQy0zKS4gRmlqYSBEZXNkZT1IYXN0YSB5IGJ1c2NhLgpmdW5jdGlvbiBzZXRWZW5SYW5nbyhkaWFzQXRyYXMpewogIGNvbnN0IGQ9bmV3IERhdGUoRGF0ZS5ub3coKS0zKjM2MDAqMTAwMC0oZGlhc0F0cmFzfHwwKSo4NjQwMDAwMCkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTsKICBpZigkKCd2ZW5fZnJvbScpKSAkKCd2ZW5fZnJvbScpLnZhbHVlPWQ7CiAgaWYoJCgndmVuX3RvJykpICQoJ3Zlbl90bycpLnZhbHVlPWQ7CiAgbG9hZFZlbnRhcygpOwp9CmFzeW5jIGZ1bmN0aW9uIGxvYWRWZW50YXMoKXsKICBjb25zdCBpZD0kKCdhY2NvdW50JykudmFsdWU7aWYoIWlkKXt0b2FzdCgnRWxlZ8OtIHVuYSBjdWVudGEnKTtyZXR1cm47fQogIGNvbnN0IGZyb209JCgndmVuX2Zyb20nKS52YWx1ZSwgdG89JCgndmVuX3RvJykudmFsdWU7CiAgY29uc3QgaXNBbGw9KGlkPT09J2FsbCcpOwogICQoJ3Zlbl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjE3IiBjbGFzcz0ibG9hZGluZyI+JysoaXNBbGw/J1RyYXllbmRvIHZlbnRhcyBkZSA8Yj50b2RhcyBsYXMgY3VlbnRhczwvYj4g4oCUIHB1ZWRlIHRhcmRhciBiYXN0YW50ZeKApic6J1RyYXllbmRvIHZlbnRhcyB5IGVudsOtb3MgcmVhbGVzIGRlIE1lcmNhZG8gTGlicmXigKYgKHB1ZWRlIHRhcmRhciB1bm9zIHNlZ3VuZG9zKScpKyc8L3RkPjwvdHI+JzsKICB0cnl7CiAgICBjb25zdCB1cmw9aXNBbGw/KCcvYXBpL2Fkcy92ZW50YXMtYWxsPycrKGZyb20/KCdmcm9tPScrZnJvbSk6JycpKyh0bz8oJyZ0bz0nK3RvKTonJykpOignL2FwaS9hZHMvdmVudGFzP2FjY291bnRfaWQ9JytpZCsoZnJvbT8oJyZmcm9tPScrZnJvbSk6JycpKyh0bz8oJyZ0bz0nK3RvKTonJykpOwogICAgY29uc3QgZD1hd2FpdCBhcGkodXJsKTtWRU49ZDsKICAgIGlmKGQudGF4UGN0IT1udWxsJiYkKCd2ZW5fdGF4JykudmFsdWU9PT0nJykkKCd2ZW5fdGF4JykudmFsdWU9ZC50YXhQY3Q7CiAgICByZW5kZXJWZW50YXMoZCk7CiAgfWNhdGNoKGUpeyQoJ3Zlbl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjE3IiBjbGFzcz0ibG9hZGluZyI+RXJyb3I6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkrJzwvdGQ+PC90cj4nO30KfQpmdW5jdGlvbiByZW5kZXJWZW50YXMoZCl7CiAgaWYoIWR8fCFkLnJlc3VtZW4pe3JldHVybjt9CiAgY29uc3Qgcj1kLnJlc3VtZW47CiAgY29uc3QgdnQ9JCgndmVuVGFibGUnKTtpZih2dCl2dC5jbGFzc0xpc3QudG9nZ2xlKCdoaWRlLWFjYycsIWQuYWxsKTsgIC8vIG11ZXN0cmEgbGEgY29sdW1uYSBDdWVudGEgc29sbyBlbiAiVG9kYXMgbGFzIGN1ZW50YXMiCiAgY29uc3QgbUNscz1yLm1hcmdpbj09bnVsbD8nJzooci5tYXJnaW4+PTEwPydnb29kJzooci5tYXJnaW4+PTU/J3dhcm4nOidiYWQnKSk7CiAgLy8gVmVudGFzIFNJTiBDT1NUTzogc3UgcHJvZHVjdG8gbm8gZXN0w6EgZW4gZWwgX0NPTVBMRVRPIGltcG9ydGFkbyAoY29zdD09bnVsbCDihpIgwqtzL2Nvc3RvwrspLgogIGNvbnN0IHNpbkNvc3RvPShkLnZlbnRhc3x8W10pLmZpbHRlcih2PT52LmNvc3Q9PW51bGwpLmxlbmd0aDsKICBjb25zdCB0aWxlcz1bCiAgICBbJ1ZlbnRhcycsKHIub3JkZXJzIT1udWxsP3Iub3JkZXJzOnIuY291bnQpLCcnXSwKICAgIFsnRmFjdHVyYWNpw7NuICgnK3IuZGF5cysnZCknLGZtdE1vbmV5KHIuZmFjdHVyYWNpb24pLCcnXSwKICAgIFsnUXVlZMOzIGVuIGN1ZW50YScsZm10TW9uZXkoci5xdWVkYVRvdGFsfHwwKSwnJ10sCiAgICBbJ0dhbmFuY2lhIHJlYWwnLGZtdE1vbmV5KHIuZ2FuYW5jaWEpLHIuZ2FuYW5jaWE+PTA/J2dvb2QnOidiYWQnXSwKICAgIFsnTWFyZ2VuIHJlYWwnLHIubWFyZ2luPT1udWxsPyfigJQnOmZtdFBjdChyLm1hcmdpbiksbUNsc10sCiAgICBbJ0EgcMOpcmRpZGEnLHIucGVyZGlkYSsoci5wZXJkaWRhPycg4pqg77iPJzonJyksci5wZXJkaWRhPydiYWQnOidnb29kJ10sCiAgICBbJ1NpbiBjb3N0bycsc2luQ29zdG8rKHNpbkNvc3RvPycg8J+Pt++4jyc6JycpLHNpbkNvc3RvPyd3YXJuJzonZ29vZCddCiAgXTsKICAkKCd2ZW5fa3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAodD0+JzxkaXYgY2xhc3M9ImtwaSAnK3RbMl0rJyI+PGRpdiBjbGFzcz0iayI+Jyt0WzBdKyc8L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3RbMV0rJzwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogIC8vIFBvYmxhciBlbCBmaWx0cm8gcG9yIGN1ZW50YSBjb24gbGFzIGN1ZW50YXMgcHJlc2VudGVzIGVuIGxvIHRyYcOtZG8gKHNvbG8gY2FtYmlhIHNpIGRpZmllcmUpLgogIHtjb25zdCBzZWw9JCgndmVuX2FjY3RfZmlsdGVyJyk7CiAgIGlmKHNlbCl7Y29uc3QgbmFtZXM9Wy4uLm5ldyBTZXQoKGQudmVudGFzfHxbXSkubWFwKHY9PnYuYWNjb3VudF9uYW1lfHwnJykuZmlsdGVyKEJvb2xlYW4pKV0uc29ydCgoYSxiKT0+YS5sb2NhbGVDb21wYXJlKGIpKTsKICAgICBjb25zdCB3YW50PSc8b3B0aW9uIHZhbHVlPSIiPlRvZGFzPC9vcHRpb24+JytuYW1lcy5tYXAobj0+JzxvcHRpb24gdmFsdWU9IicrZXNjKG4pKyciPicrZXNjKG4pKyc8L29wdGlvbj4nKS5qb2luKCcnKTsKICAgICBpZihzZWwuZGF0YXNldC5idWlsdCE9PXdhbnQpe2NvbnN0IGN1cj1zZWwudmFsdWU7c2VsLmlubmVySFRNTD13YW50O3NlbC5kYXRhc2V0LmJ1aWx0PXdhbnQ7aWYobmFtZXMuaW5jbHVkZXMoY3VyKSlzZWwudmFsdWU9Y3VyO30KICAgfX0KICBjb25zdCBoaWRkZW5Ob3RlPXIuaGlkZGVuPygnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjRweCI+8J+aqyAnK3IuaGlkZGVuKycgb3JkZW4nKyhyLmhpZGRlbj4xPydlcyc6JycpKycgb2N1bHRhJysoci5oaWRkZW4+MT8ncyc6JycpKycgKGNhbmNlbGFkYXMgbyBjb24gZGV2b2x1Y2nDs24gYWwgY29tcHJhZG9yKTwvZGl2PicpOicnOwogIGNvbnN0IHNhdmVkTm90ZT0oci5zYXZlZCE9bnVsbHx8ci5mcmVzaCE9bnVsbCk/KCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6NHB4Ij7wn5K+ICcrKHIuc2F2ZWR8fDApKycgY29uIGNvc3RvIGNvbmdlbGFkbyDCtyAnKyhyLmZyZXNofHwwKSsnIG51ZXZhJysoKHIuZnJlc2h8fDApPT09MT8nJzoncycpKycgZW4gZWwgbGVkZ2VyPC9kaXY+Jyk6Jyc7CiAgY29uc3QgY29zdEZpeE5vdGU9KHIuY29zdEZpeGVkPjApPygnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjRweCI+8J+UhCAnK3IuY29zdEZpeGVkKycgdmVudGEnKyhyLmNvc3RGaXhlZD09PTE/Jyc6J3MnKSsnIHRvbWFyb24gc3UgY29zdG8gcmVhbCBkZSBsYSBsaXN0YSBhY3R1YWxpemFkYSAoYW50ZXMgcXVlZGFiYW4gwqtzL2Nvc3RvwrspPC9kaXY+Jyk6Jyc7CiAgY29uc3QgdGF4Tm90ZT1yLnRheFJlYWwhPW51bGw/KCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6NHB4Ij7wn6e+IEltcHVlc3RvIHJlYWwgZGUgTUwgZW4gJytyLnRheFJlYWwrJyBkZSAnKyhyLm9yZGVyc3x8ci5jb3VudCkrJyDDs3JkZW5lcycrKHIudGF4UmVhbDwoci5vcmRlcnN8fHIuY291bnQpPygnIMK3IGVuIGVsIHJlc3RvIE1MIG5vIGluZm9ybcOzIGltcHVlc3RvIChxdWVkYSAkMCknKTonJykrJyDCtyBsYSBmYWN0dXJhICglIG1lbnN1YWwpIHZhIGFwYXJ0ZSwgZW4gbGEgY29sdW1uYSBGYWN0dXJhPC9kaXY+Jyk6Jyc7CiAgY29uc3Qgc2hpcE5vdGU9ci5zaGlwRmV0Y2hlZCE9bnVsbD8oJzxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjExcHg7bWFyZ2luLXRvcDo2cHgiPvCfmpogRW52w61vIHJlYWwgZGUgTUwgZW4gJytyLnNoaXBGZXRjaGVkKycgZGUgJysoci5vcmRlcnN8fHIuY291bnQpKycgw7NyZGVuZXMnKyhyLnNoaXBGZXRjaGVkPChyLm9yZGVyc3x8ci5jb3VudCk/JyDCtyBlbCByZXN0byB1c2EgbGEgZXN0aW1hY2nDs24gZGVsIEV4Y2VsJzonJykrJzwvZGl2PicpOicnOwogICQoJ3Zlbl9wcm9ncmVzc19jYXJkJykuc3R5bGUuZGlzcGxheT0nYmxvY2snOwogICQoJ3Zlbl9wcm9ncmVzcycpLmlubmVySFRNTD0nPGRpdiBzdHlsZT0iZm9udC1zaXplOjEycHgiPjxiPicrKHIub3JkZXJzfHxyLmNvdW50fHwwKSsnPC9iPiB2ZW50YXMgwrcgcGVyw61vZG8gJytlc2MoZC5mcm9tfHwnJykrJyBhICcrZXNjKGQudG98fCcnKSsnIMK3IHVuaWRhZGVzOiAnKyhyLnVuaWRhZGVzfHwwKSsnPC9kaXY+JytzYXZlZE5vdGUrY29zdEZpeE5vdGUrdGF4Tm90ZStoaWRkZW5Ob3RlK3NoaXBOb3RlOwogIGxldCByb3dzPShkLnZlbnRhc3x8W10pLnNsaWNlKCk7CiAgY29uc3Qgb3E9KCgkKCd2ZW5fb3JkZXInKSYmJCgndmVuX29yZGVyJykudmFsdWUpfHwnJykudHJpbSgpOwogIGlmKG9xKXsgcm93cz1yb3dzLmZpbHRlcih2PT5TdHJpbmcodi5wYWNrX2lkfHwnJykuaW5jbHVkZXMob3EpfHxTdHJpbmcodi5vcmRlcl9pZHx8JycpLmluY2x1ZGVzKG9xKSk7IH0KICBjb25zdCBhZj0oKCQoJ3Zlbl9hY2N0X2ZpbHRlcicpJiYkKCd2ZW5fYWNjdF9maWx0ZXInKS52YWx1ZSl8fCcnKS50cmltKCk7CiAgaWYoYWYpeyByb3dzPXJvd3MuZmlsdGVyKHY9PlN0cmluZyh2LmFjY291bnRfbmFtZXx8JycpPT09YWYpOyB9CiAgaWYoJCgndmVuX29ubHlfc2luY29zdG8nKSYmJCgndmVuX29ubHlfc2luY29zdG8nKS5jaGVja2VkKXsgcm93cz1yb3dzLmZpbHRlcih2PT52LmNvc3Q9PW51bGwpOyB9CiAgY29uc3Qgaz1WU09SVC5rZXksZGlyPVZTT1JULmRpcjsKICByb3dzLnNvcnQoKGEsYik9PntsZXQgeD1hW2tdLHk9YltrXTtpZihrPT09J3RpdGxlJ3x8az09PSdzdGF0dXMnfHxrPT09J2FjY291bnRfbmFtZSd8fGs9PT0nc2t1Jyl7eD1TdHJpbmcoeHx8JycpO3k9U3RyaW5nKHl8fCcnKTtyZXR1cm4gZGlyKngubG9jYWxlQ29tcGFyZSh5KTt9aWYoaz09PSdzdG9jaycpe3JldHVybiBkaXIqKCh4PzE6MCktKHk/MTowKSk7fXg9KHg9PW51bGw/LUluZmluaXR5OngpO3k9KHk9PW51bGw/LUluZmluaXR5OnkpO3JldHVybiBkaXIqKHgteSk7fSk7CiAgLy8gQWdydXBhciBDQVJSSVRPUzogbG9zIMOtdGVtcyBkZWwgbWlzbW8gcGFxdWV0ZSBxdWVkYW4ganVudG9zICh1bm8gZGViYWpvIGRlbCBvdHJvKSwgZW4gbGEgcG9zaWNpw7NuIGRlbCBwcmltZXJvLgogIHtjb25zdCBfc2Vlbj17fSxfZz1bXTtmb3IoY29uc3QgdiBvZiByb3dzKXtjb25zdCBwaz12LnBhY2tfaWR8fHYub3JkZXJfaWQ7aWYoX3NlZW5bcGtdKWNvbnRpbnVlO19zZWVuW3BrXT0xO2Zvcihjb25zdCB4IG9mIHJvd3Mpe2lmKCh4LnBhY2tfaWR8fHgub3JkZXJfaWQpPT09cGspX2cucHVzaCh4KTt9fXJvd3M9X2c7fQogIHVwZGF0ZVZlbkFycm93cygpOwogIGlmKCFyb3dzLmxlbmd0aCl7JCgndmVuX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTciIGNsYXNzPSJlbXB0eSI+Jysob3E/J05pbmd1bmEgdmVudGEgY29uIGVzZSBuw7ptZXJvLic6J1NpbiB2ZW50YXMgZW4gZWwgcGVyw61vZG8uJykrJzwvdGQ+PC90cj4nO3JldHVybjt9CiAgJCgndmVuX2JvZHknKS5pbm5lckhUTUw9cm93cy5tYXAodj0+e2NvbnN0IGxvc3M9di5uZXQhPW51bGwmJnYubmV0PDA7CiAgICByZXR1cm4gJzx0ciBzdHlsZT0iJysobG9zcz8nYmFja2dyb3VuZDp2YXIoLS1yZWRiZyk7Jzoodi5wYWNrPydiYWNrZ3JvdW5kOiNmM2YwZmY7JzonJykpKyh2LnBhY2s/J2JvcmRlci1sZWZ0OjNweCBzb2xpZCAjYTc4YmZhOyc6JycpKyciPicrCiAgICAgICc8dGQgY2xhc3M9Im5hbWUiPicrKHYucGFjaz8nPHNwYW4gdGl0bGU9IlZlbnRhIGVuIGNhcnJpdG86IGNvbXBhcnRlIGVsIGVudsOtbyBjb24gb3Ryb3MgcHJvZHVjdG9zLiBFbCBlbnbDrW8gdmEgZW50ZXJvIGVuIGVsIHByb2R1Y3RvIGRlIG1heW9yIHZhbG9yIGRlbCBjYXJyaXRvLiIgc3R5bGU9ImRpc3BsYXk6aW5saW5lLWJsb2NrO2JhY2tncm91bmQ6dmFyKC0tYmx1ZWJnKTtjb2xvcjp2YXIoLS1ibHVlKTtmb250LXNpemU6MTBweDtmb250LXdlaWdodDo3MDA7cGFkZGluZzoxcHggNnB4O2JvcmRlci1yYWRpdXM6OHB4O21hcmdpbi1yaWdodDo1cHgiPvCfm5IgY2Fycml0bzwvc3Bhbj4nOicnKStlc2Modi50aXRsZXx8di5pdGVtX2lkKSsnPHNwYW4gY2xhc3M9ImlkIj4nKyh2Lml0ZW1faWR8fCcnKSsnIMK3ICcrKHYuZGF0ZXx8JycpKycgwrcgVmVudGEgIycrKHYucGFja19pZHx8di5vcmRlcl9pZHx8JycpKyc8L3NwYW4+PC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJhY2NvbCI+Jytlc2Modi5hY2NvdW50X25hbWV8fCcnKSsnPC90ZD4nKwogICAgICAnPHRkPicrc3RhdHVzUGlsbCh2LnN0YXR1cykrJzwvdGQ+JysKICAgICAgJzx0ZD4nKyh2LnN0b2NrPyc8c3BhbiBjbGFzcz0icGlsbCBwLWFtYmVyIj5Tw608L3NwYW4+JzonPHNwYW4gY2xhc3M9Im11dGVkIj7igJQ8L3NwYW4+JykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyh2LnF0eXx8MSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHYucmV2ZW51ZSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+4oiSJytmbXRNb25leSh2LmZlZSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysodi5lbnZpbz8oJ+KIkicrZm10TW9uZXkodi5lbnZpbykpOifigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyh2LnRheD8oJ+KIkicrZm10TW9uZXkodi50YXgpKToodi50YXhSZWFsPT09ZmFsc2U/JzxzcGFuIGNsYXNzPSJtdXRlZCIgdGl0bGU9Ik1MIG5vIGluZm9ybcOzIGltcHVlc3RvIGVuIGVzdGEgb3JkZW4iPuKAlDwvc3Bhbj4nOickMCcpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0gYiI+JytmbXRNb25leSh2LnF1ZWRhKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyh2LmNvc3Q9PW51bGw/JzxzcGFuIGNsYXNzPSJtdXRlZCI+cy9jb3N0bzwvc3Bhbj4nOign4oiSJytmbXRNb25leSh2LmNvc3QpKSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysodi5mYWN0dXJhPygn4oiSJytmbXRNb25leSh2LmZhY3R1cmEpKTon4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iZm9udC13ZWlnaHQ6ODAwO2NvbG9yOicrKHYubmV0PT1udWxsPyd2YXIoLS1tdXQpJzoodi5uZXQ+PTA/J3ZhcigtLWdyZWVuKSc6J3ZhcigtLXJlZCknKSkrJyI+Jysodi5uZXQ9PW51bGw/J+KAlCc6Zm10TW9uZXkodi5uZXQpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKHYubmV0X3Npbl9mbGV4PT1udWxsPyfigJQnOmZtdE1vbmV5KHYubmV0X3Npbl9mbGV4KSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyh2Lm1hcmdpblBjdD09bnVsbD8n4oCUJzpmbXRQY3Qodi5tYXJnaW5QY3QpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKHYuY3VvdGFzfHwwKSsnPC90ZD4nKwogICAgICAnPHRkPicrZXNjKHYuc2t1fHwnJykrJzwvdGQ+PC90cj4nO30pLmpvaW4oJycpOwp9Ci8vIEd1YXJkYSBsYSBGQUNUVVJBICUgR0xPQkFMICh1bmEgc29sYSBwYXJhIHRvZGFzIGxhcyBjdWVudGFzKS4KYXN5bmMgZnVuY3Rpb24gc2F2ZUZhY3R1cmFDZmcoKXsKICBjb25zdCB2YWw9KyQoJ3Zlbl90YXgnKS52YWx1ZTsKICBpZihpc05hTih2YWwpfHx2YWw8MCl7dG9hc3QoJ1BvbsOpIHVuICUgZGUgZmFjdHVyYSB2w6FsaWRvJyk7cmV0dXJuO30KICB0cnl7YXdhaXQgYXBpKCcvYXBpL2Fkcy9jb25maWcnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2ZhY3R1cmFQY3Q6dmFsfSl9KTt0b2FzdCgnRmFjdHVyYSAlIGd1YXJkYWRhICgnK3ZhbCsnJSkgwrcgdG9jw6Eg8J+UjSBCdXNjYXIgcGFyYSByZWNhbGN1bGFyJyk7fQogIGNhdGNoKGUpe3RvYXN0KCdFcnJvcjogJysoZS5lcnJvcnx8ZSkpO30KfQovLyBHVUFSREFSIETDjUE6IGNvbmdlbGEgbGFzIHZlbnRhcyBkZWwgZMOtYSAoZmVjaGEgRGVzZGUpIGNvbiBsYSBsaXN0YSBkZSBwcmVjaW9zIGRlIGhveSDihpIgdmEgYWwgSGlzdMOzcmljby4KYXN5bmMgZnVuY3Rpb24gc2F2ZURpYSgpewogIGNvbnN0IGFjYz0kKCdhY2NvdW50JykudmFsdWU7IGlmKCFhY2Mpe3RvYXN0KCdFbGVnw60gdW5hIGN1ZW50YSAobyBUb2RhcyknKTtyZXR1cm47fQogIGNvbnN0IGRhdGU9JCgndmVuX2Zyb20nKS52YWx1ZTsgaWYoIWRhdGUpe3RvYXN0KCdFbGVnw60gbGEgZmVjaGEgKERlc2RlKSBkZWwgZMOtYSBhIGd1YXJkYXInKTtyZXR1cm47fQogIGlmKCQoJ3Zlbl90bycpLnZhbHVlICYmICQoJ3Zlbl90bycpLnZhbHVlIT09ZGF0ZSl7CiAgICBpZighY29uZmlybSgnVmFzIGEgZ3VhcmRhciBTT0xPIGVsIGTDrWEgJytkYXRlKycgKGxhIGZlY2hhICJEZXNkZSIpLiBFbCBoaXN0w7NyaWNvIHNlIGd1YXJkYSBkw61hIHBvciBkw61hLiDCv0NvbnRpbnVhcj8nKSkgcmV0dXJuOwogIH0KICB0b2FzdCgnR3VhcmRhbmRvIGTDrWEgJytkYXRlKyfigKYgKHRyYWUgdmVudGFzIHJlYWxlcyBkZSBNTCwgcHVlZGUgdGFyZGFyKScpOwogIHRyeXsKICAgIGNvbnN0IHI9YXdhaXQgYXBpKCcvYXBpL2dlc3Rpb24vc2F2ZS1kYXknLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2RhdGUsYWNjb3VudF9pZDphY2N9KX0pOwogICAgdG9hc3QoJ+KchSBEw61hICcrZGF0ZSsnIGd1YXJkYWRvIMK3ICcrci5jb3VudCsnIHZlbnRhcycrKHIub3Zlcndyb3RlPycgKHNvYnJlZXNjcml0byknOicnKSsnIMK3IGdhbmFuY2lhICcrZm10TW9uZXkoci50b3RhbHMmJnIudG90YWxzLmdhbmFuY2lhfHwwKSk7CiAgICBISVNUX0xPQURFRD1mYWxzZTsgLy8gZm9yemFyIHJlY2FyZ2EgZGVsIGhpc3TDs3JpY28gbGEgcHLDs3hpbWEgdmV6CiAgfWNhdGNoKGUpe3RvYXN0KCdFcnJvciBhbCBndWFyZGFyOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpKTt9Cn0KLy8gRUxJTUlOQVIgRMONQTogYm9ycmEgZGVsIEhpc3TDs3JpY28gZWwgZMOtYSBndWFyZGFkbyAoZmVjaGEgRGVzZGUpLCBwYXJhIHZvbHZlciBhIHN1YmlybG8gY29uIEd1YXJkYXIgZMOtYS4KYXN5bmMgZnVuY3Rpb24gZGVsZXRlRGlhKCl7CiAgY29uc3QgZGF0ZT0kKCd2ZW5fZnJvbScpLnZhbHVlOyBpZighZGF0ZSl7dG9hc3QoJ0VsZWfDrSBsYSBmZWNoYSAoRGVzZGUpIGRlbCBkw61hIGEgZWxpbWluYXInKTtyZXR1cm47fQogIGlmKCFjb25maXJtKCfCv0VsaW1pbmFyIGRlbCBIaXN0w7NyaWNvIGVsIGTDrWEgJytkYXRlKyc/XG5cblZhcyBhIHBvZGVyIHZvbHZlciBhIGd1YXJkYXJsbyBjb24g8J+SviBHdWFyZGFyIGTDrWEuIChObyBib3JyYSBuYWRhIGVuIE1lcmNhZG8gTGlicmUuKScpKSByZXR1cm47CiAgdHJ5ewogICAgYXdhaXQgYXBpKCcvYXBpL2dlc3Rpb24vZGVsZXRlLWRheScse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7ZGF0ZX0pfSk7CiAgICB0b2FzdCgn8J+Xke+4jyBEw61hICcrZGF0ZSsnIGVsaW1pbmFkbyBkZWwgSGlzdMOzcmljby4gQWhvcmEgcG9kw6lzIHZvbHZlciBhIGd1YXJkYXJsby4nKTsKICAgIEhJU1RfTE9BREVEPWZhbHNlOwogIH1jYXRjaChlKXsgdG9hc3QoJ0Vycm9yOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnPyhlLmVycm9yKTpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkpOyB9Cn0KCi8vIC0tLS0gRVNUUkFURUdJQSAoZWwgY2VyZWJybykgLS0tLQpsZXQgRVNPUlQ9e2tleTonc2NvcmUnLGRpcjotMX0sIEVTRUc9e2VzdHJlbGxhOjEscHJvbWVzYToxLGFqdXN0YXI6MSx2YWNhOjEsZHVybWllbnRlOjEsZHVwT25seTowLGVucmljaGVkT25seTowfTsKY29uc3QgU0VHTUVUQT17ZXN0cmVsbGE6WydwLWdyZWVuJywn4q2QIEVzdHJlbGxhJ10scHJvbWVzYTpbJ3AtYmx1ZScsJ/CfmoAgUHJvbWVzYSddLGFqdXN0YXI6WydwLXJlZCcsJ/CflKcgQWp1c3RhciddLHZhY2E6WydwLWFtYmVyJywn8J+QhCBWYWNhJ10sZHVybWllbnRlOlsncC1ncmV5Jywn8J+SpCBEdXJtaWVudGUnXX07CmZ1bmN0aW9uIHNlZ1BpbGwocyl7Y29uc3QgbT1TRUdNRVRBW3NdfHxbJ3AtZ3JleScsc107cmV0dXJuICc8c3BhbiBjbGFzcz0icGlsbCAnK21bMF0rJyI+JyttWzFdKyc8L3NwYW4+Jzt9CmZ1bmN0aW9uIHRvZ2dsZVNlZyhlbCl7ZWwuY2xhc3NMaXN0LnRvZ2dsZSgnb24nKTtFU0VHW2VsLmRhdGFzZXQuc2VnXT1lbC5jbGFzc0xpc3QuY29udGFpbnMoJ29uJyk/MTowO2lmKFNUUkFUKWxvYWRFc3RyYXRlZ2lhKCk7fQpmdW5jdGlvbiBzb3J0RXN0cihrKXtpZihFU09SVC5rZXk9PT1rKUVTT1JULmRpcio9LTE7ZWxzZXtFU09SVC5rZXk9aztFU09SVC5kaXI9KGs9PT0ndGl0bGUnfHxrPT09J2FjY291bnRfbmFtZSd8fGs9PT0nc2VnbWVudCcpPzE6LTE7fWlmKFNUUkFUKXJlbmRlckVzdHJhdGVnaWEoU1RSQVQpO30KbGV0IEVOUklDSElORz1mYWxzZTsKZnVuY3Rpb24gc3RvcEVucmlxdWVjZXIoKXsgRU5SSUNISU5HPWZhbHNlOyAkKCdlc3RyX3N0b3BfYnRuJykudGV4dENvbnRlbnQ9J0RldGVuaWVuZG/igKYnOyB9CmZ1bmN0aW9uIHNldFByb2codHh0LHN1YixwY3QpeyAkKCdlc3RyX3Byb2dfdHh0JykudGV4dENvbnRlbnQ9dHh0OyBpZihzdWIhPW51bGwpJCgnZXN0cl9wcm9nX3N1YicpLnRleHRDb250ZW50PXN1YjsgaWYocGN0IT1udWxsKSQoJ2VzdHJfcHJvZ19iYXInKS5zdHlsZS53aWR0aD1NYXRoLm1pbigxMDAsTWF0aC5tYXgoMCxwY3QpKSsnJSc7IH0KYXN5bmMgZnVuY3Rpb24gcmVmaW5hck1hcmdlbmVzKCl7CiAgaWYoRU5SSUNISU5HKSByZXR1cm47ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB5YSBlc3TDoSBjb3JyaWVuZG8KICBjb25zdCBzZWw9JCgnYWNjb3VudCcpLnZhbHVlOwogIGNvbnN0IHRhcmdldHM9KHNlbD09PSdhbGwnfHwhc2VsKT9BQ0NPVU5UUy5tYXAoYT0+YS5pZCk6W3NlbF07CiAgRU5SSUNISU5HPXRydWU7CiAgJCgnZXN0cl9wcm9ncmVzc19jYXJkJykuc3R5bGUuZGlzcGxheT0nYmxvY2snOwogICQoJ2VzdHJfc3RvcF9idG4nKS50ZXh0Q29udGVudD0n4o+5IERldGVuZXInOwogIHNldFByb2coJ0luaWNpYW5kbyBlbnJpcXVlY2ltaWVudG8gY29uIGRhdG9zIHJlYWxlcyBkZSBNTOKApicsJycsMCk7CiAgbGV0IGdyYW5kPTAsIGJhdGNoZXM9MDsKICB0cnl7CiAgICBmb3IoY29uc3QgdGlkIG9mIHRhcmdldHMpewogICAgICBpZighRU5SSUNISU5HKSBicmVhazsKICAgICAgY29uc3QgYWNjPUFDQ09VTlRTLmZpbmQoYT0+U3RyaW5nKGEuaWQpPT09U3RyaW5nKHRpZCkpOwogICAgICBjb25zdCBhY2NOYW1lPWFjYz9hY2MubmFtZTonY3VlbnRhJzsKICAgICAgLy8gUGFzbyAxIChsaXZpYW5vLCAxIHNvbGEgdmV6KTogbGVlciB2ZW50YXMgZGUgOTAgZMOtYXMgY29uIHN1IHRhc2EgcmVhbCBkZSBNTC4gU2VwYXJhZG8gZGVsIGVucmlxdWVjaW1pZW50by4KICAgICAgc2V0UHJvZygnTGV5ZW5kbyB2ZW50YXMgZGUgOTAgZMOtYXMgZGUgJythY2NOYW1lKyfigKYnLCdQYXNvIHByZXZpbyBwYXJhIGVsIG1hcmdlbiByZWFsIChjb21pc2nDs24gKyBjdW90YXMpIHkgZWwgInZlbmRlIicsMCk7CiAgICAgIGZvcihsZXQgc3Q9MDtzdDwzICYmIEVOUklDSElORztzdCsrKXsKICAgICAgICB0cnl7IGF3YWl0IGFwaSgnL2FwaS9hZHMvZXN0cmF0ZWdpYS9zb2xkOTA/YWNjb3VudF9pZD0nK3RpZCk7IGJyZWFrOyB9CiAgICAgICAgY2F0Y2goZSl7IGlmKHN0Pj0yKXsgLyogc2VndWltb3MgaWd1YWw7IHJlZmluYXIgbG8gcmVpbnRlbnRhICovIH0gZWxzZSB7IGF3YWl0IG5ldyBQcm9taXNlKHM9PnNldFRpbWVvdXQocywxMjAwKihzdCsxKSkpOyB9IH0KICAgICAgfQogICAgICBsZXQgbGFzdERvbmU9LTEsIHN0YWxsPTA7CiAgICAgIHdoaWxlKEVOUklDSElORyl7CiAgICAgICAgbGV0IHI9bnVsbCwgdHJpZXM9MDsKICAgICAgICB3aGlsZShFTlJJQ0hJTkcgJiYgdHJpZXM8Nil7ICAgICAgICAgICAgICAgICAgICAgICAvLyByZWludGVudGEgYW50ZSBjb3J0ZXMgZGUgcmVkICgiRmFpbGVkIHRvIGZldGNoIikgbyB0aW1lb3V0cwogICAgICAgICAgdHJ5eyByPWF3YWl0IGFwaSgnL2FwaS9hZHMvZXN0cmF0ZWdpYS9yZWZpbmFyP2FjY291bnRfaWQ9Jyt0aWQrJyZjYXA9MTInKTsgYnJlYWs7IH0KICAgICAgICAgIGNhdGNoKGUpeyB0cmllcysrOwogICAgICAgICAgICBpZih0cmllcz49Nil7IHNldFByb2coJ0Vycm9yIGVuICcrYWNjTmFtZSsnIOKAlCByZWludGVudG9zIGFnb3RhZG9zJywnVm9sdsOpIGEgdG9jYXIg8J+OryBFbnJpcXVlY2VyIHBhcmEgc2VndWlyIGRvbmRlIHF1ZWTDsyAoJytTdHJpbmcoZS5lcnJvcnx8ZS5tZXNzYWdlfHxlKSsnKScsMCk7IH0KICAgICAgICAgICAgZWxzZSB7IHNldFByb2coJ1JlaW50ZW50YW5kbyAnK2FjY05hbWUrJ+KApiAoJyt0cmllcysnLzUpJywnTGEgY29uZXhpw7NuIGNvbiBNTCBzZSBjb3J0w7M7IHJlaW50ZW50byBhdXRvbcOhdGljbycsMCk7IGF3YWl0IG5ldyBQcm9taXNlKHM9PnNldFRpbWVvdXQocywxMDAwKnRyaWVzKSk7IH0KICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgaWYoIXIpIGJyZWFrOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIG5vIHNlIHB1ZG8gdHJhcyByZWludGVudG9zIOKGkiBjb3J0YSBlc3RhIGN1ZW50YQogICAgICAgIGlmKHIuYnVzeSl7IGF3YWl0IG5ldyBQcm9taXNlKHM9PnNldFRpbWVvdXQocywxNTAwKSk7IGNvbnRpbnVlOyB9ICAvLyBvdHJvIGxvdGUgZW4gY3Vyc28g4oaSIGVzcGVyYXIgeSBzZWd1aXIKICAgICAgICBncmFuZCs9ci5yZWZpbmVkfHwwOyBiYXRjaGVzKys7CiAgICAgICAgY29uc3QgZG9uZT1yLmVucmljaGVkX3RvdGFsfHwwLCB0b3Q9ci5hY2NvdW50X3RvdGFsfHwwOwogICAgICAgIGNvbnN0IGV4dHJhPShyLmZpbGVfdG90YWwhPW51bGwpPygnIMK3IGFyY2hpdm86ICcrKHIuZmlsZV90b3RhbHx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrKChyLnBhdXNhZGFzKT8oJyAoJytyLnBhdXNhZGFzKycgcGF1c2FkYXMgZnVlcmEpJyk6JycpKTonJzsKICAgICAgICBzZXRQcm9nKCdFbnJpcXVlY2llbmRvICcrYWNjTmFtZSsnOiAnK2RvbmUudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyAvICcrdG90LnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgYWN0aXZhcycrZXh0cmEsCiAgICAgICAgICAgICAgICAn8J+TpiAnK2dyYW5kLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgZW4gZXN0YSBjb3JyaWRhIMK3IGxvdGUgJytiYXRjaGVzKycgwrcgdHJhZSB0w610dWxvLCBwcmVjaW8gY29uIHByb21vLCB2ZW50YXMgeSB2aXNpdGFzIGRlIE1MJywKICAgICAgICAgICAgICAgIHRvdD9kb25lL3RvdCoxMDA6MTAwKTsKICAgICAgICBpZihiYXRjaGVzJTM9PT0wKSBhd2FpdCBsb2FkRXN0cmF0ZWdpYSgpOyAgICAgICAgICAvLyByZWZyZXNjYSBsb3MgbsO6bWVyb3MgY2FkYSAzIGxvdGVzCiAgICAgICAgaWYoZG9uZT49dG90KSBicmVhazsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gY3VlbnRhIHRlcm1pbmFkYQogICAgICAgIGlmKGRvbmU8PWxhc3REb25lKXsgc3RhbGwrKzsgaWYoc3RhbGw+PTUpIGJyZWFrOyB9IGVsc2UgeyBzdGFsbD0wOyB9ICAgLy8gc2luIGF2YW5jZSA1IHZlY2VzIHNlZ3VpZGFzIOKGkiBjb3J0YXIKICAgICAgICBsYXN0RG9uZT1kb25lOwogICAgICB9CiAgICB9CiAgfSBmaW5hbGx5IHsKICAgIGNvbnN0IHN0b3BwZWQ9IUVOUklDSElORzsKICAgIEVOUklDSElORz1mYWxzZTsKICAgIHNldFByb2coc3RvcHBlZD8oJ0RldGVuaWRvIMK3ICcrZ3JhbmQudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBlbnJpcXVlY2lkb3MnKTooJ+KchSBMaXN0byDCtyAnK2dyYW5kLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgcHJvZHVjdG9zIGVucmlxdWVjaWRvcyBjb24gZGF0YSByZWFsIGRlIE1MJyksJycsMTAwKTsKICAgIGF3YWl0IGxvYWRFc3RyYXRlZ2lhKCk7CiAgICBzZXRUaW1lb3V0KCgpPT57IGlmKCFFTlJJQ0hJTkcpICQoJ2VzdHJfcHJvZ3Jlc3NfY2FyZCcpLnN0eWxlLmRpc3BsYXk9J25vbmUnOyB9LDUwMDApOwogIH0KfQpmdW5jdGlvbiBtYXJnaW5TcmNEb3Qoc3JjKXtyZXR1cm4gc3JjPT09J3NpbSc/J/CflLUnOifwn5+gJzt9CmZ1bmN0aW9uIGVzdHJQYXJhbXMoKXtjb25zdCBnPSQoJ2VzdHJfaGlnaCcpLnZhbHVlLG1zPSQoJ2VzdHJfbWluc2FsZXMnKS52YWx1ZSxtdj0kKCdlc3RyX21pbnZpcycpLnZhbHVlLGh2PSQoJ2VzdHJfaG90dmlzJykudmFsdWUscm89JCgnZXN0cl9yb2FzJykudmFsdWU7cmV0dXJuICdtYXJnaW5IaWdoPScrKGd8fDEyKSsnJm1pblNhbGVzPScrKG1zfHwxKSsnJm1pblZpc2l0cz0nKyhtdnx8OCkrJyZob3RWaXNpdHM9JysoaHZ8fDMwKSsnJnJvYXM9Jysocm98fDUpO30KLy8gRmlsdHJvcyBkZSB2aXN0YSDihpIgdmFuIGFsIFNFUlZJRE9SIChlbCB0b3AtNTAwIG5vIGFsY2FuemEgcGFyYSB2ZXIgcGF1c2FyL2R1cm1pZW50ZS91bmEgY3VlbnRhKS4KZnVuY3Rpb24gZXN0ckZpbHRlclBhcmFtcygpewogIGNvbnN0IHNlZ3M9Wydlc3RyZWxsYScsJ3Byb21lc2EnLCdhanVzdGFyJywndmFjYScsJ2R1cm1pZW50ZSddLmZpbHRlcihzPT5FU0VHW3NdKTsKICBsZXQgcT0nJnNlZ3M9JytlbmNvZGVVUklDb21wb25lbnQoc2Vncy5qb2luKCcsJykpOwogIGlmKEVTRUcuZHVwT25seSlxKz0nJmR1cE9ubHk9MSc7CiAgaWYoRVNFRy5lbnJpY2hlZE9ubHkpcSs9JyZlbnJpY2hlZE9ubHk9MSc7CiAgaWYoRUFDVElPTilxKz0nJmFjdGlvbj0nK2VuY29kZVVSSUNvbXBvbmVudChFQUNUSU9OKTsKICBpZihFQUNDVClxKz0nJnZpZXdBY2NvdW50PScrZW5jb2RlVVJJQ29tcG9uZW50KEVBQ0NUKTsKICByZXR1cm4gcTsKfQphc3luYyBmdW5jdGlvbiBsb2FkRXN0cmF0ZWdpYSgpewogICQoJ2VzdHJfYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMSIgY2xhc3M9ImxvYWRpbmciPkNydXphbmRvIGN1ZW50YXMgcG9yIHTDrXR1bG8geSBjbGFzaWZpY2FuZG/igKY8L3RkPjwvdHI+JzsKICB0cnl7CiAgICBjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvZXN0cmF0ZWdpYT8nK2VzdHJQYXJhbXMoKStlc3RyRmlsdGVyUGFyYW1zKCkpOwogICAgaWYoZC5lbXB0eSl7JCgnZXN0cl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjExIiBjbGFzcz0iZW1wdHkiPicrZXNjKGQubm90ZXx8J0ltcG9ydMOhIGxvcyBfQ09NUExFVE8gcHJpbWVyby4nKSsnPC90ZD48L3RyPic7JCgnZXN0cl9rcGlzJykuaW5uZXJIVE1MPScnO1NUUkFUPW51bGw7cmV0dXJuO30KICAgIFNUUkFUPWQ7cmVuZGVyRXN0cmF0ZWdpYShkKTsKICB9Y2F0Y2goZSl7JCgnZXN0cl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjExIiBjbGFzcz0iZW1wdHkiPkVycm9yOiAnK2VzYyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpKyc8L3RkPjwvdHI+Jzt9Cn0KZnVuY3Rpb24gcmVuZGVyRXN0cmF0ZWdpYShkKXsKICBjb25zdCBzPWQuc2VnbWVudG9zfHx7fSx0PWQudG90YWxzfHx7fSxkdT1kLmR1cGxpY2Fkb3N8fHt9OwogIGNvbnN0IGVucj0oZC5jdWVudGFzfHxbXSkucmVkdWNlKChhLGMpPT5hKyhjLmVucmljaGVkfHwwKSwwKTsKICBjb25zdCB0aWxlcz1bCiAgICBbJ0FjdGl2YXMnLCh0LnByb2R1Y3Rvc3x8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrKHQucGF1c2FkYXM/KCcgwrcgJyt0LnBhdXNhZGFzLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgcGF1c2FkYXMgZnVlcmEnKTonJyksJyddLAogICAgWyfinIUgRW5yaXF1ZWNpZG9zJyxlbnIudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyAvICcrKHQucHJvZHVjdG9zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSxlbnI+MD8oZW5yPj0odC5wcm9kdWN0b3N8fDApPydnb29kJzond2FybicpOidiYWQnXSwKICAgIFsn4q2QIEVzdHJlbGxhcycsKHMuZXN0cmVsbGF8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLCdnb29kJ10sCiAgICBbJ/CfmoAgUHJvbWVzYXMnLChzLnByb21lc2F8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLCcnXSwKICAgIFsn8J+UpyBBanVzdGFyJywocy5hanVzdGFyfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSwocy5hanVzdGFyfHwwKT8nd2Fybic6JyddLAogICAgWyfwn5CEIFZhY2FzJywocy52YWNhfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSwnd2FybiddLAogICAgWyfwn5KkIER1cm1pZW50ZXMnLChzLmR1cm1pZW50ZXx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJyksJyddLAogICAgWyfwn5SBIER1cGxpY2Fkb3MnLChkdS5pdGVtc3x8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrKGR1LmdydXBvcz8oJyDCtyAnK2R1LmdydXBvcysnIGdyJyk6JycpLGR1Lml0ZW1zPydiYWQnOidnb29kJ10sCiAgXTsKICAkKCdlc3RyX2twaXMnKS5pbm5lckhUTUw9dGlsZXMubWFwKHg9Pic8ZGl2IGNsYXNzPSJrcGkgJyt4WzJdKyciPjxkaXYgY2xhc3M9ImsiPicreFswXSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+Jyt4WzFdKyc8L2Rpdj48L2Rpdj4nKS5qb2luKCcnKTsKICByZW5kZXJQbGFuKGQpOwogIHJlbmRlckFjY3RDZmcoZC5jdWVudGFzfHxbXSk7CiAgJCgnZXN0cl9wbGFuX2NhcmQnKS5zdHlsZS5kaXNwbGF5PSdibG9jayc7CiAgLy8gQ3VlbnRhcyBoYWNpYSBzdSBvYmpldGl2byAobWVzIGNvcnJpZG8gKyBBRFMgc3VnZXJpZG8pCiAgY29uc3QgYWNjdHM9ZC5jdWVudGFzfHxbXTsKICAkKCdlc3RyX2FjY3RzX2NhcmQnKS5zdHlsZS5kaXNwbGF5PWFjY3RzLmxlbmd0aD8nYmxvY2snOidub25lJzsKICAkKCdlc3RyX2xlZ2VuZCcpLnN0eWxlLmRpc3BsYXk9J2ZsZXgnOyQoJ2VzdHJfZmlsdGVycycpLnN0eWxlLmRpc3BsYXk9J2ZsZXgnOwogIGlmKCFFQUNDVCkgZmlsbEFjY3RGaWx0ZXIoYWNjdHMpOyAgIC8vIGVsIGRlc3BsZWdhYmxlIHNlIGFybWEgY29uIFRPREFTIGxhcyBjdWVudGFzICh2aXN0YSBjb21wbGV0YSkKICAkKCdlc3RyX2FjY3RzJykuaW5uZXJIVE1MPWFjY3RzLm1hcChhPT57CiAgICBjb25zdCBhdj1hLmF2YW5jZXx8MDsKICAgIHJldHVybiAnPHRyPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2MoYS5hY2NvdW50X25hbWV8fCfigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoYS5vYmpldGl2bykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KGEucHJveV9tZW5zdWFsKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo3MDA7Y29sb3I6JysoYXY+PTEwMD8ndmFyKC0tZ3JlZW4pJzphdj49NjA/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLXJlZCknKSsnIj4nK2F2LnRvRml4ZWQoMCkrJyU8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKGEuZmFsdGFudGU+MD8ndmFyKC0tcmVkKSc6J3ZhcigtLWdyZWVuKScpKyciPicrKGEuZmFsdGFudGU+MD9mbXRNb25leShhLmZhbHRhbnRlKTon4pyTJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIGIiIHN0eWxlPSJjb2xvcjp2YXIoLS1uYXZ5KSI+JysoYS5hZHNfYnVkZ2V0PjA/Zm10TW9uZXkoYS5hZHNfYnVkZ2V0KTon4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6JysoKGEuZW5yaWNoZWR8fDApPj0oYS5pdGVtc3x8MCk/J3ZhcigtLWdyZWVuKSc6KGEuZW5yaWNoZWQ/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLXJlZCknKSkrJyI+JysoYS5lbnJpY2hlZHx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJy8nKyhhLml0ZW1zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKGEuZXN0cmVsbGF8fDApKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhhLnByb21vdmVyfHwwKSsnPC90ZD48dGQgY2xhc3M9Im51bSBiIj4nKyhhLmxpZGVyfHwwKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJyk7CiAgLy8gVGFibGEgZGUgcHJvZHVjdG9zIChmaWx0cmFkYSArIG9yZGVuYWRhKQogIGNvbnN0IHJvd3M9ZmlsdGVyZWRFc3RySXRlbXMoKTsKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjZXN0clRhYmxlIHRoZWFkIHRoJykuZm9yRWFjaCh0aD0+e2NvbnN0IGE9dGgucXVlcnlTZWxlY3RvcignLmFycicpO2lmKGEpYS5yZW1vdmUoKTtpZih0aC5kYXRhc2V0Lms9PT1FU09SVC5rZXkpe2NvbnN0IHNwPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKTtzcC5jbGFzc05hbWU9J2Fycic7c3AudGV4dENvbnRlbnQ9RVNPUlQuZGlyPjA/JyDilrInOicg4pa8Jzt0aC5hcHBlbmRDaGlsZChzcCk7fX0pOwogIC8vIEluZGljYWRvciBkZSBjdcOhbnRvcyBjb2luY2lkZW4gdnMgY3XDoW50b3Mgc2UgbXVlc3RyYW4gKGVsIHNlcnZlciBsaW1pdGEgYSA1MDAgcG9yIHZleikuCiAgY29uc3QgY0VsPSQoJ2VzdHJfY291bnQnKSwgbWF0Y2hlZD0oZC5tYXRjaGVkIT1udWxsP2QubWF0Y2hlZDpyb3dzLmxlbmd0aCksIHNob3duPShkLnNob3duIT1udWxsP2Quc2hvd246cm93cy5sZW5ndGgpOwogIGlmKGNFbCl7IGlmKG1hdGNoZWQ+c2hvd24pe2NFbC5zdHlsZS5kaXNwbGF5PSdibG9jayc7Y0VsLmlubmVySFRNTD0nTW9zdHJhbmRvIDxiPicrc2hvd24udG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJzwvYj4gZGUgPGI+JyttYXRjaGVkLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2I+IHF1ZSBjb2luY2lkZW4gKGFmaW7DoSBsb3MgZmlsdHJvcyBvIGRlc2NhcmfDoSBlbCBFeGNlbCBwYXJhIHZlciB0b2RvKS4nO30gZWxzZSB7Y0VsLnN0eWxlLmRpc3BsYXk9bWF0Y2hlZD8nYmxvY2snOidub25lJztjRWwuaW5uZXJIVE1MPSc8Yj4nK21hdGNoZWQudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJzwvYj4gcHVibGljYWNpb25lcyc7fSB9CiAgaWYoIXJvd3MubGVuZ3RoKXskKCdlc3RyX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTEiIGNsYXNzPSJlbXB0eSI+U2luIHByb2R1Y3RvcyBjb24gZXNvcyBmaWx0cm9zLjwvdGQ+PC90cj4nO3JldHVybjt9CiAgJCgnZXN0cl9ib2R5JykuaW5uZXJIVE1MPXJvd3Muc2xpY2UoMCwxMDAwKS5tYXAoaT0+ewogICAgY29uc3QgbGVhZD1pLmR1cGxpY2F0ZWQ/KGkuaXNMZWFkZXI/JzxzcGFuIGNsYXNzPSJwaWxsIHAtZ3JlZW4iPvCfkZEgTMOtZGVyPC9zcGFuPic6JzxzcGFuIGNsYXNzPSJwaWxsIHAtZ3JleSI+8J+MsSBPcmfDoW5pY288L3NwYW4+Jyk6JzxzcGFuIGNsYXNzPSJtdXRlZCI+w7puaWNvPC9zcGFuPic7CiAgICBjb25zdCBzYz1pLnNjb3JlfHwwLCBzY0NvbD1zYz49NjY/J3ZhcigtLWdyZWVuKSc6c2M+PTMzPyd2YXIoLS1hbWJlciknOid2YXIoLS1tdXQpJzsKICAgIGNvbnN0IHByb21vVGFnPWkuZW5Qcm9tbz8nIDxzcGFuIGNsYXNzPSJwaWxsIHAtcmVkIiBzdHlsZT0iZm9udC1zaXplOjlweDtwYWRkaW5nOjFweCA2cHgiPnByb21vPC9zcGFuPic6Jyc7CiAgICByZXR1cm4gJzx0cicrKChpLmR1cGxpY2F0ZWQmJiFpLmlzTGVhZGVyKT8nIHN0eWxlPSJiYWNrZ3JvdW5kOiNmOGZhZmMiJzonJykrJz4nKwogICAgICAnPHRkIGNsYXNzPSJuYW1lIj4nK2VzYyhpLnRpdGxlfHxpLml0ZW1faWQpK3Byb21vVGFnKyc8c3BhbiBjbGFzcz0iaWQiPicrKGkuaXRlbV9pZHx8JycpKyhpLmVucmljaGVkPycnOicgwrcgc2luIGVucmlxdWVjZXInKSsoaS5kdXBsaWNhdGVkPygnIMK3IHJlcGV0aWRvJyk6JycpKyc8L3NwYW4+PC90ZD4nKwogICAgICAnPHRkPicrZXNjKGkuYWNjb3VudF9uYW1lfHwn4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZD4nK3NlZ1BpbGwoaS5zZWdtZW50KSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0gYiIgc3R5bGU9ImNvbG9yOicrc2NDb2wrJyI+JytzYysnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKygoaS5tYXJnaW4hPW51bGwmJmkubWFyZ2luPj0oKyQoJ2VzdHJfaGlnaCcpLnZhbHVlfHwxMikpPyd2YXIoLS1ncmVlbiknOid2YXIoLS1hbWJlciknKSsnIiB0aXRsZT0iJysoaS5tYXJnaW5TcmM9PT0nc2ltJz8nc2ltdWxhZG8gY29uIGVsIGNvc3RvIGV4YWN0byBkZSBNTCBhbCBwcmVjaW8gcmVhbCc6J21hcmdlbiBkZSBsaXN0YSAoZW5yaXF1ZWPDqSBwYXJhIGVsIGV4YWN0byknKSsnIj4nKyhpLm1hcmdpbj09bnVsbD8n4oCUJzpmbXRQY3QoaS5tYXJnaW4pKSsnIDxzcGFuIHN0eWxlPSJmb250LXNpemU6OXB4Ij4nK21hcmdpblNyY0RvdChpLm1hcmdpblNyYykrJzwvc3Bhbj48L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JysoaS5wcmljZT09bnVsbD8n4oCUJzpmbXRNb25leShpLnByaWNlKSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiB0aXRsZT0iJysoKGkuc29sZFRvdGFsIT1udWxsKT8oJ2FjdW11bGFkbyBoaXN0w7NyaWNvOiAnK2kuc29sZFRvdGFsKTonJykrJyI+JysoaS5zb2xkfHwwKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKGkudmlzaXRzfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKyhpLmNvbnY9PW51bGw/J3ZhcigtLW11dCknOihpLmNvbnY+PTM/J3ZhcigtLWdyZWVuKSc6aS5jb252Pj0xPyd2YXIoLS1hbWJlciknOid2YXIoLS1yZWQpJykpKyciPicrKGkuY29udj09bnVsbD8n4oCUJzppLmNvbnYudG9GaXhlZCgxKSsnJScpKyc8L3RkPicrCiAgICAgICc8dGQ+JytsZWFkKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im11dGVkIiBzdHlsZT0id2hpdGUtc3BhY2U6bm9ybWFsO21heC13aWR0aDozMjBweCI+Jytlc2MoaS5hY3Rpb258fCcnKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJyk7Cn0KLy8gQXBsaWNhIGxvcyBmaWx0cm9zIGFjdHVhbGVzIChzZWdtZW50b3MgKyBhY2Npw7NuICsgZHVwbGljYWRvcy9lbnJpcXVlY2lkb3MpIHkgb3JkZW5hLCBpZ3VhbCBxdWUgbGEgdGFibGEuCmZ1bmN0aW9uIGZpbHRlcmVkRXN0ckl0ZW1zKCl7CiAgaWYoIVNUUkFUfHwhU1RSQVQuaXRlbXMpIHJldHVybiBbXTsKICAvLyBFbCBTRVJWSURPUiB5YSBhcGxpY8OzIGxvcyBmaWx0cm9zIChzZWdtZW50bywgY3VlbnRhLCBhY2Npw7NuLCBkdXBsaWNhZG9zLCBlbnJpcXVlY2lkb3MpLgogIC8vIEFjw6Egc8OzbG8gb3JkZW5hbW9zIGxvIHJlY2liaWRvIHNlZ8O6biBsYSBjb2x1bW5hIGVsZWdpZGEuCiAgbGV0IHJvd3M9U1RSQVQuaXRlbXMuc2xpY2UoKTsKICBjb25zdCBrPUVTT1JULmtleSxkaXI9RVNPUlQuZGlyOwogIHJldHVybiByb3dzLnNsaWNlKCkuc29ydCgoYSxiKT0+e2xldCB4PWFba10seT1iW2tdOwogICAgaWYoaz09PSd0aXRsZSd8fGs9PT0nYWNjb3VudF9uYW1lJ3x8az09PSdzZWdtZW50Jyl7eD1TdHJpbmcoeHx8JycpO3k9U3RyaW5nKHl8fCcnKTtyZXR1cm4gZGlyKngubG9jYWxlQ29tcGFyZSh5KTt9CiAgICBpZihrPT09J2lzTGVhZGVyJyl7cmV0dXJuIGRpciooKHg/MTowKS0oeT8xOjApKTt9CiAgICB4PSh4PT1udWxsPy1JbmZpbml0eTp4KTt5PSh5PT1udWxsPy1JbmZpbml0eTp5KTtyZXR1cm4gZGlyKih4LXkpO30pOwp9CmZ1bmN0aW9uIGVzdHJJdGVtc1RvWGxzeChsaXN0KXtyZXR1cm4gbGlzdC5tYXAoaT0+KHtQcm9kdWN0bzppLnRpdGxlLEl0ZW1JRDppLml0ZW1faWQsQ3VlbnRhOmkuYWNjb3VudF9uYW1lLFNlZ21lbnRvOmkuc2VnbWVudCxQb3RlbmNpYWw6aS5zY29yZXx8MCxNYXJnZW5fcGN0OmkubWFyZ2luPT1udWxsPycnOitpLm1hcmdpbi50b0ZpeGVkKDEpLE1hcmdlbl9vcmlnZW46KGkubWFyZ2luU3JjPT09J3NpbSc/J3NpbXVsYWRvIE1MJzonbGlzdGEnKSxQcmVjaW86aS5wcmljZT09bnVsbD8nJzppLnByaWNlLEVuX3Byb21vOmkuZW5Qcm9tbz8nU8OtJzonJyxWZW50YXNfM206aS5zb2xkfHwwLFZlbnRhc190b3RhbDppLnNvbGRUb3RhbD09bnVsbD8nJzppLnNvbGRUb3RhbCxWaXNpdGFzXzNtOmkudmlzaXRzfHwwLENvbnZlcnNpb25fcGN0OmkuY29udj09bnVsbD8nJzoraS5jb252LnRvRml4ZWQoMiksRXhwb3NpY2lvbjppLmxpc3RpbmdUeXBlfHwnJyxFbnJpcXVlY2lkbzppLmVucmljaGVkPydTw60nOicnLER1cGxpY2FkbzppLmR1cGxpY2F0ZWQ/J1PDrSc6JycsTGlkZXI6aS5kdXBsaWNhdGVkPyhpLmlzTGVhZGVyPydMw61kZXInOidTb2xvIG9yZ8OhbmljbycpOifDum5pY28nLExpZGVyX2N1ZW50YTppLmxlYWRlck5hbWV8fCcnLFN0b2NrX29mZXJ0YTppLnN0b2NrPydTw60nOicnLEFjY2lvbjppLmFjdGlvbn0pKTt9CmZ1bmN0aW9uIGRvd25sb2FkRXN0cmF0ZWdpYVhsc3goKXsKICBpZighU1RSQVR8fCFTVFJBVC5pdGVtc3x8IVNUUkFULml0ZW1zLmxlbmd0aCl7dG9hc3QoJ0NhbGN1bMOhIGxhIGVzdHJhdGVnaWEgcHJpbWVybycpO3JldHVybjt9CiAgY29uc3Qgd3M9WExTWC51dGlscy5qc29uX3RvX3NoZWV0KGVzdHJJdGVtc1RvWGxzeChTVFJBVC5pdGVtcykpO2NvbnN0IHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTtYTFNYLnV0aWxzLmJvb2tfYXBwZW5kX3NoZWV0KHdiLHdzLCdFc3RyYXRlZ2lhJyk7CiAgWExTWC53cml0ZUZpbGUod2IsJ2VzdHJhdGVnaWFfbXVsdGljdWVudGFfJysobmV3IERhdGUoKS50b0lTT1N0cmluZygpLnNsaWNlKDAsMTApKSsnLnhsc3gnKTsKfQovLyBCYWphIFRPRE8gbG8gcXVlIGNvaW5jaWRlIGNvbiBsb3MgZmlsdHJvcyBhY3R1YWxlcyAocGlkZSBhbCBzZXJ2ZXIgaGFzdGEgMjAuMDAwLCBubyBzw7NsbyBsbyB2aXNpYmxlKS4KYXN5bmMgZnVuY3Rpb24gZG93bmxvYWRFc3RyYXRlZ2lhVmlzaWJsZVhsc3goKXsKICBpZighU1RSQVQpe3RvYXN0KCdDYWxjdWzDoSBsYSBlc3RyYXRlZ2lhIHByaW1lcm8nKTtyZXR1cm47fQogIHRvYXN0KCdQcmVwYXJhbmRvIGRlc2NhcmdhIGRlIHRvZG8gbG8gZmlsdHJhZG/igKYnKTsKICBsZXQgcm93czsKICB0cnl7IGNvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9lc3RyYXRlZ2lhPycrZXN0clBhcmFtcygpK2VzdHJGaWx0ZXJQYXJhbXMoKSsnJmxpbWl0PTIwMDAwJyk7IHJvd3M9ZC5pdGVtc3x8W107IH0KICBjYXRjaChlKXsgcm93cz1maWx0ZXJlZEVzdHJJdGVtcygpOyB9CiAgaWYoIXJvd3MubGVuZ3RoKXt0b2FzdCgnTm8gaGF5IGZpbGFzIGNvbiBlc29zIGZpbHRyb3MnKTtyZXR1cm47fQogIGNvbnN0IHdzPVhMU1gudXRpbHMuanNvbl90b19zaGVldChlc3RySXRlbXNUb1hsc3gocm93cykpO2NvbnN0IHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTtYTFNYLnV0aWxzLmJvb2tfYXBwZW5kX3NoZWV0KHdiLHdzLCdGaWx0cmFkbycpOwogIFhMU1gud3JpdGVGaWxlKHdiLCdlc3RyYXRlZ2lhX2ZpbHRyYWRvXycrKG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKSkrJy54bHN4Jyk7CiAgdG9hc3QoJ0Rlc2NhcmdhbmRvICcrcm93cy5sZW5ndGgudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBmaWxhcyBmaWx0cmFkYXMnKTsKfQoKLy8gLS0tLSBQTEFOIERFIEFDQ0nDk04gKHRpbGVzIGNsaWNrZWFibGVzIHF1ZSBmaWx0cmFuIGxhIHRhYmxhKSAtLS0tCmxldCBFQUNUSU9OPW51bGwsIEVBQ0NUPScnOwpjb25zdCBBQ1RfQ09MT1I9e2VzY2FsYXI6J2dvb2QnLHByb21vdmVyOidnb29kJyxhanVzdGFyOid3YXJuJyxwcmVjaW86J3dhcm4nLHBhdXNhcjonYmFkJyxvcmdhbmljbzonJyxyZXZpc2FyOicnfTsKZnVuY3Rpb24gZmlsdGVyQWN0aW9uKGNvZGUpeyBFQUNUSU9OPShFQUNUSU9OPT09Y29kZSk/bnVsbDpjb2RlOyBpZihTVFJBVClsb2FkRXN0cmF0ZWdpYSgpOyB9CmZ1bmN0aW9uIGZpbHRlckFjY3Qodil7IEVBQ0NUPXZ8fCcnOyBpZihTVFJBVClsb2FkRXN0cmF0ZWdpYSgpOyB9Ci8vIExsZW5hIGVsIGRlc3BsZWdhYmxlIGRlIGN1ZW50YXMgKHVuYSBzb2xhIHZleiksIGNvbnNlcnZhbmRvIGxhIHNlbGVjY2nDs24gYWN0dWFsLgpmdW5jdGlvbiBmaWxsQWNjdEZpbHRlcihjdWVudGFzKXsKICBjb25zdCBzZWw9JCgnZXN0cl9hY2N0Jyk7IGlmKCFzZWwpIHJldHVybjsKICBjb25zdCBjdXI9c2VsLnZhbHVlOwogIGNvbnN0IG9wdHM9Wyc8b3B0aW9uIHZhbHVlPSIiPvCfj6IgVG9kYXMgbGFzIGN1ZW50YXM8L29wdGlvbj4nXS5jb25jYXQoCiAgICAoY3VlbnRhc3x8W10pLm1hcChjPT4nPG9wdGlvbiB2YWx1ZT0iJytlc2MoU3RyaW5nKGMuYWNjb3VudF9pZCkpKyciPicrZXNjKGMuYWNjb3VudF9uYW1lfHxjLmFjY291bnRfaWQpKycgKCcrKChjLml0ZW1zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSkrJyk8L29wdGlvbj4nKSk7CiAgc2VsLmlubmVySFRNTD1vcHRzLmpvaW4oJycpOwogIHNlbC52YWx1ZT1jdXI7ICAgICAgICAgICAgICAgICAgICAgICAgIC8vIG1hbnRpZW5lIGxhIGN1ZW50YSBlbGVnaWRhIHRyYXMgcmVjYWxjdWxhcgogIGlmKHNlbC52YWx1ZSE9PWN1cikgRUFDQ1Q9Jyc7ICAgICAgICAgICAvLyBzaSB5YSBubyBleGlzdGUsIHZ1ZWx2ZSBhIFRvZGFzCn0KZnVuY3Rpb24gcmVuZGVyUGxhbihkKXsKICBjb25zdCBwbGFuPWQucGxhbnx8e30sIG1ldGE9ZC5wbGFuTWV0YXx8e307CiAgY29uc3Qgb3JkZXI9T2JqZWN0LmtleXMobWV0YSkuc29ydCgoYSxiKT0+KG1ldGFbYV0ucHJpfHw5KS0obWV0YVtiXS5wcml8fDkpKTsKICAkKCdlc3RyX3BsYW4nKS5pbm5lckhUTUw9b3JkZXIubWFwKGNvZGU9PnsKICAgIGNvbnN0IG09bWV0YVtjb2RlXSwgbj1wbGFuW2NvZGVdfHwwLCBvbj0oRUFDVElPTj09PWNvZGUpOwogICAgcmV0dXJuICc8ZGl2IG9uY2xpY2s9ImZpbHRlckFjdGlvbihcJycrY29kZSsnXCcpIiBjbGFzcz0ia3BpICcrKEFDVF9DT0xPUltjb2RlXXx8JycpKyciIHN0eWxlPSJjdXJzb3I6cG9pbnRlcjsnKyhvbj8nb3V0bGluZToycHggc29saWQgdmFyKC0tbmF2eSknOicnKSsnIj4nKwogICAgICAnPGRpdiBjbGFzcz0iayI+Jytlc2MobS5sYWJlbCkrJzwvZGl2PjxkaXYgY2xhc3M9InYgc21hbGwiPicrbi50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC9kaXY+JysKICAgICAgJzxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEwcHg7bWFyZ2luLXRvcDo0cHg7d2hpdGUtc3BhY2U6bm9ybWFsIj4nK2VzYyhtLmhpbnQpKyc8L2Rpdj48L2Rpdj4nOwogIH0pLmpvaW4oJycpOwp9Ci8vIC0tLS0gQ09ORklHIFBPUiBDVUVOVEEgKG9iamV0aXZvICsgZmFjdHVyYSkgLS0tLQpmdW5jdGlvbiByZW5kZXJBY2N0Q2ZnKGN1ZW50YXMpewogIGNvbnN0IGJ5SWQ9e307IChjdWVudGFzfHxbXSkuZm9yRWFjaChjPT5ieUlkW2MuYWNjb3VudF9pZF09Yyk7CiAgJCgnZXN0cl9hY2N0Y2ZnJykuaW5uZXJIVE1MPUFDQ09VTlRTLm1hcChhPT57CiAgICBjb25zdCBjPWJ5SWRbYS5pZF18fHt9OwogICAgY29uc3Qgb2JqPShjLm9iamV0aXZvIT1udWxsP2Mub2JqZXRpdm86KGEub2JqZXRpdm8hPW51bGw/YS5vYmpldGl2bzoxMDAwMDAwMDApKTsKICAgIGNvbnN0IGZhYz0oYy5mYWN0dXJhIT1udWxsP2MuZmFjdHVyYTooYS5mYWN0dXJhIT1udWxsP2EuZmFjdHVyYTo1KSk7CiAgICByZXR1cm4gJzxkaXYgc3R5bGU9ImJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweCAxMnB4O2JhY2tncm91bmQ6I2ZmZiI+JysKICAgICAgJzxkaXYgY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweDt3aGl0ZS1zcGFjZTpub3dyYXA7b3ZlcmZsb3c6aGlkZGVuO3RleHQtb3ZlcmZsb3c6ZWxsaXBzaXMiPicrZXNjKGEubmFtZSkrJzwvZGl2PicrCiAgICAgICc8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDttYXJnaW4tdG9wOjZweDthbGlnbi1pdGVtczpmbGV4LWVuZCI+JysKICAgICAgICAnPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5PYmpldGl2by9tZXM8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJvYmotJythLmlkKyciIHN0ZXA9IjEwMDAwMDAiIHZhbHVlPSInK29iaisnIiBzdHlsZT0id2lkdGg6MTMwcHgiPjwvZGl2PicrCiAgICAgICAgJzxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RmFjdHVyYSAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZmFjLScrYS5pZCsnIiBzdGVwPSIwLjUiIHZhbHVlPSInK2ZhYysnIiBzdHlsZT0id2lkdGg6NzBweCI+PC9kaXY+JysKICAgICAgICAnPGJ1dHRvbiBvbmNsaWNrPSJzYXZlQWNjdENmZygnK2EuaWQrJykiPkd1YXJkYXI8L2J1dHRvbj4nKwogICAgICAnPC9kaXY+PC9kaXY+JzsKICB9KS5qb2luKCcnKTsKfQphc3luYyBmdW5jdGlvbiBzYXZlQWNjdENmZyhpZCl7CiAgY29uc3Qgb2JqZXRpdm89KyQoJ29iai0nK2lkKS52YWx1ZSwgdGF4UGN0PSskKCdmYWMtJytpZCkudmFsdWU7CiAgdHJ5eyBhd2FpdCBhcGkoJy9hcGkvYWRzL2FjY291bnQtY29uZmlnJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHthY2NvdW50X2lkOmlkLG9iamV0aXZvLHRheFBjdH0pfSk7CiAgICB0b2FzdCgnQ3VlbnRhIGd1YXJkYWRhIMK3IHJlY2FsY3Vsw6EgbyByZS1lbnJpcXVlY8OpIHBhcmEgYXBsaWNhciBsYSBmYWN0dXJhIGFsIG1hcmdlbicpOyB9CiAgY2F0Y2goZSl7IHRvYXN0KCdFcnJvcjogJysoZS5lcnJvcnx8ZSkpOyB9Cn0KLy8gLS0tLSBBQ1RVQUxJWkFET1IgREUgUFJFQ0lPUyBNQVNJVk8gLS0tLQpjb25zdCBQUklDRV9BQ1RJT05TPVsKICB7Y29kZTonb3JnYW5pY28nLGxhYmVsOifwn4yxIE5vIGFudW5jaWFyICh0w610dWxvIHJlcGV0aWRvKScsbW9kZTonbWFyZ2luJyx2YWw6MjV9LAogIHtjb2RlOidyZXZpc2FyJyxsYWJlbDon8J+SpCBEdXJtaWVudGUgKHNpbiBkZW1hbmRhKScsbW9kZTonbWFyZ2luJyx2YWw6MjB9LAogIHtjb2RlOidwcmVjaW8nLGxhYmVsOifwn5CEIFZhY2EgKG1hcmdlbiBmbGFjbyknLG1vZGU6J21hcmdpbicsdmFsOjE1fSwKICB7Y29kZTonYWp1c3RhcicsbGFiZWw6J/CflKcgQWp1c3RhciAobm8gY29udmllcnRlKScsbW9kZToncGN0Jyx2YWw6LTh9LAogIHtjb2RlOidwcm9tb3ZlcicsbGFiZWw6J/Cfjq8gUHJvbW92ZXIgKGdhbmFyIHZlbnRhKScsbW9kZToncGN0Jyx2YWw6LTV9LAogIHtjb2RlOidlc2NhbGFyJyxsYWJlbDon4q2QIEVzY2FsYXIgKGVzdHJlbGxhKScsbW9kZTonbm9uZScsdmFsOjB9LApdOwpmdW5jdGlvbiByZW5kZXJQcmVjaW9SdWxlcygpewogIGlmKCQoJ3ByZWNpb19ydWxlcycpLmRhdGFzZXQuZG9uZSlyZXR1cm47IC8vIHNvbG8gbGEgcHJpbWVyYSB2ZXogKG5vIHBpc2FyIGxvIHF1ZSBlbCB1c3VhcmlvIHRvY8OzKQogICQoJ3ByZWNpb19ydWxlcycpLmlubmVySFRNTD1QUklDRV9BQ1RJT05TLm1hcChyPT4KICAgICc8ZGl2IHN0eWxlPSJib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjEwcHggMTJweDtiYWNrZ3JvdW5kOiNmZmYiPicrCiAgICAgICc8ZGl2IGNsYXNzPSJiIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPicrci5sYWJlbCsnPC9kaXY+JysKICAgICAgJzxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O21hcmdpbi10b3A6NnB4O2FsaWduLWl0ZW1zOmZsZXgtZW5kIj4nKwogICAgICAgICc8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPlJlZ2xhPC9sYWJlbD48c2VsZWN0IGlkPSJwci1tb2RlLScrci5jb2RlKyciIG9uY2hhbmdlPSJwck1vZGVDaGFuZ2UoXCcnK3IuY29kZSsnXCcpIj4nKwogICAgICAgICAgJzxvcHRpb24gdmFsdWU9Im5vbmUiJysoci5tb2RlPT09J25vbmUnPycgc2VsZWN0ZWQnOicnKSsnPlNpbiBjYW1iaW88L29wdGlvbj4nKwogICAgICAgICAgJzxvcHRpb24gdmFsdWU9Im1hcmdpbiInKyhyLm1vZGU9PT0nbWFyZ2luJz8nIHNlbGVjdGVkJzonJykrJz5NYXJnZW4gb2JqZXRpdm8gJTwvb3B0aW9uPicrCiAgICAgICAgICAnPG9wdGlvbiB2YWx1ZT0icGN0IicrKHIubW9kZT09PSdwY3QnPycgc2VsZWN0ZWQnOicnKSsnPkFqdXN0ZSAlPC9vcHRpb24+JysKICAgICAgICAnPC9zZWxlY3Q+PC9kaXY+JysKICAgICAgICAnPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbCBpZD0icHItbGJsLScrci5jb2RlKyciPicrKHIubW9kZT09PSdtYXJnaW4nPydNYXJnZW4gJSc6J0FqdXN0ZSAlJykrJzwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InByLXZhbC0nK3IuY29kZSsnIiBzdGVwPSIwLjUiIHZhbHVlPSInK3IudmFsKyciIHN0eWxlPSJ3aWR0aDo4MHB4IicrKHIubW9kZT09PSdub25lJz8nIGRpc2FibGVkJzonJykrJz48L2Rpdj4nKwogICAgICAnPC9kaXY+PC9kaXY+Jykuam9pbignJyk7CiAgJCgncHJlY2lvX3J1bGVzJykuZGF0YXNldC5kb25lPScxJzsKfQpmdW5jdGlvbiBwck1vZGVDaGFuZ2UoY29kZSl7Y29uc3QgbT0kKCdwci1tb2RlLScrY29kZSkudmFsdWU7JCgncHItdmFsLScrY29kZSkuZGlzYWJsZWQ9KG09PT0nbm9uZScpOyQoJ3ByLWxibC0nK2NvZGUpLnRleHRDb250ZW50PShtPT09J21hcmdpbic/J01hcmdlbiAlJzonQWp1c3RlICUnKTt9CmZ1bmN0aW9uIGN1cnJlbnRQcmljZVJ1bGVzKCl7Y29uc3QgcnVsZXM9e307UFJJQ0VfQUNUSU9OUy5mb3JFYWNoKHI9Pntjb25zdCBtb2RlPSQoJ3ByLW1vZGUtJytyLmNvZGUpLnZhbHVlO2NvbnN0IHZhbHVlPSskKCdwci12YWwtJytyLmNvZGUpLnZhbHVlO3J1bGVzW3IuY29kZV09e21vZGUsdmFsdWV9O30pO3JldHVybiBydWxlczt9CmxldCBQUkVWSUVXPVtdOwphc3luYyBmdW5jdGlvbiBwcmV2aWV3UHJlY2lvcygpewogIGNvbnN0IHNlbD0kKCdhY2NvdW50JykudmFsdWU7CiAgJCgncHJlY2lvX3ByZXZfaW5mbycpLnRleHRDb250ZW50PSdDYWxjdWxhbmRvIHByZWNpb3PigKYnOwogIHRyeXsKICAgIGNvbnN0IGJvZHk9e3J1bGVzOmN1cnJlbnRQcmljZVJ1bGVzKCksYWNjb3VudF9pZDpzZWx9OwogICAgY29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL3ByZWNpb3MvcGxhbj8nK2VzdHJQYXJhbXMoKSx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KGJvZHkpfSk7CiAgICBQUkVWSUVXPWQuY2hhbmdlc3x8W107CiAgICBjb25zdCBzaz1kLnNraXBwZWR8fHt9OwogICAgJCgncHJlY2lvX3ByZXZfaW5mbycpLmlubmVySFRNTD0oZC5jb3VudHx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBjYW1iaW9zJysoKHNrLnNpbl9lbnJpcXVlY2VyfHxzay5tYXJnZW5faW1wb3NpYmxlKT8oJyDCtyA8c3BhbiBjbGFzcz0ibXV0ZWQiPicrKHNrLnNpbl9lbnJpcXVlY2VyfHwwKSsnIHNpbiBlbnJpcXVlY2VyLCAnKyhzay5tYXJnZW5faW1wb3NpYmxlfHwwKSsnIG1hcmdlbiBpbXBvc2libGU8L3NwYW4+Jyk6JycpOwogICAgcmVuZGVyUHJldmlldygpOwogIH1jYXRjaChlKXskKCdwcmVjaW9fcHJldl9pbmZvJykudGV4dENvbnRlbnQ9J0Vycm9yOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpO30KfQpmdW5jdGlvbiByZW5kZXJQcmV2aWV3KCl7CiAgY29uc3QgdGI9JCgncHJlY2lvX2JvZHknKTsKICBpZighUFJFVklFVy5sZW5ndGgpeyQoJ3ByZWNpb1RhYmxlJykuc3R5bGUuZGlzcGxheT0nbm9uZSc7JCgncHJlY2lvX2FwcGx5X2J0bicpLnN0eWxlLmRpc3BsYXk9J25vbmUnOyQoJ3ByZWNpb194bHN4X2J0bicpLnN0eWxlLmRpc3BsYXk9J25vbmUnO3JldHVybjt9CiAgJCgncHJlY2lvVGFibGUnKS5zdHlsZS5kaXNwbGF5PScnOyQoJ3ByZWNpb194bHN4X2J0bicpLnN0eWxlLmRpc3BsYXk9Jyc7CiAgdGIuaW5uZXJIVE1MPVBSRVZJRVcuc2xpY2UoMCwzMDApLm1hcCgoYyxpZHgpPT57CiAgICBjb25zdCB1cD0oYy5kZWx0YVBjdHx8MCk+PTA7CiAgICByZXR1cm4gJzx0cj48dGQ+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBjbGFzcz0icHItY2hrIiBkYXRhLWlkeD0iJytpZHgrJyIgY2hlY2tlZCBvbmNsaWNrPSJ1cGRhdGVBcHBseUNvdW50KCkiPjwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibmFtZSI+Jytlc2MoYy50aXRsZXx8Yy5pdGVtX2lkKSsnPHNwYW4gY2xhc3M9ImlkIj4nK2MuaXRlbV9pZCsnPC9zcGFuPjwvdGQ+JysKICAgICAgJzx0ZD4nK2VzYyhjLmFjY291bnRfbmFtZXx8JycpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjExcHgiPicrZXNjKChjLmFjdGlvbkNvZGV8fCcnKSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KGMucHJpY2VOb3cpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSBiIj4nK2ZtdE1vbmV5KGMucHJpY2VOZXcpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKHVwPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykrJyI+JysoYy5kZWx0YVBjdD09bnVsbD8n4oCUJzoodXA/JysnOicnKStjLmRlbHRhUGN0LnRvRml4ZWQoMSkrJyUnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKGMubWFyZ2luTm93PT1udWxsPyfigJQnOmZtdFBjdChjLm1hcmdpbk5vdykpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSBiIiBzdHlsZT0iY29sb3I6dmFyKC0tZ3JlZW4pIj4nKyhjLm1hcmdpbk5ldz09bnVsbD8n4oCUJzpmbXRQY3QoYy5tYXJnaW5OZXcpKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJyk7CiAgdXBkYXRlQXBwbHlDb3VudCgpOwp9CmZ1bmN0aW9uIHRvZ2dsZVByZWNpb0FsbChlbCl7ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnByLWNoaycpLmZvckVhY2goYz0+Yy5jaGVja2VkPWVsLmNoZWNrZWQpO3VwZGF0ZUFwcGx5Q291bnQoKTt9CmZ1bmN0aW9uIHNlbGVjdGVkQ2hhbmdlcygpe2NvbnN0IG91dD1bXTtkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcucHItY2hrJykuZm9yRWFjaChjPT57aWYoYy5jaGVja2VkKXtjb25zdCBpdD1QUkVWSUVXWytjLmRhdGFzZXQuaWR4XTtpZihpdClvdXQucHVzaCh7aXRlbV9pZDppdC5pdGVtX2lkLGFjY291bnRfaWQ6aXQuYWNjb3VudF9pZCxwcmljZTppdC5wcmljZU5ld30pO319KTtyZXR1cm4gb3V0O30KZnVuY3Rpb24gdXBkYXRlQXBwbHlDb3VudCgpe2NvbnN0IG49c2VsZWN0ZWRDaGFuZ2VzKCkubGVuZ3RoOyQoJ3ByZWNpb19hcHBseV9uJykudGV4dENvbnRlbnQ9bjskKCdwcmVjaW9fYXBwbHlfYnRuJykuc3R5bGUuZGlzcGxheT1uPycnOidub25lJzt9CmFzeW5jIGZ1bmN0aW9uIGFwbGljYXJQcmVjaW9zKCl7CiAgY29uc3QgY2hhbmdlcz1zZWxlY3RlZENoYW5nZXMoKTsKICBpZighY2hhbmdlcy5sZW5ndGgpe3RvYXN0KCdObyBoYXkgY2FtYmlvcyBzZWxlY2Npb25hZG9zJyk7cmV0dXJuO30KICBpZighY29uZmlybSgnVmFzIGEgY2FtYmlhciBlbCBwcmVjaW8gZGUgJytjaGFuZ2VzLmxlbmd0aCsnIHB1YmxpY2FjaW9uZXMgZW4gTWVyY2FkbyBMaWJyZS4gwr9Db25maXJtw6FzPycpKXJldHVybjsKICAkKCdwcmVjaW9fYXBwbHlfYnRuJykuZGlzYWJsZWQ9dHJ1ZTskKCdwcmVjaW9fcHJldl9pbmZvJykudGV4dENvbnRlbnQ9J0FwbGljYW5kbyAnK2NoYW5nZXMubGVuZ3RoKycgY2FtYmlvcyBlbiBNTOKApic7CiAgdHJ5ewogICAgbGV0IG9rPTAsZXJyPTA7CiAgICBmb3IobGV0IGk9MDtpPGNoYW5nZXMubGVuZ3RoO2krPTIwMCl7CiAgICAgIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9wcmVjaW9zL2FwbGljYXInLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2NoYW5nZXM6Y2hhbmdlcy5zbGljZShpLGkrMjAwKX0pfSk7CiAgICAgIG9rKz1kLmFwcGxpZWR8fDA7ZXJyKz1kLmZhaWxlZHx8MDsKICAgICAgJCgncHJlY2lvX3ByZXZfaW5mbycpLnRleHRDb250ZW50PSdBcGxpY2Fkb3MgJytvaysnIMK3IGVycm9yZXMgJytlcnIrJ+KApic7CiAgICB9CiAgICB0b2FzdCgn4pyFIFByZWNpb3MgYXBsaWNhZG9zOiAnK29rKycgwrcgZXJyb3JlczogJytlcnIpOwogICAgJCgncHJlY2lvX3ByZXZfaW5mbycpLnRleHRDb250ZW50PSdMaXN0bzogJytvaysnIGFwbGljYWRvcywgJytlcnIrJyBlcnJvcmVzLiBSZS1lbnJpcXVlY8OpIHBhcmEgdmVyIGxvcyBudWV2b3MgbcOhcmdlbmVzLic7CiAgfWNhdGNoKGUpe3RvYXN0KCdFcnJvcjogJysoZS5lcnJvcnx8ZSkpO30KICBmaW5hbGx5eyQoJ3ByZWNpb19hcHBseV9idG4nKS5kaXNhYmxlZD1mYWxzZTt9Cn0KZnVuY3Rpb24gZG93bmxvYWRQcmVjaW9zWGxzeCgpewogIGlmKCFQUkVWSUVXLmxlbmd0aCl7dG9hc3QoJ0hhY8OpIGxhIHZpc3RhIHByZXZpYSBwcmltZXJvJyk7cmV0dXJuO30KICBjb25zdCBkYXRhPVBSRVZJRVcubWFwKGM9Pih7UHJvZHVjdG86Yy50aXRsZSxJdGVtSUQ6Yy5pdGVtX2lkLEN1ZW50YTpjLmFjY291bnRfbmFtZSxBY2Npb246Yy5hY3Rpb25Db2RlLFByZWNpb19hY3R1YWw6Yy5wcmljZU5vdyxQcmVjaW9fbnVldm86Yy5wcmljZU5ldyxEZWx0YV9wY3Q6Yy5kZWx0YVBjdD09bnVsbD8nJzorYy5kZWx0YVBjdC50b0ZpeGVkKDEpLE1hcmdlbl9hY3R1YWw6Yy5tYXJnaW5Ob3c9PW51bGw/Jyc6K2MubWFyZ2luTm93LnRvRml4ZWQoMSksTWFyZ2VuX251ZXZvOmMubWFyZ2luTmV3PT1udWxsPycnOitjLm1hcmdpbk5ldy50b0ZpeGVkKDEpfSkpOwogIGNvbnN0IHdzPVhMU1gudXRpbHMuanNvbl90b19zaGVldChkYXRhKTtjb25zdCB3Yj1YTFNYLnV0aWxzLmJvb2tfbmV3KCk7WExTWC51dGlscy5ib29rX2FwcGVuZF9zaGVldCh3Yix3cywnUHJlY2lvcycpOwogIFhMU1gud3JpdGVGaWxlKHdiLCdwbGFuX3ByZWNpb3NfJysobmV3IERhdGUoKS50b0lTT1N0cmluZygpLnNsaWNlKDAsMTApKSsnLnhsc3gnKTsKfQoKLy8gLS0tLSBQVUJMSUNJREFEIC0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZENhbXBhaWducygpewogIGNvbnN0IGlkPSQoJ2FjY291bnQnKS52YWx1ZTtpZighaWQpcmV0dXJuOwogICQoJ2Jhbm5lcicpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICAkKCd0Ym9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMiIgY2xhc3M9ImxvYWRpbmciPkNhcmdhbmRvIGNhbXBhw7Fhc+KApjwvdGQ+PC90cj4nOwogIHRyeXtjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvY2FtcGFpZ25zP2FjY291bnRfaWQ9JytpZCk7U1RBVEUuY2ZnPWQuY29uZmlnfHxTVEFURS5jZmc7U1RBVEUucm93cz0oZC5jYW1wYWlnbnN8fFtdKS5tYXAoZW5yaWNoKTtyZW5kZXIoKTt9CiAgY2F0Y2goZSl7U1RBVEUucm93cz1bXTtyZW5kZXIoKTskKCdiYW5uZXJNc2cnKS50ZXh0Q29udGVudD10eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcik7JCgnYmFubmVyJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpO30KfQpmdW5jdGlvbiBlbnJpY2gocil7Y29uc3QgbT1yLm1ldHJpY3N8fHt9O2NvbnN0IGN0cj1tLnByaW50cz4wPyhtLmNsaWNrcy9tLnByaW50cyoxMDApOm51bGw7cmV0dXJuIHsuLi5yLGNvc3Q6bS5jb3N0fHwwLHJldmVudWU6bS5yZXZlbnVlfHwwLGFjb3M6bS5hY29zLHJvYXM6bS5yb2FzLGNsaWNrczptLmNsaWNrc3x8MCxwcmludHM6bS5wcmludHN8fDAsdW5pdHM6bS51bml0c3x8MCxjdHJ9O30KZnVuY3Rpb24gdG9nZ2xlQ2hpcChlbCl7ZWwuY2xhc3NMaXN0LnRvZ2dsZSgnb24nKTtTVEFURS5hY3RzW2VsLmRhdGFzZXQuYWN0XT1lbC5jbGFzc0xpc3QuY29udGFpbnMoJ29uJyk/MTowO3JlbmRlcigpO30KZnVuY3Rpb24gc29ydEJ5KGspe2lmKFNUQVRFLnNvcnRLZXk9PT1rKVNUQVRFLnNvcnREaXIqPS0xO2Vsc2V7U1RBVEUuc29ydEtleT1rO1NUQVRFLnNvcnREaXI9LTE7fXJlbmRlcigpO30KZnVuY3Rpb24gYWN0aW9uUGlsbChhKXtjb25zdCBtYXA9e0VTQ0FMQVI6WydwLWdyZWVuJywn8J+foiBFc2NhbGFyJ10sTUFOVEVORVI6WydwLWFtYmVyJywn8J+foSBNYW50ZW5lciddLEpVTlRBUl9EQVRPUzpbJ3AtYmx1ZScsJ/CflLUgSnVudGFyIGRhdG9zJ10sUEFVU0FSOlsncC1yZWQnLCfwn5S0IFBhdXNhciddfTtjb25zdFtjbHMsdHh0XT1tYXBbYV18fFsncC1ncmV5JyxhXTtyZXR1cm4gJzxzcGFuIGNsYXNzPSJwaWxsICcrY2xzKyciPicrdHh0Kyc8L3NwYW4+Jzt9CmZ1bmN0aW9uIGFjb3NCYXIoYWNvcyxiZSl7Y29uc3QgYmUyPShiZSE9bnVsbCk/YmU6KCtTVEFURS5jZmcubWFyZ2lufHwxMik7Y29uc3QgdGFyZ2V0PShiZSE9bnVsbCk/YmUqMC42OigrU1RBVEUuY2ZnLmFjb3NUYXJnZXR8fDcpO2lmKGFjb3M9PW51bGwpcmV0dXJuICc8c3BhbiBjbGFzcz0ibXV0ZWQiPnMvdmVudGE8L3NwYW4+Jztjb25zdCBwY3Q9TWF0aC5taW4oMTAwLGFjb3MvKGJlMioxLjYpKjEwMCk7bGV0IGNvbD1hY29zPD10YXJnZXQ/J3ZhcigtLWdyZWVuKSc6KGFjb3M8PWJlMj8ndmFyKC0tYW1iZXIpJzondmFyKC0tcmVkKScpO3JldHVybiAnPGRpdiBjbGFzcz0iYWNvc2NlbGwiPjxzcGFuPicrZm10UGN0KGFjb3MpKyc8L3NwYW4+PGRpdiBjbGFzcz0iYWNvc2JhciI+PGkgc3R5bGU9IndpZHRoOicrcGN0KyclO2JhY2tncm91bmQ6Jytjb2wrJyI+PC9pPjwvZGl2PjwvZGl2Pic7fQpmdW5jdGlvbiBmaWx0ZXJlZFJvd3MoKXtjb25zdCBxPSgkKCdzZWFyY2gnKS52YWx1ZXx8JycpLnRvTG93ZXJDYXNlKCkudHJpbSgpO2NvbnN0IHN0PSQoJ3N0YXR1c0ZpbHRlcicpLnZhbHVlO2xldCByb3dzPVNUQVRFLnJvd3MuZmlsdGVyKHI9PlNUQVRFLmFjdHNbci5hY3Rpb25dKTtpZihzdCE9PSdhbGwnKXJvd3M9cm93cy5maWx0ZXIocj0+U3RyaW5nKHIuc3RhdHVzKS50b0xvd2VyQ2FzZSgpPT09c3QpO2lmKHEpcm93cz1yb3dzLmZpbHRlcihyPT4oci5uYW1lfHwnJykudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhxKXx8U3RyaW5nKHIuY2FtcGFpZ25faWQpLmluY2x1ZGVzKHEpKTtjb25zdCBrPVNUQVRFLnNvcnRLZXksZGlyPVNUQVRFLnNvcnREaXI7cm93cy5zb3J0KChhLGIpPT57bGV0IHg9YVtrXSx5PWJba107aWYoaz09PSduYW1lJ3x8az09PSdzdGF0dXMnfHxrPT09J2FjdGlvbicpe3g9U3RyaW5nKHh8fCcnKTt5PVN0cmluZyh5fHwnJyk7cmV0dXJuIGRpcip4LmxvY2FsZUNvbXBhcmUoeSk7fXg9KHg9PW51bGw/LTE6eCk7eT0oeT09bnVsbD8tMTp5KTtyZXR1cm4gZGlyKih4LXkpO30pO3JldHVybiByb3dzO30KZnVuY3Rpb24gcmVuZGVyKCl7CiAgY29uc3Qgcm93cz1maWx0ZXJlZFJvd3MoKTtyZW5kZXJLcGlzKCk7Y29uc3QgdGI9JCgndGJvZHknKTsKICBpZighcm93cy5sZW5ndGgpe3RiLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMiIgY2xhc3M9ImVtcHR5Ij5ObyBoYXkgY2FtcGHDsWFzIHF1ZSBjb2luY2lkYW4uPC90ZD48L3RyPic7cmV0dXJuO30KICB0Yi5pbm5lckhUTUw9cm93cy5tYXAocj0+e2NvbnN0IGlzQT1TdHJpbmcoci5zdGF0dXMpLnRvTG93ZXJDYXNlKCk9PT0nYWN0aXZlJztjb25zdCBzdFBpbGw9aXNBPyc8c3BhbiBjbGFzcz0icGlsbCBwLWdyZWVuIj5BY3RpdmE8L3NwYW4+JzonPHNwYW4gY2xhc3M9InBpbGwgcC1ncmV5Ij4nKyhyLnN0YXR1c3x8J+KAlCcpKyc8L3NwYW4+JzsKICAgIGNvbnN0IGJ0bj1pc0E/JzxidXR0b24gY2xhc3M9InJvd2J0biBwYXVzZSIgb25jbGljaz0ic2V0U3RhdHVzKFwnJytyLmNhbXBhaWduX2lkKydcJyxcJ3BhdXNlZFwnKSI+UGF1c2FyPC9idXR0b24+JzonPGJ1dHRvbiBjbGFzcz0icm93YnRuIHBsYXkiIG9uY2xpY2s9InNldFN0YXR1cyhcJycrci5jYW1wYWlnbl9pZCsnXCcsXCdhY3RpdmVcJykiPkFjdGl2YXI8L2J1dHRvbj4nOwogICAgcmV0dXJuICc8dHI+PHRkIGNsYXNzPSJuYW1lIj4nK2VzYyhyLm5hbWUpKyc8c3BhbiBjbGFzcz0iaWQiPicrci5jYW1wYWlnbl9pZCsnPC9zcGFuPjwvdGQ+PHRkPicrc3RQaWxsKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHIuY29zdCkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoci5yZXZlbnVlKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JythY29zQmFyKHIuYWNvcyxyLmJyZWFrZXZlbkFjb3MpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhyLmJyZWFrZXZlbkFjb3MhPW51bGw/Zm10UGN0KHIuYnJlYWtldmVuQWNvcyk6JzxzcGFuIGNsYXNzPSJtdXRlZCI+cy9jb3N0bzwvc3Bhbj4nKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDtjb2xvcjonKyhyLm5ldFByb2ZpdD09bnVsbD8ndmFyKC0tbXV0KSc6KHIubmV0UHJvZml0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykpKyciPicrKHIubmV0UHJvZml0PT1udWxsPyfigJQnOmZtdE1vbmV5KHIubmV0UHJvZml0KSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10WChyLnJvYXMpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK3IuY2xpY2tzLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L3RkPjx0ZD4nK2FjdGlvblBpbGwoci5hY3Rpb24pKyc8L3RkPjx0ZCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJ3aGl0ZS1zcGFjZTpub3JtYWw7bWF4LXdpZHRoOjIwMHB4Ij4nK2VzYyhyLnJlYXNvbnx8JycpKyc8L3RkPjx0ZD4nK2J0bisnPC90ZD48L3RyPic7fSkuam9pbignJyk7Cn0KZnVuY3Rpb24gcmVuZGVyS3BpcygpewogIGNvbnN0IHJvd3M9U1RBVEUucm93cztjb25zdCBjb3N0PXJvd3MucmVkdWNlKChzLHIpPT5zKyhyLmNvc3R8fDApLDApO2NvbnN0IHJldj1yb3dzLnJlZHVjZSgocyxyKT0+cysoci5yZXZlbnVlfHwwKSwwKTsKICBjb25zdCBhY29zPXJldj4wP2Nvc3QvcmV2KjEwMDpudWxsO2NvbnN0IHJvYXM9Y29zdD4wP3Jldi9jb3N0Om51bGw7Y29uc3QgbWFyZ2luPStTVEFURS5jZmcubWFyZ2lufHwxMjsKICBjb25zdCBjbnQ9YT0+cm93cy5maWx0ZXIocj0+ci5hY3Rpb249PT1hKS5sZW5ndGg7CiAgY29uc3QgcmVhbFJvd3M9cm93cy5maWx0ZXIocj0+ci5uZXRQcm9maXQhPW51bGwpO2NvbnN0IHJlYWxOZXQ9cmVhbFJvd3MucmVkdWNlKChzLHIpPT5zK3IubmV0UHJvZml0LDApO2NvbnN0IGhhc1JlYWw9cmVhbFJvd3MubGVuZ3RoPjA7CiAgY29uc3QgYWNvc0Nscz1hY29zPT1udWxsPycnOihhY29zPD0oK1NUQVRFLmNmZy5hY29zVGFyZ2V0fHw3KT8nZ29vZCc6KGFjb3M8PW1hcmdpbj8nd2Fybic6J2JhZCcpKTsKICBjb25zdCB0aWxlcz1bWydJbnZlcnNpw7NuJyxmbXRNb25leShjb3N0KSwnJ10sWydWZW50YXMgcG9yIHB1Yi4nLGZtdE1vbmV5KHJldiksJyddLFsnQUNPUyBnbG9iYWwnLGZtdFBjdChhY29zKSxhY29zQ2xzXSxbJ1JPQVMgZ2xvYmFsJyxmbXRYKHJvYXMpLHJvYXMmJnJvYXM+PTEvKG1hcmdpbi8xMDApPydnb29kJzond2FybiddLFtoYXNSZWFsPydHYW5hbmNpYSBuZXRhIHJlYWwnOidHYW5hbmNpYSBlc3RpbS4nLGZtdE1vbmV5KGhhc1JlYWw/cmVhbE5ldDpyZXYqKG1hcmdpbi8xMDApLWNvc3QpLChoYXNSZWFsP3JlYWxOZXQ6cmV2KihtYXJnaW4vMTAwKS1jb3N0KT49MD8nZ29vZCc6J2JhZCddLFsn8J+foicrY250KCdFU0NBTEFSJykrJyDwn5+hJytjbnQoJ01BTlRFTkVSJykrJyDwn5S0JytjbnQoJ1BBVVNBUicpLCcnLCcnXV07CiAgJCgna3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAoKHQsaSk9Pmk9PT01Pyc8ZGl2IGNsYXNzPSJrcGkiPjxkaXYgY2xhc3M9ImsiPlNlbcOhZm9ybzwvZGl2PjxkaXYgY2xhc3M9InYgc21hbGwiPicrdFswXSsnPC9kaXY+PC9kaXY+JzonPGRpdiBjbGFzcz0ia3BpICcrdFsyXSsnIj48ZGl2IGNsYXNzPSJrIj4nK3RbMF0rJzwvZGl2PjxkaXYgY2xhc3M9InYgc21hbGwiPicrdFsxXSsnPC9kaXY+PC9kaXY+Jykuam9pbignJyk7Cn0KYXN5bmMgZnVuY3Rpb24gc2V0U3RhdHVzKGNpZCxzdGF0dXMpewogIGNvbnN0IGFjY291bnRfaWQ9JCgnYWNjb3VudCcpLnZhbHVlOwogIHRyeXthd2FpdCBhcGkoJy9hcGkvYWRzL2NhbXBhaWduLXN0YXR1cycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7YWNjb3VudF9pZCxjYW1wYWlnbl9pZDpjaWQsc3RhdHVzfSl9KTtjb25zdCByb3c9U1RBVEUucm93cy5maW5kKHI9PlN0cmluZyhyLmNhbXBhaWduX2lkKT09PVN0cmluZyhjaWQpKTtpZihyb3cpcm93LnN0YXR1cz1zdGF0dXM7dG9hc3QoJ0NhbXBhw7FhICcrKHN0YXR1cz09PSdwYXVzZWQnPydwYXVzYWRhJzonYWN0aXZhZGEnKSk7cmVuZGVyKCk7fQogIGNhdGNoKGUpe3RvYXN0KCdObyBzZSBwdWRvOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpKTt9Cn0KYXN5bmMgZnVuY3Rpb24gcnVuTm93KCl7CiAgdHJ5e3RvYXN0KCdDb3JyaWVuZG8gYW7DoWxpc2lz4oCmJyk7Y29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL3J1bi1ub3cnLHttZXRob2Q6J1BPU1QnfSk7Y29uc3QgcGF1c2VkPWQucmVzdWx0cy5maWx0ZXIocj0+ci5wYXVzZWQpLmxlbmd0aCx3b3VsZD1kLnJlc3VsdHMuZmlsdGVyKHI9PnIud291bGRfcGF1c2UpLmxlbmd0aDt0b2FzdChkLmRyeV9ydW4/KCdEUlktUlVOOiBwYXVzYXLDrWEgJyt3b3VsZCk6KCdMaXN0bzogJytwYXVzZWQrJyBwYXVzYWRhcycpKTtsb2FkQ2FtcGFpZ25zKCk7bG9hZExvZygpO30KICBjYXRjaChlKXt0b2FzdCgnRXJyb3I6ICcrKGUuZXJyb3J8fGUpKTt9Cn0KYXN5bmMgZnVuY3Rpb24gbG9hZExvZygpewogIHRyeXtjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvbG9nJyk7JCgnbGFzdFJ1bicpLnRleHRDb250ZW50PWQubGFzdF9ydW4/KCfDmmx0aW1hIGNvcnJpZGE6ICcrbmV3IERhdGUoZC5sYXN0X3J1bikudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykpOidTaW4gY29ycmlkYXMgYcO6bic7CiAgY29uc3QgcnVucz1kLnJ1bnN8fFtdOyQoJ2xvZ2NhcmQnKS5pbm5lckhUTUw9cnVucy5sZW5ndGg/cnVucy5tYXAocnVuPT57Y29uc3QgaGVhZD0nPGRpdiBjbGFzcz0iYiI+JytuZXcgRGF0ZShydW4uYXQpLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgwrcgJysocnVuLmRyeV9ydW4/J0RSWS1SVU4nOidMSVZFJykrJzwvZGl2Pic7Y29uc3QgaXRlbXM9KHJ1bi5yZXN1bHRzfHxbXSkuZmlsdGVyKHI9PnIud291bGRfcGF1c2V8fHIucGF1c2VkfHxyLmVycm9yKS5tYXAocj0+JzxkaXYgY2xhc3M9ImxvZ3JvdyI+PHNwYW4gY2xhc3M9InBpbGwgJysoci5wYXVzZWQ/J3AtcmVkJzooci5lcnJvcj8ncC1ncmV5JzoncC1hbWJlcicpKSsnIj4nKyhyLnBhdXNlZD8ncGF1c2FkYSc6KHIuZXJyb3I/J2Vycm9yJzonYSBwYXVzYXInKSkrJzwvc3Bhbj4gPHNwYW4gY2xhc3M9ImIiPicrZXNjKHIubmFtZXx8ci5hY2NvdW50fHwnJykrJzwvc3Bhbj4gPHNwYW4gY2xhc3M9Im11dGVkIj4nK2VzYyhyLnJlYXNvbnx8ci5lcnJvcnx8JycpKyc8L3NwYW4+PC9kaXY+Jykuam9pbignJyl8fCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9InBhZGRpbmc6NnB4IDAiPlNpbiBjYW1iaW9zLjwvZGl2Pic7cmV0dXJuIGhlYWQraXRlbXM7fSkuam9pbignPGhyIHN0eWxlPSJib3JkZXI6bm9uZTtib3JkZXItdG9wOjFweCBzb2xpZCB2YXIoLS1saW5lKTttYXJnaW46MTBweCAwIj4nKTonPGRpdiBjbGFzcz0ibXV0ZWQiPlNpbiBjb3JyaWRhcy48L2Rpdj4nO31jYXRjaChlKXt9Cn0KZnVuY3Rpb24gdG9nZ2xlTG9nKCl7Y29uc3QgYz0kKCdsb2djYXJkJyk7Yy5jbGFzc0xpc3QudG9nZ2xlKCdzaG93Jyk7aWYoYy5jbGFzc0xpc3QuY29udGFpbnMoJ3Nob3cnKSlsb2FkTG9nKCk7fQoKLy8gLS0tLSBHQU5BRE9SQVMgLS0tLQphc3luYyBmdW5jdGlvbiBsb2FkV2lubmVycygpewogIGNvbnN0IGlkPSQoJ2FjY291bnQnKS52YWx1ZTtpZighaWQpe3RvYXN0KCdFbGVnw60gdW5hIGN1ZW50YScpO3JldHVybjt9CiAgY29uc3QgbT0kKCd3aW5fbWFyZ2luJykudmFsdWV8fDEyLHM9JCgnd2luX3NhbGVzJykudmFsdWV8fDAsbD0kKCd3aW5fbGltaXQnKS52YWx1ZXx8NDA7CiAgJCgnd2luU3RhdHVzJykudGV4dENvbnRlbnQ9J0J1c2NhbmRv4oCmJzsKICB0cnl7Y29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL3dpbm5lcnM/YWNjb3VudF9pZD0nK2lkKycmbWluTWFyZ2luPScrbSsnJm1pblNhbGVzPScrcysnJmxpbWl0PScrbCk7V0lOTkVSUz1kLndpbm5lcnN8fFtdOwogICQoJ3dpblN0YXR1cycpLmlubmVySFRNTD0nPGI+JytXSU5ORVJTLmxlbmd0aCsnPC9iPiBnYW5hZG9yYXMnKyhkLnNjYW5uZWQ/KCcgKGRlICcrZC5zY2FubmVkKycgcmV2aXNhZGFzKScpOicnKSsoZC5ub3RlPygnIMK3ICcrZXNjKGQubm90ZSkpOicnKTtyZW5kZXJXaW5uZXJzKCk7fQogIGNhdGNoKGUpeyQoJ3dpblN0YXR1cycpLnRleHRDb250ZW50PSdFcnJvcjogJysodHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKTt9Cn0KZnVuY3Rpb24gcmVuZGVyV2lubmVycygpewogIGNvbnN0IHRiPSQoJ3dpbkJvZHknKTtpZighV0lOTkVSUy5sZW5ndGgpe3RiLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSI1IiBjbGFzcz0iZW1wdHkiPlNpbiByZXN1bHRhZG9zLjwvdGQ+PC90cj4nO3JldHVybjt9CiAgdGIuaW5uZXJIVE1MPVdJTk5FUlMubWFwKHc9Pic8dHI+PHRkIGNsYXNzPSJuYW1lIj48YSBocmVmPSInKyh3LnBlcm1hbGlua3x8JyMnKSsnIiB0YXJnZXQ9Il9ibGFuayI+Jytlc2Mody50aXRsZXx8dy5pdGVtX2lkKSsnPC9hPjxzcGFuIGNsYXNzPSJpZCI+Jyt3Lml0ZW1faWQrJzwvc3Bhbj48L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdFBjdCh3Lm1hcmdpbikrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkody5wcmljZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrdy5zdG9jaysnPC90ZD48dGQgY2xhc3M9Im51bSI+Jyt3LnNvbGQrJzwvdGQ+PC90cj4nKS5qb2luKCcnKTsKfQpmdW5jdGlvbiBjb3B5V2lubmVycygpe2lmKCFXSU5ORVJTLmxlbmd0aCl7dG9hc3QoJ0J1c2PDoSBnYW5hZG9yYXMgcHJpbWVybycpO3JldHVybjt9Y29uc3QgaWRzPVdJTk5FUlMubWFwKHc9PncuaXRlbV9pZCkuam9pbignLCAnKTtpZihuYXZpZ2F0b3IuY2xpcGJvYXJkKXtuYXZpZ2F0b3IuY2xpcGJvYXJkLndyaXRlVGV4dChpZHMpLnRoZW4oKCk9PnRvYXN0KCdDb3BpYWRvcyAnK1dJTk5FUlMubGVuZ3RoKycgSURzJykpLmNhdGNoKCgpPT5wcm9tcHQoJ0NvcGnDoSBsb3MgSURzOicsaWRzKSk7fWVsc2UgcHJvbXB0KCdDb3Bpw6EgbG9zIElEczonLGlkcyk7fQpmdW5jdGlvbiBjc3ZXaW5uZXJzKCl7aWYoIVdJTk5FUlMubGVuZ3RoKXt0b2FzdCgnQnVzY8OhIGdhbmFkb3JhcyBwcmltZXJvJyk7cmV0dXJuO31jb25zdCByb3dzPVtbJ2l0ZW1faWQnLCd0aXR1bG8nLCdtYXJnZW5fJScsJ3ByZWNpbycsJ3N0b2NrJywndmVudGFzJ11dO1dJTk5FUlMuZm9yRWFjaCh3PT5yb3dzLnB1c2goW3cuaXRlbV9pZCwnIicrU3RyaW5nKHcudGl0bGV8fCcnKS5yZXBsYWNlKC8iL2csJycpKyciJyx3Lm1hcmdpbi50b0ZpeGVkKDEpLHcucHJpY2Usdy5zdG9jayx3LnNvbGRdKSk7Y29uc3QgY3N2PXJvd3MubWFwKHI9PnIuam9pbignLCcpKS5qb2luKCdcbicpO2NvbnN0IGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYScpO2EuaHJlZj0nZGF0YTp0ZXh0L2NzdjtjaGFyc2V0PXV0Zi04LCcrZW5jb2RlVVJJQ29tcG9uZW50KGNzdik7YS5kb3dubG9hZD0nZ2FuYWRvcmFzLmNzdic7YS5jbGljaygpO30KCi8vID09PT09PT09PT09PT09PT09PT09IEhJU1TDk1JJQ08gKGdlc3Rpw7NuIMK3IGTDrWFzIGd1YXJkYWRvcykgPT09PT09PT09PT09PT09PT09PT0KdmFyIEhJU1RfTE9BREVEPWZhbHNlLCBISVNUPW51bGwsIEhDSEFSVFM9e30sIEhGSUxUPW51bGw7CmZ1bmN0aW9uIGRQbHVzKGRzLG4pe2NvbnN0IHA9ZHMuc3BsaXQoJy0nKS5tYXAoTnVtYmVyKTtjb25zdCBkdD1uZXcgRGF0ZShEYXRlLlVUQyhwWzBdLHBbMV0tMSxwWzJdKSk7ZHQuc2V0VVRDRGF0ZShkdC5nZXRVVENEYXRlKCkrbik7cmV0dXJuIGR0LnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCk7fQpmdW5jdGlvbiBkb3dMYWJlbChkcyl7Y29uc3QgcD1kcy5zcGxpdCgnLScpLm1hcChOdW1iZXIpO2NvbnN0IGc9bmV3IERhdGUoRGF0ZS5VVEMocFswXSxwWzFdLTEscFsyXSkpLmdldFVUQ0RheSgpO3JldHVybiBbJ0RPTUlOR08nLCdMVU5FUycsJ01BUlRFUycsJ01Jw4lSQ09MRVMnLCdKVUVWRVMnLCdWSUVSTkVTJywnU8OBQkFETyddW2ddO30KZnVuY3Rpb24gYWdnU2FsZXMoc2FsZXMpewogIHZhciBUPXtmYWN0dXJhY2lvbjowLHVuaWRhZGVzOjAsZmVlVG90YWw6MCxlbnZpb1RvdGFsOjAsdGF4VG90YWw6MCxmYWN0dXJhVG90YWw6MCxxdWVkYVRvdGFsOjAsY29zdFRvdGFsOjAsY29zdFN0b2NrVG90YWw6MCxnYW5hbmNpYTowLGdhbmFuY2lhU2luRmxleDowLHBlcmRpZGE6MCxwZXJkaWRhTW9udG86MCxjdW90YXNDb3VudDowLGNvbm9jaWRhczowLHNpbkNvc3RvOjAsZmFjdENvbm9jaWRhOjAsY291bnQ6MCxib25vVG90YWw6MCxmbGV4Q291bnQ6MH07CiAgdmFyIG9yZHM9e307CiAgZm9yKHZhciBpPTA7aTxzYWxlcy5sZW5ndGg7aSsrKXt2YXIgcz1zYWxlc1tpXTtULmNvdW50Kys7b3Jkc1tzLm9yZGVyX2lkXT0xO1QuZmFjdHVyYWNpb24rPXMucmV2ZW51ZXx8MDtULnVuaWRhZGVzKz1zLnF0eXx8MDtULmZlZVRvdGFsKz1zLmZlZXx8MDtULmVudmlvVG90YWwrPXMuZW52aW98fDA7VC50YXhUb3RhbCs9cy50YXh8fDA7VC5mYWN0dXJhVG90YWwrPXMuZmFjdHVyYXx8MDtULnF1ZWRhVG90YWwrPXMucXVlZGF8fDA7VC5ib25vVG90YWwrPXMuYm9ub3x8MDtpZihzLmZsZXgpVC5mbGV4Q291bnQrKztpZigocy5jdW90YXN8fDApPjEpVC5jdW90YXNDb3VudCsrOwogICAgaWYocy5rbm93bil7VC5jb25vY2lkYXMrKztULmZhY3RDb25vY2lkYSs9cy5yZXZlbnVlfHwwO1QuY29zdFRvdGFsKz1zLmNvc3R8fDA7VC5jb3N0U3RvY2tUb3RhbCs9KHMuY29zdF9zdG9jayE9bnVsbD9zLmNvc3Rfc3RvY2s6KHMuc3RvY2s/KHMuY29zdHx8MCk6MCkpO1QuZ2FuYW5jaWErPXMubmV0fHwwO1QuZ2FuYW5jaWFTaW5GbGV4Kz0ocy5uZXRfc2luX2ZsZXghPW51bGw/cy5uZXRfc2luX2ZsZXg6MCk7aWYocy5uZXQ8MCl7VC5wZXJkaWRhKys7VC5wZXJkaWRhTW9udG8rPXMubmV0O319ZWxzZSBULnNpbkNvc3RvKys7fQogIFQub3JkZXJzPU9iamVjdC5rZXlzKG9yZHMpLmxlbmd0aDtULm1hcmdpbj1ULmZhY3RDb25vY2lkYT4wPyhULmdhbmFuY2lhL1QuZmFjdENvbm9jaWRhKSoxMDA6bnVsbDtyZXR1cm4gVDsKfQphc3luYyBmdW5jdGlvbiBoaXN0TG9hZCgpewogICQoJ2hfbWV0YScpLnRleHRDb250ZW50PSdDYXJnYW5kbyBoaXN0w7NyaWNv4oCmJzsKICB0cnl7CiAgICBjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9nZXN0aW9uL2hpc3Rvcnk/ZGV0YWlsPTEnKTtISVNUPWQ7SElTVF9MT0FERUQ9dHJ1ZTsKICAgIGNvbnN0IGFjY3M9e30sc3RzPXt9OyhkLmRheXN8fFtdKS5mb3JFYWNoKGZ1bmN0aW9uKGRheSl7KGRheS5zYWxlc3x8W10pLmZvckVhY2goZnVuY3Rpb24ocyl7aWYocy5hY2NvdW50X25hbWUpYWNjc1tzLmFjY291bnRfbmFtZV09MTtpZihzLnN0YXR1cylzdHNbcy5zdGF0dXNdPTE7fSk7fSk7CiAgICBoaXN0RmlsbFNlbCgnaF9hY2NvdW50JyxPYmplY3Qua2V5cyhhY2NzKS5zb3J0KCksbnVsbCk7CiAgICBoaXN0RmlsbFNlbCgnaF9zdGF0dXMnLE9iamVjdC5rZXlzKHN0cykuc29ydCgpLHN0YXR1c0xhYmVsKTsKICAgIGNvbnN0IGR0cz0oZC5zYXZlZF9kYXRlc3x8W10pLnNsaWNlKCk7CiAgICBpZihkdHMubGVuZ3RoKXtpZighJCgnaF9mcm9tJykudmFsdWUpJCgnaF9mcm9tJykudmFsdWU9ZHRzWzBdO2lmKCEkKCdoX3RvJykudmFsdWUpJCgnaF90bycpLnZhbHVlPWR0c1tkdHMubGVuZ3RoLTFdO30KICAgIGhpc3RBcHBseUZpbHRlcnMoKTsKICB9Y2F0Y2goZSl7JCgnaF9tZXRhJykudGV4dENvbnRlbnQ9J0Vycm9yIGNhcmdhbmRvIGhpc3TDs3JpY286ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSk7fQp9CmZ1bmN0aW9uIGhpc3RGaWxsU2VsKGlkLGFycixsYWJlbEZuKXt2YXIgZWw9JChpZCk7aWYoIWVsKXJldHVybjt2YXIgY3VyPWVsLnZhbHVlO3ZhciBmPWVsLnF1ZXJ5U2VsZWN0b3IoJ29wdGlvbicpO3ZhciBoZWFkPWY/Zi50ZXh0Q29udGVudDonVG9kb3MnO2VsLmlubmVySFRNTD0nPG9wdGlvbiB2YWx1ZT0iIj4nK2hlYWQrJzwvb3B0aW9uPicrYXJyLm1hcChmdW5jdGlvbih2KXtyZXR1cm4gJzxvcHRpb24gdmFsdWU9IicrZXNjKFN0cmluZyh2KSkrJyI+Jytlc2MobGFiZWxGbj9sYWJlbEZuKHYpOlN0cmluZyh2KSkrJzwvb3B0aW9uPic7fSkuam9pbignJyk7ZWwudmFsdWU9Y3VyO30KZnVuY3Rpb24gaGlzdEZpbHRlclNhbGUocyl7CiAgdmFyIGFjYz0kKCdoX2FjY291bnQnKS52YWx1ZSxzdD0kKCdoX3N0YXR1cycpLnZhbHVlLGZsZXg9JCgnaF9mbGV4JykudmFsdWUsY29zdG89JCgnaF9jb3N0bycpLnZhbHVlLHJlcz0kKCdoX3JlcycpLnZhbHVlOwogIHZhciBvcmQ9KCQoJ2hfb3JkZXInKS52YWx1ZXx8JycpLnRyaW0oKSx0eHQ9KCQoJ2hfdGV4dCcpLnZhbHVlfHwnJykudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgaWYoYWNjJiYocy5hY2NvdW50X25hbWV8fCcnKSE9PWFjYylyZXR1cm4gZmFsc2U7CiAgaWYoc3QmJihzLnN0YXR1c3x8JycpIT09c3QpcmV0dXJuIGZhbHNlOwogIGlmKGZsZXg9PT0nMScmJiFzLmZsZXgpcmV0dXJuIGZhbHNlOwogIGlmKGZsZXg9PT0nMCcmJnMuZmxleClyZXR1cm4gZmFsc2U7CiAgaWYoY29zdG89PT0nMScmJiFzLmtub3duKXJldHVybiBmYWxzZTsKICBpZihjb3N0bz09PScwJyYmcy5rbm93bilyZXR1cm4gZmFsc2U7CiAgaWYocmVzPT09J2xvc3MnJiYhKHMubmV0IT1udWxsJiZzLm5ldDwwKSlyZXR1cm4gZmFsc2U7CiAgaWYocmVzPT09J3dpbicmJiEocy5uZXQhPW51bGwmJnMubmV0Pj0wKSlyZXR1cm4gZmFsc2U7CiAgaWYob3JkJiZTdHJpbmcocy5wYWNrX2lkfHwnJykuaW5kZXhPZihvcmQpPDAmJlN0cmluZyhzLm9yZGVyX2lkfHwnJykuaW5kZXhPZihvcmQpPDApcmV0dXJuIGZhbHNlOwogIGlmKHR4dCl7dmFyIGhheT0oKHMudGl0bGV8fCcnKSsnICcrKHMuc2t1fHwnJykrJyAnKyhzLnByb3ZlZWRvcnx8JycpKycgJysocy5pdGVtX2lkfHwnJykpLnRvTG93ZXJDYXNlKCk7aWYoaGF5LmluZGV4T2YodHh0KTwwKXJldHVybiBmYWxzZTt9CiAgcmV0dXJuIHRydWU7Cn0KZnVuY3Rpb24gaGlzdEFwcGx5RmlsdGVycygpewogIGlmKCFISVNUKXtyZXR1cm47fQogIHZhciBmcm9tPSQoJ2hfZnJvbScpLnZhbHVlLHRvPSQoJ2hfdG8nKS52YWx1ZTsKICB2YXIgZGF5cz0oSElTVC5kYXlzfHxbXSkuZmlsdGVyKGZ1bmN0aW9uKGQpe3JldHVybiAoIWZyb218fGQuZGF0ZT49ZnJvbSkmJighdG98fGQuZGF0ZTw9dG8pO30pOwogIHZhciBwZXJEYXk9ZGF5cy5tYXAoZnVuY3Rpb24oZCl7cmV0dXJuIHtkYXRlOmQuZGF0ZSxzYXZlZEJ5OmQuc2F2ZWRCeSxzYXZlZEF0OmQuc2F2ZWRBdCx0YXhQY3Q6ZC50YXhQY3Qsc2NvcGU6ZC5zY29wZSxzYWxlczooZC5zYWxlc3x8W10pLmZpbHRlcihoaXN0RmlsdGVyU2FsZSl9O30pOwogIHZhciBzYWxlcz1bXTtwZXJEYXkuZm9yRWFjaChmdW5jdGlvbihkKXtzYWxlcz1zYWxlcy5jb25jYXQoZC5zYWxlcyk7fSk7CiAgdmFyIFQ9YWdnU2FsZXMoc2FsZXMpOwogIEhGSUxUPXtwZXJEYXk6cGVyRGF5LHNhbGVzOnNhbGVzLGRheXM6ZGF5c307CiAgaGlzdFJlbmRlcktwaXMoVCk7aGlzdFJlbmRlck1ldGEoZGF5cyxzYWxlcyxUKTtoaXN0UmVuZGVyQ29tcGFyZShwZXJEYXksVCk7aGlzdFJlbmRlckNoYXJ0cyhwZXJEYXkpO2hpc3RSZW5kZXJSYW5raW5ncyhoaXN0U2FsZXM2MCgpKTtoaXN0UmVuZGVyRGFpbHkocGVyRGF5KTtoaXN0UmVuZGVyRGV0YWlsKHNhbGVzKTsKfQovLyBWZW50YXMgZGUgbG9zIMOaTFRJTU9TIDYwIETDjUFTIChmaWpvLCBubyBkZXBlbmRlIGRlbCBmaWx0cm8gZGUgZmVjaGFzKSDigJQgcGFyYSBsb3MgNCByYW5raW5ncy4KZnVuY3Rpb24gaGlzdFNhbGVzNjAoKXsKICBpZighSElTVClyZXR1cm4gW107CiAgdmFyIHRvZGF5PW5ldyBEYXRlKERhdGUubm93KCktMyozNjAwKjEwMDApLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCk7CiAgdmFyIGN1dD1kUGx1cyh0b2RheSwtNjApOwogIHZhciBvdXQ9W107CiAgKEhJU1QuZGF5c3x8W10pLmZvckVhY2goZnVuY3Rpb24oZCl7IGlmKGQuZGF0ZT49Y3V0KSBvdXQ9b3V0LmNvbmNhdChkLnNhbGVzfHxbXSk7IH0pOwogIHJldHVybiBvdXQ7Cn0KLy8gRGV0YWxsZSBjb21wbGV0byBkZSBsYXMgdmVudGFzIGRlIGxvcyDDumx0aW1vcyA2MCBkw61hcyAoYWwgdG9jYXIgdW4gcmFua2luZykuCmZ1bmN0aW9uIGhpc3RTaG93QWxsNjAoY3JpdCl7CiAgdmFyIHNhbGVzPWhpc3RTYWxlczYwKCkuc2xpY2UoKTsKICB2YXIgdHRsTWFwPXtzb2xkOifwn4+GIE3DoXMgdmVuZGlkb3MnLHByb2ZpdDon8J+SsCBNw6FzIHJlbnRhYmxlcycsbG9zczon4pqg77iPIEEgcMOpcmRpZGEgLyBtYXJnZW4gZmxhY28nLHByb3Y6J/Cfk4cgUG9yIHByb3ZlZWRvcid9OwogIHNhbGVzLmZvckVhY2goZnVuY3Rpb24ocyl7IHMuX209KHMua25vd24mJnMucmV2ZW51ZT4wKT8ocy5uZXQvcy5yZXZlbnVlKjEwMCk6bnVsbDsgfSk7CiAgaWYoY3JpdD09PSdzb2xkJykgc2FsZXMuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiAoYi5xdHl8fDApLShhLnF0eXx8MCk7fSk7CiAgZWxzZSBpZihjcml0PT09J3Byb2ZpdCcpIHNhbGVzLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gKGIuX209PW51bGw/LTFlOTpiLl9tKS0oYS5fbT09bnVsbD8tMWU5OmEuX20pO30pOwogIGVsc2UgaWYoY3JpdD09PSdsb3NzJykgc2FsZXMuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiAoYS5fbT09bnVsbD8xZTk6YS5fbSktKGIuX209PW51bGw/MWU5OmIuX20pO30pOwogIGVsc2UgaWYoY3JpdD09PSdwcm92Jykgc2FsZXMuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiBTdHJpbmcoYS5wcm92ZWVkb3J8fCcnKS5sb2NhbGVDb21wYXJlKFN0cmluZyhiLnByb3ZlZWRvcnx8JycpKTt9KTsKICAkKCdoX21vZGFsNjBfdHRsJykudGV4dENvbnRlbnQ9KHR0bE1hcFtjcml0XXx8J0RldGFsbGUnKSsnIMK3IHRvZGFzIGxhcyB2ZW50YXMgZGUgbG9zIMO6bHRpbW9zIDYwIGTDrWFzICgnK3NhbGVzLmxlbmd0aCsnKSc7CiAgJCgnaF9tb2RhbDYwX2JvZHknKS5pbm5lckhUTUw9c2FsZXMubGVuZ3RoP3NhbGVzLm1hcChmdW5jdGlvbihzKXt2YXIgbG9zcz1zLm5ldCE9bnVsbCYmcy5uZXQ8MDsKICAgIHJldHVybiAnPHRyJysobG9zcz8nIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXJlZGJnKSInOicnKSsnPjx0ZD4nKyhzLmRhdGV8fCcnKSsnPC90ZD48dGQgY2xhc3M9Im5hbWUiPicrZXNjKHMudGl0bGV8fHMuaXRlbV9pZCkrJzwvdGQ+PHRkPicrZXNjKHMuYWNjb3VudF9uYW1lfHwnJykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHMucXR5fHwxKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leShzLnJldmVudWUpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHMucXVlZGEpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysocy5jb3N0PT1udWxsPydzL2MnOign4oiSJytmbXRNb25leShzLmNvc3QpKSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo3MDA7Y29sb3I6Jysocy5uZXQ9PW51bGw/J3ZhcigtLW11dCknOihzLm5ldD49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKSsnIj4nKyhzLm5ldD09bnVsbD8n4oCUJzpmbXRNb25leShzLm5ldCkpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhzLl9tPT1udWxsPyfigJQnOmZtdFBjdChzLl9tKSkrJzwvdGQ+PHRkPicrZXNjKHMucHJvdmVlZG9yfHwnJykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHMucGFja19pZHx8cy5vcmRlcl9pZHx8JycpKyc8L3RkPjwvdHI+JzsKICB9KS5qb2luKCcnKTonPHRyPjx0ZCBjb2xzcGFuPSIxMSIgY2xhc3M9ImVtcHR5Ij5TaW4gdmVudGFzIGVuIGxvcyDDumx0aW1vcyA2MCBkw61hcy48L3RkPjwvdHI+JzsKICAkKCdoX21vZGFsNjAnKS5zdHlsZS5kaXNwbGF5PSdibG9jayc7Cn0KZnVuY3Rpb24gaGlzdFJlbmRlck1ldGEoZGF5cyxzYWxlcyxUKXsKICB2YXIgc2F2ZWRUb3RhbD0oSElTVCYmSElTVC5zYXZlZF9kYXRlc3x8W10pLmxlbmd0aDsKICAkKCdoX21ldGEnKS5pbm5lckhUTUw9J/Cfk4YgPGI+JytkYXlzLmxlbmd0aCsnPC9iPiBkw61hKHMpIGVuIGVsIHJhbmdvIChkZSAnK3NhdmVkVG90YWwrJyBndWFyZGFkb3MgZW4gdG90YWwpIMK3IDxiPicrKFQub3JkZXJzfHwwKSsnPC9iPiB2ZW50YXMgwrcgPGI+JytULnVuaWRhZGVzKyc8L2I+IHVuaWRhZGVzLiAnKwogICAgJ05vIGVudHJhbiBjYW5jZWxhZGFzIG5pIHJlY2xhbW9zIGNvbiBkZXZvbHVjacOzbiAodXPDoSA8Yj7wn5SEIFJldmFsaWRhcjwvYj4gcGFyYSBwdXJnYXIgdmVudGFzIHF1ZSBzZSBjYXllcm9uIGRlc3B1w6lzIGRlIGd1YXJkYXIpLic7Cn0KZnVuY3Rpb24gaGlzdFJlbmRlcktwaXMoVCl7CiAgdmFyIHRpY2tldD0oVC5vcmRlcnM+MCk/KFQuZmFjdHVyYWNpb24vVC5vcmRlcnMpOjA7CiAgdmFyIG1DbHM9VC5tYXJnaW49PW51bGw/Jyc6KFQubWFyZ2luPj0xMD8nZ29vZCc6KFQubWFyZ2luPj01Pyd3YXJuJzonYmFkJykpOwogIHZhciB0aWxlcz1bCiAgICBbJ1ZlbnRhcycsKFQub3JkZXJzfHwwKSwnJ10sCiAgICBbJ1VuaWRhZGVzJywoVC51bmlkYWRlc3x8MCksJyddLAogICAgWydGYWN0dXJhY2nDs24nLGZtdE1vbmV5KFQuZmFjdHVyYWNpb24pLCcnXSwKICAgIFsnVGlja2V0IHByb21lZGlvJyxmbXRNb25leSh0aWNrZXQpLCcnXSwKICAgIFsnUXVlZMOzIGVuIGN1ZW50YScsZm10TW9uZXkoVC5xdWVkYVRvdGFsKSwnJ10sCiAgICBbJ0dhbmFuY2lhIHJlYWwnLGZtdE1vbmV5KFQuZ2FuYW5jaWEpLFQuZ2FuYW5jaWE+PTA/J2dvb2QnOidiYWQnXSwKICAgIFsnTWFyZ2VuIHJlYWwnLFQubWFyZ2luPT1udWxsPyfigJQnOmZtdFBjdChULm1hcmdpbiksbUNsc10sCiAgICBbJ1ZlbnRhcyBGbGV4JywoVC5mbGV4Q291bnR8fDApLCcnXSwKICAgIFsnQ29zdG8gcHJvZHVjdG9zJyxmbXRNb25leShULmNvc3RUb3RhbHx8MCksJyddLAogICAgWydJbXB1ZXN0byBNTCcsZm10TW9uZXkoVC50YXhUb3RhbCksJyddLAogICAgWydCb25pZmljYWNpw7NuIEZsZXgnLGZtdE1vbmV5KFQuYm9ub1RvdGFsfHwwKSwnZ29vZCddLAogICAgWydBIHDDqXJkaWRhJywoVC5wZXJkaWRhfHwwKSsoVC5wZXJkaWRhPygnIMK3ICcrZm10TW9uZXkoVC5wZXJkaWRhTW9udG8pKTonJyksVC5wZXJkaWRhPydiYWQnOidnb29kJ10KICBdOwogICQoJ2hfa3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAoZnVuY3Rpb24odCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJrcGkgJyt0WzJdKyciPjxkaXYgY2xhc3M9ImsiPicrdFswXSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+Jyt0WzFdKyc8L2Rpdj48L2Rpdj4nO30pLmpvaW4oJycpOwp9CmZ1bmN0aW9uIGhpc3RSZW5kZXJDb21wYXJlKHBlckRheSxUKXsKICB2YXIgZWw9JCgnaF9jb21wYXJlJyk7CiAgaWYoIXBlckRheS5sZW5ndGgpe2VsLnN0eWxlLmRpc3BsYXk9J25vbmUnO3JldHVybjt9ZWwuc3R5bGUuZGlzcGxheT0nYmxvY2snOwogIHZhciBkZD1wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3ZhciB0PWFnZ1NhbGVzKGQuc2FsZXMpO3JldHVybiB7ZGF0ZTpkLmRhdGUsZzp0LmdhbmFuY2lhLGY6dC5mYWN0dXJhY2lvbn07fSkuZmlsdGVyKGZ1bmN0aW9uKHgpe3JldHVybiB0cnVlO30pOwogIHZhciBzb3J0ZWQ9ZGQuc2xpY2UoKS5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIGIuZy1hLmc7fSk7CiAgdmFyIGJlc3Q9c29ydGVkWzBdLHdvcnN0PXNvcnRlZFtzb3J0ZWQubGVuZ3RoLTFdOwogIHZhciBieU1vbnRoPXt9OyhISVNULmRheXN8fFtdKS5mb3JFYWNoKGZ1bmN0aW9uKGQpe3ZhciBtPWQuZGF0ZS5zbGljZSgwLDcpO2J5TW9udGhbbV09KGJ5TW9udGhbbV18fDApKygoZC50b3RhbHMmJmQudG90YWxzLmdhbmFuY2lhKXx8MCk7fSk7CiAgdmFyIG1vbnRocz1PYmplY3Qua2V5cyhieU1vbnRoKS5zb3J0KCk7dmFyIG1vbnRoVHh0PSfigJQnOwogIGlmKG1vbnRocy5sZW5ndGg+PTIpe3ZhciBjdXI9bW9udGhzW21vbnRocy5sZW5ndGgtMV0scHJldj1tb250aHNbbW9udGhzLmxlbmd0aC0yXSxjPWJ5TW9udGhbY3VyXSxwPWJ5TW9udGhbcHJldl07dmFyIHY9KHAhPT0wKT8oKGMtcCkvTWF0aC5hYnMocCkqMTAwKTpudWxsO21vbnRoVHh0PSc8Yj4nK2N1cisnPC9iPjogJytmbXRNb25leShjKSsnIHZzIDxiPicrcHJldisnPC9iPjogJytmbXRNb25leShwKSsodiE9bnVsbD8oJyDCtyA8YiBzdHlsZT0iY29sb3I6Jysodj49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKyciPicrKHY+PTA/JysnOicnKSt2LnRvRml4ZWQoMCkrJyU8L2I+Jyk6JycpO30KICBlbHNlIGlmKG1vbnRocy5sZW5ndGg9PT0xKXttb250aFR4dD0nPGI+Jyttb250aHNbMF0rJzwvYj46ICcrZm10TW9uZXkoYnlNb250aFttb250aHNbMF1dKSsnIDxzcGFuIGNsYXNzPSJtdXRlZCI+KGHDum4gc2luIG1lcyBhbnRlcmlvciBwYXJhIGNvbXBhcmFyKTwvc3Bhbj4nO30KICB2YXIgZnJvbT0kKCdoX2Zyb20nKS52YWx1ZSx0bz0kKCdoX3RvJykudmFsdWU7dmFyIHNhdmVkU2V0PXt9OyhISVNULnNhdmVkX2RhdGVzfHxbXSkuZm9yRWFjaChmdW5jdGlvbih4KXtzYXZlZFNldFt4XT0xO30pO3ZhciBtaXNzaW5nPVtdOwogIGlmKGZyb20mJnRvJiZmcm9tPD10byl7dmFyIGN1cjI9ZnJvbTt2YXIgZ3VhcmQ9MDt3aGlsZShjdXIyPD10byYmZ3VhcmQ8NDAwKXtpZighc2F2ZWRTZXRbY3VyMl0pbWlzc2luZy5wdXNoKGN1cjIpO2N1cjI9ZFBsdXMoY3VyMiwxKTtndWFyZCsrO319CiAgZWwuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJ0dGwiPvCfk4ogQ29tcGFyYXRpdmFzIHkgY2FsaWRhZCBkZSBkYXRvczwvZGl2PjxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxM3B4O2xpbmUtaGVpZ2h0OjEuOTUiPicrCiAgICAn8J+ThSBNZXMgYWN0dWFsIHZzIGFudGVyaW9yIChnYW5hbmNpYSk6ICcrbW9udGhUeHQrJzxicj4nKwogICAgJ/CfpYcgTWVqb3IgZMOtYTogPGI+JysoYmVzdD9iZXN0LmRhdGUrJyAoJytmbXRNb25leShiZXN0LmcpKycpJzon4oCUJykrJzwvYj4gJm5ic3A7wrcmbmJzcDsg8J+ltiBQZW9yIGTDrWE6IDxiPicrKHdvcnN0P3dvcnN0LmRhdGUrJyAoJytmbXRNb25leSh3b3JzdC5nKSsnKSc6J+KAlCcpKyc8L2I+PGJyPicrCiAgICAn8J+nqSBWZW50YXMgc2luIGNvc3RvIGNvbm9jaWRvOiA8Yj4nKyhULnNpbkNvc3RvfHwwKSsnPC9iPicrKFQuc2luQ29zdG8/JyA8c3BhbiBjbGFzcz0ibXV0ZWQiPihjb21wbGV0w6EgZWwgX0NPTVBMRVRPIHBhcmEgY2FsY3VsYXJsZXMgbWFyZ2VuKTwvc3Bhbj4nOicnKSsnPGJyPicrCiAgICAn8J+Vs++4jyBEw61hcyBzaW4gZ3VhcmRhciBlbiBlbCByYW5nbzogPGI+JyttaXNzaW5nLmxlbmd0aCsnPC9iPicrKG1pc3NpbmcubGVuZ3RoPygnIDxzcGFuIGNsYXNzPSJtdXRlZCI+wrcgJyttaXNzaW5nLnNsaWNlKDAsMTIpLmpvaW4oJywgJykrKG1pc3NpbmcubGVuZ3RoPjEyPyfigKYnOicnKSsnPC9zcGFuPicpOicgPHNwYW4gY2xhc3M9Im11dGVkIj4obmluZ3VubyDwn5GMKTwvc3Bhbj4nKSsnPC9kaXY+JzsKfQpmdW5jdGlvbiBoTWtDaGFydChpZCxjZmcpe2lmKEhDSEFSVFNbaWRdKXtIQ0hBUlRTW2lkXS5kZXN0cm95KCk7fXZhciBjdj0kKGlkKTtpZighY3YpcmV0dXJuO0hDSEFSVFNbaWRdPW5ldyBDaGFydChjdi5nZXRDb250ZXh0KCcyZCcpLGNmZyk7fQpmdW5jdGlvbiBoaXN0UmVuZGVyQ2hhcnRzKHBlckRheSl7CiAgdmFyIGxhYmVscz1wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3JldHVybiBkLmRhdGU7fSk7CiAgdmFyIGZhY3Q9cGVyRGF5Lm1hcChmdW5jdGlvbihkKXtyZXR1cm4gTWF0aC5yb3VuZChhZ2dTYWxlcyhkLnNhbGVzKS5mYWN0dXJhY2lvbik7fSk7CiAgdmFyIGdhbj1wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3JldHVybiBNYXRoLnJvdW5kKGFnZ1NhbGVzKGQuc2FsZXMpLmdhbmFuY2lhKTt9KTsKICB2YXIgbWFyZz1wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3ZhciB0PWFnZ1NhbGVzKGQuc2FsZXMpO3JldHVybiB0Lm1hcmdpbj09bnVsbD9udWxsOit0Lm1hcmdpbi50b0ZpeGVkKDEpO30pOwogIGhNa0NoYXJ0KCdoX2NfZGFpbHknLHt0eXBlOidiYXInLGRhdGE6e2xhYmVsczpsYWJlbHMsZGF0YXNldHM6W3tsYWJlbDonRmFjdHVyYWNpw7NuJyxkYXRhOmZhY3QsYmFja2dyb3VuZENvbG9yOidyZ2JhKDQ2LDg0LDE1MCwuMzUpJyxib3JkZXJDb2xvcjonIzJlNTQ5Nicsb3JkZXI6Mn0se2xhYmVsOidHYW5hbmNpYScsZGF0YTpnYW4sdHlwZTonbGluZScsYm9yZGVyQ29sb3I6JyMxNmEzNGEnLGJhY2tncm91bmRDb2xvcjonIzE2YTM0YScsdGVuc2lvbjouMjUsb3JkZXI6MSx5QXhpc0lEOid5J31dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxwbHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6dHJ1ZX19LHNjYWxlczp7eDp7dGlja3M6e21heFJvdGF0aW9uOjYwLG1pblJvdGF0aW9uOjB9fX19fSk7CiAgaE1rQ2hhcnQoJ2hfY19tYXJnaW4nLHt0eXBlOidsaW5lJyxkYXRhOntsYWJlbHM6bGFiZWxzLGRhdGFzZXRzOlt7bGFiZWw6J01hcmdlbiAlJyxkYXRhOm1hcmcsYm9yZGVyQ29sb3I6JyNkOTc3MDYnLGJhY2tncm91bmRDb2xvcjonI2Q5NzcwNicsdGVuc2lvbjouMjUsc3BhbkdhcHM6dHJ1ZX1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxwbHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6ZmFsc2V9fX19KTsKICB2YXIgZG93PVswLDAsMCwwLDAsMCwwXSxkb3dMYmw9WydET00nLCdMVU4nLCdNQVInLCdNScOJJywnSlVFJywnVklFJywnU8OBQiddOwogIHBlckRheS5mb3JFYWNoKGZ1bmN0aW9uKGQpe3ZhciBwPWQuZGF0ZS5zcGxpdCgnLScpLm1hcChOdW1iZXIpO3ZhciBnPW5ldyBEYXRlKERhdGUuVVRDKHBbMF0scFsxXS0xLHBbMl0pKS5nZXRVVENEYXkoKTtkb3dbZ10rPWFnZ1NhbGVzKGQuc2FsZXMpLm9yZGVyczt9KTsKICBoTWtDaGFydCgnaF9jX2Rvdycse3R5cGU6J2JhcicsZGF0YTp7bGFiZWxzOmRvd0xibCxkYXRhc2V0czpbe2xhYmVsOidWZW50YXMnLGRhdGE6ZG93LGJhY2tncm91bmRDb2xvcjonIzJlNTQ5Nid9XX0sb3B0aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0aW86ZmFsc2UscGx1Z2luczp7bGVnZW5kOntkaXNwbGF5OmZhbHNlfX19fSk7CiAgdmFyIGFjYz0wLGN1bT1nYW4ubWFwKGZ1bmN0aW9uKGcpe2FjYys9ZztyZXR1cm4gYWNjO30pOwogIGhNa0NoYXJ0KCdoX2NfY3VtJyx7dHlwZTonbGluZScsZGF0YTp7bGFiZWxzOmxhYmVscyxkYXRhc2V0czpbe2xhYmVsOidHYW5hbmNpYSBhY3VtdWxhZGEnLGRhdGE6Y3VtLGJvcmRlckNvbG9yOicjMTZhMzRhJyxiYWNrZ3JvdW5kQ29sb3I6J3JnYmEoMjIsMTYzLDc0LC4xNSknLGZpbGw6dHJ1ZSx0ZW5zaW9uOi4yNX1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxwbHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6ZmFsc2V9fX19KTsKfQpmdW5jdGlvbiBoaXN0R3JvdXBCeShzYWxlcyxrZXlGbil7dmFyIG09e307c2FsZXMuZm9yRWFjaChmdW5jdGlvbihzKXt2YXIgaz1rZXlGbihzKTtpZighbVtrXSltW2tdPXtrZXk6ayx0aXRsZTpzLnRpdGxlfHxrLHF0eTowLHJldjowLG5ldDowLGtub3duOjB9O21ba10ucXR5Kz1zLnF0eXx8MDttW2tdLnJldis9cy5yZXZlbnVlfHwwO2lmKHMua25vd24pe21ba10ubmV0Kz1zLm5ldHx8MDttW2tdLmtub3duKz1zLnJldmVudWV8fDA7fX0pO3JldHVybiBPYmplY3Qua2V5cyhtKS5tYXAoZnVuY3Rpb24oayl7cmV0dXJuIG1ba107fSk7fQpmdW5jdGlvbiBoaXN0UmVuZGVyUmFua2luZ3Moc2FsZXMpewogIHZhciBnPWhpc3RHcm91cEJ5KHNhbGVzLGZ1bmN0aW9uKHMpe3JldHVybiBzLml0ZW1faWR8fHMudGl0bGU7fSk7CiAgdmFyIHNvbGQ9Zy5zbGljZSgpLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gYi5xdHktYS5xdHk7fSkuc2xpY2UoMCwxMik7CiAgJCgnaF90b3Bfc29sZCcpLmlubmVySFRNTD1zb2xkLmxlbmd0aD9zb2xkLm1hcChmdW5jdGlvbih4KXtyZXR1cm4gJzx0cj48dGQgY2xhc3M9Im5hbWUiPicrZXNjKHgudGl0bGUpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK3gucXR5Kyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHgucmV2KSsnPC90ZD48L3RyPic7fSkuam9pbignJyk6Jzx0cj48dGQgY29sc3Bhbj0iMyIgY2xhc3M9ImVtcHR5Ij7igJQ8L3RkPjwvdHI+JzsKICAvLyBNw4FTIFJFTlRBQkxFUzogcG9yIE1BUkdFTiAocmVudGFiaWxpZGFkKSBkZSBtYXlvciBhIG1lbm9yLgogIHZhciBwcm9mPWcuZmlsdGVyKGZ1bmN0aW9uKHgpe3JldHVybiB4Lmtub3duPjA7fSkubWFwKGZ1bmN0aW9uKHgpe3gubT14Lm5ldC94Lmtub3duKjEwMDtyZXR1cm4geDt9KS5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIGIubS1hLm07fSkuc2xpY2UoMCwxMik7CiAgJCgnaF90b3BfcHJvZml0JykuaW5uZXJIVE1MPXByb2YubGVuZ3RoP3Byb2YubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPHRyPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2MoeC50aXRsZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKyh4Lm5ldD49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKyciPicrZm10TW9uZXkoeC5uZXQpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdFBjdCh4Lm0pKyc8L3RkPjwvdHI+Jzt9KS5qb2luKCcnKTonPHRyPjx0ZCBjb2xzcGFuPSIzIiBjbGFzcz0iZW1wdHkiPuKAlDwvdGQ+PC90cj4nOwogIC8vIEEgUMOJUkRJREEgLyBNQVJHRU4gRkxBQ086IFNPTE8gbG9zIHF1ZSB0aWVuZW4gbWVub3MgZGUgMTAlIGRlIG1hcmdlbiwgZGVsIHBlb3IgYWwgbWVqb3IuCiAgdmFyIGxvc3M9Zy5maWx0ZXIoZnVuY3Rpb24oeCl7cmV0dXJuIHgua25vd24+MDt9KS5tYXAoZnVuY3Rpb24oeCl7eC5tPXgubmV0L3gua25vd24qMTAwO3JldHVybiB4O30pLmZpbHRlcihmdW5jdGlvbih4KXtyZXR1cm4geC5tPDEwO30pLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gYS5tLWIubTt9KS5zbGljZSgwLDEyKTsKICAkKCdoX3RvcF9sb3NzJykuaW5uZXJIVE1MPWxvc3MubGVuZ3RoP2xvc3MubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPHRyJysoeC5uZXQ8MD8nIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXJlZGJnKSInOicnKSsnPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2MoeC50aXRsZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKyh4Lm5ldD49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKyciPicrZm10TW9uZXkoeC5uZXQpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6JysoeC5tPDA/J3ZhcigtLXJlZCknOih4Lm08NT8ndmFyKC0tYW1iZXIpJzonJykpKyciPicrZm10UGN0KHgubSkrJzwvdGQ+PC90cj4nO30pLmpvaW4oJycpOic8dHI+PHRkIGNvbHNwYW49IjMiIGNsYXNzPSJlbXB0eSI+TmluZ3VubyBjb24gbWFyZ2VuICZsdDsxMCU8L3RkPjwvdHI+JzsKICB2YXIgcHJvdj1oaXN0R3JvdXBCeShzYWxlcyxmdW5jdGlvbihzKXtyZXR1cm4gKHMucHJvdmVlZG9yfHwnKHNpbiBwcm92ZWVkb3IpJyk7fSkuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiBiLm5ldC1hLm5ldDt9KS5zbGljZSgwLDE1KTsKICAkKCdoX2J5X3Byb3YnKS5pbm5lckhUTUw9cHJvdi5sZW5ndGg/cHJvdi5tYXAoZnVuY3Rpb24oeCl7cmV0dXJuICc8dHI+PHRkPicrZXNjKHgua2V5KSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jyt4LnF0eSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKHgubmV0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykrJyI+JytmbXRNb25leSh4Lm5ldCkrJzwvdGQ+PC90cj4nO30pLmpvaW4oJycpOic8dHI+PHRkIGNvbHNwYW49IjMiIGNsYXNzPSJlbXB0eSI+4oCUPC90ZD48L3RyPic7Cn0KZnVuY3Rpb24gaGlzdFJlbmRlckRhaWx5KHBlckRheSl7CiAgaWYoIXBlckRheS5sZW5ndGgpeyQoJ2hfZGFpbHlfcm93cycpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMyIgY2xhc3M9ImVtcHR5Ij5ObyBoYXkgZMOtYXMgZ3VhcmRhZG9zIGVuIGVsIHJhbmdvLiBHdWFyZMOhIGTDrWFzIGRlc2RlIGxhIHNvbGFwYSBHZXN0acOzbi48L3RkPjwvdHI+JztyZXR1cm47fQogICQoJ2hfZGFpbHlfcm93cycpLmlubmVySFRNTD1wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3ZhciB0PWFnZ1NhbGVzKGQuc2FsZXMpOwogICAgcmV0dXJuICc8dHI+PHRkPicrZC5kYXRlKyc8L3RkPjx0ZD4nK2Rvd0xhYmVsKGQuZGF0ZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkodC5mYWN0dXJhY2lvbikrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkodC5xdWVkYVRvdGFsKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh0LmNvc3RUb3RhbCkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkodC5jb3N0VG90YWwrdC5lbnZpb1RvdGFsKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh0LmZhY3R1cmFUb3RhbCkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo3MDA7Y29sb3I6JysodC5nYW5hbmNpYT49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKyciPicrZm10TW9uZXkodC5nYW5hbmNpYSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHQubWFyZ2luPT1udWxsPyfigJQnOmZtdFBjdCh0Lm1hcmdpbikpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHQuZ2FuYW5jaWFTaW5GbGV4KSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh0LmNvc3RTdG9ja1RvdGFsKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jyt0LmN1b3Rhc0NvdW50Kyc8L3RkPjx0ZD48YnV0dG9uIGNsYXNzPSJtaW5pIiB0aXRsZT0iQm9ycmFyIGVzdGUgZMOtYSIgb25jbGljaz0iaGlzdERlbGV0ZURheShcJycrZC5kYXRlKydcJykiPvCfl5HvuI88L2J1dHRvbj48L3RkPjwvdHI+JzsKICB9KS5qb2luKCcnKTsKfQpmdW5jdGlvbiBoaXN0UmVuZGVyRGV0YWlsKHNhbGVzKXsKICB2YXIgcm93cz1zYWxlcy5zbGljZSgwLDYwMCk7CiAgaWYoIXJvd3MubGVuZ3RoKXskKCdoX2RldGFpbF9yb3dzJykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjE3IiBjbGFzcz0iZW1wdHkiPlNpbiB2ZW50YXMgY29uIGVzdG9zIGZpbHRyb3MuPC90ZD48L3RyPic7cmV0dXJuO30KICAkKCdoX2RldGFpbF9yb3dzJykuaW5uZXJIVE1MPXJvd3MubWFwKGZ1bmN0aW9uKHMpe3ZhciBsb3NzPXMubmV0IT1udWxsJiZzLm5ldDwwOwogICAgcmV0dXJuICc8dHInKyhsb3NzPycgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVkYmcpIic6JycpKyc+PHRkPicrKHMuZGF0ZXx8JycpKyc8L3RkPjx0ZCBjbGFzcz0ibmFtZSI+Jysocy5wYWNrPyc8c3BhbiB0aXRsZT0iVmVudGEgZW4gY2Fycml0byIgc3R5bGU9ImRpc3BsYXk6aW5saW5lLWJsb2NrO2JhY2tncm91bmQ6dmFyKC0tYmx1ZWJnKTtjb2xvcjp2YXIoLS1ibHVlKTtmb250LXNpemU6MTBweDtmb250LXdlaWdodDo3MDA7cGFkZGluZzoxcHggNXB4O2JvcmRlci1yYWRpdXM6OHB4O21hcmdpbi1yaWdodDo1cHgiPvCfm5I8L3NwYW4+JzonJykrZXNjKHMudGl0bGV8fHMuaXRlbV9pZCkrJzwvdGQ+PHRkPicrZXNjKHMuYWNjb3VudF9uYW1lfHwnJykrJzwvdGQ+PHRkPicrZXNjKHN0YXR1c0xhYmVsKHMuc3RhdHVzKSkrJzwvdGQ+PHRkPicrKHMuc3RvY2s/J1PDrSc6J+KAlCcpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHMucmV2ZW51ZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj7iiJInK2ZtdE1vbmV5KHMuZmVlKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrKHMuZW52aW8/KCfiiJInK2ZtdE1vbmV5KHMuZW52aW8pKTon4oCUJykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyhzLnRheD8oJ+KIkicrZm10TW9uZXkocy50YXgpKTonJDAnKSsnPC90ZD48dGQgY2xhc3M9Im51bSBiIj4nK2ZtdE1vbmV5KHMucXVlZGEpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysocy5jb3N0PT1udWxsPydzL2Nvc3RvJzooJ+KIkicrZm10TW9uZXkocy5jb3N0KSkpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysocy5mYWN0dXJhPygn4oiSJytmbXRNb25leShzLmZhY3R1cmEpKTon4oCUJykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo3MDA7Y29sb3I6Jysocy5uZXQ9PW51bGw/J3ZhcigtLW11dCknOihzLm5ldD49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKSsnIj4nKyhzLm5ldD09bnVsbD8n4oCUJzpmbXRNb25leShzLm5ldCkpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhzLm1hcmdpblBjdD09bnVsbD8n4oCUJzpmbXRQY3Qocy5tYXJnaW5QY3QpKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jysocy5jdW90YXN8fDApKyc8L3RkPjx0ZD4nK2VzYyhzLnNrdXx8JycpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhzLnBhY2tfaWR8fHMub3JkZXJfaWR8fCcnKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJykrKHNhbGVzLmxlbmd0aD42MDA/KCc8dHI+PHRkIGNvbHNwYW49IjE3IiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRlciI+4oCmICcrKHNhbGVzLmxlbmd0aC02MDApKycgdmVudGFzIG3DoXMgKGFmaW7DoSBsb3MgZmlsdHJvcyBvIGRlc2NhcmfDoSBlbCBYTFNYIHBhcmEgdmVybGFzIHRvZGFzKTwvdGQ+PC90cj4nKTonJyk7Cn0KYXN5bmMgZnVuY3Rpb24gaGlzdERlbGV0ZURheShkYXRlKXsKICBpZighY29uZmlybSgnwr9Cb3JyYXIgZWwgZMOtYSAnK2RhdGUrJyBkZWwgaGlzdMOzcmljbz8gKG5vIGJvcnJhIGxhcyB2ZW50YXMgZW4gTUwsIHNvbG8gZWwgc25hcHNob3QgZ3VhcmRhZG8pJykpcmV0dXJuOwogIHRyeXthd2FpdCBhcGkoJy9hcGkvZ2VzdGlvbi9kZWxldGUtZGF5Jyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtkYXRlOmRhdGV9KX0pO3RvYXN0KCdEw61hICcrZGF0ZSsnIGJvcnJhZG8nKTtISVNUX0xPQURFRD1mYWxzZTthd2FpdCBoaXN0TG9hZCgpO30KICBjYXRjaChlKXt0b2FzdCgnRXJyb3I6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkpO30KfQphc3luYyBmdW5jdGlvbiBoaXN0UmV2YWxpZGF0ZSgpewogIGlmKCFjb25maXJtKCfCv1JldmFsaWRhciBsb3MgZMOtYXMgZ3VhcmRhZG9zIGRlbCByYW5nbyBjb250cmEgTUw/IFNhY2EgdmVudGFzIGNhbmNlbGFkYXMgbyBjb24gZGV2b2x1Y2nDs24gYWwgY29tcHJhZG9yLiBQdWVkZSB0YXJkYXIgdW5vcyBtaW51dG9zLicpKXJldHVybjsKICB2YXIgZnJvbT0kKCdoX2Zyb20nKS52YWx1ZSx0bz0kKCdoX3RvJykudmFsdWU7JCgnaF9tZXRhJykudGV4dENvbnRlbnQ9J1JldmFsaWRhbmRvIGTDrWFzIGNvbnRyYSBNTOKApiAocHVlZGUgdGFyZGFyKSc7CiAgdHJ5e3ZhciByPWF3YWl0IGFwaSgnL2FwaS9nZXN0aW9uL3JldmFsaWRhdGUnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2Zyb206ZnJvbSx0bzp0b30pfSk7dG9hc3QoJ+KchSBSZXZhbGlkYWRvcyAnK3IuZGF5cysnIGTDrWEocykgwrcgJytyLnJlbW92ZWQrJyB2ZW50YShzKSByZW1vdmlkYShzKScpO0hJU1RfTE9BREVEPWZhbHNlO2F3YWl0IGhpc3RMb2FkKCk7fQogIGNhdGNoKGUpe3RvYXN0KCdFcnJvciBhbCByZXZhbGlkYXI6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkpOyQoJ2hfbWV0YScpLnRleHRDb250ZW50PSdFcnJvciBhbCByZXZhbGlkYXIuJzt9Cn0KZnVuY3Rpb24gaGlzdERvd25sb2FkWGxzeCgpewogIGlmKCFIRklMVHx8IUhGSUxULnBlckRheS5sZW5ndGgpe3RvYXN0KCdObyBoYXkgZMOtYXMgcGFyYSBleHBvcnRhcicpO3JldHVybjt9CiAgdmFyIHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTsKICB2YXIgcmVzdW1lbj1IRklMVC5wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3ZhciB0PWFnZ1NhbGVzKGQuc2FsZXMpO3JldHVybiB7RkVDSEE6ZC5kYXRlLERJQTpkb3dMYWJlbChkLmRhdGUpLCdWRU5UQVMgQlJVVEFTJzpNYXRoLnJvdW5kKHQuZmFjdHVyYWNpb24pLCdRVUVETyBFTiBDVUVOVEEnOk1hdGgucm91bmQodC5xdWVkYVRvdGFsKSwnQ09TVE8gRkFDVFVSQSc6TWF0aC5yb3VuZCh0LmNvc3RUb3RhbCksJ0NPU1RPIENPTiBGTEVYJzpNYXRoLnJvdW5kKHQuY29zdFRvdGFsK3QuZW52aW9Ub3RhbCksJ0ZBQ1RVUkEnOk1hdGgucm91bmQodC5mYWN0dXJhVG90YWwpLCdHQU5BTkNJQSBDT04gRkxFWCc6TWF0aC5yb3VuZCh0LmdhbmFuY2lhKSwnUE9SQ0VOVEFKRSc6dC5tYXJnaW49PW51bGw/Jyc6K3QubWFyZ2luLnRvRml4ZWQoMiksJ0dBTkFOQ0lBIFNJTiBGTEVYJzpNYXRoLnJvdW5kKHQuZ2FuYW5jaWFTaW5GbGV4KSwnUVVFRE8gVkVOVEEgU1RPQ0snOk1hdGgucm91bmQodC5jb3N0U3RvY2tUb3RhbCksJ0NVT1RBUyc6dC5jdW90YXNDb3VudH07fSk7CiAgdmFyIFRUPWFnZ1NhbGVzKEhGSUxULnNhbGVzKTsKICByZXN1bWVuLnB1c2goe0ZFQ0hBOidSRVNVTUVOJyxESUE6JycsJ1ZFTlRBUyBCUlVUQVMnOk1hdGgucm91bmQoVFQuZmFjdHVyYWNpb24pLCdRVUVETyBFTiBDVUVOVEEnOk1hdGgucm91bmQoVFQucXVlZGFUb3RhbCksJ0NPU1RPIEZBQ1RVUkEnOk1hdGgucm91bmQoVFQuY29zdFRvdGFsKSwnQ09TVE8gQ09OIEZMRVgnOk1hdGgucm91bmQoVFQuY29zdFRvdGFsK1RULmVudmlvVG90YWwpLCdGQUNUVVJBJzpNYXRoLnJvdW5kKFRULmZhY3R1cmFUb3RhbCksJ0dBTkFOQ0lBIENPTiBGTEVYJzpNYXRoLnJvdW5kKFRULmdhbmFuY2lhKSwnUE9SQ0VOVEFKRSc6VFQubWFyZ2luPT1udWxsPycnOitUVC5tYXJnaW4udG9GaXhlZCgyKSwnR0FOQU5DSUEgU0lOIEZMRVgnOk1hdGgucm91bmQoVFQuZ2FuYW5jaWFTaW5GbGV4KSwnUVVFRE8gVkVOVEEgU1RPQ0snOk1hdGgucm91bmQoVFQuY29zdFN0b2NrVG90YWwpLCdDVU9UQVMnOlRULmN1b3Rhc0NvdW50fSk7CiAgWExTWC51dGlscy5ib29rX2FwcGVuZF9zaGVldCh3YixYTFNYLnV0aWxzLmpzb25fdG9fc2hlZXQocmVzdW1lbiksJ1JFU1VNRU4gRElBUklPJyk7CiAgdmFyIHVzZWQ9e307CiAgSEZJTFQucGVyRGF5LmZvckVhY2goZnVuY3Rpb24oZCl7CiAgICB2YXIgcm93cz1kLnNhbGVzLm1hcChmdW5jdGlvbihzKXtyZXR1cm4geydOVU1FUk8gREUgVkVOVEEnOlN0cmluZyhzLnBhY2tfaWR8fHMub3JkZXJfaWR8fCcnKSwnRVNUQURPJzpzdGF0dXNMYWJlbChzLnN0YXR1cyksJ1NLVSc6cy5za3V8fCcnLCdERVNDUklQQ0lPTic6cy50aXRsZXx8JycsJ1BST1ZFRURPUic6cy5wcm92ZWVkb3J8fCcnLCdDQU5USURBRCc6cy5xdHl8fDEsJ0ZMRVgnOnMuZmxleD8nRmxleCc6JycsJ1BSRUNJTyBWRU5UQSc6TWF0aC5yb3VuZChzLnJldmVudWV8fDApLCdRVUVEQSc6TWF0aC5yb3VuZChzLnF1ZWRhfHwwKSwnUFJFQ0lPIENPU1RPJzpzLmNvc3Q9PW51bGw/Jyc6TWF0aC5yb3VuZChzLmNvc3QpLCdDT1NUTyc6cy5jb3N0PT1udWxsPycnOk1hdGgucm91bmQoKHMuY29zdHx8MCkrKHMuZW52aW98fDApKSwnRkFDVFVSQSc6TWF0aC5yb3VuZChzLmZhY3R1cmF8fDApLCdHQU5BTkNJQSc6cy5uZXQ9PW51bGw/Jyc6TWF0aC5yb3VuZChzLm5ldCksJ1BPUkNFTlRBSkUnOnMubWFyZ2luUGN0PT1udWxsPycnOitzLm1hcmdpblBjdC50b0ZpeGVkKDIpLCdDVUVOVEEnOnMuYWNjb3VudF9uYW1lfHwnJywnU1RPQ0snOnMuc3RvY2s/J1PDrSc6JycsJ0NVT1RBUyc6cy5jdW90YXN8fDAsJ0ZFQ0hBJzpkLmRhdGV9O30pOwogICAgdmFyIG5tPVN0cmluZyhwYXJzZUludChkLmRhdGUuc2xpY2UoOCwxMCksMTApKTtpZih1c2VkW25tXSlubT1kLmRhdGU7dXNlZFtubV09MTtubT1ubS5zbGljZSgwLDMxKTsKICAgIFhMU1gudXRpbHMuYm9va19hcHBlbmRfc2hlZXQod2IsWExTWC51dGlscy5qc29uX3RvX3NoZWV0KHJvd3MubGVuZ3RoP3Jvd3M6W3snTlVNRVJPIERFIFZFTlRBJzonKHNpbiB2ZW50YXMgY29uIGVzdG9zIGZpbHRyb3MpJ31dKSxubSk7CiAgfSk7CiAgWExTWC53cml0ZUZpbGUod2IsJ2dlc3Rpb25faGlzdG9yaWNvXycrKCQoJ2hfZnJvbScpLnZhbHVlfHwnJykrJ18nKygkKCdoX3RvJykudmFsdWV8fCcnKSsnLnhsc3gnKTsKfQoKLy8gPT09PT09PT09PT09PT09PT09PT0gU09MQVBBIEZMRVggKGNvbnRyb2wgZGUgYm9uaWZpY2FjaW9uZXMpID09PT09PT09PT09PT09PT09PT09CnZhciBGTEVYX0xPQURFRD1mYWxzZSwgRkxFWERBVEE9bnVsbDsKYXN5bmMgZnVuY3Rpb24gZmxleExvYWQoKXsKICBjb25zdCBpZD0kKCdhY2NvdW50JykudmFsdWV8fCdhbGwnOwogIGNvbnN0IGZyb209JCgnZl9mcm9tJykudmFsdWUsIHRvPSQoJ2ZfdG8nKS52YWx1ZTsKICBjb25zdCBpc0FsbD0oaWQ9PT0nYWxsJyk7CiAgJCgnZl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjkiIGNsYXNzPSJsb2FkaW5nIj5UcmF5ZW5kbyB2ZW50YXMgRmxleCBkZSBNZXJjYWRvIExpYnJl4oCmIChwdWVkZSB0YXJkYXIpPC90ZD48L3RyPic7CiAgdHJ5ewogICAgY29uc3QgdXJsPWlzQWxsPygnL2FwaS9hZHMvdmVudGFzLWFsbD8nKyhmcm9tPygnZnJvbT0nK2Zyb20pOicnKSsodG8/KCcmdG89Jyt0byk6JycpKTooJy9hcGkvYWRzL3ZlbnRhcz9hY2NvdW50X2lkPScraWQrKGZyb20/KCcmZnJvbT0nK2Zyb20pOicnKSsodG8/KCcmdG89Jyt0byk6JycpKTsKICAgIGNvbnN0IGQ9YXdhaXQgYXBpKHVybCk7IEZMRVhEQVRBPWQ7IEZMRVhfTE9BREVEPXRydWU7CiAgICBmbGV4UmVuZGVyKCk7CiAgfWNhdGNoKGUpeyAkKCdmX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iOSIgY2xhc3M9ImxvYWRpbmciPkVycm9yOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpKyc8L3RkPjwvdHI+JzsgfQp9CmZ1bmN0aW9uIGZsZXhSb3dzKCl7CiAgaWYoIUZMRVhEQVRBKXJldHVybiBbXTsKICBsZXQgcm93cz0oRkxFWERBVEEudmVudGFzfHxbXSkuZmlsdGVyKGZ1bmN0aW9uKHYpe3JldHVybiB2LmZsZXg7fSk7CiAgdmFyIG9xPSgoJCgnZl9vcmRlcicpLnZhbHVlKXx8JycpLnRyaW0oKTsKICBpZihvcSkgcm93cz1yb3dzLmZpbHRlcihmdW5jdGlvbih2KXtyZXR1cm4gU3RyaW5nKHYucGFja19pZHx8JycpLmluZGV4T2Yob3EpPj0wfHxTdHJpbmcodi5vcmRlcl9pZHx8JycpLmluZGV4T2Yob3EpPj0wO30pOwogIHJldHVybiByb3dzOwp9CmZ1bmN0aW9uIGZsZXhSZW5kZXIoKXsKICBpZighRkxFWERBVEEpe3JldHVybjt9CiAgY29uc3QgZD1GTEVYREFUQTsKICBjb25zdCB2dD0kKCdmbGV4VGFibGUnKTsgaWYodnQpIHZ0LmNsYXNzTGlzdC50b2dnbGUoJ2hpZGUtYWNjJywhZC5hbGwpOwogIGNvbnN0IHJvd3M9ZmxleFJvd3MoKTsKICB2YXIgYm9ubz0wLCBlbnZpbz0wLCBwcmVjaW89MDsKICByb3dzLmZvckVhY2goZnVuY3Rpb24odil7IGJvbm8rPSh2LmJvbm98fDApOyBlbnZpbys9KHYuZW52aW98fDApOyBwcmVjaW8rPSh2LnJldmVudWV8fDApOyB9KTsKICBjb25zdCB0aWxlcz1bWydWZW50YXMgRmxleCcscm93cy5sZW5ndGgsJyddLFsnQm9uaWZpY2FjacOzbiB0b3RhbCcsZm10TW9uZXkoYm9ubyksJ2dvb2QnXSxbJ0VudsOtbyBGbGV4IHRvdGFsJyxmbXRNb25leShlbnZpbyksJyddLFsnRmFjdHVyYWNpw7NuIEZsZXgnLGZtdE1vbmV5KHByZWNpbyksJyddXTsKICAkKCdmX2twaXMnKS5pbm5lckhUTUw9dGlsZXMubWFwKGZ1bmN0aW9uKHQpe3JldHVybiAnPGRpdiBjbGFzcz0ia3BpICcrdFsyXSsnIj48ZGl2IGNsYXNzPSJrIj4nK3RbMF0rJzwvZGl2PjxkaXYgY2xhc3M9InYgc21hbGwiPicrdFsxXSsnPC9kaXY+PC9kaXY+Jzt9KS5qb2luKCcnKTsKICAkKCdmX21ldGEnKS5pbm5lckhUTUw9J+KciO+4jyA8Yj4nK3Jvd3MubGVuZ3RoKyc8L2I+IHZlbnRhcyBGbGV4IMK3IGJvbmlmaWNhY2nDs24gdG90YWwgPGIgc3R5bGU9ImNvbG9yOnZhcigtLWdyZWVuKSI+JytmbXRNb25leShib25vKSsnPC9iPiDCtyBwZXLDrW9kbyAnK2VzYyhkLmZyb218fCcnKSsnIGEgJytlc2MoZC50b3x8JycpOwogIGlmKCFyb3dzLmxlbmd0aCl7ICQoJ2ZfYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSI5IiBjbGFzcz0iZW1wdHkiPlNpbiB2ZW50YXMgRmxleCBlbiBlbCBwZXLDrW9kby48L3RkPjwvdHI+JzsgcmV0dXJuOyB9CiAgJCgnZl9ib2R5JykuaW5uZXJIVE1MPXJvd3MubWFwKGZ1bmN0aW9uKHYpewogICAgcmV0dXJuICc8dHI+JysKICAgICAgJzx0ZCBjbGFzcz0ibmFtZSI+Jytlc2Modi50aXRsZXx8di5pdGVtX2lkKSsnPHNwYW4gY2xhc3M9ImlkIj4nKyh2Lml0ZW1faWR8fCcnKSsnIMK3ICcrKHYuZGF0ZXx8JycpKyc8L3NwYW4+PC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJhY2NvbCI+Jytlc2Modi5hY2NvdW50X25hbWV8fCcnKSsnPC90ZD4nKwogICAgICAnPHRkPicrc3RhdHVzUGlsbCh2LnN0YXR1cykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHYucmV2ZW51ZSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysodi5lbnZpbz8oJ+KIkicrZm10TW9uZXkodi5lbnZpbykpOifigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1ncmVlbik7Zm9udC13ZWlnaHQ6NzAwIj4nKyh2LmJvbm8/KCcrJytmbXRNb25leSh2LmJvbm8pKTon4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyh2LmN1b3Rhc3x8MCkrJzwvdGQ+JysKICAgICAgJzx0ZD4nK2VzYyh2LnNrdXx8JycpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+Jysodi5wYWNrX2lkfHx2Lm9yZGVyX2lkfHwnJykrJzwvdGQ+PC90cj4nOwogIH0pLmpvaW4oJycpOwp9CmZ1bmN0aW9uIGZsZXhEb3dubG9hZFhsc3goKXsKICBjb25zdCByb3dzPWZsZXhSb3dzKCk7CiAgaWYoIXJvd3MubGVuZ3RoKXt0b2FzdCgnTm8gaGF5IHZlbnRhcyBGbGV4IHBhcmEgZXhwb3J0YXInKTtyZXR1cm47fQogIGNvbnN0IGRhdGE9cm93cy5tYXAoZnVuY3Rpb24odil7cmV0dXJuIHtGZWNoYTp2LmRhdGUsIE5fdmVudGE6di5wYWNrX2lkfHx2Lm9yZGVyX2lkfHwnJywgQ3VlbnRhOnYuYWNjb3VudF9uYW1lfHwnJywgUHVibGljYWNpb246di50aXRsZSwgQ29kX1NLVTp2LnNrdXx8JycsIEVzdGFkbzpzdGF0dXNMYWJlbCh2LnN0YXR1cyksIFByZWNpbzpNYXRoLnJvdW5kKHYucmV2ZW51ZXx8MCksIEVudmlvOk1hdGgucm91bmQodi5lbnZpb3x8MCksIEJvbmlmaWNhY2lvbl9NTDpNYXRoLnJvdW5kKHYuYm9ub3x8MCksIEN1b3Rhczp2LmN1b3Rhc3x8MH07fSk7CiAgY29uc3Qgd3M9WExTWC51dGlscy5qc29uX3RvX3NoZWV0KGRhdGEpOyBjb25zdCB3Yj1YTFNYLnV0aWxzLmJvb2tfbmV3KCk7IFhMU1gudXRpbHMuYm9va19hcHBlbmRfc2hlZXQod2Isd3MsJ0ZMRVgnKTsKICBYTFNYLndyaXRlRmlsZSh3YiwnZmxleF9ib25pZmljYWNpb25lc18nKygkKCdmX2Zyb20nKS52YWx1ZXx8JycpKydfJysoJCgnZl90bycpLnZhbHVlfHwnJykrJy54bHN4Jyk7Cn0KCmluaXQoKTsKPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=", "base64").toString("utf8");
// El mismo panel se sirve en dos modos: /publicidad = Estrategia, /gestion = Gestión (rentabilidad diaria).
function servePanel(mode, req, res) {
  const sess = requireAuth(req);
  if (!sess) { res.writeHead(302, { Location: '/' }); return res.end(); }
  // GESTIÓN y ESTRATEGIA: solo admin. Un usuario no-admin que intente entrar vuelve al inicio.
  if ((mode === 'gestion' || mode === 'estrategia') && sess.role !== 'admin') { res.writeHead(302, { Location: '/' }); return res.end(); }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(ADS_PANEL_HTML.replace('%%MODE%%', mode));
}
route('GET', '/publicidad', async (req, res) => servePanel('estrategia', req, res));
route('GET', '/gestion', async (req, res) => servePanel('gestion', req, res));
registerAds({ route, mlGet, mlPut, getValidToken, refreshToken, loadDB, saveDB, sendJSON, requireAuth, parseBody, ML_CLIENT_ID });
})();

const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);
  // Force HTTPS in production (Render terminates TLS at its edge proxy and
  // tells us the original protocol via x-forwarded-proto).
  if (req.headers['x-forwarded-proto'] === 'http') {
    const host = req.headers.host || '';
    res.writeHead(301, { Location: `https://${host}${req.url}` });
    return res.end();
  }
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  const method = req.method;
  const routeKey = `${method}:${pathname}`;
  if (routes[routeKey]) {
    try {
      await routes[routeKey](req, res);
    } catch (err) {
      if (err && err.statusCode === 413) {
        return sendJSON(res, 413, { error: 'Solicitud demasiado grande' });
      }
      console.error('Server error:', err);
      if (!res.headersSent) sendJSON(res, 500, { error: 'Error interno del servidor' });
    }
    return;
  }
  if (method === 'GET') {
    serveStatic(req, res);
    return;
  }
  sendJSON(res, 404, { error: 'Ruta no encontrada' });
});
server.listen(PORT, () => {
  console.log(`AUTOCHAP VENTAS corriendo en ${BASE_URL}`);
  console.log(`Puerto: ${PORT}`);
});
// PARACAÍDAS: en Node moderno una promesa rechazada sin capturar (o una excepción suelta) MATA el proceso.
// Durante el enriquecimiento hacemos muchas llamadas a ML en paralelo; si una falla raro, NO queremos
// que se caiga todo el servidor. Registramos los datos y seguimos vivos.
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection] (ignorado para no matar el server):', reason && (reason.message || reason));
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException] (ignorado para no matar el server):', err && (err.stack || err.message || err));
});
// Graceful shutdown: save sessions before Render kills the process
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Guardando datos y sesiones...');
  // Save sessions to sessions.json
  saveSessions();
  // Also save sessions inside data.json so DB_BACKUP includes them
  const currentDb = loadDB();
  currentDb.sessions = sessions;
  saveDB(currentDb);
  console.log('[SHUTDOWN] Listo. Cerrando servidor.');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
});
