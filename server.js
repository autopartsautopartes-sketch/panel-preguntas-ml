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
    async function verifyPriceApplied(itemId, target) {
      try {
        const it = await mlGet(`https://api.mercadolibre.com/items/${itemId}`, token, { attributes: 'price' });
        const curP = Number(it && it.price);
        if (!isFinite(curP)) return true;
        return Math.floor(curP) === Math.floor(Number(target));
      } catch (e) { return true; }
    }
    // Intenta actualizar y, si hubo cambio de precio, VERIFICA que ML lo haya aplicado de verdad.
    // Si ML devolvio OK pero el precio no cambio (falla silenciosa por promocion), lo marcamos
    // como bloqueo de promo para que el flujo de abajo saque la promo y reintente.
    async function attemptWithVerify() {
      let errs = await attemptUpdateOnce();
      if (!errs.length && _targetPrice != null && !_isVariation) {
        const aplicado = await verifyPriceApplied(item.item_id, _targetPrice);
        if (!aplicado) {
          errs = [{ kind: 'promo-silent', status: 400, message: 'promotion: el precio no quedo aplicado (probable promo activa)' }];
        }
      }
      return errs;
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
    sendJSON(res, 200, { ok: true });
  } catch (err) {
    console.error('Error answering:', err.response?.data || err.message || err);
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
  const period = Math.max(1, Math.min(30, parseInt(urlObj.searchParams.get('period') || '7')));
  const accountId = urlObj.searchParams.get('account_id') || '';
  // Argentina = UTC-3
  const now = new Date();
  const argNow = new Date(now.getTime() - 3 * 60 * 60 * 1000);
  // Inicio del día actual en Argentina (= 03:00 UTC)
  const todayArgStart = new Date(Date.UTC(argNow.getUTCFullYear(), argNow.getUTCMonth(), argNow.getUTCDate(), 3, 0, 0));
  // Inicio del período
  const periodStart = new Date(todayArgStart.getTime() - (period - 1) * 24 * 60 * 60 * 1000);
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
        if (!results.length || offset >= (ordersData.paging?.total || 0) || offset >= 500) break;
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
    return sendJSON(res, 200, out);
  } catch (e) {
    out.error = (e && e.response && e.response.data) || String(e.message || e);
    return sendJSON(res, 500, out);
  }
});
// Marcador de version: para confirmar que este deploy quedo live (sin auth, inofensivo)
route('GET', '/api/version', async (req, res) => {
  sendJSON(res, 200, { version: '2026-07-17-promo-serialize-per-campaign-v14', features: ['anto_deposito', 'catalogo_gtin', 'prep_stats_admin', 'promo_proactive_remove', 'conflict_409_retry', 'promo_serialize_per_campaign'] });
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


const ADS_PANEL_HTML = Buffer.from("PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVzIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+UGFuZWwgRXN0cmF0w6lnaWNvIMK3IEF1dG9jaGFwPC90aXRsZT4KPHNjcmlwdD53aW5kb3cuX19QQU5FTF9NT0RFX189JyUlTU9ERSUlJzs8L3NjcmlwdD4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL3hsc3gvMC4xOC41L3hsc3guZnVsbC5taW4uanMiPjwvc2NyaXB0Pgo8c2NyaXB0IHNyYz0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvQ2hhcnQuanMvNC40LjEvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxzdHlsZT4KICA6cm9vdHstLW5hdnk6IzFmMzg2NDstLWJsdWU6IzJlNTQ5NjstLWJnOiNmNGY2ZmI7LS1jYXJkOiNmZmY7LS1saW5lOiNlMmU4ZjA7LS1pbms6IzFlMjkzYjstLW11dDojNjQ3NDhiOwogIC0tZ3JlZW46IzE2YTM0YTstLWdyZWVuYmc6I2RjZmNlNzstLWFtYmVyOiNkOTc3MDY7LS1hbWJlcmJnOiNmZWYzYzc7LS1yZWQ6I2RjMjYyNjstLXJlZGJnOiNmZWUyZTI7LS1ibHVlYmc6I2RiZWFmZTt9CiAgKntib3gtc2l6aW5nOmJvcmRlci1ib3h9CiAgYm9keXttYXJnaW46MDtmb250LWZhbWlseTotYXBwbGUtc3lzdGVtLEJsaW5rTWFjU3lzdGVtRm9udCwiU2Vnb2UgVUkiLFJvYm90byxBcmlhbCxzYW5zLXNlcmlmO2JhY2tncm91bmQ6dmFyKC0tYmcpO2NvbG9yOnZhcigtLWluayk7Zm9udC1zaXplOjE0cHh9CiAgLndyYXB7bWF4LXdpZHRoOm1pbig5OHZ3LDI0MDBweCk7bWFyZ2luOjAgYXV0bztwYWRkaW5nOjE4cHh9CiAgaGVhZGVyLnRvcHtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMnB4O21hcmdpbi1ib3R0b206MTRweH0KICBoZWFkZXIudG9wIGgxe2ZvbnQtc2l6ZToyMHB4O21hcmdpbjowO2NvbG9yOnZhcigtLW5hdnkpO2ZvbnQtd2VpZ2h0OjgwMH0KICBoZWFkZXIudG9wIC5zdWJ7Y29sb3I6dmFyKC0tbXV0KTtmb250LXNpemU6MTJweH0KICAuc3BhY2Vye2ZsZXg6MX0KICBzZWxlY3QsaW5wdXQsYnV0dG9ue2ZvbnQ6aW5oZXJpdDtjb2xvcjp2YXIoLS1pbmspfQogIHNlbGVjdCxpbnB1dFt0eXBlPXRleHRdLGlucHV0W3R5cGU9bnVtYmVyXXtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6OHB4IDEwcHg7YmFja2dyb3VuZDojZmZmfQogIGJ1dHRvbntjdXJzb3I6cG9pbnRlcjtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6OHB4IDEzcHg7YmFja2dyb3VuZDojZmZmO2ZvbnQtd2VpZ2h0OjYwMDt0cmFuc2l0aW9uOi4xMnN9CiAgYnV0dG9uOmhvdmVye2JhY2tncm91bmQ6I2YxZjVmOX0KICBidXR0b24ucHJpbWFyeXtiYWNrZ3JvdW5kOnZhcigtLW5hdnkpO2NvbG9yOiNmZmY7Ym9yZGVyLWNvbG9yOnZhcigtLW5hdnkpfSBidXR0b24ucHJpbWFyeTpob3ZlcntiYWNrZ3JvdW5kOiMxNjJhNGR9CiAgLnBpbGx7ZGlzcGxheTppbmxpbmUtZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweDtib3JkZXItcmFkaXVzOjk5OXB4O3BhZGRpbmc6NHB4IDExcHg7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NzAwO2JvcmRlcjoxcHggc29saWQgdHJhbnNwYXJlbnR9CiAgLnAtZ3JlZW57YmFja2dyb3VuZDp2YXIoLS1ncmVlbmJnKTtjb2xvcjojMTY2NTM0fSAucC1hbWJlcntiYWNrZ3JvdW5kOnZhcigtLWFtYmVyYmcpO2NvbG9yOiM5MjQwMGV9CiAgLnAtcmVke2JhY2tncm91bmQ6dmFyKC0tcmVkYmcpO2NvbG9yOiM5OTFiMWJ9IC5wLWJsdWV7YmFja2dyb3VuZDp2YXIoLS1ibHVlYmcpO2NvbG9yOiMxZTQwYWZ9IC5wLWdyZXl7YmFja2dyb3VuZDojZjFmNWY5O2NvbG9yOiM0NzU1Njl9CiAgLyogVGFicyAqLwogIC50YWJze2Rpc3BsYXk6ZmxleDtnYXA6NnB4O2JvcmRlci1ib3R0b206MnB4IHNvbGlkIHZhcigtLWxpbmUpO21hcmdpbi1ib3R0b206MTZweDtmbGV4LXdyYXA6d3JhcDtwb3NpdGlvbjpzdGlja3k7dG9wOjA7ei1pbmRleDozMDtiYWNrZ3JvdW5kOnZhcigtLWJnKTtwYWRkaW5nLXRvcDo2cHh9CiAgLyogU2Nyb2xsIGludGVybm8gY29uIGhlYWRlcnMgZmlqb3M6IGxhIHRhYmxhIHNjcm9sbGVhIHNvbGEgeSBzdSBlbmNhYmV6YWRvIHF1ZWRhIHBlZ2FkbyBhcnJpYmEuICovCiAgLnZzY3JvbGx7bWF4LWhlaWdodDpjYWxjKDEwMHZoIC0gMzAwcHgpO21pbi1oZWlnaHQ6MjgwcHg7b3ZlcmZsb3c6YXV0b30KICAudnNjcm9sbCB0aGVhZCB0aHt0b3A6MDt6LWluZGV4OjR9CiAgLnRhYntwYWRkaW5nOjEwcHggMThweDtib3JkZXI6MDtiYWNrZ3JvdW5kOnRyYW5zcGFyZW50O2JvcmRlci1yYWRpdXM6MTBweCAxMHB4IDAgMDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tbXV0KTtjdXJzb3I6cG9pbnRlcjtib3JkZXItYm90dG9tOjNweCBzb2xpZCB0cmFuc3BhcmVudDttYXJnaW4tYm90dG9tOi0ycHh9CiAgLnRhYi5hY3RpdmV7Y29sb3I6dmFyKC0tbmF2eSk7Ym9yZGVyLWJvdHRvbS1jb2xvcjp2YXIoLS1uYXZ5KX0KICAudGFiOmhvdmVye2JhY2tncm91bmQ6I2VlZjJmN30KICAucGFuZWx7ZGlzcGxheTpub25lfSAucGFuZWwuYWN0aXZle2Rpc3BsYXk6YmxvY2t9CiAgLyogQ29zdCBiYXIgKi8KICAuY29zdGJhcntiYWNrZ3JvdW5kOnZhcigtLWNhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMnB4O3BhZGRpbmc6MTJweCAxNnB4O21hcmdpbi1ib3R0b206MTRweDtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjEycHg7YWxpZ24taXRlbXM6Y2VudGVyfQogIC5iYW5uZXJ7YmFja2dyb3VuZDojZmZmN2VkO2JvcmRlcjoxcHggc29saWQgI2ZlZDdhYTtjb2xvcjojOWEzNDEyO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjE0cHggMTZweDttYXJnaW4tYm90dG9tOjE0cHg7ZGlzcGxheTpub25lfQogIC5iYW5uZXIuc2hvd3tkaXNwbGF5OmJsb2NrfSAuYmFubmVyIGJ7Y29sb3I6IzdjMmQxMn0gLmJhbm5lciBvbHttYXJnaW46OHB4IDAgMDtwYWRkaW5nLWxlZnQ6MjBweH0KICAuY2FyZHtiYWNrZ3JvdW5kOnZhcigtLWNhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMnB4O3BhZGRpbmc6MTRweCAxNnB4O21hcmdpbi1ib3R0b206MTRweH0KICAuY2FyZCBoM3ttYXJnaW46MCAwIDEwcHg7Zm9udC1zaXplOjEzcHg7Y29sb3I6dmFyKC0tbXV0KTt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6LjZweH0KICAuY2Zncmlke2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDtnYXA6MTRweDthbGlnbi1pdGVtczpmbGV4LWVuZH0KICAuZmllbGR7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6NHB4fQogIC5maWVsZCBsYWJlbHtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1tdXQpO2ZvbnQtd2VpZ2h0OjYwMH0KICAuZmllbGQgaW5wdXR7d2lkdGg6MTEwcHh9IC5maWVsZCAuaGludHtmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS1tdXQpfQogIC5hdXRvdGFne21hcmdpbi1sZWZ0OmF1dG87Zm9udC1zaXplOjEycHh9CiAgLmtwaXN7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNiwxZnIpO2dhcDoxMnB4O21hcmdpbi1ib3R0b206MTRweH0KICAua3Bpe2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxM3B4IDE0cHh9CiAgLmtwaSAua3tmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1tdXQpO2ZvbnQtd2VpZ2h0OjYwMDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7bGV0dGVyLXNwYWNpbmc6LjRweH0KICAua3BpIC52e2ZvbnQtc2l6ZToyMXB4O2ZvbnQtd2VpZ2h0OjgwMDttYXJnaW4tdG9wOjVweDtjb2xvcjp2YXIoLS1uYXZ5KX0gLmtwaSAudi5zbWFsbHtmb250LXNpemU6MTZweH0KICAua3BpLmdvb2QgLnZ7Y29sb3I6dmFyKC0tZ3JlZW4pfSAua3BpLndhcm4gLnZ7Y29sb3I6dmFyKC0tYW1iZXIpfSAua3BpLmJhZCAudntjb2xvcjp2YXIoLS1yZWQpfQogIEBtZWRpYShtYXgtd2lkdGg6OTgwcHgpey5rcGlze2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMywxZnIpfX0KICBAbWVkaWEobWF4LXdpZHRoOjU2MHB4KXsua3Bpc3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsMWZyKX0uZmllbGQgaW5wdXR7d2lkdGg6OTBweH19CiAgLmxlZ2VuZHtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1tdXQpO2Rpc3BsYXk6ZmxleDtnYXA6MTJweDtmbGV4LXdyYXA6d3JhcDttYXJnaW46MnB4IDJweCAxMnB4fQogIC5sZWdlbmQgc3BhbntkaXNwbGF5OmlubGluZS1mbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NXB4fSAuZG90e3dpZHRoOjlweDtoZWlnaHQ6OXB4O2JvcmRlci1yYWRpdXM6NTAlfQogIC5maWx0ZXJze2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxMnB4IDE0cHg7bWFyZ2luLWJvdHRvbToxMnB4O2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDtnYXA6MTBweDthbGlnbi1pdGVtczpjZW50ZXJ9CiAgLmZpbHRlcnMgLmNoaXB7Y3Vyc29yOnBvaW50ZXI7dXNlci1zZWxlY3Q6bm9uZTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6OTk5cHg7cGFkZGluZzo1cHggMTJweDtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2MDA7YmFja2dyb3VuZDojZmZmO2NvbG9yOnZhcigtLW11dCl9CiAgLmZpbHRlcnMgLmNoaXAub257YmFja2dyb3VuZDp2YXIoLS1uYXZ5KTtjb2xvcjojZmZmO2JvcmRlci1jb2xvcjp2YXIoLS1uYXZ5KX0KICAuZmlsdGVycyBpbnB1dFt0eXBlPXRleHRde2ZsZXg6MTttaW4td2lkdGg6MTgwcHh9CiAgLnRhYmxlY2FyZHtiYWNrZ3JvdW5kOnZhcigtLWNhcmQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMnB4O292ZXJmbG93OmhpZGRlbn0KICAudGFibGVzY3JvbGx7b3ZlcmZsb3cteDphdXRvfQogIHRhYmxle2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTt3aWR0aDoxMDAlO21pbi13aWR0aDo5MDBweH0KICB0aCx0ZHtwYWRkaW5nOjExcHggMThweDt0ZXh0LWFsaWduOmxlZnQ7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSk7d2hpdGUtc3BhY2U6bm93cmFwfQogIHRoe2JhY2tncm91bmQ6I2Y4ZmFmYztmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1tdXQpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouNHB4O2N1cnNvcjpwb2ludGVyO3Bvc2l0aW9uOnN0aWNreTt0b3A6MH0KICB0aC5udW0sdGQubnVte3RleHQtYWxpZ246cmlnaHR9CiAgdGJvZHkgdHI6aG92ZXJ7YmFja2dyb3VuZDojZjhmYWZjfQogIHRkLm5hbWV7d2hpdGUtc3BhY2U6bm9ybWFsO21pbi13aWR0aDoyMjBweDtmb250LXdlaWdodDo2MDB9CiAgdGQubmFtZSAuaWR7ZGlzcGxheTpibG9jaztmb250LXdlaWdodDo0MDA7Y29sb3I6dmFyKC0tbXV0KTtmb250LXNpemU6MTFweH0KICAuYWNvc2NlbGx7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2p1c3RpZnktY29udGVudDpmbGV4LWVuZH0KICAuYWNvc2Jhcnt3aWR0aDo1NHB4O2hlaWdodDo3cHg7Ym9yZGVyLXJhZGl1czo0cHg7YmFja2dyb3VuZDojZWVmMmY3O292ZXJmbG93OmhpZGRlbjtmbGV4Om5vbmV9IC5hY29zYmFyPml7ZGlzcGxheTpibG9jaztoZWlnaHQ6MTAwJX0KICAucm93YnRue3BhZGRpbmc6NXB4IDEwcHg7Zm9udC1zaXplOjEycHg7Ym9yZGVyLXJhZGl1czo3cHh9CiAgLnJvd2J0bi5wYXVzZXtjb2xvcjojOTkxYjFiO2JvcmRlci1jb2xvcjojZmNhNWE1fSAucm93YnRuLnBhdXNlOmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcmVkYmcpfQogIC5yb3didG4ucGxheXtjb2xvcjojMTY2NTM0O2JvcmRlci1jb2xvcjojODZlZmFjfSAucm93YnRuLnBsYXk6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1ncmVlbmJnKX0KICAuZW1wdHksLmxvYWRpbmd7cGFkZGluZzozOHB4O3RleHQtYWxpZ246Y2VudGVyO2NvbG9yOnZhcigtLW11dCl9CiAgLmFjdGlvbnN7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDoxMHB4O2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW46MTRweCAwfQogIC5iYXJ7YmFja2dyb3VuZDojZWVmMmY3O2JvcmRlci1yYWRpdXM6NnB4O2hlaWdodDoxNHB4O292ZXJmbG93OmhpZGRlbn0uYmFyPml7ZGlzcGxheTpibG9jaztoZWlnaHQ6MTAwJTtiYWNrZ3JvdW5kOnZhcigtLWJsdWUpfQogIC5sb2djYXJke2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxNHB4IDE2cHg7bWFyZ2luLXRvcDo2cHg7ZGlzcGxheTpub25lfQogIC5sb2djYXJkLnNob3d7ZGlzcGxheTpibG9ja30KICAubG9ncm93e2ZvbnQtc2l6ZToxMnB4O2JvcmRlci1ib3R0b206MXB4IGRhc2hlZCB2YXIoLS1saW5lKTtwYWRkaW5nOjdweCAwO2Rpc3BsYXk6ZmxleDtnYXA6MTBweDtmbGV4LXdyYXA6d3JhcH0KICAudG9hc3R7cG9zaXRpb246Zml4ZWQ7Ym90dG9tOjIwcHg7bGVmdDo1MCU7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTUwJSk7YmFja2dyb3VuZDp2YXIoLS1uYXZ5KTtjb2xvcjojZmZmO3BhZGRpbmc6MTFweCAxOHB4O2JvcmRlci1yYWRpdXM6MTBweDtmb250LXNpemU6MTNweDtvcGFjaXR5OjA7cG9pbnRlci1ldmVudHM6bm9uZTt0cmFuc2l0aW9uOi4yNXM7ei1pbmRleDo1MH0KICAudG9hc3Quc2hvd3tvcGFjaXR5OjF9CiAgLm11dGVke2NvbG9yOnZhcigtLW11dCl9IC5ie2ZvbnQtd2VpZ2h0OjcwMH0KICAjdmVuVGFibGUuaGlkZS1hY2MgLmFjY29se2Rpc3BsYXk6bm9uZX0KICAvKiA9PT09PSBIaXN0w7NyaWNvIChnZXN0acOzbikgPT09PT0gKi8KICAuZ3JpZDJ7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dhcDoxMnB4O21hcmdpbi1ib3R0b206MTJweH0KICBAbWVkaWEobWF4LXdpZHRoOjkwMHB4KXsuZ3JpZDJ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcn19CiAgLnR0bHtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tbmF2eSk7Zm9udC1zaXplOjEzcHg7bWFyZ2luLWJvdHRvbTo4cHh9CiAgI3BhbmVsLWhpc3QgY2FudmFze21heC1oZWlnaHQ6MjIwcHh9CiAgI3BhbmVsLWhpc3QgLnRhYmxlY2FyZHttYXJnaW4tYm90dG9tOjEycHh9CiAgLmhpc3QtaGl7YmFja2dyb3VuZDp2YXIoLS1ncmVlbmJnKX0gLmhpc3QtbG97YmFja2dyb3VuZDp2YXIoLS1yZWRiZyl9CiAgYnV0dG9uLm1pbml7cGFkZGluZzoycHggNnB4O2ZvbnQtc2l6ZToxMnB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7YmFja2dyb3VuZDojZmZmO2JvcmRlci1yYWRpdXM6NnB4O2N1cnNvcjpwb2ludGVyfQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5Pgo8ZGl2IGNsYXNzPSJ3cmFwIj4KCiAgPGhlYWRlciBjbGFzcz0idG9wIj4KICAgIDxkaXY+CiAgICAgIDxoMT7wn5OKIFBhbmVsIEVzdHJhdMOpZ2ljbyDCtyBBdXRvY2hhcDwvaDE+CiAgICAgIDxkaXYgY2xhc3M9InN1YiI+UmVudGFiaWxpZGFkIHJlYWwsIHB1YmxpY2lkYWQgeSBjcmVjaW1pZW50byDigJQgbXVsdGljdWVudGE8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3BhY2VyIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZpZWxkIiBzdHlsZT0ibWluLXdpZHRoOjIxMHB4Ij48bGFiZWw+Q3VlbnRhPC9sYWJlbD4KICAgICAgPHNlbGVjdCBpZD0iYWNjb3VudCIgb25jaGFuZ2U9Im9uQWNjb3VudENoYW5nZSgpIj48L3NlbGVjdD4KICAgIDwvZGl2PgogICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0icmVmcmVzaFRhYigpIj7ihrsgQWN0dWFsaXphcjwvYnV0dG9uPgogIDwvaGVhZGVyPgoKICA8IS0tIEJhcnJhIGRlIGNvc3RvczogdW4gY2FzaWxsZXJvIHBvciBjdWVudGEgKGNhZGEgX0NPTVBMRVRPIGxpbmtlYWRvIGEgc3UgY3VlbnRhKSAtLT4KICA8ZGl2IGNsYXNzPSJjb3N0YmFyIiBzdHlsZT0iZmxleC1kaXJlY3Rpb246Y29sdW1uO2FsaWduLWl0ZW1zOnN0cmV0Y2g7Z2FwOjhweCI+CiAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwIj4KICAgICAgPGRpdiBjbGFzcz0iYiIgc3R5bGU9ImZvbnQtc2l6ZToxM3B4Ij7wn5KwIENvc3RvcyBwb3IgcHJvZHVjdG8gKF9DT01QTEVUTykg4oCUIHVuIGFyY2hpdm8gcG9yIGN1ZW50YTwvZGl2PgogICAgICA8c3BhbiBpZD0iY29zdHN0YXR1cyIgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLWxlZnQ6YXV0byI+PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4Ij5DYWRhIGN1ZW50YSB0aWVuZSBzdSBjYXNpbGxlcm8uIEltcG9ydMOhIGVsIF9DT01QTEVUTyBkZSBjYWRhIHVuYTogcXVlZGFuIGxhcyA2IGd1YXJkYWRhcyB5IGxpbmtlYWRhcyBwYXJhIGVsIGNydWNlIHBvciB0w610dWxvIGRlIEVzdHJhdGVnaWEuIFJlaW1wb3J0YXIgdW5hIGN1ZW50YSBzb2xvIGFjdHVhbGl6YSBlc2EuPC9kaXY+CiAgICA8ZGl2IGlkPSJjb3N0c2xvdHMiIHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGwsbWlubWF4KDIzMHB4LDFmcikpO2dhcDo4cHgiPjwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJiYW5uZXIiIGlkPSJiYW5uZXIiPgogICAgPGI+4pqZ77iPIEZhbHRhIGFjdGl2YXIgZWwgYWNjZXNvIGEgUHVibGljaWRhZCBwb3IgQVBJLjwvYj4KICAgIDxkaXYgaWQ9ImJhbm5lck1zZyIgc3R5bGU9Im1hcmdpbi10b3A6NHB4Ij48L2Rpdj4KICAgIDxvbD4KICAgICAgPGxpPkFjdGl2w6EgPGI+UHJvZHVjdCBBZHM8L2I+IGVuIGxhIGN1ZW50YSAoR2VzdGnDs24gZGUgcHVibGljYWNpb25lcyDigLogUHVibGljaWRhZCkuPC9saT4KICAgICAgPGxpPkVuIHR1IGFwcCBkZSBNZXJjYWRvIExpYnJlIERldmVsb3BlcnMsIGhhYmlsaXTDoSBlbCBwZXJtaXNvIGRlIDxiPnB1YmxpY2lkYWQgKGFkdmVydGlzaW5nKTwvYj4uPC9saT4KICAgICAgPGxpPjxiPlJlY29uZWN0w6EgbGEgY3VlbnRhPC9iPiBkZXNkZSBDb25maWd1cmFjacOzbiDihpIgQ3VlbnRhcy48L2xpPgogICAgPC9vbD4KICA8L2Rpdj4KCiAgPCEtLSBQRVNUQcORQVMgLS0+CiAgPGRpdiBjbGFzcz0idGFicyI+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIgYWN0aXZlIiBpZD0idGFiLXJlbnQiIG9uY2xpY2s9InNob3dUYWIoJ3JlbnQnKSI+8J+Xgu+4jyBHZXN0acOzbjwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiIiBpZD0idGFiLWhpc3QiIG9uY2xpY2s9InNob3dUYWIoJ2hpc3QnKSI+8J+ThiBIaXN0w7NyaWNvPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItZmxleCIgb25jbGljaz0ic2hvd1RhYignZmxleCcpIj7inIjvuI8gRkxFWDwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiIiBpZD0idGFiLWVzdHIiIG9uY2xpY2s9InNob3dUYWIoJ2VzdHInKSI+8J+noCBFc3RyYXRlZ2lhPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItcHJlY2lvcyIgb25jbGljaz0ic2hvd1RhYigncHJlY2lvcycpIj7wn5KyIFByZWNpb3M8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYiIgaWQ9InRhYi1hanVzdGVzIiBvbmNsaWNrPSJzaG93VGFiKCdhanVzdGVzJykiPuKame+4jyBBanVzdGVzPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItcHViIiBvbmNsaWNrPSJzaG93VGFiKCdwdWInKSI+8J+ToiBQdWJsaWNpZGFkIChBRFMpPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItd2luIiBvbmNsaWNrPSJzaG93VGFiKCd3aW4nKSI+8J+PhiBHYW5hZG9yYXM8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPCEtLSA9PT09PSBUQUIgUkVOVEFCSUxJREFEID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIGFjdGl2ZSIgaWQ9InBhbmVsLXJlbnQiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5EZXNkZTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJ2ZW5fZnJvbSIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkhhc3RhPC9sYWJlbD48aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InZlbl90byIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkZhY3R1cmEgJTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9InZlbl90YXgiIHN0ZXA9IjAuNSIgc3R5bGU9IndpZHRoOjcwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij5nbG9iYWwgwrcgZGVmYXVsdCA1JTwvc3Bhbj48L2Rpdj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InNhdmVGYWN0dXJhQ2ZnKCkiIHRpdGxlPSJHdWFyZGFyIGxhIGZhY3R1cmEgJSBnbG9iYWwgKGFwbGljYSBhIHRvZGFzIGxhcyBjdWVudGFzKSI+8J+SviBHdWFyZGFyICU8L2J1dHRvbj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk7CsCBkZSB2ZW50YTwvbGFiZWw+PGlucHV0IHR5cGU9InRleHQiIGlkPSJ2ZW5fb3JkZXIiIHBsYWNlaG9sZGVyPSJmaWx0cmFy4oCmIiBvbmlucHV0PSJyZW5kZXJWZW50YXMoVkVOKSIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJsb2FkVmVudGFzKCkiIHRpdGxlPSJBcGxpY2FyIGVsIGZpbHRybyB5IHRyYWVyIGxhcyB2ZW50YXMiPvCflI0gQnVzY2FyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJzYXZlRGlhKCkiIHRpdGxlPSJDb25nZWxhIGxhcyB2ZW50YXMgZGVsIGTDrWEgKGZlY2hhIERlc2RlKSBjb24gbGEgbGlzdGEgZGUgcHJlY2lvcyBkZSBob3kuIFJlLWd1YXJkYXIgZWwgbWlzbW8gZMOtYSBsbyBzb2JyZWVzY3JpYmUuIj7wn5K+IEd1YXJkYXIgZMOtYTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iZGVsZXRlRGlhKCkiIHRpdGxlPSJFbGltaW5hIGRlbCBIaXN0w7NyaWNvIGVsIGTDrWEgZ3VhcmRhZG8gKGZlY2hhIERlc2RlKSwgcGFyYSBwb2RlciB2b2x2ZXIgYSBzdWJpcmxvIGNvbiBHdWFyZGFyIGTDrWEiPvCfl5HvuI8gRWxpbWluYXIgZMOtYTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iZG93bmxvYWRWZW50YXNYbHN4KCkiPuKshyBYTFNYPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi10b3A6OHB4Ij5FbGVnw60gZWwgcGVyw61vZG8geSB0b2PDoSA8Yj7wn5SNIEJ1c2NhcjwvYj4gKG5vIGJ1c2NhIHNvbG8pLiBHYW5hbmNpYSA9IHByZWNpbyDiiJIgY29taXNpw7NuIHJlYWwg4oiSIGVudsOtbyByZWFsIOKIkiA8Yj5pbXB1ZXN0byByZWFsIGRlIE1MPC9iPiDiiJIgY29zdG8g4oiSIDxiPmZhY3R1cmE8L2I+LiBMYSA8Yj5mYWN0dXJhPC9iPiAoJSBnbG9iYWwpIGVzIGVsIGNhcmdvIG1lbnN1YWwgZGUgTUwgeSBjdWVudGEgY29tbyBwYXJ0ZSBkZWwgY29zdG8uIDxiPvCfkr4gR3VhcmRhciBkw61hPC9iPiBjb25nZWxhIGVzZSBkw61hIGNvbiBzdSBsaXN0YSBkZSBwcmVjaW9zIHkgbG8gbWFuZGEgYWwgPGI+SGlzdMOzcmljbzwvYj4uIE5vIGVudHJhbiBjYW5jZWxhZGFzIG5pIHJlY2xhbW9zIGNvbiBkZXZvbHVjacOzbiBhbCBjb21wcmFkb3I7IHNpIHVuYSB2ZW50YSBzZSBjYWUgZGVzcHXDqXMgZGUgZ3VhcmRhciwgcmV2YWxpZMOhIGVuIGVsIEhpc3TDs3JpY28uIEVsIGNvc3RvIHF1ZWRhIDxiPmNvbmdlbGFkbzwvYj4gYWwgbW9tZW50byBkZSBsYSB2ZW50YS4gPGI+UXVlZMOzIGVuIGN1ZW50YTwvYj4gZXMgZWwgZGVww7NzaXRvIFJFQUwgZGUgTUw6IGVuIEZsZXggZWwgZW52w61vIG5vIHNlIGRlc2N1ZW50YSBhaMOtIChzZSBjb2JyYSBhcGFydGUpLiBFbiB2ZW50YXMgZW4gPGI+8J+bkiBjYXJyaXRvPC9iPiAodmFyaW9zIHByb2R1Y3RvcywgdW4gbWlzbW8gZW52w61vKSBlbCBlbnbDrW8gc2UgY3VlbnRhIDxiPnVuYSBzb2xhIHZlejwvYj4geSBzZSBjYXJnYSBhbCBwcm9kdWN0byBkZSBtYXlvciB2YWxvci48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ia3BpcyIgaWQ9InZlbl9rcGlzIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiIGlkPSJ2ZW5fcHJvZ3Jlc3NfY2FyZCIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+PGRpdiBpZD0idmVuX3Byb2dyZXNzIj48L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwgdnNjcm9sbCI+CiAgICAgIDx0YWJsZSBpZD0idmVuVGFibGUiIGNsYXNzPSJoaWRlLWFjYyIgc3R5bGU9Im1pbi13aWR0aDoxNTAwcHgiPgogICAgICAgIDx0aGVhZD48dHI+CiAgICAgICAgICA8dGggZGF0YS1rPSJ0aXRsZSIgb25jbGljaz0ic29ydFZlbigndGl0bGUnKSI+VmVudGE8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJhY2NvbCIgZGF0YS1rPSJhY2NvdW50X25hbWUiIG9uY2xpY2s9InNvcnRWZW4oJ2FjY291bnRfbmFtZScpIj5DdWVudGE8L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0ic3RhdHVzIiBvbmNsaWNrPSJzb3J0VmVuKCdzdGF0dXMnKSI+RXN0YWRvIGVudsOtbzwvdGg+CiAgICAgICAgICA8dGggZGF0YS1rPSJzdG9jayIgb25jbGljaz0ic29ydFZlbignc3RvY2snKSI+U3RvY2s8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0icXR5IiBvbmNsaWNrPSJzb3J0VmVuKCdxdHknKSI+Q2FudDwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJyZXZlbnVlIiBvbmNsaWNrPSJzb3J0VmVuKCdyZXZlbnVlJykiPlByZWNpbzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJmZWUiIG9uY2xpY2s9InNvcnRWZW4oJ2ZlZScpIj5Db21pc2nDs248L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iZW52aW8iIG9uY2xpY2s9InNvcnRWZW4oJ2VudmlvJykiPkVudsOtbzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJ0YXgiIG9uY2xpY2s9InNvcnRWZW4oJ3RheCcpIiB0aXRsZT0iSW1wdWVzdG8gcmVhbCBxdWUgTUwgcmV0aWVuZSBlbiBsYSB2ZW50YSAocmVzcGFsZG86ICUgc2kgbm8gdmllbmUpIj5JbXB1ZXN0b3M8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0icXVlZGEiIG9uY2xpY2s9InNvcnRWZW4oJ3F1ZWRhJykiIHRpdGxlPSJRdWVkw7MgZW4gY3VlbnRhIFJFQUwgZGUgTUwuIEVuIENvcnJlbyBNTCBkZXNjdWVudGEgZWwgZW52w61vIGRlbCBkZXDDs3NpdG87IGVuIEZsZXggTk8gKGVsIGZsZXggc2UgY29icmEgYXBhcnRlIHkgc2UgZGVzY3VlbnRhIGVuIGxhIEdhbmFuY2lhIGNvbW8gY29zdG8pLiI+UXVlZMOzIGVuIGN1ZW50YTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJjb3N0IiBvbmNsaWNrPSJzb3J0VmVuKCdjb3N0JykiPkNvc3RvPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImZhY3R1cmEiIG9uY2xpY2s9InNvcnRWZW4oJ2ZhY3R1cmEnKSIgdGl0bGU9IkNhcmdvIG1lbnN1YWwgZGUgTUwgKHBhcnRlIGRlbCBjb3N0bykiPkZhY3R1cmE8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ibmV0IiBvbmNsaWNrPSJzb3J0VmVuKCduZXQnKSI+R2FuYW5jaWE8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ibmV0X3Npbl9mbGV4IiBvbmNsaWNrPSJzb3J0VmVuKCduZXRfc2luX2ZsZXgnKSIgdGl0bGU9IkdhbmFuY2lhIHNpbiBjb250YXIgZWwgZW52w61vL2ZsZXgiPkdhbiBzL2ZsZXg8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ibWFyZ2luUGN0IiBvbmNsaWNrPSJzb3J0VmVuKCdtYXJnaW5QY3QnKSI+TWFyZ2VuPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImN1b3RhcyIgb25jbGljaz0ic29ydFZlbignY3VvdGFzJykiIHRpdGxlPSJDdW90YXMgZGVsIHBhZ28gKDAgw7MgMSA9IHNpbiBjdW90YXMpIj5DdW90YXM8L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0ic2t1IiBvbmNsaWNrPSJzb3J0VmVuKCdza3UnKSI+Q8OzZC9TS1U8L3RoPgogICAgICAgIDwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9InZlbl9ib2R5Ij48dHI+PHRkIGNvbHNwYW49IjE3IiBjbGFzcz0ibG9hZGluZyI+RWxlZ8OtIGVsIHBlcsOtb2RvIHkgdG9jw6Eg8J+UjSBCdXNjYXIgcGFyYSB0cmFlciBsYXMgdmVudGFzLjwvdGQ+PC90cj48L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+PC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIEhJU1TDk1JJQ08gKGTDrWFzIGd1YXJkYWRvcykgPT09PT0gLS0+CiAgPGRpdiBjbGFzcz0icGFuZWwiIGlkPSJwYW5lbC1oaXN0Ij4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjZmdyaWQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RGVzZGU8L2xhYmVsPjxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaF9mcm9tIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+SGFzdGE8L2xhYmVsPjxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaF90byIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkN1ZW50YTwvbGFiZWw+PHNlbGVjdCBpZD0iaF9hY2NvdW50IiBzdHlsZT0id2lkdGg6MTcwcHgiPjxvcHRpb24gdmFsdWU9IiI+VG9kYXM8L29wdGlvbj48L3NlbGVjdD48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkVzdGFkbyBlbnbDrW88L2xhYmVsPjxzZWxlY3QgaWQ9Imhfc3RhdHVzIiBzdHlsZT0id2lkdGg6MTUwcHgiPjxvcHRpb24gdmFsdWU9IiI+VG9kb3M8L29wdGlvbj48L3NlbGVjdD48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkZsZXg8L2xhYmVsPjxzZWxlY3QgaWQ9ImhfZmxleCI+PG9wdGlvbiB2YWx1ZT0iIj5Ub2Rvczwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IjEiPlNvbG8gRmxleDwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IjAiPlNpbiBGbGV4PC9vcHRpb24+PC9zZWxlY3Q+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5Db3N0bzwvbGFiZWw+PHNlbGVjdCBpZD0iaF9jb3N0byI+PG9wdGlvbiB2YWx1ZT0iIj5Ub2Rvczwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IjEiPkNvbiBjb3N0bzwvb3B0aW9uPjxvcHRpb24gdmFsdWU9IjAiPlNpbiBjb3N0bzwvb3B0aW9uPjwvc2VsZWN0PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+UmVzdWx0YWRvPC9sYWJlbD48c2VsZWN0IGlkPSJoX3JlcyI+PG9wdGlvbiB2YWx1ZT0iIj5Ub2Rvczwvb3B0aW9uPjxvcHRpb24gdmFsdWU9Imxvc3MiPkEgcMOpcmRpZGE8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJ3aW4iPkNvbiBnYW5hbmNpYTwvb3B0aW9uPjwvc2VsZWN0PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+TsKwIGRlIHZlbnRhPC9sYWJlbD48aW5wdXQgdHlwZT0idGV4dCIgaWQ9Imhfb3JkZXIiIHBsYWNlaG9sZGVyPSJuw7ptZXJv4oCmIiBzdHlsZT0id2lkdGg6MTQwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+QnVzY2FyIHRleHRvPC9sYWJlbD48aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImhfdGV4dCIgcGxhY2Vob2xkZXI9InTDrXR1bG8gLyBTS1UgLyBwcm92ZWVkb3LigKYiIHN0eWxlPSJ3aWR0aDoxOTBweCI+PC9kaXY+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0iaGlzdEFwcGx5RmlsdGVycygpIj7wn5SOIEFwbGljYXIgZmlsdHJvczwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iaGlzdFJldmFsaWRhdGUoKSIgdGl0bGU9IlJldmlzYSBjYWRhIGTDrWEgZ3VhcmRhZG8gY29udHJhIE1MIHkgc2FjYSB2ZW50YXMgY2FuY2VsYWRhcyBvIGNvbiBkZXZvbHVjacOzbiBhbCBjb21wcmFkb3IiPvCflIQgUmV2YWxpZGFyIGTDrWFzPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJoaXN0RG93bmxvYWRYbHN4KCkiIHRpdGxlPSJEZXNjYXJnYSBmb3JtYXRvIFJFU1VNRU4gRElBUklPICsgdW5hIGhvamEgcG9yIGTDrWEiPuKshyBEZXNjYXJnYXIgWExTWDwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iaGlzdExvYWQoKSIgdGl0bGU9IlJlY2FyZ2FyIGRlbCBzZXJ2aWRvciI+4oa7IFJlY2FyZ2FyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgaWQ9ImhfbWV0YSIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi10b3A6OHB4Ij5DYXJnYW5kbyBoaXN0w7NyaWNv4oCmPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImtwaXMiIGlkPSJoX2twaXMiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9ImhfY29tcGFyZSIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJncmlkMiI+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9InR0bCI+RmFjdHVyYWNpw7NuIHkgZ2FuYW5jaWEgcG9yIGTDrWE8L2Rpdj48Y2FudmFzIGlkPSJoX2NfZGFpbHkiIGhlaWdodD0iMTIwIj48L2NhbnZhcz48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0idHRsIj5NYXJnZW4gJSBwb3IgZMOtYTwvZGl2PjxjYW52YXMgaWQ9ImhfY19tYXJnaW4iIGhlaWdodD0iMTIwIj48L2NhbnZhcz48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0idHRsIj5WZW50YXMgcG9yIGTDrWEgZGUgbGEgc2VtYW5hPC9kaXY+PGNhbnZhcyBpZD0iaF9jX2RvdyIgaGVpZ2h0PSIxMjAiPjwvY2FudmFzPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJ0dGwiPkdhbmFuY2lhIGFjdW11bGFkYTwvZGl2PjxjYW52YXMgaWQ9ImhfY19jdW0iIGhlaWdodD0iMTIwIj48L2NhbnZhcz48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjZweCI+8J+TiiBSYW5raW5ncyBkZSBsb3MgPGI+w7psdGltb3MgNjAgZMOtYXM8L2I+IChmaWpvcyDigJQgbm8gZGVwZW5kZW4gZGVsIGZpbHRybyBkZSBmZWNoYXMgZGUgYXJyaWJhKS4gVG9jw6EgY3VhbHF1aWVyIHJlY3VhZHJvIHBhcmEgdmVyIGVsIGRldGFsbGUgZGUgdG9kYXMgbGFzIHZlbnRhcyBkZSBlc29zIDYwIGTDrWFzLjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZ3JpZDIiPgogICAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiIHN0eWxlPSJjdXJzb3I6cG9pbnRlciIgb25jbGljaz0iaGlzdFNob3dBbGw2MCgnc29sZCcpIj48ZGl2IGNsYXNzPSJ0dGwiIHN0eWxlPSJwYWRkaW5nOjEwcHggMTJweCAwIj7wn4+GIE3DoXMgdmVuZGlkb3MgPHNwYW4gY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC13ZWlnaHQ6NDAwIj7CtyDDumx0aW1vcyA2MCBkw61hczwvc3Bhbj48L2Rpdj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+PHRhYmxlPjx0aGVhZD48dHI+PHRoPlByb2R1Y3RvPC90aD48dGggY2xhc3M9Im51bSI+VW5pZC48L3RoPjx0aCBjbGFzcz0ibnVtIj5GYWN0dXJhY2nDs248L3RoPjwvdHI+PC90aGVhZD48dGJvZHkgaWQ9ImhfdG9wX3NvbGQiPjwvdGJvZHk+PC90YWJsZT48L2Rpdj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIiBzdHlsZT0iY3Vyc29yOnBvaW50ZXIiIG9uY2xpY2s9Imhpc3RTaG93QWxsNjAoJ3Byb2ZpdCcpIj48ZGl2IGNsYXNzPSJ0dGwiIHN0eWxlPSJwYWRkaW5nOjEwcHggMTJweCAwIj7wn5KwIE3DoXMgcmVudGFibGVzIDxzcGFuIGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtd2VpZ2h0OjQwMCI+wrcgw7psdGltb3MgNjAgZMOtYXM8L3NwYW4+PC9kaXY+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPjx0YWJsZT48dGhlYWQ+PHRyPjx0aD5Qcm9kdWN0bzwvdGg+PHRoIGNsYXNzPSJudW0iPkdhbmFuY2lhPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5IGlkPSJoX3RvcF9wcm9maXQiPjwvdGJvZHk+PC90YWJsZT48L2Rpdj48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIiBzdHlsZT0iY3Vyc29yOnBvaW50ZXIiIG9uY2xpY2s9Imhpc3RTaG93QWxsNjAoJ2xvc3MnKSI+PGRpdiBjbGFzcz0idHRsIiBzdHlsZT0icGFkZGluZzoxMHB4IDEycHggMCI+4pqg77iPIEEgcMOpcmRpZGEgLyBtYXJnZW4gZmxhY28gPHNwYW4gY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC13ZWlnaHQ6NDAwIj7CtyAmbHQ7MTAlIMK3IMO6bHRpbW9zIDYwIGTDrWFzPC9zcGFuPjwvZGl2PjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj48dGFibGU+PHRoZWFkPjx0cj48dGg+UHJvZHVjdG88L3RoPjx0aCBjbGFzcz0ibnVtIj5HYW5hbmNpYTwvdGg+PHRoIGNsYXNzPSJudW0iPk1hcmdlbjwvdGg+PC90cj48L3RoZWFkPjx0Ym9keSBpZD0iaF90b3BfbG9zcyI+PC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiIHN0eWxlPSJjdXJzb3I6cG9pbnRlciIgb25jbGljaz0iaGlzdFNob3dBbGw2MCgncHJvdicpIj48ZGl2IGNsYXNzPSJ0dGwiIHN0eWxlPSJwYWRkaW5nOjEwcHggMTJweCAwIj7wn5OHIFBvciBwcm92ZWVkb3IgPHNwYW4gY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC13ZWlnaHQ6NDAwIj7CtyDDumx0aW1vcyA2MCBkw61hczwvc3Bhbj48L2Rpdj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+PHRhYmxlPjx0aGVhZD48dHI+PHRoPlByb3ZlZWRvcjwvdGg+PHRoIGNsYXNzPSJudW0iPlVuaWQuPC90aD48dGggY2xhc3M9Im51bSI+R2FuYW5jaWE8L3RoPjwvdHI+PC90aGVhZD48dGJvZHkgaWQ9ImhfYnlfcHJvdiI+PC90Ym9keT48L3RhYmxlPjwvZGl2PjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGlkPSJoX21vZGFsNjAiIHN0eWxlPSJkaXNwbGF5Om5vbmU7cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDtiYWNrZ3JvdW5kOnJnYmEoMTUsMjMsNDIsLjU1KTt6LWluZGV4OjEwMDA7cGFkZGluZzoyNHB4IiBvbmNsaWNrPSJpZihldmVudC50YXJnZXQ9PT10aGlzKXRoaXMuc3R5bGUuZGlzcGxheT0nbm9uZSciPgogICAgICA8ZGl2IHN0eWxlPSJiYWNrZ3JvdW5kOiNmZmY7Ym9yZGVyLXJhZGl1czoxMnB4O21heC13aWR0aDoxNDAwcHg7bWFyZ2luOjAgYXV0bzttYXgtaGVpZ2h0Ojkwdmg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtvdmVyZmxvdzpoaWRkZW4iPgogICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47cGFkZGluZzoxMnB4IDE2cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSkiPgogICAgICAgICAgPGRpdiBjbGFzcz0idHRsIiBpZD0iaF9tb2RhbDYwX3R0bCIgc3R5bGU9Im1hcmdpbjowIj5EZXRhbGxlIMK3IMO6bHRpbW9zIDYwIGTDrWFzPC9kaXY+CiAgICAgICAgICA8YnV0dG9uIG9uY2xpY2s9IiQoJ2hfbW9kYWw2MCcpLnN0eWxlLmRpc3BsYXk9J25vbmUnIj7inJUgQ2VycmFyPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0idGFibGVzY3JvbGwiIHN0eWxlPSJvdmVyZmxvdzphdXRvO3BhZGRpbmc6MCA0cHggOHB4Ij4KICAgICAgICAgIDx0YWJsZSBzdHlsZT0ibWluLXdpZHRoOjEyMDBweCI+PHRoZWFkPjx0cj48dGg+RmVjaGE8L3RoPjx0aD5Qcm9kdWN0bzwvdGg+PHRoPkN1ZW50YTwvdGg+PHRoIGNsYXNzPSJudW0iPkNhbnQ8L3RoPjx0aCBjbGFzcz0ibnVtIj5QcmVjaW88L3RoPjx0aCBjbGFzcz0ibnVtIj5RdWVkw7M8L3RoPjx0aCBjbGFzcz0ibnVtIj5Db3N0bzwvdGg+PHRoIGNsYXNzPSJudW0iPkdhbmFuY2lhPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuPC90aD48dGg+UHJvdmVlZG9yPC90aD48dGggY2xhc3M9Im51bSI+TsKwIHZlbnRhPC90aD48L3RyPjwvdGhlYWQ+PHRib2R5IGlkPSJoX21vZGFsNjBfYm9keSI+PC90Ym9keT48L3RhYmxlPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIj48ZGl2IGNsYXNzPSJ0dGwiIHN0eWxlPSJwYWRkaW5nOjEwcHggMTJweCAwIj7wn5OGIFJlc3VtZW4gZGlhcmlvIOKAlCBjYWRhIGTDrWEgZ3VhcmRhZG8gKGZvcm1hdG8gRXhjZWwpPC9kaXY+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPgogICAgICA8dGFibGUgc3R5bGU9Im1pbi13aWR0aDoxMTUwcHgiPjx0aGVhZD48dHI+CiAgICAgICAgPHRoPkZlY2hhPC90aD48dGg+RMOtYTwvdGg+PHRoIGNsYXNzPSJudW0iPlZlbnRhcyBicnV0YXM8L3RoPjx0aCBjbGFzcz0ibnVtIj5RdWVkw7MgZW4gY3VlbnRhPC90aD48dGggY2xhc3M9Im51bSI+Q29zdG8gZmFjdHVyYTwvdGg+PHRoIGNsYXNzPSJudW0iPkNvc3RvIGMvZmxleDwvdGg+PHRoIGNsYXNzPSJudW0iPkZhY3R1cmE8L3RoPjx0aCBjbGFzcz0ibnVtIj5HYW5hbmNpYSBjL2ZsZXg8L3RoPjx0aCBjbGFzcz0ibnVtIj4lPC90aD48dGggY2xhc3M9Im51bSI+R2FuYW5jaWEgcy9mbGV4PC90aD48dGggY2xhc3M9Im51bSI+UXVlZMOzIHZlbnRhIHN0b2NrPC90aD48dGggY2xhc3M9Im51bSI+Q3VvdGFzPC90aD48dGg+PC90aD4KICAgICAgPC90cj48L3RoZWFkPjx0Ym9keSBpZD0iaF9kYWlseV9yb3dzIj48L3Rib2R5PjwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idHRsIiBzdHlsZT0icGFkZGluZzoxMHB4IDEycHggMCI+RGV0YWxsZSBkZSB2ZW50YXMgKHNlZ8O6biBmaWx0cm9zKTwvZGl2PjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIHZzY3JvbGwiPgogICAgICA8dGFibGUgc3R5bGU9Im1pbi13aWR0aDoxNDUwcHgiPjx0aGVhZD48dHI+CiAgICAgICAgPHRoPkZlY2hhPC90aD48dGg+VmVudGE8L3RoPjx0aD5DdWVudGE8L3RoPjx0aD5Fc3RhZG88L3RoPjx0aD5TdG9jazwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbzwvdGg+PHRoIGNsYXNzPSJudW0iPkNvbWlzacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iPkVudsOtbzwvdGg+PHRoIGNsYXNzPSJudW0iPkltcHVlc3RvczwvdGg+PHRoIGNsYXNzPSJudW0iPlF1ZWTDszwvdGg+PHRoIGNsYXNzPSJudW0iPkNvc3RvPC90aD48dGggY2xhc3M9Im51bSI+RmFjdHVyYTwvdGg+PHRoIGNsYXNzPSJudW0iPkdhbmFuY2lhPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuPC90aD48dGggY2xhc3M9Im51bSI+Q3VvdGFzPC90aD48dGg+Q8OzZC9TS1U8L3RoPjx0aD5OwrAgdmVudGE8L3RoPgogICAgICA8L3RyPjwvdGhlYWQ+PHRib2R5IGlkPSJoX2RldGFpbF9yb3dzIj48L3Rib2R5PjwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICA8L2Rpdj4KCiAgPCEtLSA9PT09PSBUQUIgRkxFWCAoY29udHJvbCBkZSBib25pZmljYWNpb25lcykgPT09PT0gLS0+CiAgPGRpdiBjbGFzcz0icGFuZWwiIGlkPSJwYW5lbC1mbGV4Ij4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjZmdyaWQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RGVzZGU8L2xhYmVsPjxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZl9mcm9tIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+SGFzdGE8L2xhYmVsPjxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iZl90byIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk7CsCBkZSB2ZW50YTwvbGFiZWw+PGlucHV0IHR5cGU9InRleHQiIGlkPSJmX29yZGVyIiBwbGFjZWhvbGRlcj0iZmlsdHJhcuKApiIgb25pbnB1dD0iZmxleFJlbmRlcigpIiBzdHlsZT0id2lkdGg6MTUwcHgiPjwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImZsZXhMb2FkKCkiPvCflI0gQnVzY2FyPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJmbGV4RG93bmxvYWRYbHN4KCkiPuKshyBEZXNjYXJnYXIgWExTWDwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIGlkPSJmX21ldGEiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tdG9wOjhweCI+Q29udHJvbCBkZSA8Yj5ib25pZmljYWNpb25lcyBGbGV4PC9iPiBkZSBNZXJjYWRvIExpYnJlIChzb2xvIHZlbnRhcyBGbGV4KS4gVXNhIGxhIDxiPmN1ZW50YSBlbGVnaWRhIGFycmliYTwvYj4uIEVsZWfDrSBlbCBwZXLDrW9kbyB5IHRvY8OhIPCflI0gQnVzY2FyLiBMYSBib25pZmljYWNpw7NuIGVzIGxhIHF1ZSBNTCB0ZSBkYSBwb3IgaGFjZXIgZWwgZW52w61vIEZsZXg7IG5vIGFmZWN0YSBsYSBnYW5hbmNpYSwgZXMgcGxhdGEgcXVlIE1MIHRlIHJlaW50ZWdyYSBwb3IgZWwgZW52w61vLjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJrcGlzIiBpZD0iZl9rcGlzIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwgdnNjcm9sbCI+CiAgICAgIDx0YWJsZSBpZD0iZmxleFRhYmxlIiBjbGFzcz0iaGlkZS1hY2MiIHN0eWxlPSJtaW4td2lkdGg6MTEwMHB4Ij48dGhlYWQ+PHRyPgogICAgICAgIDx0aD5WZW50YTwvdGg+PHRoIGNsYXNzPSJhY2NvbCI+Q3VlbnRhPC90aD48dGg+RXN0YWRvIGVudsOtbzwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbzwvdGg+PHRoIGNsYXNzPSJudW0iPkVudsOtbzwvdGg+PHRoIGNsYXNzPSJudW0iPkJvbmlmaWNhY2nDs24gTUw8L3RoPjx0aCBjbGFzcz0ibnVtIj5DdW90YXM8L3RoPjx0aD5Dw7NkL1NLVTwvdGg+PHRoIGNsYXNzPSJudW0iPk7CsCB2ZW50YTwvdGg+CiAgICAgIDwvdHI+PC90aGVhZD48dGJvZHkgaWQ9ImZfYm9keSI+PHRyPjx0ZCBjb2xzcGFuPSI5IiBjbGFzcz0ibG9hZGluZyI+VG9jw6Eg8J+UjSBCdXNjYXIgcGFyYSB0cmFlciBsYXMgdmVudGFzIEZsZXggZGVsIHBlcsOtb2RvLjwvdGQ+PC90cj48L3Rib2R5PjwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICA8L2Rpdj4KCiAgPCEtLSA9PT09PSBUQUIgRVNUUkFURUdJQSAoZWwgY2VyZWJybykgPT09PT0gLS0+CiAgPGRpdiBjbGFzcz0icGFuZWwiIGlkPSJwYW5lbC1lc3RyIj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8ZGl2IGNsYXNzPSJjZmdyaWQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+TWFyZ2VuICJidWVubyIg4omlICU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJlc3RyX2hpZ2giIHN0ZXA9IjAuNSIgdmFsdWU9IjEyIiBzdHlsZT0id2lkdGg6OTBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPmJ1ZW4gbWFyZ2VuPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+VmVuZGUgc2kgdmVudGFzIOKJpTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImVzdHJfbWluc2FsZXMiIHN0ZXA9IjEiIHZhbHVlPSIxIiBzdHlsZT0id2lkdGg6ODBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPnZlbG9jaWRhZDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkRlbWFuZGEgc2kgdmlzaXRhcyDiiaU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJlc3RyX21pbnZpcyIgc3RlcD0iMSIgdmFsdWU9IjgiIHN0eWxlPSJ3aWR0aDo5MHB4Ij48c3BhbiBjbGFzcz0iaGludCI+aGF5IGludGVyw6lzPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+TXVjaG8gdHLDoWZpY28g4omlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZXN0cl9ob3R2aXMiIHN0ZXA9IjUiIHZhbHVlPSIzMCIgc3R5bGU9IndpZHRoOjkwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij5ubyBjb252aWVydGXihpJhanVzdGFyPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+Uk9BUyBvYmpldGl2bzwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImVzdHJfcm9hcyIgc3RlcD0iMC41IiB2YWx1ZT0iNSIgc3R5bGU9IndpZHRoOjgwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij5wYXJhIGNhbGN1bGFyIEFEUzwvc3Bhbj48L2Rpdj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJsb2FkRXN0cmF0ZWdpYSgpIj7wn6egIENhbGN1bGFyIGVzdHJhdGVnaWE8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InJlZmluYXJNYXJnZW5lcygpIiB0aXRsZT0iVHJhZSBsYSBkYXRhIHJlYWwgZGUgY2FkYSBwdWJsaWNhY2nDs24gZGVzZGUgTUw6IHTDrXR1bG8sIHByZWNpbyBjb24gcHJvbW8sIHZlbnRhcywgdmlzaXRhcywgZXhwb3NpY2nDs24geSBlbCBjb3N0byBleGFjdG8gKHNpbXVsYXIgY29zdG9zKSI+8J+OryBFbnJpcXVlY2VyIGNvbiBkYXRvcyBkZSBNTDwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iZG93bmxvYWRFc3RyYXRlZ2lhWGxzeCgpIj7irIcgRGVzY2FyZ2FyIFhMU1g8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLXRvcDo4cHgiPk1vdG9yIGRlIHBvc2ljaW9uYW1pZW50bzogY3J1emEgPGI+dG9kYXMgbGFzIGN1ZW50YXM8L2I+IHBvciB0w610dWxvIHkgY2xhc2lmaWNhIGNhZGEgcHVibGljYWNpw7NuIHBvciA8Yj5tYXJnZW4gw5cgdmVudGFzIMOXIHZpc2l0YXMgw5cgY29udmVyc2nDs248L2I+LCBjb24gbGEganVnYWRhIHBhcmEgY29udmVydGlybGEgZW4gdmVudGEuIEVsIG1hcmdlbiBzYWxlIGRlbCA8Yj5zaW11bGFkb3IgZGUgTUw8L2I+IGFsIDxiPnByZWNpbyByZWFsIGNvbiBwcm9tbzwvYj4gKPCflLUpLCBmYWxsYmFjayBkZSBsaXN0YSAo8J+foCkuIDxiPkltcG9ydGFudGU6PC9iPiBsb3MgZGF0b3MgcmVhbGVzICh0w610dWxvLCB2ZW50YXMsIHZpc2l0YXMsIHByZWNpbyBjb24gcHJvbW8pIHNhbGVuIGRlIE1MIHPDs2xvIGN1YW5kbyB0b2PDoXMgPGI+8J+OryBFbnJpcXVlY2VyPC9iPiDigJQgaGFjZWxvIHBvciBjdWVudGEuIEVsIDxiPiJ2ZW5kZSI8L2I+IG1pcmEgbGFzIDxiPnZlbnRhcyBkZSBsb3Mgw7psdGltb3MgMyBtZXNlczwvYj4uPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiIGlkPSJlc3RyX3Byb2dyZXNzX2NhcmQiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ym9yZGVyLWNvbG9yOnZhcigtLW5hdnkpIj4KICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweDtmbGV4LXdyYXA6d3JhcCI+CiAgICAgICAgPGIgc3R5bGU9ImZvbnQtc2l6ZToxM3B4O2NvbG9yOnZhcigtLW5hdnkpIiBpZD0iZXN0cl9wcm9nX3R4dCI+RW5yaXF1ZWNpZW5kb+KApjwvYj4KICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiIGlkPSJlc3RyX3Byb2dfc3ViIiBzdHlsZT0iZm9udC1zaXplOjExcHgiPjwvc3Bhbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InN0b3BFbnJpcXVlY2VyKCkiIHN0eWxlPSJtYXJnaW4tbGVmdDphdXRvIiBpZD0iZXN0cl9zdG9wX2J0biI+4o+5IERldGVuZXI8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImJhciIgc3R5bGU9Im1hcmdpbi10b3A6OHB4Ij48aSBpZD0iZXN0cl9wcm9nX2JhciIgc3R5bGU9IndpZHRoOjAlO2JhY2tncm91bmQ6dmFyKC0tbmF2eSkiPjwvaT48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ia3BpcyIgaWQ9ImVzdHJfa3BpcyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0iZXN0cl9wbGFuX2NhcmQiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogICAgICA8aDM+8J+TiyBQbGFuIGRlIGFjY2nDs24g4oCUIHF1w6kgaGFjZXIsIHBvciBwcmlvcmlkYWQ8L2gzPgogICAgICA8ZGl2IGlkPSJlc3RyX3BsYW4iIHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGwsbWlubWF4KDIyMHB4LDFmcikpO2dhcDoxMHB4Ij48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjhweCI+VG9jw6EgdW5hIGFjY2nDs24gcGFyYSBmaWx0cmFyIGxhIHRhYmxhIGRlIGFiYWpvLiBFbCBvcmRlbiBlcyBwb3IgaW1wYWN0bzogcHJpbWVybyBlc2NhbGFyIHkgcHJvbW92ZXIuPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiIGlkPSJlc3RyX2FjY3RzX2NhcmQiIHN0eWxlPSJkaXNwbGF5Om5vbmUiPgogICAgICA8aDM+Q3VlbnRhcyBoYWNpYSBzdSBvYmpldGl2bzwvaDM+CiAgICAgIDxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj48dGFibGUgc3R5bGU9Im1pbi13aWR0aDoxMDAwcHgiIGlkPSJlc3RyQWNjdFRhYmxlIj4KICAgICAgICA8dGhlYWQ+PHRyPjx0aD5DdWVudGE8L3RoPjx0aCBjbGFzcz0ibnVtIj5PYmpldGl2by9tZXM8L3RoPjx0aCBjbGFzcz0ibnVtIj5Qcm95LiBtZXMgY29ycmlkbzwvdGg+PHRoIGNsYXNzPSJudW0iPkF2YW5jZTwvdGg+PHRoIGNsYXNzPSJudW0iPkZhbHRhbnRlPC90aD48dGggY2xhc3M9Im51bSI+8J+SsCBBRFMgc3VnZXJpZG8vbWVzPC90aD48dGggY2xhc3M9Im51bSI+RW5yaXF1ZWMuPC90aD48dGggY2xhc3M9Im51bSI+4q2QPC90aD48dGggY2xhc3M9Im51bSI+8J+OrzwvdGg+PHRoIGNsYXNzPSJudW0iPvCfkZE8L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9ImVzdHJfYWNjdHMiPjwvdGJvZHk+CiAgICAgIDwvdGFibGU+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImxlZ2VuZCIgaWQ9ImVzdHJfbGVnZW5kIiBzdHlsZT0iZGlzcGxheTpub25lIj4KICAgICAgPHNwYW4+PGI+4q2QIEVzdHJlbGxhOjwvYj4gdmVuZGnDsyAow7psdGltb3MgMyBtZXNlcykgKyBidWVuIG1hcmdlbiDihpIgZXNjYWxhciBBRFM8L3NwYW4+CiAgICAgIDxzcGFuPjxiPvCfmoAgUHJvbWVzYTo8L2I+IGJ1ZW4gbWFyZ2VuICsgZGVtYW5kYSwgbm8gdmVuZGUg4oaSIEFEUyArIHByb21vPC9zcGFuPgogICAgICA8c3Bhbj48Yj7wn5SnIEFqdXN0YXI6PC9iPiBtdWNobyB0csOhZmljbywgbm8gY29udmllcnRlIOKGkiBwcmVjaW8vcHVibGljYWNpw7NuIChOTyBBRFMpPC9zcGFuPgogICAgICA8c3Bhbj48Yj7wn5CEIFZhY2E6PC9iPiB2ZW5kZSArIG1hcmdlbiBmbGFjbyDihpIgb3B0aW1pemFyIHByZWNpbzwvc3Bhbj4KICAgICAgPHNwYW4+PGI+8J+SpCBEdXJtaWVudGU6PC9iPiBzaW4gZGVtYW5kYSDihpIgc3RvY2sgMCBvIHN1YmlyIHByZWNpbzwvc3Bhbj4KICAgICAgPHNwYW4+PGI+8J+MsSBPcmfDoW5pY286PC9iPiBkdXBsaWNhZG8sIG90cmEgY3VlbnRhIGxpZGVyYTwvc3Bhbj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iZmlsdGVycyIgaWQ9ImVzdHJfZmlsdGVycyIgc3R5bGU9ImRpc3BsYXk6bm9uZTttYXJnaW4tYm90dG9tOjEwcHgiPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCBvbiIgZGF0YS1zZWc9ImVzdHJlbGxhIiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiPuKtkCBFc3RyZWxsYTwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtc2VnPSJwcm9tZXNhIiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiPvCfmoAgUHJvbWVzYTwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtc2VnPSJhanVzdGFyIiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiPvCflKcgQWp1c3Rhcjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtc2VnPSJ2YWNhIiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiPvCfkIQgVmFjYTwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtc2VnPSJkdXJtaWVudGUiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSI+8J+SpCBEdXJtaWVudGU8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIiBkYXRhLXNlZz0iZW5yaWNoZWRPbmx5IiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiIHRpdGxlPSJTb2xvIGxvcyBlbnJpcXVlY2lkb3MgY29uIGRhdGEgcmVhbCBkZSBNTCI+4pyFIFNvbG8gZW5yaXF1ZWNpZG9zPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCIgZGF0YS1zZWc9ImR1cE9ubHkiIG9uY2xpY2s9InRvZ2dsZVNlZyh0aGlzKSIgdGl0bGU9IlNvbG8gcHJvZHVjdG9zIHJlcGV0aWRvcyBlbnRyZSBjdWVudGFzIj7wn5SBIFNvbG8gZHVwbGljYWRvczwvc3Bhbj4KICAgICAgPHNlbGVjdCBpZD0iZXN0cl9hY2N0IiBvbmNoYW5nZT0iZmlsdGVyQWNjdCh0aGlzLnZhbHVlKSIgdGl0bGU9Ik1vc3RyYXIgc29sbyB1bmEgY3VlbnRhIChlbCBjcnVjZSBwb3IgdMOtdHVsbyBzaWd1ZSB2aWVuZG8gdG9kYXMpIiBzdHlsZT0ibWFyZ2luLWxlZnQ6OHB4O3BhZGRpbmc6NHB4IDhweDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7Ym9yZGVyLXJhZGl1czo4cHg7Zm9udC1zaXplOjEycHgiPgogICAgICAgIDxvcHRpb24gdmFsdWU9IiI+8J+PoiBUb2RhcyBsYXMgY3VlbnRhczwvb3B0aW9uPgogICAgICA8L3NlbGVjdD4KICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJkb3dubG9hZEVzdHJhdGVnaWFWaXNpYmxlWGxzeCgpIiBzdHlsZT0ibWFyZ2luLWxlZnQ6YXV0byIgdGl0bGU9IkJhamEgYSBFeGNlbCBleGFjdGFtZW50ZSBsbyBxdWUgZXN0w6FzIHZpZW5kbywgY29uIGxvcyBmaWx0cm9zIGFwbGljYWRvcyI+4qyHIERlc2NhcmdhciBsbyBmaWx0cmFkbyAoWExTWCk8L2J1dHRvbj4KICAgIDwvZGl2PgogICAgPGRpdiBpZD0iZXN0cl9jb3VudCIgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLWJvdHRvbTo2cHg7ZGlzcGxheTpub25lIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPgogICAgICA8dGFibGUgaWQ9ImVzdHJUYWJsZSIgc3R5bGU9Im1pbi13aWR0aDoxMjgwcHgiPgogICAgICAgIDx0aGVhZD48dHI+CiAgICAgICAgICA8dGggZGF0YS1rPSJ0aXRsZSIgb25jbGljaz0ic29ydEVzdHIoJ3RpdGxlJykiPlByb2R1Y3RvPC90aD4KICAgICAgICAgIDx0aCBkYXRhLWs9ImFjY291bnRfbmFtZSIgb25jbGljaz0ic29ydEVzdHIoJ2FjY291bnRfbmFtZScpIj5DdWVudGE8L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0ic2VnbWVudCIgb25jbGljaz0ic29ydEVzdHIoJ3NlZ21lbnQnKSI+U2VnbWVudG88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ic2NvcmUiIG9uY2xpY2s9InNvcnRFc3RyKCdzY29yZScpIiB0aXRsZT0iUG90ZW5jaWFsIGRlIGFjY2nDs24gKG1hcmdlbiDDlyBkZW1hbmRhIMOXIGNvbnZlcnNpw7NuKSI+UG90ZW5jaWFsPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9Im1hcmdpbiIgb25jbGljaz0ic29ydEVzdHIoJ21hcmdpbicpIj5NYXJnZW48L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0icHJpY2UiIG9uY2xpY2s9InNvcnRFc3RyKCdwcmljZScpIj5QcmVjaW88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ic29sZCIgb25jbGljaz0ic29ydEVzdHIoJ3NvbGQnKSIgdGl0bGU9IlVuaWRhZGVzIHZlbmRpZGFzIGVuIGxvcyDDumx0aW1vcyAzIG1lc2VzIChkZWZpbmUgc2kgJ3ZlbmRlJykiPlZlbnRhcyAzbTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJ2aXNpdHMiIG9uY2xpY2s9InNvcnRFc3RyKCd2aXNpdHMnKSIgdGl0bGU9IlZpc2l0YXMgZGUgbG9zIMO6bHRpbW9zIDMgbWVzZXMgKG1pc21hIHZlbnRhbmEgcXVlIGxhcyB2ZW50YXMpIj5WaXNpdGFzIDNtPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImNvbnYiIG9uY2xpY2s9InNvcnRFc3RyKCdjb252JykiIHRpdGxlPSJDb252ZXJzacOzbiA9IHZlbnRhcyAvIHZpc2l0YXMiPkNvbnYuPC90aD4KICAgICAgICAgIDx0aCBkYXRhLWs9ImlzTGVhZGVyIiBvbmNsaWNrPSJzb3J0RXN0cignaXNMZWFkZXInKSI+TMOtZGVyPC90aD4KICAgICAgICAgIDx0aD5BY2Npw7NuPC90aD4KICAgICAgICA8L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJlc3RyX2JvZHkiPjx0cj48dGQgY29sc3Bhbj0iMTEiIGNsYXNzPSJsb2FkaW5nIj5Ub2PDoSAi8J+noCBDYWxjdWxhciBlc3RyYXRlZ2lhIiBwYXJhIGNydXphciBsYXMgY3VlbnRhcy48L3RkPjwvdHI+PC90Ym9keT4KICAgICAgPC90YWJsZT4KICAgIDwvZGl2PjwvZGl2PgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBBSlVTVEVTID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIiBpZD0icGFuZWwtYWp1c3RlcyI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGgzPuKame+4jyBPYmpldGl2byB5IGZhY3R1cmEgcG9yIGN1ZW50YTwvaDM+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLWJvdHRvbToxMHB4Ij5FbCA8Yj5vYmpldGl2byBtZW5zdWFsPC9iPiBkZSBjYWRhIGN1ZW50YSB5IHN1IDxiPiUgZGUgZmFjdHVyYTwvYj4gKGNhcmdvIG1lbnN1YWwgZGUgTUwgcXVlIGN1ZW50YSBjb21vIGNvc3RvKS4gQ29uIGVzdG8gZWwgc2lzdGVtYSBjYWxjdWxhIGVsIG1hcmdlbiByZWFsLCBlbCBhdmFuY2UgbWVzIGNvcnJpZG8geSBjdcOhbnRvIGludmVydGlyIGVuIEFEUy4gPGI+QWwgY2FtYmlhciBsYSBmYWN0dXJhLCBlbCBtYXJnZW4gc2UgcmVjYWxjdWxhIHNvbG88L2I+IGN1YW5kbyB2b2x2w6lzIGEgQ2FsY3VsYXIgZXN0cmF0ZWdpYSDigJQgbm8gaGFjZSBmYWx0YSByZS1lbnJpcXVlY2VyLjwvZGl2PgogICAgICA8ZGl2IGlkPSJlc3RyX2FjY3RjZmciIHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGwsbWlubWF4KDMwMHB4LDFmcikpO2dhcDoxMHB4Ij48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBQUkVDSU9TIChhY3R1YWxpemFkb3IgbWFzaXZvKSA9PT09PSAtLT4KICA8ZGl2IGNsYXNzPSJwYW5lbCIgaWQ9InBhbmVsLXByZWNpb3MiPgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9ImVzdHJfcHJlY2lvc19jYXJkIiBzdHlsZT0iYm9yZGVyOjJweCBzb2xpZCB2YXIoLS1uYXZ5KSI+CiAgICAgIDxoMz7wn5KyIEFjdHVhbGl6YWRvciBkZSBwcmVjaW9zIG1hc2l2byDigJQgcG9yIGVzdHJhdGVnaWE8L2gzPgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206MTBweCI+RGVmaW7DrSB1bmEgcmVnbGEgcG9yIGFjY2nDs24uIDxiPk1hcmdlbiBvYmpldGl2bzwvYj46IGVsIHNpc3RlbWEgY2FsY3VsYSBlbCBwcmVjaW8gY29uIGVsIGNvc3RvIGV4YWN0byBkZSBNTC4gPGI+QWp1c3RlICU8L2I+OiBzdWJlL2JhamEgZWwgcHJlY2lvIGFjdHVhbCBlc2UgcG9yY2VudGFqZS4gRGVzcHXDqXMgdmVzIGxhIDxiPnZpc3RhIHByZXZpYTwvYj4geSBhcHJvYsOhcyBhbnRlcyBkZSBtYW5kYXIgYSBNTC4gU29sbyBmdW5jaW9uYSBjb24gcHJvZHVjdG9zIDxiPmVucmlxdWVjaWRvczwvYj4uPC9kaXY+CiAgICAgIDxkaXYgaWQ9InByZWNpb19ydWxlcyIgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMzIwcHgsMWZyKSk7Z2FwOjEwcHgiPjwvZGl2PgogICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7ZmxleC13cmFwOndyYXA7bWFyZ2luLXRvcDoxMnB4O2FsaWduLWl0ZW1zOmNlbnRlciI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0icHJldmlld1ByZWNpb3MoKSI+8J+RgSBWaXN0YSBwcmV2aWE8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImFwbGljYXJQcmVjaW9zKCkiIGlkPSJwcmVjaW9fYXBwbHlfYnRuIiBzdHlsZT0iZGlzcGxheTpub25lO2JvcmRlci1jb2xvcjp2YXIoLS1ncmVlbik7Y29sb3I6IzE2NjUzNCI+4pyFIEFwbGljYXIgYSBNTCAoPHNwYW4gaWQ9InByZWNpb19hcHBseV9uIj4wPC9zcGFuPik8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImRvd25sb2FkUHJlY2lvc1hsc3goKSIgaWQ9InByZWNpb194bHN4X2J0biIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+4qyHIFhMU1g8L2J1dHRvbj4KICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiIGlkPSJwcmVjaW9fcHJldl9pbmZvIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPjwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIiBzdHlsZT0ibWFyZ2luLXRvcDoxMnB4Ij48dGFibGUgaWQ9InByZWNpb1RhYmxlIiBzdHlsZT0ibWluLXdpZHRoOjkwMHB4O2Rpc3BsYXk6bm9uZSI+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0icHJlY2lvX2FsbCIgY2hlY2tlZCBvbmNsaWNrPSJ0b2dnbGVQcmVjaW9BbGwodGhpcykiPjwvdGg+PHRoPlByb2R1Y3RvPC90aD48dGg+Q3VlbnRhPC90aD48dGg+QWNjacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbyBhY3R1YWw8L3RoPjx0aCBjbGFzcz0ibnVtIj5QcmVjaW8gbnVldm88L3RoPjx0aCBjbGFzcz0ibnVtIj7OlCU8L3RoPjx0aCBjbGFzcz0ibnVtIj5NYXJnZW4gYWN0dWFsPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuIG51ZXZvPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJwcmVjaW9fYm9keSI+PC90Ym9keT4KICAgICAgPC90YWJsZT48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBQVUJMSUNJREFEID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIiBpZD0icGFuZWwtcHViIj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8aDM+Q29uZmlndXJhY2nDs24gZGUgZGVjaXNpw7NuICh0dSBtYXJnZW4gbWFuZGEpPC9oMz4KICAgICAgPGRpdiBjbGFzcz0iY2ZncmlkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk1hcmdlbiBuZXRvICU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJjZmdfbWFyZ2luIiBzdGVwPSIwLjUiIG1pbj0iMCI+PHNwYW4gY2xhc3M9ImhpbnQiPmVxdWlsaWJyaW8gZGUgQUNPUzwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkFDT1Mgb2JqZXRpdm8gJTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImNmZ190YXJnZXQiIHN0ZXA9IjAuNSIgbWluPSIwIj48c3BhbiBjbGFzcz0iaGludCI+bWV0YSByZW50YWJsZTwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk3DrW4uIGNsaWNzPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iY2ZnX2NsaWNrcyIgc3RlcD0iMSIgbWluPSIwIj48c3BhbiBjbGFzcz0iaGludCI+cGFyYSBkZWNpZGlyPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+VmVudGFuYSAoZMOtYXMpPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iY2ZnX3dpbmRvdyIgc3RlcD0iMSIgbWluPSIxIiBtYXg9IjkwIj48c3BhbiBjbGFzcz0iaGludCI+bcOheCA5MDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkVudsOtbyBncmF0aXMgZGVzZGUgJDwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImNmZ19zaGlwIiBzdGVwPSIxMDAwIiBtaW49IjAiPjxzcGFuIGNsYXNzPSJoaW50Ij51bWJyYWw8L3NwYW4+PC9kaXY+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJzYXZlQ29uZmlnKCkiPkd1YXJkYXI8L2J1dHRvbj4KICAgICAgICA8ZGl2IGNsYXNzPSJhdXRvdGFnIHBpbGwgcC1ncmV5IiBpZD0iYXV0b3RhZyI+QXV0by1wYXVzYTog4oCUPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJrcGlzIiBpZD0ia3BpcyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJsZWdlbmQiPgogICAgICA8c3Bhbj48aSBjbGFzcz0iZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1ncmVlbikiPjwvaT4gPGI+RXNjYWxhcjwvYj48L3NwYW4+CiAgICAgIDxzcGFuPjxpIGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLWFtYmVyKSI+PC9pPiA8Yj5NYW50ZW5lcjwvYj48L3NwYW4+CiAgICAgIDxzcGFuPjxpIGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOiMzYjgyZjYiPjwvaT4gPGI+SnVudGFyIGRhdG9zPC9iPjwvc3Bhbj4KICAgICAgPHNwYW4+PGkgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVkKSI+PC9pPiA8Yj5QYXVzYXI8L2I+PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmaWx0ZXJzIj4KICAgICAgPHNwYW4gY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS1tdXQpIj5GaWx0cmFyOjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtYWN0PSJFU0NBTEFSIiBvbmNsaWNrPSJ0b2dnbGVDaGlwKHRoaXMpIj7wn5+iIEVzY2FsYXI8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLWFjdD0iTUFOVEVORVIiIG9uY2xpY2s9InRvZ2dsZUNoaXAodGhpcykiPvCfn6EgTWFudGVuZXI8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLWFjdD0iSlVOVEFSX0RBVE9TIiBvbmNsaWNrPSJ0b2dnbGVDaGlwKHRoaXMpIj7wn5S1IEp1bnRhciBkYXRvczwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtYWN0PSJQQVVTQVIiIG9uY2xpY2s9InRvZ2dsZUNoaXAodGhpcykiPvCflLQgUGF1c2FyPC9zcGFuPgogICAgICA8c2VsZWN0IGlkPSJzdGF0dXNGaWx0ZXIiIG9uY2hhbmdlPSJyZW5kZXIoKSI+PG9wdGlvbiB2YWx1ZT0iYWxsIj5Ub2RvcyBsb3MgZXN0YWRvczwvb3B0aW9uPjxvcHRpb24gdmFsdWU9ImFjdGl2ZSI+U29sbyBhY3RpdmFzPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0icGF1c2VkIj5Tb2xvIHBhdXNhZGFzPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0ic2VhcmNoIiBwbGFjZWhvbGRlcj0iQnVzY2FyIHBvciBub21icmUgbyBJRCBkZSBjYW1wYcOxYeKApiIgb25pbnB1dD0icmVuZGVyKCkiPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiPjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj4KICAgICAgPHRhYmxlPgogICAgICAgIDx0aGVhZD48dHI+CiAgICAgICAgICA8dGggb25jbGljaz0ic29ydEJ5KCduYW1lJykiPkNhbXBhw7FhPC90aD48dGggb25jbGljaz0ic29ydEJ5KCdzdGF0dXMnKSI+RXN0YWRvPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ2Nvc3QnKSI+SW52ZXJzacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iIG9uY2xpY2s9InNvcnRCeSgncmV2ZW51ZScpIj5WZW50YXMgcHViLjwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCdhY29zJykiPkFDT1M8L3RoPjx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ2JyZWFrZXZlbkFjb3MnKSI+RXF1aWxpYnJpbzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCduZXRQcm9maXQnKSI+R2FuYW5jaWE8L3RoPjx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ3JvYXMnKSI+Uk9BUzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCdjbGlja3MnKSI+Q2xpY3M8L3RoPjx0aCBvbmNsaWNrPSJzb3J0QnkoJ2FjdGlvbicpIj5BY2Npw7NuPC90aD48dGg+TW90aXZvPC90aD48dGg+PC90aD4KICAgICAgICA8L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJ0Ym9keSI+PHRyPjx0ZCBjb2xzcGFuPSIxMiIgY2xhc3M9ImxvYWRpbmciPkVsZWfDrSB1bmEgY3VlbnRh4oCmPC90ZD48L3RyPjwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJydW5Ob3coKSI+4pa2IENvcnJlciBhbsOhbGlzaXMgQURTPC9idXR0b24+CiAgICAgIDxidXR0b24gb25jbGljaz0idG9nZ2xlTG9nKCkiPvCfk5wgw5psdGltYXMgY29ycmlkYXM8L2J1dHRvbj4KICAgICAgPHNwYW4gY2xhc3M9Im11dGVkIiBpZD0ibGFzdFJ1biI+PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJsb2djYXJkIiBpZD0ibG9nY2FyZCI+PC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIEdBTkFET1JBUyA9PT09PSAtLT4KICA8ZGl2IGNsYXNzPSJwYW5lbCIgaWQ9InBhbmVsLXdpbiI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjEwcHgiPkNydXphIHR1IG1hcmdlbiAoZGVsIEV4Y2VsKSBjb24gZGF0b3MgZW4gdml2byBkZSBNTDogc29sbyBhY3RpdmFzLCBjb24gc3RvY2sgeSBjb24gdmVudGFzLiBDb3Bpw6FzIGxvcyBJRHMgeSBsb3MgcGVnw6FzIGFsIGNyZWFyIGxhIGNhbXBhw7FhIGVuIE1lcmNhZG8gTGlicmUuPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5NYXJnZW4gbcOtbmltbyAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0id2luX21hcmdpbiIgdmFsdWU9IjEyIiBzdGVwPSIxIiBzdHlsZT0id2lkdGg6MTAwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+VmVudGFzIG3DrW5pbWFzPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0id2luX3NhbGVzIiB2YWx1ZT0iMSIgc3RlcD0iMSIgc3R5bGU9IndpZHRoOjEwMHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkNhbnRpZGFkPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0id2luX2xpbWl0IiB2YWx1ZT0iNDAiIHN0ZXA9IjEwIiBzdHlsZT0id2lkdGg6MTAwcHgiPjwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImxvYWRXaW5uZXJzKCkiPkJ1c2NhciBnYW5hZG9yYXM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImNvcHlXaW5uZXJzKCkiPvCfk4sgQ29waWFyIElEczwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iY3N2V2lubmVycygpIj7irIcgQ1NWPC9idXR0b24+CiAgICAgICAgPHNwYW4gY2xhc3M9Im11dGVkIiBpZD0id2luU3RhdHVzIj48L3NwYW4+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiPjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj4KICAgICAgPHRhYmxlIHN0eWxlPSJtaW4td2lkdGg6NjQwcHgiPgogICAgICAgIDx0aGVhZD48dHI+PHRoPlB1YmxpY2FjacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iPk1hcmdlbjwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbzwvdGg+PHRoIGNsYXNzPSJudW0iPlN0b2NrPC90aD48dGggY2xhc3M9Im51bSI+VmVudGFzPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJ3aW5Cb2R5Ij48dHI+PHRkIGNvbHNwYW49IjUiIGNsYXNzPSJsb2FkaW5nIj5FbGVnw60gY3JpdGVyaW9zIHkgdG9jw6EgIkJ1c2NhciBnYW5hZG9yYXMiLjwvdGQ+PC90cj48L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+PC9kaXY+CiAgPC9kaXY+Cgo8L2Rpdj4KPGRpdiBjbGFzcz0idG9hc3QiIGlkPSJ0b2FzdCI+PC9kaXY+Cgo8c2NyaXB0PgondXNlIHN0cmljdCc7CmxldCBTVEFURT17cm93czpbXSxjZmc6e30sc29ydEtleTonY29zdCcsc29ydERpcjotMSxhY3RzOntFU0NBTEFSOjEsTUFOVEVORVI6MSxKVU5UQVJfREFUT1M6MSxQQVVTQVI6MX19OwpsZXQgVkVOPW51bGwsIFdJTk5FUlM9W10sIFNUUkFUPW51bGwsIENVUlRBQj0ncmVudCc7CmNvbnN0ICQ9aWQ9PmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKY29uc3QgZm10TW9uZXk9bj0+KG49PW51bGx8fGlzTmFOKG4pKT8n4oCUJzonJCcrTWF0aC5yb3VuZChuKS50b0xvY2FsZVN0cmluZygnZXMtQVInKTsKY29uc3QgZm10UGN0PW49PihuPT1udWxsfHxpc05hTihuKSk/J+KAlCc6bi50b0ZpeGVkKDEpKyclJzsKY29uc3QgZm10WD1uPT4obj09bnVsbHx8aXNOYU4obikpPyfigJQnOm4udG9GaXhlZCgxKSsneCc7CmZ1bmN0aW9uIHRvYXN0KG0pe2NvbnN0IHQ9JCgndG9hc3QnKTt0LnRleHRDb250ZW50PW07dC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7c2V0VGltZW91dCgoKT0+dC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93JyksMjYwMCk7fQpmdW5jdGlvbiBlc2Mocyl7cmV0dXJuIFN0cmluZyhzPT1udWxsPycnOnMpLnJlcGxhY2UoL1smPD4iXS9nLGM9Pih7JyYnOicmYW1wOycsJzwnOicmbHQ7JywnPic6JyZndDsnLCciJzonJnF1b3Q7J31bY10pKTt9CmFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLG9wdHMpewogIGNvbnN0IHI9YXdhaXQgZmV0Y2gocGF0aCxPYmplY3QuYXNzaWduKHtoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9fSxvcHRzKSk7CiAgaWYoci5zdGF0dXM9PT00MDEpe2xvY2F0aW9uLmhyZWY9Jy8nO3JldHVybiBuZXcgUHJvbWlzZSgoKT0+e30pO30KICBjb25zdCBkPWF3YWl0IHIuanNvbigpLmNhdGNoKCgpPT4oe30pKTsKICBpZighci5vaykgdGhyb3cgKGQuZXJyb3I/ZDp7ZXJyb3I6J0hUVFAgJytyLnN0YXR1c30pOwogIHJldHVybiBkOwp9CgpmdW5jdGlvbiBzaG93VGFiKHQpewogIENVUlRBQj10OwogIFsncmVudCcsJ2hpc3QnLCdmbGV4JywncHViJywnd2luJywnZXN0cicsJ3ByZWNpb3MnLCdhanVzdGVzJ10uZm9yRWFjaCh4PT57Y29uc3QgdGI9JCgndGFiLScreCkscG49JCgncGFuZWwtJyt4KTtpZih0Yil0Yi5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLHg9PT10KTtpZihwbilwbi5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLHg9PT10KTt9KTsKICBpZih0IT09J3B1Yicpe2NvbnN0IGI9JCgnYmFubmVyJyk7aWYoYiliLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTt9ICAvLyBlbCBiYW5uZXIgZGUgQURTIHNvbG8gdmEgZW4gUHVibGljaWRhZAogIGlmKHQ9PT0naGlzdCcpeyBpZighSElTVF9MT0FERUQpeyBoaXN0TG9hZCgpOyB9IH0KICBpZih0PT09J2ZsZXgnKXsgaWYoIUZMRVhfTE9BREVEKXsgZmxleExvYWQoKTsgfSB9CiAgcmVmcmVzaFRhYigpOwp9CmZ1bmN0aW9uIHJlZnJlc2hUYWIoKXsKICBpZighJCgnYWNjb3VudCcpLnZhbHVlKSByZXR1cm47CiAgaWYoQ1VSVEFCPT09J3JlbnQnKXsgLyogUmVudGFiaWxpZGFkIE5PIGJ1c2NhIHNvbGE6IGVsIHVzdWFyaW8gdG9jYSDwn5SNIEJ1c2NhciAqLyB9CiAgZWxzZSBpZihDVVJUQUI9PT0ncHViJyl7IGxvYWRDYW1wYWlnbnMoKTsgfQogIGVsc2UgaWYoQ1VSVEFCPT09J3dpbicpeyAvKiBvbiBkZW1hbmQgKi8gfQogIGVsc2UgaWYoQ1VSVEFCPT09J2VzdHInKXsgaWYoIVNUUkFUKSBsb2FkRXN0cmF0ZWdpYSgpOyB9CiAgZWxzZSBpZihDVVJUQUI9PT0ncHJlY2lvcycpeyByZW5kZXJQcmVjaW9SdWxlcygpOyB9CiAgZWxzZSBpZihDVVJUQUI9PT0nYWp1c3RlcycpeyByZW5kZXJBY2N0Q2ZnKFNUUkFUP1NUUkFULmN1ZW50YXM6W10pOyB9Cn0KZnVuY3Rpb24gb25BY2NvdW50Q2hhbmdlKCl7IFZFTj1udWxsOyBXSU5ORVJTPVtdOyBpZihDVVJUQUIhPT0nZXN0cicpU1RSQVQ9bnVsbDsgcmVmcmVzaFRhYigpOyB9CgpsZXQgQUNDT1VOVFM9W107CmZ1bmN0aW9uIHJlbmRlckNvc3RTbG90cygpewogIGNvbnN0IGJveD0kKCdjb3N0c2xvdHMnKTtpZighYm94KXJldHVybjsKICBib3guaW5uZXJIVE1MPUFDQ09VTlRTLm1hcChhPT4KICAgICc8ZGl2IHN0eWxlPSJib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTBweDtwYWRkaW5nOjhweCAxMHB4O2JhY2tncm91bmQ6I2ZmZiI+JysKICAgICAgJzxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweCI+JysKICAgICAgICAnPGRpdiBzdHlsZT0ibWluLXdpZHRoOjA7ZmxleDoxIj48ZGl2IGNsYXNzPSJiIiBzdHlsZT0iZm9udC1zaXplOjEycHg7d2hpdGUtc3BhY2U6bm93cmFwO292ZXJmbG93OmhpZGRlbjt0ZXh0LW92ZXJmbG93OmVsbGlwc2lzIj4nK2VzYyhhLm5hbWUpKyc8L2Rpdj4nKwogICAgICAgICc8ZGl2IGNsYXNzPSJtdXRlZCIgaWQ9InNsb3Rjb3VudC0nK2EuaWQrJyIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4Ij7igJQgc2luIGNvc3RvczwvZGl2PjwvZGl2PicrCiAgICAgICAgJzxsYWJlbCBjbGFzcz0icGlsbCBwLWJsdWUiIHN0eWxlPSJjdXJzb3I6cG9pbnRlcjt3aGl0ZS1zcGFjZTpub3dyYXAiPvCfk6UgSW1wb3J0YXInKwogICAgICAgICAgJzxpbnB1dCB0eXBlPSJmaWxlIiBhY2NlcHQ9Ii54bHN4LC54bHMiIHN0eWxlPSJkaXNwbGF5Om5vbmUiIG9uY2hhbmdlPSJpbXBvcnRDb3N0cyh0aGlzLCcrYS5pZCsnLFwnJytlc2MoYS5uYW1lKS5yZXBsYWNlKC8nL2csIlxcJyIpKydcJykiPjwvbGFiZWw+JysKICAgICAgJzwvZGl2PicrCiAgICAgICc8ZGl2IGNsYXNzPSJiYXIiIGlkPSJzbG90YmFyLScrYS5pZCsnIiBzdHlsZT0iZGlzcGxheTpub25lO2hlaWdodDo2cHg7bWFyZ2luLXRvcDo2cHgiPjxpIHN0eWxlPSJ3aWR0aDowJTtiYWNrZ3JvdW5kOnZhcigtLWJsdWUpIj48L2k+PC9kaXY+JysKICAgICc8L2Rpdj4nKS5qb2luKCcnKTsKfQovLyBNb2RvIGRlbCBwYW5lbDogJ2dlc3Rpb24nIChzb2xvIEdlc3Rpw7NuKSBvICdlc3RyYXRlZ2lhJyAoRXN0cmF0ZWdpYStQdWJsaWNpZGFkK0dhbmFkb3JhcykuCmNvbnN0IFBBTkVMX01PREU9KHdpbmRvdy5fX1BBTkVMX01PREVfXz09PSdnZXN0aW9uJyk/J2dlc3Rpb24nOidlc3RyYXRlZ2lhJzsKZnVuY3Rpb24gYXBwbHlNb2RlKCl7CiAgY29uc3Qgc2hvd1JlbnQ9KFBBTkVMX01PREU9PT0nZ2VzdGlvbicpOwogIGNvbnN0IGVzdHJUYWJzPVsnZXN0cicsJ3ByZWNpb3MnLCdhanVzdGVzJywncHViJywnd2luJ107CiAgJCgndGFiLXJlbnQnKS5zdHlsZS5kaXNwbGF5PXNob3dSZW50PycnOidub25lJzsKICBjb25zdCBoYj0kKCd0YWItaGlzdCcpOyBpZihoYikgaGIuc3R5bGUuZGlzcGxheT1zaG93UmVudD8nJzonbm9uZSc7CiAgY29uc3QgZmI9JCgndGFiLWZsZXgnKTsgaWYoZmIpIGZiLnN0eWxlLmRpc3BsYXk9c2hvd1JlbnQ/Jyc6J25vbmUnOwogIGVzdHJUYWJzLmZvckVhY2godD0+e2NvbnN0IGI9JCgndGFiLScrdCk7aWYoYiliLnN0eWxlLmRpc3BsYXk9c2hvd1JlbnQ/J25vbmUnOicnO30pOwogIC8vIFTDrXR1bG8gc2Vnw7puIG1vZG8KICBjb25zdCBoMT1kb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdoZWFkZXIudG9wIGgxJyksIHN1Yj1kb2N1bWVudC5xdWVyeVNlbGVjdG9yKCdoZWFkZXIudG9wIC5zdWInKTsKICBpZihzaG93UmVudCl7IGlmKGgxKWgxLnRleHRDb250ZW50PSfwn5eC77iPIEdlc3Rpw7NuIMK3IEF1dG9jaGFwJzsgaWYoc3ViKXN1Yi50ZXh0Q29udGVudD0nUmVudGFiaWxpZGFkIGRpYXJpYSBwb3IgY3VlbnRhIOKAlCBjdcOhbnRvIGdhbsOhcyBwb3IgZMOtYSc7IH0KICBlbHNlIHsgaWYoaDEpaDEudGV4dENvbnRlbnQ9J/Cfp6AgRXN0cmF0ZWdpYSDCtyBBdXRvY2hhcCc7IGlmKHN1YilzdWIudGV4dENvbnRlbnQ9J1NlZ21lbnRhY2nDs24sIGN1ZW50YSBsw61kZXIgeSBjcmVjaW1pZW50byBwb3IgY3VlbnRhJzsgfQogIHNob3dUYWIoc2hvd1JlbnQ/J3JlbnQnOidlc3RyJyk7Cn0KYXN5bmMgZnVuY3Rpb24gaW5pdCgpewogIHRyeXsKICAgIGNvbnN0IGFjY3M9YXdhaXQgYXBpKCcvYXBpL2Fkcy9hY2NvdW50cycpOwogICAgQUNDT1VOVFM9YWNjcy5hY2NvdW50c3x8W107CiAgICBjb25zdCBzZWw9JCgnYWNjb3VudCcpOyBzZWwuaW5uZXJIVE1MPScnOwogICAgY29uc3Qgb0FsbD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdvcHRpb24nKTtvQWxsLnZhbHVlPSdhbGwnO29BbGwudGV4dENvbnRlbnQ9J/Cfl4LvuI8gVG9kYXMgbGFzIGN1ZW50YXMnO3NlbC5hcHBlbmRDaGlsZChvQWxsKTsKICAgIEFDQ09VTlRTLmZvckVhY2goYT0+e2NvbnN0IG89ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnb3B0aW9uJyk7by52YWx1ZT1hLmlkO28udGV4dENvbnRlbnQ9YS5uYW1lKycgKCcrYS5zZWxsZXJfaWQrJyknO3NlbC5hcHBlbmRDaGlsZChvKTt9KTsKICAgIHJlbmRlckNvc3RTbG90cygpOwogIH1jYXRjaChlKXt9CiAgYXdhaXQgbG9hZENvbmZpZygpOyBsb2FkQ29zdFN0YXR1cygpOwogIC8vIEZlY2hhcyBwb3IgZGVmZWN0byBlbiBob3JhIGFyZ2VudGluYSAoVVRDLTMpLCBjb25zaXN0ZW50ZSBjb24gZWwgRGFzaGJvYXJkLgogIGNvbnN0IGFyZ1RvZGF5PW5ldyBEYXRlKERhdGUubm93KCktMyozNjAwKjEwMDApLCBhcmdBZ289bmV3IERhdGUoRGF0ZS5ub3coKS0zKjM2MDAqMTAwMC0zMCo4NjQwMDAwMCk7CiAgJCgndmVuX3RvJykudmFsdWU9YXJnVG9kYXkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTsKICAkKCd2ZW5fZnJvbScpLnZhbHVlPWFyZ0Fnby50b0lTT1N0cmluZygpLnNsaWNlKDAsMTApOwogIGlmKCQoJ2ZfdG8nKSkgJCgnZl90bycpLnZhbHVlPWFyZ1RvZGF5LnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCk7ICAgLy8gc29sYXBhIEZMRVgKICBpZigkKCdmX2Zyb20nKSkgJCgnZl9mcm9tJykudmFsdWU9YXJnQWdvLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCk7CiAgcmVuZGVyQWNjdENmZyhbXSk7ICAgICAgLy8gb2JqZXRpdm8vZmFjdHVyYSBwb3IgY3VlbnRhIHZpc2libGVzIGRlc2RlIGVsIGluaWNpbyAoY29uIGxvIGd1YXJkYWRvKQogIHJlbmRlclByZWNpb1J1bGVzKCk7ICAgIC8vIHJlZ2xhcyBkZWwgYWN0dWFsaXphZG9yIGRlIHByZWNpb3MgbGlzdGFzCiAgYXBwbHlNb2RlKCk7IC8vIG11ZXN0cmEgbGFzIHBlc3Rhw7FhcyBzZWfDum4gL2dlc3Rpb24gbyAvcHVibGljaWRhZAp9CmFzeW5jIGZ1bmN0aW9uIGxvYWRDb25maWcoKXsKICB0cnl7CiAgICBjb25zdCBjPWF3YWl0IGFwaSgnL2FwaS9hZHMvY29uZmlnJyk7IFNUQVRFLmNmZz1jOwogICAgaWYoJCgnY2ZnX21hcmdpbicpKXskKCdjZmdfbWFyZ2luJykudmFsdWU9Yy5tYXJnaW47JCgnY2ZnX3RhcmdldCcpLnZhbHVlPWMuYWNvc1RhcmdldDskKCdjZmdfY2xpY2tzJykudmFsdWU9Yy5taW5DbGlja3M7JCgnY2ZnX3dpbmRvdycpLnZhbHVlPWMud2luZG93RGF5czsKICAgICQoJ2NmZ19zaGlwJykudmFsdWU9Yy5mcmVlU2hpcFRocmVzaG9sZCE9bnVsbD9jLmZyZWVTaGlwVGhyZXNob2xkOjMzMDAwO30KICAgIGlmKCQoJ3Zlbl90YXgnKSYmISQoJ3Zlbl90YXgnKS52YWx1ZSkkKCd2ZW5fdGF4JykudmFsdWU9KGMuZmFjdHVyYVBjdCE9bnVsbD9jLmZhY3R1cmFQY3Q6NSk7ICAvLyBmYWN0dXJhICUgZ2xvYmFsCiAgICBjb25zdCB0YWc9JCgnYXV0b3RhZycpO3RhZy50ZXh0Q29udGVudD0nQXV0by1wYXVzYTogJysoYy5hdXRvUGF1c2U/J0FDVElWQSc6J0RSWS1SVU4gKG5vIHBhdXNhKScpO3RhZy5jbGFzc05hbWU9J2F1dG90YWcgcGlsbCAnKyhjLmF1dG9QYXVzZT8ncC1yZWQnOidwLWdyZXknKTsKICB9Y2F0Y2goZSl7fQp9CmFzeW5jIGZ1bmN0aW9uIHNhdmVDb25maWcoKXsKICB0cnl7Y29uc3QgYm9keT17bWFyZ2luOiskKCdjZmdfbWFyZ2luJykudmFsdWUsYWNvc1RhcmdldDorJCgnY2ZnX3RhcmdldCcpLnZhbHVlLG1pbkNsaWNrczorJCgnY2ZnX2NsaWNrcycpLnZhbHVlLHdpbmRvd0RheXM6KyQoJ2NmZ193aW5kb3cnKS52YWx1ZSxmcmVlU2hpcFRocmVzaG9sZDorJCgnY2ZnX3NoaXAnKS52YWx1ZX07CiAgY29uc3Qgcj1hd2FpdCBhcGkoJy9hcGkvYWRzL2NvbmZpZycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShib2R5KX0pO1NUQVRFLmNmZz1yLmNvbmZpZzt0b2FzdCgnQ29uZmlndXJhY2nDs24gZ3VhcmRhZGEnKTtsb2FkQ2FtcGFpZ25zKCk7fQogIGNhdGNoKGUpe3RvYXN0KCdFcnJvcjogJysoZS5lcnJvcnx8ZSkpO30KfQoKLy8gLS0tLSBDb3N0b3MgLS0tLQpmdW5jdGlvbiBwaWNrKHJvdyxuYW1lcyl7Zm9yKGNvbnN0IG4gb2YgbmFtZXMpe2Zvcihjb25zdCBrIGluIHJvdyl7aWYoU3RyaW5nKGspLnRyaW0oKS50b0xvd2VyQ2FzZSgpPT09bilyZXR1cm4gcm93W2tdO319cmV0dXJuIHVuZGVmaW5lZDt9CmZ1bmN0aW9uIGltcG9ydENvc3RzKGlucHV0LGFjY0lkLGFjY05hbWUpewogIGNvbnN0IGZpbGU9aW5wdXQuZmlsZXMmJmlucHV0LmZpbGVzWzBdO2lmKCFmaWxlKXJldHVybjsKICBpZih0eXBlb2YgWExTWD09PSd1bmRlZmluZWQnKXt0b2FzdCgnTm8gY2FyZ8OzIGxhIGxpYnJlcsOtYSBkZSBFeGNlbCcpO3JldHVybjt9CiAgaWYoIWFjY0lkKXt0b2FzdCgnQ2FzaWxsZXJvIHNpbiBjdWVudGEnKTtpbnB1dC52YWx1ZT0nJztyZXR1cm47fQogIGNvbnN0IGNudD0kKCdzbG90Y291bnQtJythY2NJZCk7aWYoY250KWNudC50ZXh0Q29udGVudD0nbGV5ZW5kbyBFeGNlbOKApic7CiAgY29uc3QgcmVhZGVyPW5ldyBGaWxlUmVhZGVyKCk7CiAgcmVhZGVyLm9ubG9hZD1hc3luYyBlPT57CiAgICB0cnl7CiAgICAgIGNvbnN0IHdiPVhMU1gucmVhZChlLnRhcmdldC5yZXN1bHQse3R5cGU6J2FycmF5J30pO2NvbnN0IHdzPXdiLlNoZWV0c1snU2hlZXQxJ118fHdiLlNoZWV0c1t3Yi5TaGVldE5hbWVzWzBdXTsKICAgICAgLy8gRmlsYXMgY29tbyBBUlJBWVMgKHLDoXBpZG8pIHkgbWFwZW8gZGUgY29sdW1uYXMgVU5BIFNPTEEgVkVaIChldml0YSByZWNvcnJlciBjb2x1bW5hcyBwb3IgY2FkYSBmaWxhKS4KICAgICAgY29uc3Qgcm93cz1YTFNYLnV0aWxzLnNoZWV0X3RvX2pzb24od3Mse2hlYWRlcjoxLGRlZnZhbDonJ30pOwogICAgICBjb25zdCBIPShyb3dzWzBdfHxbXSkubWFwKHg9PlN0cmluZyh4PT1udWxsPycnOngpLnRyaW0oKS50b0xvd2VyQ2FzZSgpKTsKICAgICAgY29uc3QgaWR4PW5hbWVzPT57Zm9yKGNvbnN0IG4gb2YgbmFtZXMpe2NvbnN0IGk9SC5pbmRleE9mKG4pO2lmKGk+PTApcmV0dXJuIGk7fXJldHVybiAtMTt9OwogICAgICBjb25zdCBjSWQ9aWR4KFsnaXRlbV9pZCddKSxjQ29zdD1pZHgoWydwcmVjaW8gY29zdG8nXSksY0NTPWlkeChbJ2Nvc3RvL2dhc3RvcyddKSxjU2g9aWR4KFsnc2hpcHBpbmcnXSksY0NvbT1pZHgoWydjb3N0byBwb3IgdmVuZGVyJ10pLGNMVD1pZHgoWydsaXN0aW5nX3R5cGVfaWQnXSksY0xQPWlkeChbJ3ByZWNpbyBmaW5hbCddKSxjTWc9aWR4KFsnbWFyZ2VuIGRlIGdhbmFuY2lhJ10pLGNPZj1pZHgoWydvZmVydGEnXSksY1RpPWlkeChbJ3RpdHVsbycsJ3TDrXR1bG8nLCd0aXRsZScsJ3B1YmxpY2FjaW9uJywncHVibGljYWNpw7NuJywnbm9tYnJlJ10pLGNTaz1pZHgoWydjb2RpZ28gdXRpbGl6YWRvJywnY8OzZGlnbyB1dGlsaXphZG8nLCdjb2RpZ29fdXRpbGl6YWRvJywnc2t1JywnY29kaWdvJywnY8OzZGlnbycsJ2NvZGlnbyBwcm92ZWVkb3InLCdjw7NkaWdvIHByb3ZlZWRvcicsJ3NrdSBwcm92ZWVkb3InXSksY1ByPWlkeChbJ3Byb3ZlZWRvciB1dGlsaXphZG8nLCdwcm92ZWVkb3JfdXRpbGl6YWRvJywncHJvdmVlZG9yJywncHJvdicsJ3Byb3ZlZWRvcjonXSk7CiAgICAgIGlmKGNJZDwwKXt0b2FzdCgnTm8gZW5jb250csOpIGxhIGNvbHVtbmEgaXRlbV9pZCBlbiBlbCBFeGNlbCcpO2lmKGNudCljbnQudGV4dENvbnRlbnQ9J+KAlCBmYWx0YSBjb2x1bW5hIGl0ZW1faWQnO3JldHVybjt9CiAgICAgIC8vIEZvcm1hdG8gQ09MVU1OQVIgKGFycmF5cywgc2luIHJlcGV0aXIgbG9zIG5vbWJyZXMgZGUgY29sdW1uYSBlbiBjYWRhIGZpbGEpIOKGkiBwYXlsb2FkIH5taXRhZCwgc3ViZSBtw6FzIHLDoXBpZG8uCiAgICAgIC8vIE9yZGVuIGZpam86IFtpdGVtX2lkLCBjb3N0LCBjb3N0U2hpcCwgc2hpcCwgY29tbWlzc2lvbiwgbGlzdGluZ1R5cGUsIGxpc3RQcmljZSwgbWFyZ2luTGlzdCwgb2ZlcnRhLCB0aXRsZSwgc2t1LCBwcm92ZWVkb3JdCiAgICAgIGNvbnN0IHJlPS9eTUxBXGQrL2k7Y29uc3QgaXRlbXM9W107CiAgICAgIGZvcihsZXQgcj0xO3I8cm93cy5sZW5ndGg7cisrKXtjb25zdCByb3c9cm93c1tyXTtpZighcm93KWNvbnRpbnVlO2NvbnN0IGl0ZW1faWQ9U3RyaW5nKHJvd1tjSWRdPT1udWxsPycnOnJvd1tjSWRdKS50cmltKCk7aWYoIXJlLnRlc3QoaXRlbV9pZCkpY29udGludWU7CiAgICAgICAgaXRlbXMucHVzaChbaXRlbV9pZCxyb3dbY0Nvc3RdLHJvd1tjQ1NdLHJvd1tjU2hdLHJvd1tjQ29tXSxyb3dbY0xUXSxyb3dbY0xQXSxyb3dbY01nXSxjT2Y+PTA/cm93W2NPZl06JycsY1RpPj0wP3Jvd1tjVGldOicnLGNTaz49MD9yb3dbY1NrXTonJyxjUHI+PTA/cm93W2NQcl06JyddKTt9CiAgICAgIGlmKCFpdGVtcy5sZW5ndGgpe3RvYXN0KCdObyBlbmNvbnRyw6kgZmlsYXMgY29uIGl0ZW1faWQgdsOhbGlkbycpO2lmKGNudCljbnQudGV4dENvbnRlbnQ9J+KAlCBzaW4gZmlsYXMgdsOhbGlkYXMnO3JldHVybjt9CiAgICAgIC8vIFN1YmlkYSBjb24gYmFycmEgZGUgcHJvZ3Jlc28gcmVhbCAoWEhSIHJlcG9ydGEgZWwgJSBkZWwgdXBsb2FkOyBmZXRjaCBubyBwdWVkZSkuCiAgICAgIGNvbnN0IHBheWxvYWQ9SlNPTi5zdHJpbmdpZnkoe2l0ZW1zLHY6MixhY2NvdW50X2lkOmFjY0lkLHJlcGxhY2U6dHJ1ZX0pOwogICAgICBjb25zdCBiYXI9JCgnc2xvdGJhci0nK2FjY0lkKSwgYmFyST1iYXI/YmFyLnF1ZXJ5U2VsZWN0b3IoJ2knKTpudWxsOwogICAgICBpZihiYXIpYmFyLnN0eWxlLmRpc3BsYXk9J2Jsb2NrJzsgaWYoYmFySSliYXJJLnN0eWxlLndpZHRoPScwJSc7CiAgICAgIGNvbnN0IHRvdGFsPWl0ZW1zLmxlbmd0aDsKICAgICAgdXBsb2FkQ29zdHMocGF5bG9hZCx7CiAgICAgICAgb25wcm9ncmVzczoocGN0KT0+eyBpZihiYXJJKWJhckkuc3R5bGUud2lkdGg9cGN0KyclJzsgaWYoY250KWNudC50ZXh0Q29udGVudD0nc3ViaWVuZG8gJytwY3QrJyUgKCcrdG90YWwudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyknOyB9LAogICAgICAgIG9udXBsb2FkOigpPT57IGlmKGJhckkpYmFySS5zdHlsZS53aWR0aD0nMTAwJSc7IGlmKGNudCljbnQudGV4dENvbnRlbnQ9J3Byb2Nlc2FuZG8gZW4gZWwgc2Vydmlkb3LigKYnOyB9LAogICAgICAgIG9uZG9uZToocmVzKT0+eyBpZihiYXIpYmFyLnN0eWxlLmRpc3BsYXk9J25vbmUnOyB0b2FzdCgnQ29zdG9zIGltcG9ydGFkb3MgKCcrKGFjY05hbWV8fChyZXMmJnJlcy5hY2NvdW50KXx8J2N1ZW50YScpKycpOiAnKygocmVzJiZyZXMuaW1wb3J0ZWQpfHwwKSk7IGxvYWRDb3N0U3RhdHVzKCk7IH0sCiAgICAgICAgb25lcnJvcjoobXNnKT0+eyBpZihiYXIpYmFyLnN0eWxlLmRpc3BsYXk9J25vbmUnOyBpZihjbnQpY250LnRleHRDb250ZW50PSfigJQgZXJyb3InOyB0b2FzdCgnRXJyb3IgaW1wb3J0YW5kbzogJyttc2cpOyB9LAogICAgICB9KTsKICAgIH1jYXRjaChlcnIpe3RvYXN0KCdFcnJvciBpbXBvcnRhbmRvOiAnKyhlcnIuZXJyb3J8fGVyci5tZXNzYWdlfHxlcnIpKTtpZihjbnQpY250LnRleHRDb250ZW50PSfigJQgZXJyb3InO30KICAgIGlucHV0LnZhbHVlPScnOwogIH07CiAgcmVhZGVyLnJlYWRBc0FycmF5QnVmZmVyKGZpbGUpOwp9Ci8vIFN1YmUgZWwgcGF5bG9hZCBjb24gWEhSIHBhcmEgcmVwb3J0YXIgZWwgJSBkZSBhdmFuY2UgZGVsIHVwbG9hZCBlbiBsYSBiYXJyYS4KZnVuY3Rpb24gdXBsb2FkQ29zdHMocGF5bG9hZCxjYil7CiAgY29uc3QgeGhyPW5ldyBYTUxIdHRwUmVxdWVzdCgpOwogIHhoci5vcGVuKCdQT1NUJywnL2FwaS9hZHMvY29zdHMnKTsKICB4aHIuc2V0UmVxdWVzdEhlYWRlcignQ29udGVudC1UeXBlJywnYXBwbGljYXRpb24vanNvbicpOwogIHhoci51cGxvYWQub25wcm9ncmVzcz1ldj0+eyBpZihldi5sZW5ndGhDb21wdXRhYmxlJiZjYi5vbnByb2dyZXNzKXsgY2Iub25wcm9ncmVzcyhNYXRoLnJvdW5kKGV2LmxvYWRlZC9ldi50b3RhbCoxMDApKTsgfSB9OwogIHhoci51cGxvYWQub25sb2FkPSgpPT57IGlmKGNiLm9udXBsb2FkKWNiLm9udXBsb2FkKCk7IH07CiAgeGhyLm9ubG9hZD0oKT0+ewogICAgaWYoeGhyLnN0YXR1cz09PTQwMSl7IGxvY2F0aW9uLmhyZWY9Jy8nOyByZXR1cm47IH0KICAgIGxldCBkPXt9OyB0cnl7IGQ9SlNPTi5wYXJzZSh4aHIucmVzcG9uc2VUZXh0fHwne30nKTsgfWNhdGNoKGUpe30KICAgIGlmKHhoci5zdGF0dXM+PTIwMCYmeGhyLnN0YXR1czwzMDApeyBpZihjYi5vbmRvbmUpY2Iub25kb25lKGQpOyB9CiAgICBlbHNlIHsgaWYoY2Iub25lcnJvciljYi5vbmVycm9yKGQuZXJyb3I/KHR5cGVvZiBkLmVycm9yPT09J3N0cmluZyc/ZC5lcnJvcjpKU09OLnN0cmluZ2lmeShkLmVycm9yKSk6KCdIVFRQICcreGhyLnN0YXR1cykpOyB9CiAgfTsKICB4aHIub25lcnJvcj0oKT0+eyBpZihjYi5vbmVycm9yKWNiLm9uZXJyb3IoJ2Vycm9yIGRlIHJlZCcpOyB9OwogIHhoci5zZW5kKHBheWxvYWQpOwp9CmFzeW5jIGZ1bmN0aW9uIGxvYWRDb3N0U3RhdHVzKCl7CiAgdHJ5e2NvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9jb3N0cycpOwogICAgY29uc3QgYnk9QXJyYXkuaXNBcnJheShkLmJ5X2FjY291bnQpP2QuYnlfYWNjb3VudDpbXTsKICAgIGNvbnN0IG5BY2M9YnkuZmlsdGVyKHg9PnguY291bnQ+MCkubGVuZ3RoOwogICAgY29uc3QgcGVyc1RhZz1kLnBlcnNpc3RlbnQ/JyDCtyA8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tZ3JlZW4pIj7wn5K+IHBlcnNpc3RlbnRlPC9zcGFuPic6JyDCtyA8c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tYW1iZXIpIiB0aXRsZT0iQ29uZmlndXLDoSBEQVRBX0RJUiBhIHVuIGRpc2NvIGRlIFJlbmRlciBwYXJhIG5vIHBlcmRlciBsb3MgZGF0b3MgZW4gY2FkYSBkZXBsb3kiPuKaoO+4jyBkYXRvcyB0ZW1wb3JhbGVzPC9zcGFuPic7CiAgICAkKCdjb3N0c3RhdHVzJykuaW5uZXJIVE1MPShkLnRvdGFsPygn4pyFIDxiPicrZC50b3RhbC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC9iPiBwcm9kdWN0b3MgwrcgJytuQWNjKycgZGUgJysoQUNDT1VOVFMubGVuZ3RofHw2KSsnIGN1ZW50YXMgY2FyZ2FkYXMnKTon4pqg77iPIFNpbiBjb3N0b3M6IGltcG9ydMOhIGVsIF9DT01QTEVUTyBkZSBjYWRhIGN1ZW50YS4nKStwZXJzVGFnOwogICAgLy8gUmVzZXRlbyBsb3MgY29udGFkb3JlcyBkZSBjYWRhIGNhc2lsbGVybyB5IGx1ZWdvIGxvcyBsbGVuby4KICAgIEFDQ09VTlRTLmZvckVhY2goYT0+e2NvbnN0IGM9JCgnc2xvdGNvdW50LScrYS5pZCk7aWYoYyljLnRleHRDb250ZW50PSfigJQgc2luIGNvc3Rvcyc7fSk7CiAgICBieS5mb3JFYWNoKHg9Pntjb25zdCBjPSQoJ3Nsb3Rjb3VudC0nK3guYWNjb3VudF9pZCk7aWYoYyljLmlubmVySFRNTD0n4pyFIDxiPicreC5jb3VudC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC9iPiBwcm9kdWN0b3MnO30pOwogIH1jYXRjaChlKXt9Cn0KCi8vIC0tLS0gUkVOVEFCSUxJREFEIC0tLS0KbGV0IFZTT1JUPXtrZXk6J25ldCcsZGlyOjF9OwpmdW5jdGlvbiBzdGF0dXNMYWJlbChzKXtjb25zdCBtPXtwZW5kaW5nOidQZW5kaWVudGUnLGhhbmRsaW5nOidQcmVwYXJhbmRvJyxyZWFkeV90b19zaGlwOidMaXN0byBwL2VudmlhcicscmVhZHlfdG9fcHJpbnQ6J0xpc3RvIHAvaW1wcmltaXInLHNoaXBwZWQ6J0VudmlhZG8nLGRlbGl2ZXJlZDonRW50cmVnYWRvJyxub3RfZGVsaXZlcmVkOidObyBlbnRyZWdhZG8nLGNhbmNlbGxlZDonQ2FuY2VsYWRvJyx0b19iZV9hZ3JlZWQ6J0EgY29udmVuaXInfTtyZXR1cm4gbVtzXXx8KHN8fCfigJQnKTt9CmZ1bmN0aW9uIHN0YXR1c1BpbGwocyl7Y29uc3QgY2xzPSh7ZGVsaXZlcmVkOidwLWdyZWVuJyxzaGlwcGVkOidwLWJsdWUnLHJlYWR5X3RvX3NoaXA6J3AtYW1iZXInLHJlYWR5X3RvX3ByaW50OidwLWFtYmVyJyxoYW5kbGluZzoncC1hbWJlcicscGVuZGluZzoncC1ncmV5JyxjYW5jZWxsZWQ6J3AtcmVkJyxub3RfZGVsaXZlcmVkOidwLXJlZCd9KVtzXXx8J3AtZ3JleSc7cmV0dXJuICc8c3BhbiBjbGFzcz0icGlsbCAnK2NscysnIj4nK3N0YXR1c0xhYmVsKHMpKyc8L3NwYW4+Jzt9CmZ1bmN0aW9uIHNvcnRWZW4oayl7IGlmKFZTT1JULmtleT09PWspVlNPUlQuZGlyKj0tMTsgZWxzZXtWU09SVC5rZXk9aztWU09SVC5kaXI9KGs9PT0ndGl0bGUnfHxrPT09J3N0YXR1cyd8fGs9PT0nc3RvY2snKT8xOi0xO30gaWYoVkVOKXJlbmRlclZlbnRhcyhWRU4pOyB9CmZ1bmN0aW9uIHVwZGF0ZVZlbkFycm93cygpe2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyN2ZW5UYWJsZSB0aGVhZCB0aCcpLmZvckVhY2godGg9Pntjb25zdCBhPXRoLnF1ZXJ5U2VsZWN0b3IoJy5hcnInKTtpZihhKWEucmVtb3ZlKCk7aWYodGguZGF0YXNldC5rPT09VlNPUlQua2V5KXtjb25zdCBzPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKTtzLmNsYXNzTmFtZT0nYXJyJztzLnRleHRDb250ZW50PVZTT1JULmRpcj4wPycg4payJzonIOKWvCc7dGguYXBwZW5kQ2hpbGQocyk7fX0pO30KZnVuY3Rpb24gZG93bmxvYWRWZW50YXNYbHN4KCl7CiAgaWYoIVZFTnx8IVZFTi52ZW50YXN8fCFWRU4udmVudGFzLmxlbmd0aCl7dG9hc3QoJ0FuYWxpesOhIHZlbnRhcyBwcmltZXJvJyk7cmV0dXJuO30KICBjb25zdCBkYXRhPVZFTi52ZW50YXMubWFwKHY9Pntjb25zdCBvPXtGZWNoYTp2LmRhdGUsTl92ZW50YTp2LnBhY2tfaWR8fHYub3JkZXJfaWR8fCcnfTtpZihWRU4uYWxsKW8uQ3VlbnRhPXYuYWNjb3VudF9uYW1lfHwnJztyZXR1cm4gT2JqZWN0LmFzc2lnbihvLHtQdWJsaWNhY2lvbjp2LnRpdGxlLEl0ZW1JRDp2Lml0ZW1faWQsQ29kX1NLVTp2LnNrdXx8JycsRXN0YWRvX2VudmlvOnN0YXR1c0xhYmVsKHYuc3RhdHVzKSxTdG9jazp2LnN0b2NrPydTw60nOicnLENhbnRpZGFkOnYucXR5fHwxLFByZWNpbzp2LnJldmVudWUsQ29taXNpb246di5mZWUsRW52aW86di5lbnZpbyxJbXB1ZXN0b3M6TWF0aC5yb3VuZCh2LnRheHx8MCksUXVlZG9fZW5fY3VlbnRhOk1hdGgucm91bmQodi5xdWVkYSksQ29zdG86di5jb3N0LEZhY3R1cmE6TWF0aC5yb3VuZCh2LmZhY3R1cmF8fDApLEdhbmFuY2lhOnYubmV0PT1udWxsPycnOk1hdGgucm91bmQodi5uZXQpLEdhbmFuY2lhX3Npbl9mbGV4OnYubmV0X3Npbl9mbGV4PT1udWxsPycnOk1hdGgucm91bmQodi5uZXRfc2luX2ZsZXgpLE1hcmdlbl9wY3Q6di5tYXJnaW5QY3Q9PW51bGw/Jyc6K3YubWFyZ2luUGN0LnRvRml4ZWQoMSksQ3VvdGFzOnYuY3VvdGFzfHwwfSk7fSk7CiAgY29uc3Qgd3M9WExTWC51dGlscy5qc29uX3RvX3NoZWV0KGRhdGEpO2NvbnN0IHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTtYTFNYLnV0aWxzLmJvb2tfYXBwZW5kX3NoZWV0KHdiLHdzLCdWZW50YXMnKTsKICBYTFNYLndyaXRlRmlsZSh3YiwndmVudGFzXycrKFZFTi5hbGw/J1RPREFTJzooJCgnYWNjb3VudCcpLnNlbGVjdGVkT3B0aW9uc1swXT8kKCdhY2NvdW50Jykuc2VsZWN0ZWRPcHRpb25zWzBdLnRleHRDb250ZW50LnNwbGl0KCcgJylbMF06J2N1ZW50YScpKSsnXycrKFZFTi5mcm9tfHwnJykrJ18nKyhWRU4udG98fCcnKSsnLnhsc3gnKTsKfQphc3luYyBmdW5jdGlvbiBsb2FkVmVudGFzKCl7CiAgY29uc3QgaWQ9JCgnYWNjb3VudCcpLnZhbHVlO2lmKCFpZCl7dG9hc3QoJ0VsZWfDrSB1bmEgY3VlbnRhJyk7cmV0dXJuO30KICBjb25zdCBmcm9tPSQoJ3Zlbl9mcm9tJykudmFsdWUsIHRvPSQoJ3Zlbl90bycpLnZhbHVlOwogIGNvbnN0IGlzQWxsPShpZD09PSdhbGwnKTsKICAkKCd2ZW5fYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxNyIgY2xhc3M9ImxvYWRpbmciPicrKGlzQWxsPydUcmF5ZW5kbyB2ZW50YXMgZGUgPGI+dG9kYXMgbGFzIGN1ZW50YXM8L2I+IOKAlCBwdWVkZSB0YXJkYXIgYmFzdGFudGXigKYnOidUcmF5ZW5kbyB2ZW50YXMgeSBlbnbDrW9zIHJlYWxlcyBkZSBNZXJjYWRvIExpYnJl4oCmIChwdWVkZSB0YXJkYXIgdW5vcyBzZWd1bmRvcyknKSsnPC90ZD48L3RyPic7CiAgdHJ5ewogICAgY29uc3QgdXJsPWlzQWxsPygnL2FwaS9hZHMvdmVudGFzLWFsbD8nKyhmcm9tPygnZnJvbT0nK2Zyb20pOicnKSsodG8/KCcmdG89Jyt0byk6JycpKTooJy9hcGkvYWRzL3ZlbnRhcz9hY2NvdW50X2lkPScraWQrKGZyb20/KCcmZnJvbT0nK2Zyb20pOicnKSsodG8/KCcmdG89Jyt0byk6JycpKTsKICAgIGNvbnN0IGQ9YXdhaXQgYXBpKHVybCk7VkVOPWQ7CiAgICBpZihkLnRheFBjdCE9bnVsbCYmJCgndmVuX3RheCcpLnZhbHVlPT09JycpJCgndmVuX3RheCcpLnZhbHVlPWQudGF4UGN0OwogICAgcmVuZGVyVmVudGFzKGQpOwogIH1jYXRjaChlKXskKCd2ZW5fYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxNyIgY2xhc3M9ImxvYWRpbmciPkVycm9yOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpKyc8L3RkPjwvdHI+Jzt9Cn0KZnVuY3Rpb24gcmVuZGVyVmVudGFzKGQpewogIGlmKCFkfHwhZC5yZXN1bWVuKXtyZXR1cm47fQogIGNvbnN0IHI9ZC5yZXN1bWVuOwogIGNvbnN0IHZ0PSQoJ3ZlblRhYmxlJyk7aWYodnQpdnQuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZS1hY2MnLCFkLmFsbCk7ICAvLyBtdWVzdHJhIGxhIGNvbHVtbmEgQ3VlbnRhIHNvbG8gZW4gIlRvZGFzIGxhcyBjdWVudGFzIgogIGNvbnN0IG1DbHM9ci5tYXJnaW49PW51bGw/Jyc6KHIubWFyZ2luPj0xMD8nZ29vZCc6KHIubWFyZ2luPj01Pyd3YXJuJzonYmFkJykpOwogIGNvbnN0IHRpbGVzPVsKICAgIFsnVmVudGFzJywoci5vcmRlcnMhPW51bGw/ci5vcmRlcnM6ci5jb3VudCksJyddLAogICAgWydGYWN0dXJhY2nDs24gKCcrci5kYXlzKydkKScsZm10TW9uZXkoci5mYWN0dXJhY2lvbiksJyddLAogICAgWydRdWVkw7MgZW4gY3VlbnRhJyxmbXRNb25leShyLnF1ZWRhVG90YWx8fDApLCcnXSwKICAgIFsnR2FuYW5jaWEgcmVhbCcsZm10TW9uZXkoci5nYW5hbmNpYSksci5nYW5hbmNpYT49MD8nZ29vZCc6J2JhZCddLAogICAgWydNYXJnZW4gcmVhbCcsci5tYXJnaW49PW51bGw/J+KAlCc6Zm10UGN0KHIubWFyZ2luKSxtQ2xzXSwKICAgIFsnQSBww6lyZGlkYScsci5wZXJkaWRhKyhyLnBlcmRpZGE/JyDimqDvuI8nOicnKSxyLnBlcmRpZGE/J2JhZCc6J2dvb2QnXQogIF07CiAgJCgndmVuX2twaXMnKS5pbm5lckhUTUw9dGlsZXMubWFwKHQ9Pic8ZGl2IGNsYXNzPSJrcGkgJyt0WzJdKyciPjxkaXYgY2xhc3M9ImsiPicrdFswXSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+Jyt0WzFdKyc8L2Rpdj48L2Rpdj4nKS5qb2luKCcnKTsKICBjb25zdCBoaWRkZW5Ob3RlPXIuaGlkZGVuPygnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjRweCI+8J+aqyAnK3IuaGlkZGVuKycgb3JkZW4nKyhyLmhpZGRlbj4xPydlcyc6JycpKycgb2N1bHRhJysoci5oaWRkZW4+MT8ncyc6JycpKycgKGNhbmNlbGFkYXMgbyBjb24gZGV2b2x1Y2nDs24gYWwgY29tcHJhZG9yKTwvZGl2PicpOicnOwogIGNvbnN0IHNhdmVkTm90ZT0oci5zYXZlZCE9bnVsbHx8ci5mcmVzaCE9bnVsbCk/KCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6NHB4Ij7wn5K+ICcrKHIuc2F2ZWR8fDApKycgY29uIGNvc3RvIGNvbmdlbGFkbyDCtyAnKyhyLmZyZXNofHwwKSsnIG51ZXZhJysoKHIuZnJlc2h8fDApPT09MT8nJzoncycpKycgZW4gZWwgbGVkZ2VyPC9kaXY+Jyk6Jyc7CiAgY29uc3QgY29zdEZpeE5vdGU9KHIuY29zdEZpeGVkPjApPygnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTFweDttYXJnaW4tdG9wOjRweCI+8J+UhCAnK3IuY29zdEZpeGVkKycgdmVudGEnKyhyLmNvc3RGaXhlZD09PTE/Jyc6J3MnKSsnIHRvbWFyb24gc3UgY29zdG8gcmVhbCBkZSBsYSBsaXN0YSBhY3R1YWxpemFkYSAoYW50ZXMgcXVlZGFiYW4gwqtzL2Nvc3RvwrspPC9kaXY+Jyk6Jyc7CiAgY29uc3QgdGF4Tm90ZT1yLnRheFJlYWwhPW51bGw/KCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6NHB4Ij7wn6e+IEltcHVlc3RvIHJlYWwgZGUgTUwgZW4gJytyLnRheFJlYWwrJyBkZSAnKyhyLm9yZGVyc3x8ci5jb3VudCkrJyDDs3JkZW5lcycrKHIudGF4UmVhbDwoci5vcmRlcnN8fHIuY291bnQpPygnIMK3IGVuIGVsIHJlc3RvIE1MIG5vIGluZm9ybcOzIGltcHVlc3RvIChxdWVkYSAkMCknKTonJykrJyDCtyBsYSBmYWN0dXJhICglIG1lbnN1YWwpIHZhIGFwYXJ0ZSwgZW4gbGEgY29sdW1uYSBGYWN0dXJhPC9kaXY+Jyk6Jyc7CiAgY29uc3Qgc2hpcE5vdGU9ci5zaGlwRmV0Y2hlZCE9bnVsbD8oJzxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjExcHg7bWFyZ2luLXRvcDo2cHgiPvCfmpogRW52w61vIHJlYWwgZGUgTUwgZW4gJytyLnNoaXBGZXRjaGVkKycgZGUgJysoci5vcmRlcnN8fHIuY291bnQpKycgw7NyZGVuZXMnKyhyLnNoaXBGZXRjaGVkPChyLm9yZGVyc3x8ci5jb3VudCk/JyDCtyBlbCByZXN0byB1c2EgbGEgZXN0aW1hY2nDs24gZGVsIEV4Y2VsJzonJykrJzwvZGl2PicpOicnOwogICQoJ3Zlbl9wcm9ncmVzc19jYXJkJykuc3R5bGUuZGlzcGxheT0nYmxvY2snOwogICQoJ3Zlbl9wcm9ncmVzcycpLmlubmVySFRNTD0nPGRpdiBzdHlsZT0iZm9udC1zaXplOjEycHgiPjxiPicrKHIub3JkZXJzfHxyLmNvdW50fHwwKSsnPC9iPiB2ZW50YXMgwrcgcGVyw61vZG8gJytlc2MoZC5mcm9tfHwnJykrJyBhICcrZXNjKGQudG98fCcnKSsnIMK3IHVuaWRhZGVzOiAnKyhyLnVuaWRhZGVzfHwwKSsnPC9kaXY+JytzYXZlZE5vdGUrY29zdEZpeE5vdGUrdGF4Tm90ZStoaWRkZW5Ob3RlK3NoaXBOb3RlOwogIGxldCByb3dzPShkLnZlbnRhc3x8W10pLnNsaWNlKCk7CiAgY29uc3Qgb3E9KCgkKCd2ZW5fb3JkZXInKSYmJCgndmVuX29yZGVyJykudmFsdWUpfHwnJykudHJpbSgpOwogIGlmKG9xKXsgcm93cz1yb3dzLmZpbHRlcih2PT5TdHJpbmcodi5wYWNrX2lkfHwnJykuaW5jbHVkZXMob3EpfHxTdHJpbmcodi5vcmRlcl9pZHx8JycpLmluY2x1ZGVzKG9xKSk7IH0KICBjb25zdCBrPVZTT1JULmtleSxkaXI9VlNPUlQuZGlyOwogIHJvd3Muc29ydCgoYSxiKT0+e2xldCB4PWFba10seT1iW2tdO2lmKGs9PT0ndGl0bGUnfHxrPT09J3N0YXR1cyd8fGs9PT0nYWNjb3VudF9uYW1lJ3x8az09PSdza3UnKXt4PVN0cmluZyh4fHwnJyk7eT1TdHJpbmcoeXx8JycpO3JldHVybiBkaXIqeC5sb2NhbGVDb21wYXJlKHkpO31pZihrPT09J3N0b2NrJyl7cmV0dXJuIGRpciooKHg/MTowKS0oeT8xOjApKTt9eD0oeD09bnVsbD8tSW5maW5pdHk6eCk7eT0oeT09bnVsbD8tSW5maW5pdHk6eSk7cmV0dXJuIGRpciooeC15KTt9KTsKICAvLyBBZ3J1cGFyIENBUlJJVE9TOiBsb3Mgw610ZW1zIGRlbCBtaXNtbyBwYXF1ZXRlIHF1ZWRhbiBqdW50b3MgKHVubyBkZWJham8gZGVsIG90cm8pLCBlbiBsYSBwb3NpY2nDs24gZGVsIHByaW1lcm8uCiAge2NvbnN0IF9zZWVuPXt9LF9nPVtdO2Zvcihjb25zdCB2IG9mIHJvd3Mpe2NvbnN0IHBrPXYucGFja19pZHx8di5vcmRlcl9pZDtpZihfc2Vlbltwa10pY29udGludWU7X3NlZW5bcGtdPTE7Zm9yKGNvbnN0IHggb2Ygcm93cyl7aWYoKHgucGFja19pZHx8eC5vcmRlcl9pZCk9PT1waylfZy5wdXNoKHgpO319cm93cz1fZzt9CiAgdXBkYXRlVmVuQXJyb3dzKCk7CiAgaWYoIXJvd3MubGVuZ3RoKXskKCd2ZW5fYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxNyIgY2xhc3M9ImVtcHR5Ij4nKyhvcT8nTmluZ3VuYSB2ZW50YSBjb24gZXNlIG7Dum1lcm8uJzonU2luIHZlbnRhcyBlbiBlbCBwZXLDrW9kby4nKSsnPC90ZD48L3RyPic7cmV0dXJuO30KICAkKCd2ZW5fYm9keScpLmlubmVySFRNTD1yb3dzLm1hcCh2PT57Y29uc3QgbG9zcz12Lm5ldCE9bnVsbCYmdi5uZXQ8MDsKICAgIHJldHVybiAnPHRyIHN0eWxlPSInKyhsb3NzPydiYWNrZ3JvdW5kOnZhcigtLXJlZGJnKTsnOih2LnBhY2s/J2JhY2tncm91bmQ6I2YzZjBmZjsnOicnKSkrKHYucGFjaz8nYm9yZGVyLWxlZnQ6M3B4IHNvbGlkICNhNzhiZmE7JzonJykrJyI+JysKICAgICAgJzx0ZCBjbGFzcz0ibmFtZSI+Jysodi5wYWNrPyc8c3BhbiB0aXRsZT0iVmVudGEgZW4gY2Fycml0bzogY29tcGFydGUgZWwgZW52w61vIGNvbiBvdHJvcyBwcm9kdWN0b3MuIEVsIGVudsOtbyB2YSBlbnRlcm8gZW4gZWwgcHJvZHVjdG8gZGUgbWF5b3IgdmFsb3IgZGVsIGNhcnJpdG8uIiBzdHlsZT0iZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1ibHVlYmcpO2NvbG9yOnZhcigtLWJsdWUpO2ZvbnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OjcwMDtwYWRkaW5nOjFweCA2cHg7Ym9yZGVyLXJhZGl1czo4cHg7bWFyZ2luLXJpZ2h0OjVweCI+8J+bkiBjYXJyaXRvPC9zcGFuPic6JycpK2VzYyh2LnRpdGxlfHx2Lml0ZW1faWQpKyc8c3BhbiBjbGFzcz0iaWQiPicrKHYuaXRlbV9pZHx8JycpKycgwrcgJysodi5kYXRlfHwnJykrJyDCtyBWZW50YSAjJysodi5wYWNrX2lkfHx2Lm9yZGVyX2lkfHwnJykrJzwvc3Bhbj48L3RkPicrCiAgICAgICc8dGQgY2xhc3M9ImFjY29sIj4nK2VzYyh2LmFjY291bnRfbmFtZXx8JycpKyc8L3RkPicrCiAgICAgICc8dGQ+JytzdGF0dXNQaWxsKHYuc3RhdHVzKSsnPC90ZD4nKwogICAgICAnPHRkPicrKHYuc3RvY2s/JzxzcGFuIGNsYXNzPSJwaWxsIHAtYW1iZXIiPlPDrTwvc3Bhbj4nOic8c3BhbiBjbGFzcz0ibXV0ZWQiPuKAlDwvc3Bhbj4nKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKHYucXR5fHwxKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkodi5yZXZlbnVlKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj7iiJInK2ZtdE1vbmV5KHYuZmVlKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyh2LmVudmlvPygn4oiSJytmbXRNb25leSh2LmVudmlvKSk6J+KAlCcpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrKHYudGF4Pygn4oiSJytmbXRNb25leSh2LnRheCkpOih2LnRheFJlYWw9PT1mYWxzZT8nPHNwYW4gY2xhc3M9Im11dGVkIiB0aXRsZT0iTUwgbm8gaW5mb3Jtw7MgaW1wdWVzdG8gZW4gZXN0YSBvcmRlbiI+4oCUPC9zcGFuPic6JyQwJykpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSBiIj4nK2ZtdE1vbmV5KHYucXVlZGEpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrKHYuY29zdD09bnVsbD8nPHNwYW4gY2xhc3M9Im11dGVkIj5zL2Nvc3RvPC9zcGFuPic6KCfiiJInK2ZtdE1vbmV5KHYuY29zdCkpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyh2LmZhY3R1cmE/KCfiiJInK2ZtdE1vbmV5KHYuZmFjdHVyYSkpOifigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo4MDA7Y29sb3I6Jysodi5uZXQ9PW51bGw/J3ZhcigtLW11dCknOih2Lm5ldD49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKSsnIj4nKyh2Lm5ldD09bnVsbD8n4oCUJzpmbXRNb25leSh2Lm5ldCkpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+Jysodi5uZXRfc2luX2ZsZXg9PW51bGw/J+KAlCc6Zm10TW9uZXkodi5uZXRfc2luX2ZsZXgpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKHYubWFyZ2luUGN0PT1udWxsPyfigJQnOmZtdFBjdCh2Lm1hcmdpblBjdCkpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+Jysodi5jdW90YXN8fDApKyc8L3RkPicrCiAgICAgICc8dGQ+Jytlc2Modi5za3V8fCcnKSsnPC90ZD48L3RyPic7fSkuam9pbignJyk7Cn0KLy8gR3VhcmRhIGxhIEZBQ1RVUkEgJSBHTE9CQUwgKHVuYSBzb2xhIHBhcmEgdG9kYXMgbGFzIGN1ZW50YXMpLgphc3luYyBmdW5jdGlvbiBzYXZlRmFjdHVyYUNmZygpewogIGNvbnN0IHZhbD0rJCgndmVuX3RheCcpLnZhbHVlOwogIGlmKGlzTmFOKHZhbCl8fHZhbDwwKXt0b2FzdCgnUG9uw6kgdW4gJSBkZSBmYWN0dXJhIHbDoWxpZG8nKTtyZXR1cm47fQogIHRyeXthd2FpdCBhcGkoJy9hcGkvYWRzL2NvbmZpZycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7ZmFjdHVyYVBjdDp2YWx9KX0pO3RvYXN0KCdGYWN0dXJhICUgZ3VhcmRhZGEgKCcrdmFsKyclKSDCtyB0b2PDoSDwn5SNIEJ1c2NhciBwYXJhIHJlY2FsY3VsYXInKTt9CiAgY2F0Y2goZSl7dG9hc3QoJ0Vycm9yOiAnKyhlLmVycm9yfHxlKSk7fQp9Ci8vIEdVQVJEQVIgRMONQTogY29uZ2VsYSBsYXMgdmVudGFzIGRlbCBkw61hIChmZWNoYSBEZXNkZSkgY29uIGxhIGxpc3RhIGRlIHByZWNpb3MgZGUgaG95IOKGkiB2YSBhbCBIaXN0w7NyaWNvLgphc3luYyBmdW5jdGlvbiBzYXZlRGlhKCl7CiAgY29uc3QgYWNjPSQoJ2FjY291bnQnKS52YWx1ZTsgaWYoIWFjYyl7dG9hc3QoJ0VsZWfDrSB1bmEgY3VlbnRhIChvIFRvZGFzKScpO3JldHVybjt9CiAgY29uc3QgZGF0ZT0kKCd2ZW5fZnJvbScpLnZhbHVlOyBpZighZGF0ZSl7dG9hc3QoJ0VsZWfDrSBsYSBmZWNoYSAoRGVzZGUpIGRlbCBkw61hIGEgZ3VhcmRhcicpO3JldHVybjt9CiAgaWYoJCgndmVuX3RvJykudmFsdWUgJiYgJCgndmVuX3RvJykudmFsdWUhPT1kYXRlKXsKICAgIGlmKCFjb25maXJtKCdWYXMgYSBndWFyZGFyIFNPTE8gZWwgZMOtYSAnK2RhdGUrJyAobGEgZmVjaGEgIkRlc2RlIikuIEVsIGhpc3TDs3JpY28gc2UgZ3VhcmRhIGTDrWEgcG9yIGTDrWEuIMK/Q29udGludWFyPycpKSByZXR1cm47CiAgfQogIHRvYXN0KCdHdWFyZGFuZG8gZMOtYSAnK2RhdGUrJ+KApiAodHJhZSB2ZW50YXMgcmVhbGVzIGRlIE1MLCBwdWVkZSB0YXJkYXIpJyk7CiAgdHJ5ewogICAgY29uc3Qgcj1hd2FpdCBhcGkoJy9hcGkvZ2VzdGlvbi9zYXZlLWRheScse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7ZGF0ZSxhY2NvdW50X2lkOmFjY30pfSk7CiAgICB0b2FzdCgn4pyFIETDrWEgJytkYXRlKycgZ3VhcmRhZG8gwrcgJytyLmNvdW50KycgdmVudGFzJysoci5vdmVyd3JvdGU/JyAoc29icmVlc2NyaXRvKSc6JycpKycgwrcgZ2FuYW5jaWEgJytmbXRNb25leShyLnRvdGFscyYmci50b3RhbHMuZ2FuYW5jaWF8fDApKTsKICAgIEhJU1RfTE9BREVEPWZhbHNlOyAvLyBmb3J6YXIgcmVjYXJnYSBkZWwgaGlzdMOzcmljbyBsYSBwcsOzeGltYSB2ZXoKICB9Y2F0Y2goZSl7dG9hc3QoJ0Vycm9yIGFsIGd1YXJkYXI6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkpO30KfQovLyBFTElNSU5BUiBEw41BOiBib3JyYSBkZWwgSGlzdMOzcmljbyBlbCBkw61hIGd1YXJkYWRvIChmZWNoYSBEZXNkZSksIHBhcmEgdm9sdmVyIGEgc3ViaXJsbyBjb24gR3VhcmRhciBkw61hLgphc3luYyBmdW5jdGlvbiBkZWxldGVEaWEoKXsKICBjb25zdCBkYXRlPSQoJ3Zlbl9mcm9tJykudmFsdWU7IGlmKCFkYXRlKXt0b2FzdCgnRWxlZ8OtIGxhIGZlY2hhIChEZXNkZSkgZGVsIGTDrWEgYSBlbGltaW5hcicpO3JldHVybjt9CiAgaWYoIWNvbmZpcm0oJ8K/RWxpbWluYXIgZGVsIEhpc3TDs3JpY28gZWwgZMOtYSAnK2RhdGUrJz9cblxuVmFzIGEgcG9kZXIgdm9sdmVyIGEgZ3VhcmRhcmxvIGNvbiDwn5K+IEd1YXJkYXIgZMOtYS4gKE5vIGJvcnJhIG5hZGEgZW4gTWVyY2FkbyBMaWJyZS4pJykpIHJldHVybjsKICB0cnl7CiAgICBhd2FpdCBhcGkoJy9hcGkvZ2VzdGlvbi9kZWxldGUtZGF5Jyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtkYXRlfSl9KTsKICAgIHRvYXN0KCfwn5eR77iPIETDrWEgJytkYXRlKycgZWxpbWluYWRvIGRlbCBIaXN0w7NyaWNvLiBBaG9yYSBwb2TDqXMgdm9sdmVyIGEgZ3VhcmRhcmxvLicpOwogICAgSElTVF9MT0FERUQ9ZmFsc2U7CiAgfWNhdGNoKGUpeyB0b2FzdCgnRXJyb3I6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/KGUuZXJyb3IpOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKSk7IH0KfQoKLy8gLS0tLSBFU1RSQVRFR0lBIChlbCBjZXJlYnJvKSAtLS0tCmxldCBFU09SVD17a2V5OidzY29yZScsZGlyOi0xfSwgRVNFRz17ZXN0cmVsbGE6MSxwcm9tZXNhOjEsYWp1c3RhcjoxLHZhY2E6MSxkdXJtaWVudGU6MSxkdXBPbmx5OjAsZW5yaWNoZWRPbmx5OjB9Owpjb25zdCBTRUdNRVRBPXtlc3RyZWxsYTpbJ3AtZ3JlZW4nLCfirZAgRXN0cmVsbGEnXSxwcm9tZXNhOlsncC1ibHVlJywn8J+agCBQcm9tZXNhJ10sYWp1c3RhcjpbJ3AtcmVkJywn8J+UpyBBanVzdGFyJ10sdmFjYTpbJ3AtYW1iZXInLCfwn5CEIFZhY2EnXSxkdXJtaWVudGU6WydwLWdyZXknLCfwn5KkIER1cm1pZW50ZSddfTsKZnVuY3Rpb24gc2VnUGlsbChzKXtjb25zdCBtPVNFR01FVEFbc118fFsncC1ncmV5JyxzXTtyZXR1cm4gJzxzcGFuIGNsYXNzPSJwaWxsICcrbVswXSsnIj4nK21bMV0rJzwvc3Bhbj4nO30KZnVuY3Rpb24gdG9nZ2xlU2VnKGVsKXtlbC5jbGFzc0xpc3QudG9nZ2xlKCdvbicpO0VTRUdbZWwuZGF0YXNldC5zZWddPWVsLmNsYXNzTGlzdC5jb250YWlucygnb24nKT8xOjA7aWYoU1RSQVQpbG9hZEVzdHJhdGVnaWEoKTt9CmZ1bmN0aW9uIHNvcnRFc3RyKGspe2lmKEVTT1JULmtleT09PWspRVNPUlQuZGlyKj0tMTtlbHNle0VTT1JULmtleT1rO0VTT1JULmRpcj0oaz09PSd0aXRsZSd8fGs9PT0nYWNjb3VudF9uYW1lJ3x8az09PSdzZWdtZW50Jyk/MTotMTt9aWYoU1RSQVQpcmVuZGVyRXN0cmF0ZWdpYShTVFJBVCk7fQpsZXQgRU5SSUNISU5HPWZhbHNlOwpmdW5jdGlvbiBzdG9wRW5yaXF1ZWNlcigpeyBFTlJJQ0hJTkc9ZmFsc2U7ICQoJ2VzdHJfc3RvcF9idG4nKS50ZXh0Q29udGVudD0nRGV0ZW5pZW5kb+KApic7IH0KZnVuY3Rpb24gc2V0UHJvZyh0eHQsc3ViLHBjdCl7ICQoJ2VzdHJfcHJvZ190eHQnKS50ZXh0Q29udGVudD10eHQ7IGlmKHN1YiE9bnVsbCkkKCdlc3RyX3Byb2dfc3ViJykudGV4dENvbnRlbnQ9c3ViOyBpZihwY3QhPW51bGwpJCgnZXN0cl9wcm9nX2JhcicpLnN0eWxlLndpZHRoPU1hdGgubWluKDEwMCxNYXRoLm1heCgwLHBjdCkpKyclJzsgfQphc3luYyBmdW5jdGlvbiByZWZpbmFyTWFyZ2VuZXMoKXsKICBpZihFTlJJQ0hJTkcpIHJldHVybjsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHlhIGVzdMOhIGNvcnJpZW5kbwogIGNvbnN0IHNlbD0kKCdhY2NvdW50JykudmFsdWU7CiAgY29uc3QgdGFyZ2V0cz0oc2VsPT09J2FsbCd8fCFzZWwpP0FDQ09VTlRTLm1hcChhPT5hLmlkKTpbc2VsXTsKICBFTlJJQ0hJTkc9dHJ1ZTsKICAkKCdlc3RyX3Byb2dyZXNzX2NhcmQnKS5zdHlsZS5kaXNwbGF5PSdibG9jayc7CiAgJCgnZXN0cl9zdG9wX2J0bicpLnRleHRDb250ZW50PSfij7kgRGV0ZW5lcic7CiAgc2V0UHJvZygnSW5pY2lhbmRvIGVucmlxdWVjaW1pZW50byBjb24gZGF0b3MgcmVhbGVzIGRlIE1M4oCmJywnJywwKTsKICBsZXQgZ3JhbmQ9MCwgYmF0Y2hlcz0wOwogIHRyeXsKICAgIGZvcihjb25zdCB0aWQgb2YgdGFyZ2V0cyl7CiAgICAgIGlmKCFFTlJJQ0hJTkcpIGJyZWFrOwogICAgICBjb25zdCBhY2M9QUNDT1VOVFMuZmluZChhPT5TdHJpbmcoYS5pZCk9PT1TdHJpbmcodGlkKSk7CiAgICAgIGNvbnN0IGFjY05hbWU9YWNjP2FjYy5uYW1lOidjdWVudGEnOwogICAgICAvLyBQYXNvIDEgKGxpdmlhbm8sIDEgc29sYSB2ZXopOiBsZWVyIHZlbnRhcyBkZSA5MCBkw61hcyBjb24gc3UgdGFzYSByZWFsIGRlIE1MLiBTZXBhcmFkbyBkZWwgZW5yaXF1ZWNpbWllbnRvLgogICAgICBzZXRQcm9nKCdMZXllbmRvIHZlbnRhcyBkZSA5MCBkw61hcyBkZSAnK2FjY05hbWUrJ+KApicsJ1Bhc28gcHJldmlvIHBhcmEgZWwgbWFyZ2VuIHJlYWwgKGNvbWlzacOzbiArIGN1b3RhcykgeSBlbCAidmVuZGUiJywwKTsKICAgICAgZm9yKGxldCBzdD0wO3N0PDMgJiYgRU5SSUNISU5HO3N0KyspewogICAgICAgIHRyeXsgYXdhaXQgYXBpKCcvYXBpL2Fkcy9lc3RyYXRlZ2lhL3NvbGQ5MD9hY2NvdW50X2lkPScrdGlkKTsgYnJlYWs7IH0KICAgICAgICBjYXRjaChlKXsgaWYoc3Q+PTIpeyAvKiBzZWd1aW1vcyBpZ3VhbDsgcmVmaW5hciBsbyByZWludGVudGEgKi8gfSBlbHNlIHsgYXdhaXQgbmV3IFByb21pc2Uocz0+c2V0VGltZW91dChzLDEyMDAqKHN0KzEpKSk7IH0gfQogICAgICB9CiAgICAgIGxldCBsYXN0RG9uZT0tMSwgc3RhbGw9MDsKICAgICAgd2hpbGUoRU5SSUNISU5HKXsKICAgICAgICBsZXQgcj1udWxsLCB0cmllcz0wOwogICAgICAgIHdoaWxlKEVOUklDSElORyAmJiB0cmllczw2KXsgICAgICAgICAgICAgICAgICAgICAgIC8vIHJlaW50ZW50YSBhbnRlIGNvcnRlcyBkZSByZWQgKCJGYWlsZWQgdG8gZmV0Y2giKSBvIHRpbWVvdXRzCiAgICAgICAgICB0cnl7IHI9YXdhaXQgYXBpKCcvYXBpL2Fkcy9lc3RyYXRlZ2lhL3JlZmluYXI/YWNjb3VudF9pZD0nK3RpZCsnJmNhcD0xMicpOyBicmVhazsgfQogICAgICAgICAgY2F0Y2goZSl7IHRyaWVzKys7CiAgICAgICAgICAgIGlmKHRyaWVzPj02KXsgc2V0UHJvZygnRXJyb3IgZW4gJythY2NOYW1lKycg4oCUIHJlaW50ZW50b3MgYWdvdGFkb3MnLCdWb2x2w6kgYSB0b2NhciDwn46vIEVucmlxdWVjZXIgcGFyYSBzZWd1aXIgZG9uZGUgcXVlZMOzICgnK1N0cmluZyhlLmVycm9yfHxlLm1lc3NhZ2V8fGUpKycpJywwKTsgfQogICAgICAgICAgICBlbHNlIHsgc2V0UHJvZygnUmVpbnRlbnRhbmRvICcrYWNjTmFtZSsn4oCmICgnK3RyaWVzKycvNSknLCdMYSBjb25leGnDs24gY29uIE1MIHNlIGNvcnTDszsgcmVpbnRlbnRvIGF1dG9tw6F0aWNvJywwKTsgYXdhaXQgbmV3IFByb21pc2Uocz0+c2V0VGltZW91dChzLDEwMDAqdHJpZXMpKTsgfQogICAgICAgICAgfQogICAgICAgIH0KICAgICAgICBpZighcikgYnJlYWs7ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gbm8gc2UgcHVkbyB0cmFzIHJlaW50ZW50b3Mg4oaSIGNvcnRhIGVzdGEgY3VlbnRhCiAgICAgICAgaWYoci5idXN5KXsgYXdhaXQgbmV3IFByb21pc2Uocz0+c2V0VGltZW91dChzLDE1MDApKTsgY29udGludWU7IH0gIC8vIG90cm8gbG90ZSBlbiBjdXJzbyDihpIgZXNwZXJhciB5IHNlZ3VpcgogICAgICAgIGdyYW5kKz1yLnJlZmluZWR8fDA7IGJhdGNoZXMrKzsKICAgICAgICBjb25zdCBkb25lPXIuZW5yaWNoZWRfdG90YWx8fDAsIHRvdD1yLmFjY291bnRfdG90YWx8fDA7CiAgICAgICAgY29uc3QgZXh0cmE9KHIuZmlsZV90b3RhbCE9bnVsbCk/KCcgwrcgYXJjaGl2bzogJysoci5maWxlX3RvdGFsfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsoKHIucGF1c2FkYXMpPygnICgnK3IucGF1c2FkYXMrJyBwYXVzYWRhcyBmdWVyYSknKTonJykpOicnOwogICAgICAgIHNldFByb2coJ0VucmlxdWVjaWVuZG8gJythY2NOYW1lKyc6ICcrZG9uZS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIC8gJyt0b3QudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBhY3RpdmFzJytleHRyYSwKICAgICAgICAgICAgICAgICfwn5OmICcrZ3JhbmQudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBlbiBlc3RhIGNvcnJpZGEgwrcgbG90ZSAnK2JhdGNoZXMrJyDCtyB0cmFlIHTDrXR1bG8sIHByZWNpbyBjb24gcHJvbW8sIHZlbnRhcyB5IHZpc2l0YXMgZGUgTUwnLAogICAgICAgICAgICAgICAgdG90P2RvbmUvdG90KjEwMDoxMDApOwogICAgICAgIGlmKGJhdGNoZXMlMz09PTApIGF3YWl0IGxvYWRFc3RyYXRlZ2lhKCk7ICAgICAgICAgIC8vIHJlZnJlc2NhIGxvcyBuw7ptZXJvcyBjYWRhIDMgbG90ZXMKICAgICAgICBpZihkb25lPj10b3QpIGJyZWFrOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBjdWVudGEgdGVybWluYWRhCiAgICAgICAgaWYoZG9uZTw9bGFzdERvbmUpeyBzdGFsbCsrOyBpZihzdGFsbD49NSkgYnJlYWs7IH0gZWxzZSB7IHN0YWxsPTA7IH0gICAvLyBzaW4gYXZhbmNlIDUgdmVjZXMgc2VndWlkYXMg4oaSIGNvcnRhcgogICAgICAgIGxhc3REb25lPWRvbmU7CiAgICAgIH0KICAgIH0KICB9IGZpbmFsbHkgewogICAgY29uc3Qgc3RvcHBlZD0hRU5SSUNISU5HOwogICAgRU5SSUNISU5HPWZhbHNlOwogICAgc2V0UHJvZyhzdG9wcGVkPygnRGV0ZW5pZG8gwrcgJytncmFuZC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIGVucmlxdWVjaWRvcycpOign4pyFIExpc3RvIMK3ICcrZ3JhbmQudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBwcm9kdWN0b3MgZW5yaXF1ZWNpZG9zIGNvbiBkYXRhIHJlYWwgZGUgTUwnKSwnJywxMDApOwogICAgYXdhaXQgbG9hZEVzdHJhdGVnaWEoKTsKICAgIHNldFRpbWVvdXQoKCk9PnsgaWYoIUVOUklDSElORykgJCgnZXN0cl9wcm9ncmVzc19jYXJkJykuc3R5bGUuZGlzcGxheT0nbm9uZSc7IH0sNTAwMCk7CiAgfQp9CmZ1bmN0aW9uIG1hcmdpblNyY0RvdChzcmMpe3JldHVybiBzcmM9PT0nc2ltJz8n8J+UtSc6J/Cfn6AnO30KZnVuY3Rpb24gZXN0clBhcmFtcygpe2NvbnN0IGc9JCgnZXN0cl9oaWdoJykudmFsdWUsbXM9JCgnZXN0cl9taW5zYWxlcycpLnZhbHVlLG12PSQoJ2VzdHJfbWludmlzJykudmFsdWUsaHY9JCgnZXN0cl9ob3R2aXMnKS52YWx1ZSxybz0kKCdlc3RyX3JvYXMnKS52YWx1ZTtyZXR1cm4gJ21hcmdpbkhpZ2g9JysoZ3x8MTIpKycmbWluU2FsZXM9JysobXN8fDEpKycmbWluVmlzaXRzPScrKG12fHw4KSsnJmhvdFZpc2l0cz0nKyhodnx8MzApKycmcm9hcz0nKyhyb3x8NSk7fQovLyBGaWx0cm9zIGRlIHZpc3RhIOKGkiB2YW4gYWwgU0VSVklET1IgKGVsIHRvcC01MDAgbm8gYWxjYW56YSBwYXJhIHZlciBwYXVzYXIvZHVybWllbnRlL3VuYSBjdWVudGEpLgpmdW5jdGlvbiBlc3RyRmlsdGVyUGFyYW1zKCl7CiAgY29uc3Qgc2Vncz1bJ2VzdHJlbGxhJywncHJvbWVzYScsJ2FqdXN0YXInLCd2YWNhJywnZHVybWllbnRlJ10uZmlsdGVyKHM9PkVTRUdbc10pOwogIGxldCBxPScmc2Vncz0nK2VuY29kZVVSSUNvbXBvbmVudChzZWdzLmpvaW4oJywnKSk7CiAgaWYoRVNFRy5kdXBPbmx5KXErPScmZHVwT25seT0xJzsKICBpZihFU0VHLmVucmljaGVkT25seSlxKz0nJmVucmljaGVkT25seT0xJzsKICBpZihFQUNUSU9OKXErPScmYWN0aW9uPScrZW5jb2RlVVJJQ29tcG9uZW50KEVBQ1RJT04pOwogIGlmKEVBQ0NUKXErPScmdmlld0FjY291bnQ9JytlbmNvZGVVUklDb21wb25lbnQoRUFDQ1QpOwogIHJldHVybiBxOwp9CmFzeW5jIGZ1bmN0aW9uIGxvYWRFc3RyYXRlZ2lhKCl7CiAgJCgnZXN0cl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjExIiBjbGFzcz0ibG9hZGluZyI+Q3J1emFuZG8gY3VlbnRhcyBwb3IgdMOtdHVsbyB5IGNsYXNpZmljYW5kb+KApjwvdGQ+PC90cj4nOwogIHRyeXsKICAgIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9lc3RyYXRlZ2lhPycrZXN0clBhcmFtcygpK2VzdHJGaWx0ZXJQYXJhbXMoKSk7CiAgICBpZihkLmVtcHR5KXskKCdlc3RyX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTEiIGNsYXNzPSJlbXB0eSI+Jytlc2MoZC5ub3RlfHwnSW1wb3J0w6EgbG9zIF9DT01QTEVUTyBwcmltZXJvLicpKyc8L3RkPjwvdHI+JzskKCdlc3RyX2twaXMnKS5pbm5lckhUTUw9Jyc7U1RSQVQ9bnVsbDtyZXR1cm47fQogICAgU1RSQVQ9ZDtyZW5kZXJFc3RyYXRlZ2lhKGQpOwogIH1jYXRjaChlKXskKCdlc3RyX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTEiIGNsYXNzPSJlbXB0eSI+RXJyb3I6ICcrZXNjKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkrJzwvdGQ+PC90cj4nO30KfQpmdW5jdGlvbiByZW5kZXJFc3RyYXRlZ2lhKGQpewogIGNvbnN0IHM9ZC5zZWdtZW50b3N8fHt9LHQ9ZC50b3RhbHN8fHt9LGR1PWQuZHVwbGljYWRvc3x8e307CiAgY29uc3QgZW5yPShkLmN1ZW50YXN8fFtdKS5yZWR1Y2UoKGEsYyk9PmErKGMuZW5yaWNoZWR8fDApLDApOwogIGNvbnN0IHRpbGVzPVsKICAgIFsnQWN0aXZhcycsKHQucHJvZHVjdG9zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsodC5wYXVzYWRhcz8oJyDCtyAnK3QucGF1c2FkYXMudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBwYXVzYWRhcyBmdWVyYScpOicnKSwnJ10sCiAgICBbJ+KchSBFbnJpcXVlY2lkb3MnLGVuci50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIC8gJysodC5wcm9kdWN0b3N8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLGVucj4wPyhlbnI+PSh0LnByb2R1Y3Rvc3x8MCk/J2dvb2QnOid3YXJuJyk6J2JhZCddLAogICAgWyfirZAgRXN0cmVsbGFzJywocy5lc3RyZWxsYXx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJyksJ2dvb2QnXSwKICAgIFsn8J+agCBQcm9tZXNhcycsKHMucHJvbWVzYXx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJyksJyddLAogICAgWyfwn5SnIEFqdXN0YXInLChzLmFqdXN0YXJ8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLChzLmFqdXN0YXJ8fDApPyd3YXJuJzonJ10sCiAgICBbJ/CfkIQgVmFjYXMnLChzLnZhY2F8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLCd3YXJuJ10sCiAgICBbJ/CfkqQgRHVybWllbnRlcycsKHMuZHVybWllbnRlfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSwnJ10sCiAgICBbJ/CflIEgRHVwbGljYWRvcycsKGR1Lml0ZW1zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsoZHUuZ3J1cG9zPygnIMK3ICcrZHUuZ3J1cG9zKycgZ3InKTonJyksZHUuaXRlbXM/J2JhZCc6J2dvb2QnXSwKICBdOwogICQoJ2VzdHJfa3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAoeD0+JzxkaXYgY2xhc3M9ImtwaSAnK3hbMl0rJyI+PGRpdiBjbGFzcz0iayI+Jyt4WzBdKyc8L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3hbMV0rJzwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogIHJlbmRlclBsYW4oZCk7CiAgcmVuZGVyQWNjdENmZyhkLmN1ZW50YXN8fFtdKTsKICAkKCdlc3RyX3BsYW5fY2FyZCcpLnN0eWxlLmRpc3BsYXk9J2Jsb2NrJzsKICAvLyBDdWVudGFzIGhhY2lhIHN1IG9iamV0aXZvIChtZXMgY29ycmlkbyArIEFEUyBzdWdlcmlkbykKICBjb25zdCBhY2N0cz1kLmN1ZW50YXN8fFtdOwogICQoJ2VzdHJfYWNjdHNfY2FyZCcpLnN0eWxlLmRpc3BsYXk9YWNjdHMubGVuZ3RoPydibG9jayc6J25vbmUnOwogICQoJ2VzdHJfbGVnZW5kJykuc3R5bGUuZGlzcGxheT0nZmxleCc7JCgnZXN0cl9maWx0ZXJzJykuc3R5bGUuZGlzcGxheT0nZmxleCc7CiAgaWYoIUVBQ0NUKSBmaWxsQWNjdEZpbHRlcihhY2N0cyk7ICAgLy8gZWwgZGVzcGxlZ2FibGUgc2UgYXJtYSBjb24gVE9EQVMgbGFzIGN1ZW50YXMgKHZpc3RhIGNvbXBsZXRhKQogICQoJ2VzdHJfYWNjdHMnKS5pbm5lckhUTUw9YWNjdHMubWFwKGE9PnsKICAgIGNvbnN0IGF2PWEuYXZhbmNlfHwwOwogICAgcmV0dXJuICc8dHI+PHRkIGNsYXNzPSJuYW1lIj4nK2VzYyhhLmFjY291bnRfbmFtZXx8J+KAlCcpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JytmbXRNb25leShhLm9iamV0aXZvKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoYS5wcm95X21lbnN1YWwpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDtjb2xvcjonKyhhdj49MTAwPyd2YXIoLS1ncmVlbiknOmF2Pj02MD8ndmFyKC0tYW1iZXIpJzondmFyKC0tcmVkKScpKyciPicrYXYudG9GaXhlZCgwKSsnJTwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6JysoYS5mYWx0YW50ZT4wPyd2YXIoLS1yZWQpJzondmFyKC0tZ3JlZW4pJykrJyI+JysoYS5mYWx0YW50ZT4wP2ZtdE1vbmV5KGEuZmFsdGFudGUpOifinJMnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0gYiIgc3R5bGU9ImNvbG9yOnZhcigtLW5hdnkpIj4nKyhhLmFkc19idWRnZXQ+MD9mbXRNb25leShhLmFkc19idWRnZXQpOifigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKygoYS5lbnJpY2hlZHx8MCk+PShhLml0ZW1zfHwwKT8ndmFyKC0tZ3JlZW4pJzooYS5lbnJpY2hlZD8ndmFyKC0tYW1iZXIpJzondmFyKC0tcmVkKScpKSsnIj4nKyhhLmVucmljaGVkfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnLycrKGEuaXRlbXN8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JysoYS5lc3RyZWxsYXx8MCkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKGEucHJvbW92ZXJ8fDApKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIGIiPicrKGEubGlkZXJ8fDApKyc8L3RkPjwvdHI+JzsKICB9KS5qb2luKCcnKTsKICAvLyBUYWJsYSBkZSBwcm9kdWN0b3MgKGZpbHRyYWRhICsgb3JkZW5hZGEpCiAgY29uc3Qgcm93cz1maWx0ZXJlZEVzdHJJdGVtcygpOwogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyNlc3RyVGFibGUgdGhlYWQgdGgnKS5mb3JFYWNoKHRoPT57Y29uc3QgYT10aC5xdWVyeVNlbGVjdG9yKCcuYXJyJyk7aWYoYSlhLnJlbW92ZSgpO2lmKHRoLmRhdGFzZXQuaz09PUVTT1JULmtleSl7Y29uc3Qgc3A9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpO3NwLmNsYXNzTmFtZT0nYXJyJztzcC50ZXh0Q29udGVudD1FU09SVC5kaXI+MD8nIOKWsic6JyDilrwnO3RoLmFwcGVuZENoaWxkKHNwKTt9fSk7CiAgLy8gSW5kaWNhZG9yIGRlIGN1w6FudG9zIGNvaW5jaWRlbiB2cyBjdcOhbnRvcyBzZSBtdWVzdHJhbiAoZWwgc2VydmVyIGxpbWl0YSBhIDUwMCBwb3IgdmV6KS4KICBjb25zdCBjRWw9JCgnZXN0cl9jb3VudCcpLCBtYXRjaGVkPShkLm1hdGNoZWQhPW51bGw/ZC5tYXRjaGVkOnJvd3MubGVuZ3RoKSwgc2hvd249KGQuc2hvd24hPW51bGw/ZC5zaG93bjpyb3dzLmxlbmd0aCk7CiAgaWYoY0VsKXsgaWYobWF0Y2hlZD5zaG93bil7Y0VsLnN0eWxlLmRpc3BsYXk9J2Jsb2NrJztjRWwuaW5uZXJIVE1MPSdNb3N0cmFuZG8gPGI+JytzaG93bi50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC9iPiBkZSA8Yj4nK21hdGNoZWQudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJzwvYj4gcXVlIGNvaW5jaWRlbiAoYWZpbsOhIGxvcyBmaWx0cm9zIG8gZGVzY2FyZ8OhIGVsIEV4Y2VsIHBhcmEgdmVyIHRvZG8pLic7fSBlbHNlIHtjRWwuc3R5bGUuZGlzcGxheT1tYXRjaGVkPydibG9jayc6J25vbmUnO2NFbC5pbm5lckhUTUw9JzxiPicrbWF0Y2hlZC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC9iPiBwdWJsaWNhY2lvbmVzJzt9IH0KICBpZighcm93cy5sZW5ndGgpeyQoJ2VzdHJfYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMSIgY2xhc3M9ImVtcHR5Ij5TaW4gcHJvZHVjdG9zIGNvbiBlc29zIGZpbHRyb3MuPC90ZD48L3RyPic7cmV0dXJuO30KICAkKCdlc3RyX2JvZHknKS5pbm5lckhUTUw9cm93cy5zbGljZSgwLDEwMDApLm1hcChpPT57CiAgICBjb25zdCBsZWFkPWkuZHVwbGljYXRlZD8oaS5pc0xlYWRlcj8nPHNwYW4gY2xhc3M9InBpbGwgcC1ncmVlbiI+8J+RkSBMw61kZXI8L3NwYW4+JzonPHNwYW4gY2xhc3M9InBpbGwgcC1ncmV5Ij7wn4yxIE9yZ8Ohbmljbzwvc3Bhbj4nKTonPHNwYW4gY2xhc3M9Im11dGVkIj7Dum5pY288L3NwYW4+JzsKICAgIGNvbnN0IHNjPWkuc2NvcmV8fDAsIHNjQ29sPXNjPj02Nj8ndmFyKC0tZ3JlZW4pJzpzYz49MzM/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLW11dCknOwogICAgY29uc3QgcHJvbW9UYWc9aS5lblByb21vPycgPHNwYW4gY2xhc3M9InBpbGwgcC1yZWQiIHN0eWxlPSJmb250LXNpemU6OXB4O3BhZGRpbmc6MXB4IDZweCI+cHJvbW88L3NwYW4+JzonJzsKICAgIHJldHVybiAnPHRyJysoKGkuZHVwbGljYXRlZCYmIWkuaXNMZWFkZXIpPycgc3R5bGU9ImJhY2tncm91bmQ6I2Y4ZmFmYyInOicnKSsnPicrCiAgICAgICc8dGQgY2xhc3M9Im5hbWUiPicrZXNjKGkudGl0bGV8fGkuaXRlbV9pZCkrcHJvbW9UYWcrJzxzcGFuIGNsYXNzPSJpZCI+JysoaS5pdGVtX2lkfHwnJykrKGkuZW5yaWNoZWQ/Jyc6JyDCtyBzaW4gZW5yaXF1ZWNlcicpKyhpLmR1cGxpY2F0ZWQ/KCcgwrcgcmVwZXRpZG8nKTonJykrJzwvc3Bhbj48L3RkPicrCiAgICAgICc8dGQ+Jytlc2MoaS5hY2NvdW50X25hbWV8fCfigJQnKSsnPC90ZD4nKwogICAgICAnPHRkPicrc2VnUGlsbChpLnNlZ21lbnQpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSBiIiBzdHlsZT0iY29sb3I6JytzY0NvbCsnIj4nK3NjKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKChpLm1hcmdpbiE9bnVsbCYmaS5tYXJnaW4+PSgrJCgnZXN0cl9oaWdoJykudmFsdWV8fDEyKSk/J3ZhcigtLWdyZWVuKSc6J3ZhcigtLWFtYmVyKScpKyciIHRpdGxlPSInKyhpLm1hcmdpblNyYz09PSdzaW0nPydzaW11bGFkbyBjb24gZWwgY29zdG8gZXhhY3RvIGRlIE1MIGFsIHByZWNpbyByZWFsJzonbWFyZ2VuIGRlIGxpc3RhIChlbnJpcXVlY8OpIHBhcmEgZWwgZXhhY3RvKScpKyciPicrKGkubWFyZ2luPT1udWxsPyfigJQnOmZtdFBjdChpLm1hcmdpbikpKycgPHNwYW4gc3R5bGU9ImZvbnQtc2l6ZTo5cHgiPicrbWFyZ2luU3JjRG90KGkubWFyZ2luU3JjKSsnPC9zcGFuPjwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyhpLnByaWNlPT1udWxsPyfigJQnOmZtdE1vbmV5KGkucHJpY2UpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHRpdGxlPSInKygoaS5zb2xkVG90YWwhPW51bGwpPygnYWN1bXVsYWRvIGhpc3TDs3JpY286ICcraS5zb2xkVG90YWwpOicnKSsnIj4nKyhpLnNvbGR8fDApKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JysoaS52aXNpdHN8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKGkuY29udj09bnVsbD8ndmFyKC0tbXV0KSc6KGkuY29udj49Mz8ndmFyKC0tZ3JlZW4pJzppLmNvbnY+PTE/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLXJlZCknKSkrJyI+JysoaS5jb252PT1udWxsPyfigJQnOmkuY29udi50b0ZpeGVkKDEpKyclJykrJzwvdGQ+JysKICAgICAgJzx0ZD4nK2xlYWQrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJ3aGl0ZS1zcGFjZTpub3JtYWw7bWF4LXdpZHRoOjMyMHB4Ij4nK2VzYyhpLmFjdGlvbnx8JycpKyc8L3RkPjwvdHI+JzsKICB9KS5qb2luKCcnKTsKfQovLyBBcGxpY2EgbG9zIGZpbHRyb3MgYWN0dWFsZXMgKHNlZ21lbnRvcyArIGFjY2nDs24gKyBkdXBsaWNhZG9zL2VucmlxdWVjaWRvcykgeSBvcmRlbmEsIGlndWFsIHF1ZSBsYSB0YWJsYS4KZnVuY3Rpb24gZmlsdGVyZWRFc3RySXRlbXMoKXsKICBpZighU1RSQVR8fCFTVFJBVC5pdGVtcykgcmV0dXJuIFtdOwogIC8vIEVsIFNFUlZJRE9SIHlhIGFwbGljw7MgbG9zIGZpbHRyb3MgKHNlZ21lbnRvLCBjdWVudGEsIGFjY2nDs24sIGR1cGxpY2Fkb3MsIGVucmlxdWVjaWRvcykuCiAgLy8gQWPDoSBzw7NsbyBvcmRlbmFtb3MgbG8gcmVjaWJpZG8gc2Vnw7puIGxhIGNvbHVtbmEgZWxlZ2lkYS4KICBsZXQgcm93cz1TVFJBVC5pdGVtcy5zbGljZSgpOwogIGNvbnN0IGs9RVNPUlQua2V5LGRpcj1FU09SVC5kaXI7CiAgcmV0dXJuIHJvd3Muc2xpY2UoKS5zb3J0KChhLGIpPT57bGV0IHg9YVtrXSx5PWJba107CiAgICBpZihrPT09J3RpdGxlJ3x8az09PSdhY2NvdW50X25hbWUnfHxrPT09J3NlZ21lbnQnKXt4PVN0cmluZyh4fHwnJyk7eT1TdHJpbmcoeXx8JycpO3JldHVybiBkaXIqeC5sb2NhbGVDb21wYXJlKHkpO30KICAgIGlmKGs9PT0naXNMZWFkZXInKXtyZXR1cm4gZGlyKigoeD8xOjApLSh5PzE6MCkpO30KICAgIHg9KHg9PW51bGw/LUluZmluaXR5OngpO3k9KHk9PW51bGw/LUluZmluaXR5OnkpO3JldHVybiBkaXIqKHgteSk7fSk7Cn0KZnVuY3Rpb24gZXN0ckl0ZW1zVG9YbHN4KGxpc3Qpe3JldHVybiBsaXN0Lm1hcChpPT4oe1Byb2R1Y3RvOmkudGl0bGUsSXRlbUlEOmkuaXRlbV9pZCxDdWVudGE6aS5hY2NvdW50X25hbWUsU2VnbWVudG86aS5zZWdtZW50LFBvdGVuY2lhbDppLnNjb3JlfHwwLE1hcmdlbl9wY3Q6aS5tYXJnaW49PW51bGw/Jyc6K2kubWFyZ2luLnRvRml4ZWQoMSksTWFyZ2VuX29yaWdlbjooaS5tYXJnaW5TcmM9PT0nc2ltJz8nc2ltdWxhZG8gTUwnOidsaXN0YScpLFByZWNpbzppLnByaWNlPT1udWxsPycnOmkucHJpY2UsRW5fcHJvbW86aS5lblByb21vPydTw60nOicnLFZlbnRhc18zbTppLnNvbGR8fDAsVmVudGFzX3RvdGFsOmkuc29sZFRvdGFsPT1udWxsPycnOmkuc29sZFRvdGFsLFZpc2l0YXNfM206aS52aXNpdHN8fDAsQ29udmVyc2lvbl9wY3Q6aS5jb252PT1udWxsPycnOitpLmNvbnYudG9GaXhlZCgyKSxFeHBvc2ljaW9uOmkubGlzdGluZ1R5cGV8fCcnLEVucmlxdWVjaWRvOmkuZW5yaWNoZWQ/J1PDrSc6JycsRHVwbGljYWRvOmkuZHVwbGljYXRlZD8nU8OtJzonJyxMaWRlcjppLmR1cGxpY2F0ZWQ/KGkuaXNMZWFkZXI/J0zDrWRlcic6J1NvbG8gb3Jnw6FuaWNvJyk6J8O6bmljbycsTGlkZXJfY3VlbnRhOmkubGVhZGVyTmFtZXx8JycsU3RvY2tfb2ZlcnRhOmkuc3RvY2s/J1PDrSc6JycsQWNjaW9uOmkuYWN0aW9ufSkpO30KZnVuY3Rpb24gZG93bmxvYWRFc3RyYXRlZ2lhWGxzeCgpewogIGlmKCFTVFJBVHx8IVNUUkFULml0ZW1zfHwhU1RSQVQuaXRlbXMubGVuZ3RoKXt0b2FzdCgnQ2FsY3Vsw6EgbGEgZXN0cmF0ZWdpYSBwcmltZXJvJyk7cmV0dXJuO30KICBjb25zdCB3cz1YTFNYLnV0aWxzLmpzb25fdG9fc2hlZXQoZXN0ckl0ZW1zVG9YbHN4KFNUUkFULml0ZW1zKSk7Y29uc3Qgd2I9WExTWC51dGlscy5ib29rX25ldygpO1hMU1gudXRpbHMuYm9va19hcHBlbmRfc2hlZXQod2Isd3MsJ0VzdHJhdGVnaWEnKTsKICBYTFNYLndyaXRlRmlsZSh3YiwnZXN0cmF0ZWdpYV9tdWx0aWN1ZW50YV8nKyhuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCkpKycueGxzeCcpOwp9Ci8vIEJhamEgVE9ETyBsbyBxdWUgY29pbmNpZGUgY29uIGxvcyBmaWx0cm9zIGFjdHVhbGVzIChwaWRlIGFsIHNlcnZlciBoYXN0YSAyMC4wMDAsIG5vIHPDs2xvIGxvIHZpc2libGUpLgphc3luYyBmdW5jdGlvbiBkb3dubG9hZEVzdHJhdGVnaWFWaXNpYmxlWGxzeCgpewogIGlmKCFTVFJBVCl7dG9hc3QoJ0NhbGN1bMOhIGxhIGVzdHJhdGVnaWEgcHJpbWVybycpO3JldHVybjt9CiAgdG9hc3QoJ1ByZXBhcmFuZG8gZGVzY2FyZ2EgZGUgdG9kbyBsbyBmaWx0cmFkb+KApicpOwogIGxldCByb3dzOwogIHRyeXsgY29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL2VzdHJhdGVnaWE/Jytlc3RyUGFyYW1zKCkrZXN0ckZpbHRlclBhcmFtcygpKycmbGltaXQ9MjAwMDAnKTsgcm93cz1kLml0ZW1zfHxbXTsgfQogIGNhdGNoKGUpeyByb3dzPWZpbHRlcmVkRXN0ckl0ZW1zKCk7IH0KICBpZighcm93cy5sZW5ndGgpe3RvYXN0KCdObyBoYXkgZmlsYXMgY29uIGVzb3MgZmlsdHJvcycpO3JldHVybjt9CiAgY29uc3Qgd3M9WExTWC51dGlscy5qc29uX3RvX3NoZWV0KGVzdHJJdGVtc1RvWGxzeChyb3dzKSk7Y29uc3Qgd2I9WExTWC51dGlscy5ib29rX25ldygpO1hMU1gudXRpbHMuYm9va19hcHBlbmRfc2hlZXQod2Isd3MsJ0ZpbHRyYWRvJyk7CiAgWExTWC53cml0ZUZpbGUod2IsJ2VzdHJhdGVnaWFfZmlsdHJhZG9fJysobmV3IERhdGUoKS50b0lTT1N0cmluZygpLnNsaWNlKDAsMTApKSsnLnhsc3gnKTsKICB0b2FzdCgnRGVzY2FyZ2FuZG8gJytyb3dzLmxlbmd0aC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIGZpbGFzIGZpbHRyYWRhcycpOwp9CgovLyAtLS0tIFBMQU4gREUgQUNDScOTTiAodGlsZXMgY2xpY2tlYWJsZXMgcXVlIGZpbHRyYW4gbGEgdGFibGEpIC0tLS0KbGV0IEVBQ1RJT049bnVsbCwgRUFDQ1Q9Jyc7CmNvbnN0IEFDVF9DT0xPUj17ZXNjYWxhcjonZ29vZCcscHJvbW92ZXI6J2dvb2QnLGFqdXN0YXI6J3dhcm4nLHByZWNpbzond2FybicscGF1c2FyOidiYWQnLG9yZ2FuaWNvOicnLHJldmlzYXI6Jyd9OwpmdW5jdGlvbiBmaWx0ZXJBY3Rpb24oY29kZSl7IEVBQ1RJT049KEVBQ1RJT049PT1jb2RlKT9udWxsOmNvZGU7IGlmKFNUUkFUKWxvYWRFc3RyYXRlZ2lhKCk7IH0KZnVuY3Rpb24gZmlsdGVyQWNjdCh2KXsgRUFDQ1Q9dnx8Jyc7IGlmKFNUUkFUKWxvYWRFc3RyYXRlZ2lhKCk7IH0KLy8gTGxlbmEgZWwgZGVzcGxlZ2FibGUgZGUgY3VlbnRhcyAodW5hIHNvbGEgdmV6KSwgY29uc2VydmFuZG8gbGEgc2VsZWNjacOzbiBhY3R1YWwuCmZ1bmN0aW9uIGZpbGxBY2N0RmlsdGVyKGN1ZW50YXMpewogIGNvbnN0IHNlbD0kKCdlc3RyX2FjY3QnKTsgaWYoIXNlbCkgcmV0dXJuOwogIGNvbnN0IGN1cj1zZWwudmFsdWU7CiAgY29uc3Qgb3B0cz1bJzxvcHRpb24gdmFsdWU9IiI+8J+PoiBUb2RhcyBsYXMgY3VlbnRhczwvb3B0aW9uPiddLmNvbmNhdCgKICAgIChjdWVudGFzfHxbXSkubWFwKGM9Pic8b3B0aW9uIHZhbHVlPSInK2VzYyhTdHJpbmcoYy5hY2NvdW50X2lkKSkrJyI+Jytlc2MoYy5hY2NvdW50X25hbWV8fGMuYWNjb3VudF9pZCkrJyAoJysoKGMuaXRlbXN8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKSsnKTwvb3B0aW9uPicpKTsKICBzZWwuaW5uZXJIVE1MPW9wdHMuam9pbignJyk7CiAgc2VsLnZhbHVlPWN1cjsgICAgICAgICAgICAgICAgICAgICAgICAgLy8gbWFudGllbmUgbGEgY3VlbnRhIGVsZWdpZGEgdHJhcyByZWNhbGN1bGFyCiAgaWYoc2VsLnZhbHVlIT09Y3VyKSBFQUNDVD0nJzsgICAgICAgICAgIC8vIHNpIHlhIG5vIGV4aXN0ZSwgdnVlbHZlIGEgVG9kYXMKfQpmdW5jdGlvbiByZW5kZXJQbGFuKGQpewogIGNvbnN0IHBsYW49ZC5wbGFufHx7fSwgbWV0YT1kLnBsYW5NZXRhfHx7fTsKICBjb25zdCBvcmRlcj1PYmplY3Qua2V5cyhtZXRhKS5zb3J0KChhLGIpPT4obWV0YVthXS5wcml8fDkpLShtZXRhW2JdLnByaXx8OSkpOwogICQoJ2VzdHJfcGxhbicpLmlubmVySFRNTD1vcmRlci5tYXAoY29kZT0+ewogICAgY29uc3QgbT1tZXRhW2NvZGVdLCBuPXBsYW5bY29kZV18fDAsIG9uPShFQUNUSU9OPT09Y29kZSk7CiAgICByZXR1cm4gJzxkaXYgb25jbGljaz0iZmlsdGVyQWN0aW9uKFwnJytjb2RlKydcJykiIGNsYXNzPSJrcGkgJysoQUNUX0NPTE9SW2NvZGVdfHwnJykrJyIgc3R5bGU9ImN1cnNvcjpwb2ludGVyOycrKG9uPydvdXRsaW5lOjJweCBzb2xpZCB2YXIoLS1uYXZ5KSc6JycpKyciPicrCiAgICAgICc8ZGl2IGNsYXNzPSJrIj4nK2VzYyhtLmxhYmVsKSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+JytuLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2Rpdj4nKwogICAgICAnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTBweDttYXJnaW4tdG9wOjRweDt3aGl0ZS1zcGFjZTpub3JtYWwiPicrZXNjKG0uaGludCkrJzwvZGl2PjwvZGl2Pic7CiAgfSkuam9pbignJyk7Cn0KLy8gLS0tLSBDT05GSUcgUE9SIENVRU5UQSAob2JqZXRpdm8gKyBmYWN0dXJhKSAtLS0tCmZ1bmN0aW9uIHJlbmRlckFjY3RDZmcoY3VlbnRhcyl7CiAgY29uc3QgYnlJZD17fTsgKGN1ZW50YXN8fFtdKS5mb3JFYWNoKGM9PmJ5SWRbYy5hY2NvdW50X2lkXT1jKTsKICAkKCdlc3RyX2FjY3RjZmcnKS5pbm5lckhUTUw9QUNDT1VOVFMubWFwKGE9PnsKICAgIGNvbnN0IGM9YnlJZFthLmlkXXx8e307CiAgICBjb25zdCBvYmo9KGMub2JqZXRpdm8hPW51bGw/Yy5vYmpldGl2bzooYS5vYmpldGl2byE9bnVsbD9hLm9iamV0aXZvOjEwMDAwMDAwMCkpOwogICAgY29uc3QgZmFjPShjLmZhY3R1cmEhPW51bGw/Yy5mYWN0dXJhOihhLmZhY3R1cmEhPW51bGw/YS5mYWN0dXJhOjUpKTsKICAgIHJldHVybiAnPGRpdiBzdHlsZT0iYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4IDEycHg7YmFja2dyb3VuZDojZmZmIj4nKwogICAgICAnPGRpdiBjbGFzcz0iYiIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O3doaXRlLXNwYWNlOm5vd3JhcDtvdmVyZmxvdzpoaWRkZW47dGV4dC1vdmVyZmxvdzplbGxpcHNpcyI+Jytlc2MoYS5uYW1lKSsnPC9kaXY+JysKICAgICAgJzxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O21hcmdpbi10b3A6NnB4O2FsaWduLWl0ZW1zOmZsZXgtZW5kIj4nKwogICAgICAgICc8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk9iamV0aXZvL21lczwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9Im9iai0nK2EuaWQrJyIgc3RlcD0iMTAwMDAwMCIgdmFsdWU9Iicrb2JqKyciIHN0eWxlPSJ3aWR0aDoxMzBweCI+PC9kaXY+JysKICAgICAgICAnPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5GYWN0dXJhICU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJmYWMtJythLmlkKyciIHN0ZXA9IjAuNSIgdmFsdWU9IicrZmFjKyciIHN0eWxlPSJ3aWR0aDo3MHB4Ij48L2Rpdj4nKwogICAgICAgICc8YnV0dG9uIG9uY2xpY2s9InNhdmVBY2N0Q2ZnKCcrYS5pZCsnKSI+R3VhcmRhcjwvYnV0dG9uPicrCiAgICAgICc8L2Rpdj48L2Rpdj4nOwogIH0pLmpvaW4oJycpOwp9CmFzeW5jIGZ1bmN0aW9uIHNhdmVBY2N0Q2ZnKGlkKXsKICBjb25zdCBvYmpldGl2bz0rJCgnb2JqLScraWQpLnZhbHVlLCB0YXhQY3Q9KyQoJ2ZhYy0nK2lkKS52YWx1ZTsKICB0cnl7IGF3YWl0IGFwaSgnL2FwaS9hZHMvYWNjb3VudC1jb25maWcnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2FjY291bnRfaWQ6aWQsb2JqZXRpdm8sdGF4UGN0fSl9KTsKICAgIHRvYXN0KCdDdWVudGEgZ3VhcmRhZGEgwrcgcmVjYWxjdWzDoSBvIHJlLWVucmlxdWVjw6kgcGFyYSBhcGxpY2FyIGxhIGZhY3R1cmEgYWwgbWFyZ2VuJyk7IH0KICBjYXRjaChlKXsgdG9hc3QoJ0Vycm9yOiAnKyhlLmVycm9yfHxlKSk7IH0KfQovLyAtLS0tIEFDVFVBTElaQURPUiBERSBQUkVDSU9TIE1BU0lWTyAtLS0tCmNvbnN0IFBSSUNFX0FDVElPTlM9WwogIHtjb2RlOidvcmdhbmljbycsbGFiZWw6J/CfjLEgTm8gYW51bmNpYXIgKHTDrXR1bG8gcmVwZXRpZG8pJyxtb2RlOidtYXJnaW4nLHZhbDoyNX0sCiAge2NvZGU6J3JldmlzYXInLGxhYmVsOifwn5KkIER1cm1pZW50ZSAoc2luIGRlbWFuZGEpJyxtb2RlOidtYXJnaW4nLHZhbDoyMH0sCiAge2NvZGU6J3ByZWNpbycsbGFiZWw6J/CfkIQgVmFjYSAobWFyZ2VuIGZsYWNvKScsbW9kZTonbWFyZ2luJyx2YWw6MTV9LAogIHtjb2RlOidhanVzdGFyJyxsYWJlbDon8J+UpyBBanVzdGFyIChubyBjb252aWVydGUpJyxtb2RlOidwY3QnLHZhbDotOH0sCiAge2NvZGU6J3Byb21vdmVyJyxsYWJlbDon8J+OryBQcm9tb3ZlciAoZ2FuYXIgdmVudGEpJyxtb2RlOidwY3QnLHZhbDotNX0sCiAge2NvZGU6J2VzY2FsYXInLGxhYmVsOifirZAgRXNjYWxhciAoZXN0cmVsbGEpJyxtb2RlOidub25lJyx2YWw6MH0sCl07CmZ1bmN0aW9uIHJlbmRlclByZWNpb1J1bGVzKCl7CiAgaWYoJCgncHJlY2lvX3J1bGVzJykuZGF0YXNldC5kb25lKXJldHVybjsgLy8gc29sbyBsYSBwcmltZXJhIHZleiAobm8gcGlzYXIgbG8gcXVlIGVsIHVzdWFyaW8gdG9jw7MpCiAgJCgncHJlY2lvX3J1bGVzJykuaW5uZXJIVE1MPVBSSUNFX0FDVElPTlMubWFwKHI9PgogICAgJzxkaXYgc3R5bGU9ImJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweCAxMnB4O2JhY2tncm91bmQ6I2ZmZiI+JysKICAgICAgJzxkaXYgY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweCI+JytyLmxhYmVsKyc8L2Rpdj4nKwogICAgICAnPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7bWFyZ2luLXRvcDo2cHg7YWxpZ24taXRlbXM6ZmxleC1lbmQiPicrCiAgICAgICAgJzxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+UmVnbGE8L2xhYmVsPjxzZWxlY3QgaWQ9InByLW1vZGUtJytyLmNvZGUrJyIgb25jaGFuZ2U9InByTW9kZUNoYW5nZShcJycrci5jb2RlKydcJykiPicrCiAgICAgICAgICAnPG9wdGlvbiB2YWx1ZT0ibm9uZSInKyhyLm1vZGU9PT0nbm9uZSc/JyBzZWxlY3RlZCc6JycpKyc+U2luIGNhbWJpbzwvb3B0aW9uPicrCiAgICAgICAgICAnPG9wdGlvbiB2YWx1ZT0ibWFyZ2luIicrKHIubW9kZT09PSdtYXJnaW4nPycgc2VsZWN0ZWQnOicnKSsnPk1hcmdlbiBvYmpldGl2byAlPC9vcHRpb24+JysKICAgICAgICAgICc8b3B0aW9uIHZhbHVlPSJwY3QiJysoci5tb2RlPT09J3BjdCc/JyBzZWxlY3RlZCc6JycpKyc+QWp1c3RlICU8L29wdGlvbj4nKwogICAgICAgICc8L3NlbGVjdD48L2Rpdj4nKwogICAgICAgICc8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsIGlkPSJwci1sYmwtJytyLmNvZGUrJyI+Jysoci5tb2RlPT09J21hcmdpbic/J01hcmdlbiAlJzonQWp1c3RlICUnKSsnPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0icHItdmFsLScrci5jb2RlKyciIHN0ZXA9IjAuNSIgdmFsdWU9Iicrci52YWwrJyIgc3R5bGU9IndpZHRoOjgwcHgiJysoci5tb2RlPT09J25vbmUnPycgZGlzYWJsZWQnOicnKSsnPjwvZGl2PicrCiAgICAgICc8L2Rpdj48L2Rpdj4nKS5qb2luKCcnKTsKICAkKCdwcmVjaW9fcnVsZXMnKS5kYXRhc2V0LmRvbmU9JzEnOwp9CmZ1bmN0aW9uIHByTW9kZUNoYW5nZShjb2RlKXtjb25zdCBtPSQoJ3ByLW1vZGUtJytjb2RlKS52YWx1ZTskKCdwci12YWwtJytjb2RlKS5kaXNhYmxlZD0obT09PSdub25lJyk7JCgncHItbGJsLScrY29kZSkudGV4dENvbnRlbnQ9KG09PT0nbWFyZ2luJz8nTWFyZ2VuICUnOidBanVzdGUgJScpO30KZnVuY3Rpb24gY3VycmVudFByaWNlUnVsZXMoKXtjb25zdCBydWxlcz17fTtQUklDRV9BQ1RJT05TLmZvckVhY2gocj0+e2NvbnN0IG1vZGU9JCgncHItbW9kZS0nK3IuY29kZSkudmFsdWU7Y29uc3QgdmFsdWU9KyQoJ3ByLXZhbC0nK3IuY29kZSkudmFsdWU7cnVsZXNbci5jb2RlXT17bW9kZSx2YWx1ZX07fSk7cmV0dXJuIHJ1bGVzO30KbGV0IFBSRVZJRVc9W107CmFzeW5jIGZ1bmN0aW9uIHByZXZpZXdQcmVjaW9zKCl7CiAgY29uc3Qgc2VsPSQoJ2FjY291bnQnKS52YWx1ZTsKICAkKCdwcmVjaW9fcHJldl9pbmZvJykudGV4dENvbnRlbnQ9J0NhbGN1bGFuZG8gcHJlY2lvc+KApic7CiAgdHJ5ewogICAgY29uc3QgYm9keT17cnVsZXM6Y3VycmVudFByaWNlUnVsZXMoKSxhY2NvdW50X2lkOnNlbH07CiAgICBjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvcHJlY2lvcy9wbGFuPycrZXN0clBhcmFtcygpLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoYm9keSl9KTsKICAgIFBSRVZJRVc9ZC5jaGFuZ2VzfHxbXTsKICAgIGNvbnN0IHNrPWQuc2tpcHBlZHx8e307CiAgICAkKCdwcmVjaW9fcHJldl9pbmZvJykuaW5uZXJIVE1MPShkLmNvdW50fHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIGNhbWJpb3MnKygoc2suc2luX2VucmlxdWVjZXJ8fHNrLm1hcmdlbl9pbXBvc2libGUpPygnIMK3IDxzcGFuIGNsYXNzPSJtdXRlZCI+Jysoc2suc2luX2VucmlxdWVjZXJ8fDApKycgc2luIGVucmlxdWVjZXIsICcrKHNrLm1hcmdlbl9pbXBvc2libGV8fDApKycgbWFyZ2VuIGltcG9zaWJsZTwvc3Bhbj4nKTonJyk7CiAgICByZW5kZXJQcmV2aWV3KCk7CiAgfWNhdGNoKGUpeyQoJ3ByZWNpb19wcmV2X2luZm8nKS50ZXh0Q29udGVudD0nRXJyb3I6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSk7fQp9CmZ1bmN0aW9uIHJlbmRlclByZXZpZXcoKXsKICBjb25zdCB0Yj0kKCdwcmVjaW9fYm9keScpOwogIGlmKCFQUkVWSUVXLmxlbmd0aCl7JCgncHJlY2lvVGFibGUnKS5zdHlsZS5kaXNwbGF5PSdub25lJzskKCdwcmVjaW9fYXBwbHlfYnRuJykuc3R5bGUuZGlzcGxheT0nbm9uZSc7JCgncHJlY2lvX3hsc3hfYnRuJykuc3R5bGUuZGlzcGxheT0nbm9uZSc7cmV0dXJuO30KICAkKCdwcmVjaW9UYWJsZScpLnN0eWxlLmRpc3BsYXk9Jyc7JCgncHJlY2lvX3hsc3hfYnRuJykuc3R5bGUuZGlzcGxheT0nJzsKICB0Yi5pbm5lckhUTUw9UFJFVklFVy5zbGljZSgwLDMwMCkubWFwKChjLGlkeCk9PnsKICAgIGNvbnN0IHVwPShjLmRlbHRhUGN0fHwwKT49MDsKICAgIHJldHVybiAnPHRyPjx0ZD48aW5wdXQgdHlwZT0iY2hlY2tib3giIGNsYXNzPSJwci1jaGsiIGRhdGEtaWR4PSInK2lkeCsnIiBjaGVja2VkIG9uY2xpY2s9InVwZGF0ZUFwcGx5Q291bnQoKSI+PC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJuYW1lIj4nK2VzYyhjLnRpdGxlfHxjLml0ZW1faWQpKyc8c3BhbiBjbGFzcz0iaWQiPicrYy5pdGVtX2lkKyc8L3NwYW4+PC90ZD4nKwogICAgICAnPHRkPicrZXNjKGMuYWNjb3VudF9uYW1lfHwnJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTFweCI+Jytlc2MoKGMuYWN0aW9uQ29kZXx8JycpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoYy5wcmljZU5vdykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIGIiPicrZm10TW9uZXkoYy5wcmljZU5ldykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6JysodXA/J3ZhcigtLWdyZWVuKSc6J3ZhcigtLXJlZCknKSsnIj4nKyhjLmRlbHRhUGN0PT1udWxsPyfigJQnOih1cD8nKyc6JycpK2MuZGVsdGFQY3QudG9GaXhlZCgxKSsnJScpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JysoYy5tYXJnaW5Ob3c9PW51bGw/J+KAlCc6Zm10UGN0KGMubWFyZ2luTm93KSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIGIiIHN0eWxlPSJjb2xvcjp2YXIoLS1ncmVlbikiPicrKGMubWFyZ2luTmV3PT1udWxsPyfigJQnOmZtdFBjdChjLm1hcmdpbk5ldykpKyc8L3RkPjwvdHI+JzsKICB9KS5qb2luKCcnKTsKICB1cGRhdGVBcHBseUNvdW50KCk7Cn0KZnVuY3Rpb24gdG9nZ2xlUHJlY2lvQWxsKGVsKXtkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcucHItY2hrJykuZm9yRWFjaChjPT5jLmNoZWNrZWQ9ZWwuY2hlY2tlZCk7dXBkYXRlQXBwbHlDb3VudCgpO30KZnVuY3Rpb24gc2VsZWN0ZWRDaGFuZ2VzKCl7Y29uc3Qgb3V0PVtdO2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5wci1jaGsnKS5mb3JFYWNoKGM9PntpZihjLmNoZWNrZWQpe2NvbnN0IGl0PVBSRVZJRVdbK2MuZGF0YXNldC5pZHhdO2lmKGl0KW91dC5wdXNoKHtpdGVtX2lkOml0Lml0ZW1faWQsYWNjb3VudF9pZDppdC5hY2NvdW50X2lkLHByaWNlOml0LnByaWNlTmV3fSk7fX0pO3JldHVybiBvdXQ7fQpmdW5jdGlvbiB1cGRhdGVBcHBseUNvdW50KCl7Y29uc3Qgbj1zZWxlY3RlZENoYW5nZXMoKS5sZW5ndGg7JCgncHJlY2lvX2FwcGx5X24nKS50ZXh0Q29udGVudD1uOyQoJ3ByZWNpb19hcHBseV9idG4nKS5zdHlsZS5kaXNwbGF5PW4/Jyc6J25vbmUnO30KYXN5bmMgZnVuY3Rpb24gYXBsaWNhclByZWNpb3MoKXsKICBjb25zdCBjaGFuZ2VzPXNlbGVjdGVkQ2hhbmdlcygpOwogIGlmKCFjaGFuZ2VzLmxlbmd0aCl7dG9hc3QoJ05vIGhheSBjYW1iaW9zIHNlbGVjY2lvbmFkb3MnKTtyZXR1cm47fQogIGlmKCFjb25maXJtKCdWYXMgYSBjYW1iaWFyIGVsIHByZWNpbyBkZSAnK2NoYW5nZXMubGVuZ3RoKycgcHVibGljYWNpb25lcyBlbiBNZXJjYWRvIExpYnJlLiDCv0NvbmZpcm3DoXM/JykpcmV0dXJuOwogICQoJ3ByZWNpb19hcHBseV9idG4nKS5kaXNhYmxlZD10cnVlOyQoJ3ByZWNpb19wcmV2X2luZm8nKS50ZXh0Q29udGVudD0nQXBsaWNhbmRvICcrY2hhbmdlcy5sZW5ndGgrJyBjYW1iaW9zIGVuIE1M4oCmJzsKICB0cnl7CiAgICBsZXQgb2s9MCxlcnI9MDsKICAgIGZvcihsZXQgaT0wO2k8Y2hhbmdlcy5sZW5ndGg7aSs9MjAwKXsKICAgICAgY29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL3ByZWNpb3MvYXBsaWNhcicse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7Y2hhbmdlczpjaGFuZ2VzLnNsaWNlKGksaSsyMDApfSl9KTsKICAgICAgb2srPWQuYXBwbGllZHx8MDtlcnIrPWQuZmFpbGVkfHwwOwogICAgICAkKCdwcmVjaW9fcHJldl9pbmZvJykudGV4dENvbnRlbnQ9J0FwbGljYWRvcyAnK29rKycgwrcgZXJyb3JlcyAnK2Vycisn4oCmJzsKICAgIH0KICAgIHRvYXN0KCfinIUgUHJlY2lvcyBhcGxpY2Fkb3M6ICcrb2srJyDCtyBlcnJvcmVzOiAnK2Vycik7CiAgICAkKCdwcmVjaW9fcHJldl9pbmZvJykudGV4dENvbnRlbnQ9J0xpc3RvOiAnK29rKycgYXBsaWNhZG9zLCAnK2VycisnIGVycm9yZXMuIFJlLWVucmlxdWVjw6kgcGFyYSB2ZXIgbG9zIG51ZXZvcyBtw6FyZ2VuZXMuJzsKICB9Y2F0Y2goZSl7dG9hc3QoJ0Vycm9yOiAnKyhlLmVycm9yfHxlKSk7fQogIGZpbmFsbHl7JCgncHJlY2lvX2FwcGx5X2J0bicpLmRpc2FibGVkPWZhbHNlO30KfQpmdW5jdGlvbiBkb3dubG9hZFByZWNpb3NYbHN4KCl7CiAgaWYoIVBSRVZJRVcubGVuZ3RoKXt0b2FzdCgnSGFjw6kgbGEgdmlzdGEgcHJldmlhIHByaW1lcm8nKTtyZXR1cm47fQogIGNvbnN0IGRhdGE9UFJFVklFVy5tYXAoYz0+KHtQcm9kdWN0bzpjLnRpdGxlLEl0ZW1JRDpjLml0ZW1faWQsQ3VlbnRhOmMuYWNjb3VudF9uYW1lLEFjY2lvbjpjLmFjdGlvbkNvZGUsUHJlY2lvX2FjdHVhbDpjLnByaWNlTm93LFByZWNpb19udWV2bzpjLnByaWNlTmV3LERlbHRhX3BjdDpjLmRlbHRhUGN0PT1udWxsPycnOitjLmRlbHRhUGN0LnRvRml4ZWQoMSksTWFyZ2VuX2FjdHVhbDpjLm1hcmdpbk5vdz09bnVsbD8nJzorYy5tYXJnaW5Ob3cudG9GaXhlZCgxKSxNYXJnZW5fbnVldm86Yy5tYXJnaW5OZXc9PW51bGw/Jyc6K2MubWFyZ2luTmV3LnRvRml4ZWQoMSl9KSk7CiAgY29uc3Qgd3M9WExTWC51dGlscy5qc29uX3RvX3NoZWV0KGRhdGEpO2NvbnN0IHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTtYTFNYLnV0aWxzLmJvb2tfYXBwZW5kX3NoZWV0KHdiLHdzLCdQcmVjaW9zJyk7CiAgWExTWC53cml0ZUZpbGUod2IsJ3BsYW5fcHJlY2lvc18nKyhuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCkpKycueGxzeCcpOwp9CgovLyAtLS0tIFBVQkxJQ0lEQUQgLS0tLQphc3luYyBmdW5jdGlvbiBsb2FkQ2FtcGFpZ25zKCl7CiAgY29uc3QgaWQ9JCgnYWNjb3VudCcpLnZhbHVlO2lmKCFpZClyZXR1cm47CiAgJCgnYmFubmVyJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwogICQoJ3Rib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjEyIiBjbGFzcz0ibG9hZGluZyI+Q2FyZ2FuZG8gY2FtcGHDsWFz4oCmPC90ZD48L3RyPic7CiAgdHJ5e2NvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9jYW1wYWlnbnM/YWNjb3VudF9pZD0nK2lkKTtTVEFURS5jZmc9ZC5jb25maWd8fFNUQVRFLmNmZztTVEFURS5yb3dzPShkLmNhbXBhaWduc3x8W10pLm1hcChlbnJpY2gpO3JlbmRlcigpO30KICBjYXRjaChlKXtTVEFURS5yb3dzPVtdO3JlbmRlcigpOyQoJ2Jhbm5lck1zZycpLnRleHRDb250ZW50PXR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKTskKCdiYW5uZXInKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7fQp9CmZ1bmN0aW9uIGVucmljaChyKXtjb25zdCBtPXIubWV0cmljc3x8e307Y29uc3QgY3RyPW0ucHJpbnRzPjA/KG0uY2xpY2tzL20ucHJpbnRzKjEwMCk6bnVsbDtyZXR1cm4gey4uLnIsY29zdDptLmNvc3R8fDAscmV2ZW51ZTptLnJldmVudWV8fDAsYWNvczptLmFjb3Mscm9hczptLnJvYXMsY2xpY2tzOm0uY2xpY2tzfHwwLHByaW50czptLnByaW50c3x8MCx1bml0czptLnVuaXRzfHwwLGN0cn07fQpmdW5jdGlvbiB0b2dnbGVDaGlwKGVsKXtlbC5jbGFzc0xpc3QudG9nZ2xlKCdvbicpO1NUQVRFLmFjdHNbZWwuZGF0YXNldC5hY3RdPWVsLmNsYXNzTGlzdC5jb250YWlucygnb24nKT8xOjA7cmVuZGVyKCk7fQpmdW5jdGlvbiBzb3J0Qnkoayl7aWYoU1RBVEUuc29ydEtleT09PWspU1RBVEUuc29ydERpcio9LTE7ZWxzZXtTVEFURS5zb3J0S2V5PWs7U1RBVEUuc29ydERpcj0tMTt9cmVuZGVyKCk7fQpmdW5jdGlvbiBhY3Rpb25QaWxsKGEpe2NvbnN0IG1hcD17RVNDQUxBUjpbJ3AtZ3JlZW4nLCfwn5+iIEVzY2FsYXInXSxNQU5URU5FUjpbJ3AtYW1iZXInLCfwn5+hIE1hbnRlbmVyJ10sSlVOVEFSX0RBVE9TOlsncC1ibHVlJywn8J+UtSBKdW50YXIgZGF0b3MnXSxQQVVTQVI6WydwLXJlZCcsJ/CflLQgUGF1c2FyJ119O2NvbnN0W2Nscyx0eHRdPW1hcFthXXx8WydwLWdyZXknLGFdO3JldHVybiAnPHNwYW4gY2xhc3M9InBpbGwgJytjbHMrJyI+Jyt0eHQrJzwvc3Bhbj4nO30KZnVuY3Rpb24gYWNvc0JhcihhY29zLGJlKXtjb25zdCBiZTI9KGJlIT1udWxsKT9iZTooK1NUQVRFLmNmZy5tYXJnaW58fDEyKTtjb25zdCB0YXJnZXQ9KGJlIT1udWxsKT9iZSowLjY6KCtTVEFURS5jZmcuYWNvc1RhcmdldHx8Nyk7aWYoYWNvcz09bnVsbClyZXR1cm4gJzxzcGFuIGNsYXNzPSJtdXRlZCI+cy92ZW50YTwvc3Bhbj4nO2NvbnN0IHBjdD1NYXRoLm1pbigxMDAsYWNvcy8oYmUyKjEuNikqMTAwKTtsZXQgY29sPWFjb3M8PXRhcmdldD8ndmFyKC0tZ3JlZW4pJzooYWNvczw9YmUyPyd2YXIoLS1hbWJlciknOid2YXIoLS1yZWQpJyk7cmV0dXJuICc8ZGl2IGNsYXNzPSJhY29zY2VsbCI+PHNwYW4+JytmbXRQY3QoYWNvcykrJzwvc3Bhbj48ZGl2IGNsYXNzPSJhY29zYmFyIj48aSBzdHlsZT0id2lkdGg6JytwY3QrJyU7YmFja2dyb3VuZDonK2NvbCsnIj48L2k+PC9kaXY+PC9kaXY+Jzt9CmZ1bmN0aW9uIGZpbHRlcmVkUm93cygpe2NvbnN0IHE9KCQoJ3NlYXJjaCcpLnZhbHVlfHwnJykudG9Mb3dlckNhc2UoKS50cmltKCk7Y29uc3Qgc3Q9JCgnc3RhdHVzRmlsdGVyJykudmFsdWU7bGV0IHJvd3M9U1RBVEUucm93cy5maWx0ZXIocj0+U1RBVEUuYWN0c1tyLmFjdGlvbl0pO2lmKHN0IT09J2FsbCcpcm93cz1yb3dzLmZpbHRlcihyPT5TdHJpbmcoci5zdGF0dXMpLnRvTG93ZXJDYXNlKCk9PT1zdCk7aWYocSlyb3dzPXJvd3MuZmlsdGVyKHI9PihyLm5hbWV8fCcnKS50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKHEpfHxTdHJpbmcoci5jYW1wYWlnbl9pZCkuaW5jbHVkZXMocSkpO2NvbnN0IGs9U1RBVEUuc29ydEtleSxkaXI9U1RBVEUuc29ydERpcjtyb3dzLnNvcnQoKGEsYik9PntsZXQgeD1hW2tdLHk9YltrXTtpZihrPT09J25hbWUnfHxrPT09J3N0YXR1cyd8fGs9PT0nYWN0aW9uJyl7eD1TdHJpbmcoeHx8JycpO3k9U3RyaW5nKHl8fCcnKTtyZXR1cm4gZGlyKngubG9jYWxlQ29tcGFyZSh5KTt9eD0oeD09bnVsbD8tMTp4KTt5PSh5PT1udWxsPy0xOnkpO3JldHVybiBkaXIqKHgteSk7fSk7cmV0dXJuIHJvd3M7fQpmdW5jdGlvbiByZW5kZXIoKXsKICBjb25zdCByb3dzPWZpbHRlcmVkUm93cygpO3JlbmRlcktwaXMoKTtjb25zdCB0Yj0kKCd0Ym9keScpOwogIGlmKCFyb3dzLmxlbmd0aCl7dGIuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjEyIiBjbGFzcz0iZW1wdHkiPk5vIGhheSBjYW1wYcOxYXMgcXVlIGNvaW5jaWRhbi48L3RkPjwvdHI+JztyZXR1cm47fQogIHRiLmlubmVySFRNTD1yb3dzLm1hcChyPT57Y29uc3QgaXNBPVN0cmluZyhyLnN0YXR1cykudG9Mb3dlckNhc2UoKT09PSdhY3RpdmUnO2NvbnN0IHN0UGlsbD1pc0E/JzxzcGFuIGNsYXNzPSJwaWxsIHAtZ3JlZW4iPkFjdGl2YTwvc3Bhbj4nOic8c3BhbiBjbGFzcz0icGlsbCBwLWdyZXkiPicrKHIuc3RhdHVzfHwn4oCUJykrJzwvc3Bhbj4nOwogICAgY29uc3QgYnRuPWlzQT8nPGJ1dHRvbiBjbGFzcz0icm93YnRuIHBhdXNlIiBvbmNsaWNrPSJzZXRTdGF0dXMoXCcnK3IuY2FtcGFpZ25faWQrJ1wnLFwncGF1c2VkXCcpIj5QYXVzYXI8L2J1dHRvbj4nOic8YnV0dG9uIGNsYXNzPSJyb3didG4gcGxheSIgb25jbGljaz0ic2V0U3RhdHVzKFwnJytyLmNhbXBhaWduX2lkKydcJyxcJ2FjdGl2ZVwnKSI+QWN0aXZhcjwvYnV0dG9uPic7CiAgICByZXR1cm4gJzx0cj48dGQgY2xhc3M9Im5hbWUiPicrZXNjKHIubmFtZSkrJzxzcGFuIGNsYXNzPSJpZCI+JytyLmNhbXBhaWduX2lkKyc8L3NwYW4+PC90ZD48dGQ+JytzdFBpbGwrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoci5jb3N0KSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leShyLnJldmVudWUpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2Fjb3NCYXIoci5hY29zLHIuYnJlYWtldmVuQWNvcykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHIuYnJlYWtldmVuQWNvcyE9bnVsbD9mbXRQY3Qoci5icmVha2V2ZW5BY29zKTonPHNwYW4gY2xhc3M9Im11dGVkIj5zL2Nvc3RvPC9zcGFuPicpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iZm9udC13ZWlnaHQ6NzAwO2NvbG9yOicrKHIubmV0UHJvZml0PT1udWxsPyd2YXIoLS1tdXQpJzooci5uZXRQcm9maXQ+PTA/J3ZhcigtLWdyZWVuKSc6J3ZhcigtLXJlZCknKSkrJyI+Jysoci5uZXRQcm9maXQ9PW51bGw/J+KAlCc6Zm10TW9uZXkoci5uZXRQcm9maXQpKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRYKHIucm9hcykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrci5jbGlja3MudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJzwvdGQ+PHRkPicrYWN0aW9uUGlsbChyLmFjdGlvbikrJzwvdGQ+PHRkIGNsYXNzPSJtdXRlZCIgc3R5bGU9IndoaXRlLXNwYWNlOm5vcm1hbDttYXgtd2lkdGg6MjAwcHgiPicrZXNjKHIucmVhc29ufHwnJykrJzwvdGQ+PHRkPicrYnRuKyc8L3RkPjwvdHI+Jzt9KS5qb2luKCcnKTsKfQpmdW5jdGlvbiByZW5kZXJLcGlzKCl7CiAgY29uc3Qgcm93cz1TVEFURS5yb3dzO2NvbnN0IGNvc3Q9cm93cy5yZWR1Y2UoKHMscik9PnMrKHIuY29zdHx8MCksMCk7Y29uc3QgcmV2PXJvd3MucmVkdWNlKChzLHIpPT5zKyhyLnJldmVudWV8fDApLDApOwogIGNvbnN0IGFjb3M9cmV2PjA/Y29zdC9yZXYqMTAwOm51bGw7Y29uc3Qgcm9hcz1jb3N0PjA/cmV2L2Nvc3Q6bnVsbDtjb25zdCBtYXJnaW49K1NUQVRFLmNmZy5tYXJnaW58fDEyOwogIGNvbnN0IGNudD1hPT5yb3dzLmZpbHRlcihyPT5yLmFjdGlvbj09PWEpLmxlbmd0aDsKICBjb25zdCByZWFsUm93cz1yb3dzLmZpbHRlcihyPT5yLm5ldFByb2ZpdCE9bnVsbCk7Y29uc3QgcmVhbE5ldD1yZWFsUm93cy5yZWR1Y2UoKHMscik9PnMrci5uZXRQcm9maXQsMCk7Y29uc3QgaGFzUmVhbD1yZWFsUm93cy5sZW5ndGg+MDsKICBjb25zdCBhY29zQ2xzPWFjb3M9PW51bGw/Jyc6KGFjb3M8PSgrU1RBVEUuY2ZnLmFjb3NUYXJnZXR8fDcpPydnb29kJzooYWNvczw9bWFyZ2luPyd3YXJuJzonYmFkJykpOwogIGNvbnN0IHRpbGVzPVtbJ0ludmVyc2nDs24nLGZtdE1vbmV5KGNvc3QpLCcnXSxbJ1ZlbnRhcyBwb3IgcHViLicsZm10TW9uZXkocmV2KSwnJ10sWydBQ09TIGdsb2JhbCcsZm10UGN0KGFjb3MpLGFjb3NDbHNdLFsnUk9BUyBnbG9iYWwnLGZtdFgocm9hcykscm9hcyYmcm9hcz49MS8obWFyZ2luLzEwMCk/J2dvb2QnOid3YXJuJ10sW2hhc1JlYWw/J0dhbmFuY2lhIG5ldGEgcmVhbCc6J0dhbmFuY2lhIGVzdGltLicsZm10TW9uZXkoaGFzUmVhbD9yZWFsTmV0OnJldioobWFyZ2luLzEwMCktY29zdCksKGhhc1JlYWw/cmVhbE5ldDpyZXYqKG1hcmdpbi8xMDApLWNvc3QpPj0wPydnb29kJzonYmFkJ10sWyfwn5+iJytjbnQoJ0VTQ0FMQVInKSsnIPCfn6EnK2NudCgnTUFOVEVORVInKSsnIPCflLQnK2NudCgnUEFVU0FSJyksJycsJyddXTsKICAkKCdrcGlzJykuaW5uZXJIVE1MPXRpbGVzLm1hcCgodCxpKT0+aT09PTU/JzxkaXYgY2xhc3M9ImtwaSI+PGRpdiBjbGFzcz0iayI+U2Vtw6Fmb3JvPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+Jyt0WzBdKyc8L2Rpdj48L2Rpdj4nOic8ZGl2IGNsYXNzPSJrcGkgJyt0WzJdKyciPjxkaXYgY2xhc3M9ImsiPicrdFswXSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+Jyt0WzFdKyc8L2Rpdj48L2Rpdj4nKS5qb2luKCcnKTsKfQphc3luYyBmdW5jdGlvbiBzZXRTdGF0dXMoY2lkLHN0YXR1cyl7CiAgY29uc3QgYWNjb3VudF9pZD0kKCdhY2NvdW50JykudmFsdWU7CiAgdHJ5e2F3YWl0IGFwaSgnL2FwaS9hZHMvY2FtcGFpZ24tc3RhdHVzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHthY2NvdW50X2lkLGNhbXBhaWduX2lkOmNpZCxzdGF0dXN9KX0pO2NvbnN0IHJvdz1TVEFURS5yb3dzLmZpbmQocj0+U3RyaW5nKHIuY2FtcGFpZ25faWQpPT09U3RyaW5nKGNpZCkpO2lmKHJvdylyb3cuc3RhdHVzPXN0YXR1czt0b2FzdCgnQ2FtcGHDsWEgJysoc3RhdHVzPT09J3BhdXNlZCc/J3BhdXNhZGEnOidhY3RpdmFkYScpKTtyZW5kZXIoKTt9CiAgY2F0Y2goZSl7dG9hc3QoJ05vIHNlIHB1ZG86ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkpO30KfQphc3luYyBmdW5jdGlvbiBydW5Ob3coKXsKICB0cnl7dG9hc3QoJ0NvcnJpZW5kbyBhbsOhbGlzaXPigKYnKTtjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvcnVuLW5vdycse21ldGhvZDonUE9TVCd9KTtjb25zdCBwYXVzZWQ9ZC5yZXN1bHRzLmZpbHRlcihyPT5yLnBhdXNlZCkubGVuZ3RoLHdvdWxkPWQucmVzdWx0cy5maWx0ZXIocj0+ci53b3VsZF9wYXVzZSkubGVuZ3RoO3RvYXN0KGQuZHJ5X3J1bj8oJ0RSWS1SVU46IHBhdXNhcsOtYSAnK3dvdWxkKTooJ0xpc3RvOiAnK3BhdXNlZCsnIHBhdXNhZGFzJykpO2xvYWRDYW1wYWlnbnMoKTtsb2FkTG9nKCk7fQogIGNhdGNoKGUpe3RvYXN0KCdFcnJvcjogJysoZS5lcnJvcnx8ZSkpO30KfQphc3luYyBmdW5jdGlvbiBsb2FkTG9nKCl7CiAgdHJ5e2NvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9sb2cnKTskKCdsYXN0UnVuJykudGV4dENvbnRlbnQ9ZC5sYXN0X3J1bj8oJ8OabHRpbWEgY29ycmlkYTogJytuZXcgRGF0ZShkLmxhc3RfcnVuKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSk6J1NpbiBjb3JyaWRhcyBhw7puJzsKICBjb25zdCBydW5zPWQucnVuc3x8W107JCgnbG9nY2FyZCcpLmlubmVySFRNTD1ydW5zLmxlbmd0aD9ydW5zLm1hcChydW49Pntjb25zdCBoZWFkPSc8ZGl2IGNsYXNzPSJiIj4nK25ldyBEYXRlKHJ1bi5hdCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyDCtyAnKyhydW4uZHJ5X3J1bj8nRFJZLVJVTic6J0xJVkUnKSsnPC9kaXY+Jztjb25zdCBpdGVtcz0ocnVuLnJlc3VsdHN8fFtdKS5maWx0ZXIocj0+ci53b3VsZF9wYXVzZXx8ci5wYXVzZWR8fHIuZXJyb3IpLm1hcChyPT4nPGRpdiBjbGFzcz0ibG9ncm93Ij48c3BhbiBjbGFzcz0icGlsbCAnKyhyLnBhdXNlZD8ncC1yZWQnOihyLmVycm9yPydwLWdyZXknOidwLWFtYmVyJykpKyciPicrKHIucGF1c2VkPydwYXVzYWRhJzooci5lcnJvcj8nZXJyb3InOidhIHBhdXNhcicpKSsnPC9zcGFuPiA8c3BhbiBjbGFzcz0iYiI+Jytlc2Moci5uYW1lfHxyLmFjY291bnR8fCcnKSsnPC9zcGFuPiA8c3BhbiBjbGFzcz0ibXV0ZWQiPicrZXNjKHIucmVhc29ufHxyLmVycm9yfHwnJykrJzwvc3Bhbj48L2Rpdj4nKS5qb2luKCcnKXx8JzxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0icGFkZGluZzo2cHggMCI+U2luIGNhbWJpb3MuPC9kaXY+JztyZXR1cm4gaGVhZCtpdGVtczt9KS5qb2luKCc8aHIgc3R5bGU9ImJvcmRlcjpub25lO2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWxpbmUpO21hcmdpbjoxMHB4IDAiPicpOic8ZGl2IGNsYXNzPSJtdXRlZCI+U2luIGNvcnJpZGFzLjwvZGl2Pic7fWNhdGNoKGUpe30KfQpmdW5jdGlvbiB0b2dnbGVMb2coKXtjb25zdCBjPSQoJ2xvZ2NhcmQnKTtjLmNsYXNzTGlzdC50b2dnbGUoJ3Nob3cnKTtpZihjLmNsYXNzTGlzdC5jb250YWlucygnc2hvdycpKWxvYWRMb2coKTt9CgovLyAtLS0tIEdBTkFET1JBUyAtLS0tCmFzeW5jIGZ1bmN0aW9uIGxvYWRXaW5uZXJzKCl7CiAgY29uc3QgaWQ9JCgnYWNjb3VudCcpLnZhbHVlO2lmKCFpZCl7dG9hc3QoJ0VsZWfDrSB1bmEgY3VlbnRhJyk7cmV0dXJuO30KICBjb25zdCBtPSQoJ3dpbl9tYXJnaW4nKS52YWx1ZXx8MTIscz0kKCd3aW5fc2FsZXMnKS52YWx1ZXx8MCxsPSQoJ3dpbl9saW1pdCcpLnZhbHVlfHw0MDsKICAkKCd3aW5TdGF0dXMnKS50ZXh0Q29udGVudD0nQnVzY2FuZG/igKYnOwogIHRyeXtjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvd2lubmVycz9hY2NvdW50X2lkPScraWQrJyZtaW5NYXJnaW49JyttKycmbWluU2FsZXM9JytzKycmbGltaXQ9JytsKTtXSU5ORVJTPWQud2lubmVyc3x8W107CiAgJCgnd2luU3RhdHVzJykuaW5uZXJIVE1MPSc8Yj4nK1dJTk5FUlMubGVuZ3RoKyc8L2I+IGdhbmFkb3JhcycrKGQuc2Nhbm5lZD8oJyAoZGUgJytkLnNjYW5uZWQrJyByZXZpc2FkYXMpJyk6JycpKyhkLm5vdGU/KCcgwrcgJytlc2MoZC5ub3RlKSk6JycpO3JlbmRlcldpbm5lcnMoKTt9CiAgY2F0Y2goZSl7JCgnd2luU3RhdHVzJykudGV4dENvbnRlbnQ9J0Vycm9yOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpO30KfQpmdW5jdGlvbiByZW5kZXJXaW5uZXJzKCl7CiAgY29uc3QgdGI9JCgnd2luQm9keScpO2lmKCFXSU5ORVJTLmxlbmd0aCl7dGIuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjUiIGNsYXNzPSJlbXB0eSI+U2luIHJlc3VsdGFkb3MuPC90ZD48L3RyPic7cmV0dXJuO30KICB0Yi5pbm5lckhUTUw9V0lOTkVSUy5tYXAodz0+Jzx0cj48dGQgY2xhc3M9Im5hbWUiPjxhIGhyZWY9IicrKHcucGVybWFsaW5rfHwnIycpKyciIHRhcmdldD0iX2JsYW5rIj4nK2VzYyh3LnRpdGxlfHx3Lml0ZW1faWQpKyc8L2E+PHNwYW4gY2xhc3M9ImlkIj4nK3cuaXRlbV9pZCsnPC9zcGFuPjwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10UGN0KHcubWFyZ2luKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh3LnByaWNlKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jyt3LnN0b2NrKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK3cuc29sZCsnPC90ZD48L3RyPicpLmpvaW4oJycpOwp9CmZ1bmN0aW9uIGNvcHlXaW5uZXJzKCl7aWYoIVdJTk5FUlMubGVuZ3RoKXt0b2FzdCgnQnVzY8OhIGdhbmFkb3JhcyBwcmltZXJvJyk7cmV0dXJuO31jb25zdCBpZHM9V0lOTkVSUy5tYXAodz0+dy5pdGVtX2lkKS5qb2luKCcsICcpO2lmKG5hdmlnYXRvci5jbGlwYm9hcmQpe25hdmlnYXRvci5jbGlwYm9hcmQud3JpdGVUZXh0KGlkcykudGhlbigoKT0+dG9hc3QoJ0NvcGlhZG9zICcrV0lOTkVSUy5sZW5ndGgrJyBJRHMnKSkuY2F0Y2goKCk9PnByb21wdCgnQ29wacOhIGxvcyBJRHM6JyxpZHMpKTt9ZWxzZSBwcm9tcHQoJ0NvcGnDoSBsb3MgSURzOicsaWRzKTt9CmZ1bmN0aW9uIGNzdldpbm5lcnMoKXtpZighV0lOTkVSUy5sZW5ndGgpe3RvYXN0KCdCdXNjw6EgZ2FuYWRvcmFzIHByaW1lcm8nKTtyZXR1cm47fWNvbnN0IHJvd3M9W1snaXRlbV9pZCcsJ3RpdHVsbycsJ21hcmdlbl8lJywncHJlY2lvJywnc3RvY2snLCd2ZW50YXMnXV07V0lOTkVSUy5mb3JFYWNoKHc9PnJvd3MucHVzaChbdy5pdGVtX2lkLCciJytTdHJpbmcody50aXRsZXx8JycpLnJlcGxhY2UoLyIvZywnJykrJyInLHcubWFyZ2luLnRvRml4ZWQoMSksdy5wcmljZSx3LnN0b2NrLHcuc29sZF0pKTtjb25zdCBjc3Y9cm93cy5tYXAocj0+ci5qb2luKCcsJykpLmpvaW4oJ1xuJyk7Y29uc3QgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7YS5ocmVmPSdkYXRhOnRleHQvY3N2O2NoYXJzZXQ9dXRmLTgsJytlbmNvZGVVUklDb21wb25lbnQoY3N2KTthLmRvd25sb2FkPSdnYW5hZG9yYXMuY3N2JzthLmNsaWNrKCk7fQoKLy8gPT09PT09PT09PT09PT09PT09PT0gSElTVMOTUklDTyAoZ2VzdGnDs24gwrcgZMOtYXMgZ3VhcmRhZG9zKSA9PT09PT09PT09PT09PT09PT09PQp2YXIgSElTVF9MT0FERUQ9ZmFsc2UsIEhJU1Q9bnVsbCwgSENIQVJUUz17fSwgSEZJTFQ9bnVsbDsKZnVuY3Rpb24gZFBsdXMoZHMsbil7Y29uc3QgcD1kcy5zcGxpdCgnLScpLm1hcChOdW1iZXIpO2NvbnN0IGR0PW5ldyBEYXRlKERhdGUuVVRDKHBbMF0scFsxXS0xLHBbMl0pKTtkdC5zZXRVVENEYXRlKGR0LmdldFVUQ0RhdGUoKStuKTtyZXR1cm4gZHQudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTt9CmZ1bmN0aW9uIGRvd0xhYmVsKGRzKXtjb25zdCBwPWRzLnNwbGl0KCctJykubWFwKE51bWJlcik7Y29uc3QgZz1uZXcgRGF0ZShEYXRlLlVUQyhwWzBdLHBbMV0tMSxwWzJdKSkuZ2V0VVRDRGF5KCk7cmV0dXJuIFsnRE9NSU5HTycsJ0xVTkVTJywnTUFSVEVTJywnTUnDiVJDT0xFUycsJ0pVRVZFUycsJ1ZJRVJORVMnLCdTw4FCQURPJ11bZ107fQpmdW5jdGlvbiBhZ2dTYWxlcyhzYWxlcyl7CiAgdmFyIFQ9e2ZhY3R1cmFjaW9uOjAsdW5pZGFkZXM6MCxmZWVUb3RhbDowLGVudmlvVG90YWw6MCx0YXhUb3RhbDowLGZhY3R1cmFUb3RhbDowLHF1ZWRhVG90YWw6MCxjb3N0VG90YWw6MCxjb3N0U3RvY2tUb3RhbDowLGdhbmFuY2lhOjAsZ2FuYW5jaWFTaW5GbGV4OjAscGVyZGlkYTowLHBlcmRpZGFNb250bzowLGN1b3Rhc0NvdW50OjAsY29ub2NpZGFzOjAsc2luQ29zdG86MCxmYWN0Q29ub2NpZGE6MCxjb3VudDowLGJvbm9Ub3RhbDowLGZsZXhDb3VudDowfTsKICB2YXIgb3Jkcz17fTsKICBmb3IodmFyIGk9MDtpPHNhbGVzLmxlbmd0aDtpKyspe3ZhciBzPXNhbGVzW2ldO1QuY291bnQrKztvcmRzW3Mub3JkZXJfaWRdPTE7VC5mYWN0dXJhY2lvbis9cy5yZXZlbnVlfHwwO1QudW5pZGFkZXMrPXMucXR5fHwwO1QuZmVlVG90YWwrPXMuZmVlfHwwO1QuZW52aW9Ub3RhbCs9cy5lbnZpb3x8MDtULnRheFRvdGFsKz1zLnRheHx8MDtULmZhY3R1cmFUb3RhbCs9cy5mYWN0dXJhfHwwO1QucXVlZGFUb3RhbCs9cy5xdWVkYXx8MDtULmJvbm9Ub3RhbCs9cy5ib25vfHwwO2lmKHMuZmxleClULmZsZXhDb3VudCsrO2lmKChzLmN1b3Rhc3x8MCk+MSlULmN1b3Rhc0NvdW50Kys7CiAgICBpZihzLmtub3duKXtULmNvbm9jaWRhcysrO1QuZmFjdENvbm9jaWRhKz1zLnJldmVudWV8fDA7VC5jb3N0VG90YWwrPXMuY29zdHx8MDtULmNvc3RTdG9ja1RvdGFsKz0ocy5jb3N0X3N0b2NrIT1udWxsP3MuY29zdF9zdG9jazoocy5zdG9jaz8ocy5jb3N0fHwwKTowKSk7VC5nYW5hbmNpYSs9cy5uZXR8fDA7VC5nYW5hbmNpYVNpbkZsZXgrPShzLm5ldF9zaW5fZmxleCE9bnVsbD9zLm5ldF9zaW5fZmxleDowKTtpZihzLm5ldDwwKXtULnBlcmRpZGErKztULnBlcmRpZGFNb250bys9cy5uZXQ7fX1lbHNlIFQuc2luQ29zdG8rKzt9CiAgVC5vcmRlcnM9T2JqZWN0LmtleXMob3JkcykubGVuZ3RoO1QubWFyZ2luPVQuZmFjdENvbm9jaWRhPjA/KFQuZ2FuYW5jaWEvVC5mYWN0Q29ub2NpZGEpKjEwMDpudWxsO3JldHVybiBUOwp9CmFzeW5jIGZ1bmN0aW9uIGhpc3RMb2FkKCl7CiAgJCgnaF9tZXRhJykudGV4dENvbnRlbnQ9J0NhcmdhbmRvIGhpc3TDs3JpY2/igKYnOwogIHRyeXsKICAgIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2dlc3Rpb24vaGlzdG9yeT9kZXRhaWw9MScpO0hJU1Q9ZDtISVNUX0xPQURFRD10cnVlOwogICAgY29uc3QgYWNjcz17fSxzdHM9e307KGQuZGF5c3x8W10pLmZvckVhY2goZnVuY3Rpb24oZGF5KXsoZGF5LnNhbGVzfHxbXSkuZm9yRWFjaChmdW5jdGlvbihzKXtpZihzLmFjY291bnRfbmFtZSlhY2NzW3MuYWNjb3VudF9uYW1lXT0xO2lmKHMuc3RhdHVzKXN0c1tzLnN0YXR1c109MTt9KTt9KTsKICAgIGhpc3RGaWxsU2VsKCdoX2FjY291bnQnLE9iamVjdC5rZXlzKGFjY3MpLnNvcnQoKSxudWxsKTsKICAgIGhpc3RGaWxsU2VsKCdoX3N0YXR1cycsT2JqZWN0LmtleXMoc3RzKS5zb3J0KCksc3RhdHVzTGFiZWwpOwogICAgY29uc3QgZHRzPShkLnNhdmVkX2RhdGVzfHxbXSkuc2xpY2UoKTsKICAgIGlmKGR0cy5sZW5ndGgpe2lmKCEkKCdoX2Zyb20nKS52YWx1ZSkkKCdoX2Zyb20nKS52YWx1ZT1kdHNbMF07aWYoISQoJ2hfdG8nKS52YWx1ZSkkKCdoX3RvJykudmFsdWU9ZHRzW2R0cy5sZW5ndGgtMV07fQogICAgaGlzdEFwcGx5RmlsdGVycygpOwogIH1jYXRjaChlKXskKCdoX21ldGEnKS50ZXh0Q29udGVudD0nRXJyb3IgY2FyZ2FuZG8gaGlzdMOzcmljbzogJysodHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKTt9Cn0KZnVuY3Rpb24gaGlzdEZpbGxTZWwoaWQsYXJyLGxhYmVsRm4pe3ZhciBlbD0kKGlkKTtpZighZWwpcmV0dXJuO3ZhciBjdXI9ZWwudmFsdWU7dmFyIGY9ZWwucXVlcnlTZWxlY3Rvcignb3B0aW9uJyk7dmFyIGhlYWQ9Zj9mLnRleHRDb250ZW50OidUb2Rvcyc7ZWwuaW5uZXJIVE1MPSc8b3B0aW9uIHZhbHVlPSIiPicraGVhZCsnPC9vcHRpb24+JythcnIubWFwKGZ1bmN0aW9uKHYpe3JldHVybiAnPG9wdGlvbiB2YWx1ZT0iJytlc2MoU3RyaW5nKHYpKSsnIj4nK2VzYyhsYWJlbEZuP2xhYmVsRm4odik6U3RyaW5nKHYpKSsnPC9vcHRpb24+Jzt9KS5qb2luKCcnKTtlbC52YWx1ZT1jdXI7fQpmdW5jdGlvbiBoaXN0RmlsdGVyU2FsZShzKXsKICB2YXIgYWNjPSQoJ2hfYWNjb3VudCcpLnZhbHVlLHN0PSQoJ2hfc3RhdHVzJykudmFsdWUsZmxleD0kKCdoX2ZsZXgnKS52YWx1ZSxjb3N0bz0kKCdoX2Nvc3RvJykudmFsdWUscmVzPSQoJ2hfcmVzJykudmFsdWU7CiAgdmFyIG9yZD0oJCgnaF9vcmRlcicpLnZhbHVlfHwnJykudHJpbSgpLHR4dD0oJCgnaF90ZXh0JykudmFsdWV8fCcnKS50cmltKCkudG9Mb3dlckNhc2UoKTsKICBpZihhY2MmJihzLmFjY291bnRfbmFtZXx8JycpIT09YWNjKXJldHVybiBmYWxzZTsKICBpZihzdCYmKHMuc3RhdHVzfHwnJykhPT1zdClyZXR1cm4gZmFsc2U7CiAgaWYoZmxleD09PScxJyYmIXMuZmxleClyZXR1cm4gZmFsc2U7CiAgaWYoZmxleD09PScwJyYmcy5mbGV4KXJldHVybiBmYWxzZTsKICBpZihjb3N0bz09PScxJyYmIXMua25vd24pcmV0dXJuIGZhbHNlOwogIGlmKGNvc3RvPT09JzAnJiZzLmtub3duKXJldHVybiBmYWxzZTsKICBpZihyZXM9PT0nbG9zcycmJiEocy5uZXQhPW51bGwmJnMubmV0PDApKXJldHVybiBmYWxzZTsKICBpZihyZXM9PT0nd2luJyYmIShzLm5ldCE9bnVsbCYmcy5uZXQ+PTApKXJldHVybiBmYWxzZTsKICBpZihvcmQmJlN0cmluZyhzLnBhY2tfaWR8fCcnKS5pbmRleE9mKG9yZCk8MCYmU3RyaW5nKHMub3JkZXJfaWR8fCcnKS5pbmRleE9mKG9yZCk8MClyZXR1cm4gZmFsc2U7CiAgaWYodHh0KXt2YXIgaGF5PSgocy50aXRsZXx8JycpKycgJysocy5za3V8fCcnKSsnICcrKHMucHJvdmVlZG9yfHwnJykrJyAnKyhzLml0ZW1faWR8fCcnKSkudG9Mb3dlckNhc2UoKTtpZihoYXkuaW5kZXhPZih0eHQpPDApcmV0dXJuIGZhbHNlO30KICByZXR1cm4gdHJ1ZTsKfQpmdW5jdGlvbiBoaXN0QXBwbHlGaWx0ZXJzKCl7CiAgaWYoIUhJU1Qpe3JldHVybjt9CiAgdmFyIGZyb209JCgnaF9mcm9tJykudmFsdWUsdG89JCgnaF90bycpLnZhbHVlOwogIHZhciBkYXlzPShISVNULmRheXN8fFtdKS5maWx0ZXIoZnVuY3Rpb24oZCl7cmV0dXJuICghZnJvbXx8ZC5kYXRlPj1mcm9tKSYmKCF0b3x8ZC5kYXRlPD10byk7fSk7CiAgdmFyIHBlckRheT1kYXlzLm1hcChmdW5jdGlvbihkKXtyZXR1cm4ge2RhdGU6ZC5kYXRlLHNhdmVkQnk6ZC5zYXZlZEJ5LHNhdmVkQXQ6ZC5zYXZlZEF0LHRheFBjdDpkLnRheFBjdCxzY29wZTpkLnNjb3BlLHNhbGVzOihkLnNhbGVzfHxbXSkuZmlsdGVyKGhpc3RGaWx0ZXJTYWxlKX07fSk7CiAgdmFyIHNhbGVzPVtdO3BlckRheS5mb3JFYWNoKGZ1bmN0aW9uKGQpe3NhbGVzPXNhbGVzLmNvbmNhdChkLnNhbGVzKTt9KTsKICB2YXIgVD1hZ2dTYWxlcyhzYWxlcyk7CiAgSEZJTFQ9e3BlckRheTpwZXJEYXksc2FsZXM6c2FsZXMsZGF5czpkYXlzfTsKICBoaXN0UmVuZGVyS3BpcyhUKTtoaXN0UmVuZGVyTWV0YShkYXlzLHNhbGVzLFQpO2hpc3RSZW5kZXJDb21wYXJlKHBlckRheSxUKTtoaXN0UmVuZGVyQ2hhcnRzKHBlckRheSk7aGlzdFJlbmRlclJhbmtpbmdzKGhpc3RTYWxlczYwKCkpO2hpc3RSZW5kZXJEYWlseShwZXJEYXkpO2hpc3RSZW5kZXJEZXRhaWwoc2FsZXMpOwp9Ci8vIFZlbnRhcyBkZSBsb3Mgw5pMVElNT1MgNjAgRMONQVMgKGZpam8sIG5vIGRlcGVuZGUgZGVsIGZpbHRybyBkZSBmZWNoYXMpIOKAlCBwYXJhIGxvcyA0IHJhbmtpbmdzLgpmdW5jdGlvbiBoaXN0U2FsZXM2MCgpewogIGlmKCFISVNUKXJldHVybiBbXTsKICB2YXIgdG9kYXk9bmV3IERhdGUoRGF0ZS5ub3coKS0zKjM2MDAqMTAwMCkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTsKICB2YXIgY3V0PWRQbHVzKHRvZGF5LC02MCk7CiAgdmFyIG91dD1bXTsKICAoSElTVC5kYXlzfHxbXSkuZm9yRWFjaChmdW5jdGlvbihkKXsgaWYoZC5kYXRlPj1jdXQpIG91dD1vdXQuY29uY2F0KGQuc2FsZXN8fFtdKTsgfSk7CiAgcmV0dXJuIG91dDsKfQovLyBEZXRhbGxlIGNvbXBsZXRvIGRlIGxhcyB2ZW50YXMgZGUgbG9zIMO6bHRpbW9zIDYwIGTDrWFzIChhbCB0b2NhciB1biByYW5raW5nKS4KZnVuY3Rpb24gaGlzdFNob3dBbGw2MChjcml0KXsKICB2YXIgc2FsZXM9aGlzdFNhbGVzNjAoKS5zbGljZSgpOwogIHZhciB0dGxNYXA9e3NvbGQ6J/Cfj4YgTcOhcyB2ZW5kaWRvcycscHJvZml0Oifwn5KwIE3DoXMgcmVudGFibGVzJyxsb3NzOifimqDvuI8gQSBww6lyZGlkYSAvIG1hcmdlbiBmbGFjbycscHJvdjon8J+ThyBQb3IgcHJvdmVlZG9yJ307CiAgc2FsZXMuZm9yRWFjaChmdW5jdGlvbihzKXsgcy5fbT0ocy5rbm93biYmcy5yZXZlbnVlPjApPyhzLm5ldC9zLnJldmVudWUqMTAwKTpudWxsOyB9KTsKICBpZihjcml0PT09J3NvbGQnKSBzYWxlcy5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIChiLnF0eXx8MCktKGEucXR5fHwwKTt9KTsKICBlbHNlIGlmKGNyaXQ9PT0ncHJvZml0Jykgc2FsZXMuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiAoYi5fbT09bnVsbD8tMWU5OmIuX20pLShhLl9tPT1udWxsPy0xZTk6YS5fbSk7fSk7CiAgZWxzZSBpZihjcml0PT09J2xvc3MnKSBzYWxlcy5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIChhLl9tPT1udWxsPzFlOTphLl9tKS0oYi5fbT09bnVsbD8xZTk6Yi5fbSk7fSk7CiAgZWxzZSBpZihjcml0PT09J3Byb3YnKSBzYWxlcy5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIFN0cmluZyhhLnByb3ZlZWRvcnx8JycpLmxvY2FsZUNvbXBhcmUoU3RyaW5nKGIucHJvdmVlZG9yfHwnJykpO30pOwogICQoJ2hfbW9kYWw2MF90dGwnKS50ZXh0Q29udGVudD0odHRsTWFwW2NyaXRdfHwnRGV0YWxsZScpKycgwrcgdG9kYXMgbGFzIHZlbnRhcyBkZSBsb3Mgw7psdGltb3MgNjAgZMOtYXMgKCcrc2FsZXMubGVuZ3RoKycpJzsKICAkKCdoX21vZGFsNjBfYm9keScpLmlubmVySFRNTD1zYWxlcy5sZW5ndGg/c2FsZXMubWFwKGZ1bmN0aW9uKHMpe3ZhciBsb3NzPXMubmV0IT1udWxsJiZzLm5ldDwwOwogICAgcmV0dXJuICc8dHInKyhsb3NzPycgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVkYmcpIic6JycpKyc+PHRkPicrKHMuZGF0ZXx8JycpKyc8L3RkPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2Mocy50aXRsZXx8cy5pdGVtX2lkKSsnPC90ZD48dGQ+Jytlc2Mocy5hY2NvdW50X25hbWV8fCcnKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jysocy5xdHl8fDEpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHMucmV2ZW51ZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkocy5xdWVkYSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyhzLmNvc3Q9PW51bGw/J3MvYyc6KCfiiJInK2ZtdE1vbmV5KHMuY29zdCkpKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDtjb2xvcjonKyhzLm5ldD09bnVsbD8ndmFyKC0tbXV0KSc6KHMubmV0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykpKyciPicrKHMubmV0PT1udWxsPyfigJQnOmZtdE1vbmV5KHMubmV0KSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHMuX209PW51bGw/J+KAlCc6Zm10UGN0KHMuX20pKSsnPC90ZD48dGQ+Jytlc2Mocy5wcm92ZWVkb3J8fCcnKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jysocy5wYWNrX2lkfHxzLm9yZGVyX2lkfHwnJykrJzwvdGQ+PC90cj4nOwogIH0pLmpvaW4oJycpOic8dHI+PHRkIGNvbHNwYW49IjExIiBjbGFzcz0iZW1wdHkiPlNpbiB2ZW50YXMgZW4gbG9zIMO6bHRpbW9zIDYwIGTDrWFzLjwvdGQ+PC90cj4nOwogICQoJ2hfbW9kYWw2MCcpLnN0eWxlLmRpc3BsYXk9J2Jsb2NrJzsKfQpmdW5jdGlvbiBoaXN0UmVuZGVyTWV0YShkYXlzLHNhbGVzLFQpewogIHZhciBzYXZlZFRvdGFsPShISVNUJiZISVNULnNhdmVkX2RhdGVzfHxbXSkubGVuZ3RoOwogICQoJ2hfbWV0YScpLmlubmVySFRNTD0n8J+ThiA8Yj4nK2RheXMubGVuZ3RoKyc8L2I+IGTDrWEocykgZW4gZWwgcmFuZ28gKGRlICcrc2F2ZWRUb3RhbCsnIGd1YXJkYWRvcyBlbiB0b3RhbCkgwrcgPGI+JysoVC5vcmRlcnN8fDApKyc8L2I+IHZlbnRhcyDCtyA8Yj4nK1QudW5pZGFkZXMrJzwvYj4gdW5pZGFkZXMuICcrCiAgICAnTm8gZW50cmFuIGNhbmNlbGFkYXMgbmkgcmVjbGFtb3MgY29uIGRldm9sdWNpw7NuICh1c8OhIDxiPvCflIQgUmV2YWxpZGFyPC9iPiBwYXJhIHB1cmdhciB2ZW50YXMgcXVlIHNlIGNheWVyb24gZGVzcHXDqXMgZGUgZ3VhcmRhcikuJzsKfQpmdW5jdGlvbiBoaXN0UmVuZGVyS3BpcyhUKXsKICB2YXIgdGlja2V0PShULm9yZGVycz4wKT8oVC5mYWN0dXJhY2lvbi9ULm9yZGVycyk6MDsKICB2YXIgbUNscz1ULm1hcmdpbj09bnVsbD8nJzooVC5tYXJnaW4+PTEwPydnb29kJzooVC5tYXJnaW4+PTU/J3dhcm4nOidiYWQnKSk7CiAgdmFyIHRpbGVzPVsKICAgIFsnVmVudGFzJywoVC5vcmRlcnN8fDApLCcnXSwKICAgIFsnVW5pZGFkZXMnLChULnVuaWRhZGVzfHwwKSwnJ10sCiAgICBbJ0ZhY3R1cmFjacOzbicsZm10TW9uZXkoVC5mYWN0dXJhY2lvbiksJyddLAogICAgWydUaWNrZXQgcHJvbWVkaW8nLGZtdE1vbmV5KHRpY2tldCksJyddLAogICAgWydRdWVkw7MgZW4gY3VlbnRhJyxmbXRNb25leShULnF1ZWRhVG90YWwpLCcnXSwKICAgIFsnR2FuYW5jaWEgcmVhbCcsZm10TW9uZXkoVC5nYW5hbmNpYSksVC5nYW5hbmNpYT49MD8nZ29vZCc6J2JhZCddLAogICAgWydNYXJnZW4gcmVhbCcsVC5tYXJnaW49PW51bGw/J+KAlCc6Zm10UGN0KFQubWFyZ2luKSxtQ2xzXSwKICAgIFsnVmVudGFzIEZsZXgnLChULmZsZXhDb3VudHx8MCksJyddLAogICAgWydDb3N0byBwcm9kdWN0b3MnLGZtdE1vbmV5KFQuY29zdFRvdGFsfHwwKSwnJ10sCiAgICBbJ0ltcHVlc3RvIE1MJyxmbXRNb25leShULnRheFRvdGFsKSwnJ10sCiAgICBbJ0JvbmlmaWNhY2nDs24gRmxleCcsZm10TW9uZXkoVC5ib25vVG90YWx8fDApLCdnb29kJ10sCiAgICBbJ0EgcMOpcmRpZGEnLChULnBlcmRpZGF8fDApKyhULnBlcmRpZGE/KCcgwrcgJytmbXRNb25leShULnBlcmRpZGFNb250bykpOicnKSxULnBlcmRpZGE/J2JhZCc6J2dvb2QnXQogIF07CiAgJCgnaF9rcGlzJykuaW5uZXJIVE1MPXRpbGVzLm1hcChmdW5jdGlvbih0KXtyZXR1cm4gJzxkaXYgY2xhc3M9ImtwaSAnK3RbMl0rJyI+PGRpdiBjbGFzcz0iayI+Jyt0WzBdKyc8L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3RbMV0rJzwvZGl2PjwvZGl2Pic7fSkuam9pbignJyk7Cn0KZnVuY3Rpb24gaGlzdFJlbmRlckNvbXBhcmUocGVyRGF5LFQpewogIHZhciBlbD0kKCdoX2NvbXBhcmUnKTsKICBpZighcGVyRGF5Lmxlbmd0aCl7ZWwuc3R5bGUuZGlzcGxheT0nbm9uZSc7cmV0dXJuO31lbC5zdHlsZS5kaXNwbGF5PSdibG9jayc7CiAgdmFyIGRkPXBlckRheS5tYXAoZnVuY3Rpb24oZCl7dmFyIHQ9YWdnU2FsZXMoZC5zYWxlcyk7cmV0dXJuIHtkYXRlOmQuZGF0ZSxnOnQuZ2FuYW5jaWEsZjp0LmZhY3R1cmFjaW9ufTt9KS5maWx0ZXIoZnVuY3Rpb24oeCl7cmV0dXJuIHRydWU7fSk7CiAgdmFyIHNvcnRlZD1kZC5zbGljZSgpLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gYi5nLWEuZzt9KTsKICB2YXIgYmVzdD1zb3J0ZWRbMF0sd29yc3Q9c29ydGVkW3NvcnRlZC5sZW5ndGgtMV07CiAgdmFyIGJ5TW9udGg9e307KEhJU1QuZGF5c3x8W10pLmZvckVhY2goZnVuY3Rpb24oZCl7dmFyIG09ZC5kYXRlLnNsaWNlKDAsNyk7YnlNb250aFttXT0oYnlNb250aFttXXx8MCkrKChkLnRvdGFscyYmZC50b3RhbHMuZ2FuYW5jaWEpfHwwKTt9KTsKICB2YXIgbW9udGhzPU9iamVjdC5rZXlzKGJ5TW9udGgpLnNvcnQoKTt2YXIgbW9udGhUeHQ9J+KAlCc7CiAgaWYobW9udGhzLmxlbmd0aD49Mil7dmFyIGN1cj1tb250aHNbbW9udGhzLmxlbmd0aC0xXSxwcmV2PW1vbnRoc1ttb250aHMubGVuZ3RoLTJdLGM9YnlNb250aFtjdXJdLHA9YnlNb250aFtwcmV2XTt2YXIgdj0ocCE9PTApPygoYy1wKS9NYXRoLmFicyhwKSoxMDApOm51bGw7bW9udGhUeHQ9JzxiPicrY3VyKyc8L2I+OiAnK2ZtdE1vbmV5KGMpKycgdnMgPGI+JytwcmV2Kyc8L2I+OiAnK2ZtdE1vbmV5KHApKyh2IT1udWxsPygnIMK3IDxiIHN0eWxlPSJjb2xvcjonKyh2Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykrJyI+Jysodj49MD8nKyc6JycpK3YudG9GaXhlZCgwKSsnJTwvYj4nKTonJyk7fQogIGVsc2UgaWYobW9udGhzLmxlbmd0aD09PTEpe21vbnRoVHh0PSc8Yj4nK21vbnRoc1swXSsnPC9iPjogJytmbXRNb25leShieU1vbnRoW21vbnRoc1swXV0pKycgPHNwYW4gY2xhc3M9Im11dGVkIj4oYcO6biBzaW4gbWVzIGFudGVyaW9yIHBhcmEgY29tcGFyYXIpPC9zcGFuPic7fQogIHZhciBmcm9tPSQoJ2hfZnJvbScpLnZhbHVlLHRvPSQoJ2hfdG8nKS52YWx1ZTt2YXIgc2F2ZWRTZXQ9e307KEhJU1Quc2F2ZWRfZGF0ZXN8fFtdKS5mb3JFYWNoKGZ1bmN0aW9uKHgpe3NhdmVkU2V0W3hdPTE7fSk7dmFyIG1pc3Npbmc9W107CiAgaWYoZnJvbSYmdG8mJmZyb208PXRvKXt2YXIgY3VyMj1mcm9tO3ZhciBndWFyZD0wO3doaWxlKGN1cjI8PXRvJiZndWFyZDw0MDApe2lmKCFzYXZlZFNldFtjdXIyXSltaXNzaW5nLnB1c2goY3VyMik7Y3VyMj1kUGx1cyhjdXIyLDEpO2d1YXJkKys7fX0KICBlbC5pbm5lckhUTUw9JzxkaXYgY2xhc3M9InR0bCI+8J+TiiBDb21wYXJhdGl2YXMgeSBjYWxpZGFkIGRlIGRhdG9zPC9kaXY+PGRpdiBzdHlsZT0iZm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS45NSI+JysKICAgICfwn5OFIE1lcyBhY3R1YWwgdnMgYW50ZXJpb3IgKGdhbmFuY2lhKTogJyttb250aFR4dCsnPGJyPicrCiAgICAn8J+lhyBNZWpvciBkw61hOiA8Yj4nKyhiZXN0P2Jlc3QuZGF0ZSsnICgnK2ZtdE1vbmV5KGJlc3QuZykrJyknOifigJQnKSsnPC9iPiAmbmJzcDvCtyZuYnNwOyDwn6W2IFBlb3IgZMOtYTogPGI+Jysod29yc3Q/d29yc3QuZGF0ZSsnICgnK2ZtdE1vbmV5KHdvcnN0LmcpKycpJzon4oCUJykrJzwvYj48YnI+JysKICAgICfwn6epIFZlbnRhcyBzaW4gY29zdG8gY29ub2NpZG86IDxiPicrKFQuc2luQ29zdG98fDApKyc8L2I+JysoVC5zaW5Db3N0bz8nIDxzcGFuIGNsYXNzPSJtdXRlZCI+KGNvbXBsZXTDoSBlbCBfQ09NUExFVE8gcGFyYSBjYWxjdWxhcmxlcyBtYXJnZW4pPC9zcGFuPic6JycpKyc8YnI+JysKICAgICfwn5Wz77iPIETDrWFzIHNpbiBndWFyZGFyIGVuIGVsIHJhbmdvOiA8Yj4nK21pc3NpbmcubGVuZ3RoKyc8L2I+JysobWlzc2luZy5sZW5ndGg/KCcgPHNwYW4gY2xhc3M9Im11dGVkIj7CtyAnK21pc3Npbmcuc2xpY2UoMCwxMikuam9pbignLCAnKSsobWlzc2luZy5sZW5ndGg+MTI/J+KApic6JycpKyc8L3NwYW4+Jyk6JyA8c3BhbiBjbGFzcz0ibXV0ZWQiPihuaW5ndW5vIPCfkYwpPC9zcGFuPicpKyc8L2Rpdj4nOwp9CmZ1bmN0aW9uIGhNa0NoYXJ0KGlkLGNmZyl7aWYoSENIQVJUU1tpZF0pe0hDSEFSVFNbaWRdLmRlc3Ryb3koKTt9dmFyIGN2PSQoaWQpO2lmKCFjdilyZXR1cm47SENIQVJUU1tpZF09bmV3IENoYXJ0KGN2LmdldENvbnRleHQoJzJkJyksY2ZnKTt9CmZ1bmN0aW9uIGhpc3RSZW5kZXJDaGFydHMocGVyRGF5KXsKICB2YXIgbGFiZWxzPXBlckRheS5tYXAoZnVuY3Rpb24oZCl7cmV0dXJuIGQuZGF0ZTt9KTsKICB2YXIgZmFjdD1wZXJEYXkubWFwKGZ1bmN0aW9uKGQpe3JldHVybiBNYXRoLnJvdW5kKGFnZ1NhbGVzKGQuc2FsZXMpLmZhY3R1cmFjaW9uKTt9KTsKICB2YXIgZ2FuPXBlckRheS5tYXAoZnVuY3Rpb24oZCl7cmV0dXJuIE1hdGgucm91bmQoYWdnU2FsZXMoZC5zYWxlcykuZ2FuYW5jaWEpO30pOwogIHZhciBtYXJnPXBlckRheS5tYXAoZnVuY3Rpb24oZCl7dmFyIHQ9YWdnU2FsZXMoZC5zYWxlcyk7cmV0dXJuIHQubWFyZ2luPT1udWxsP251bGw6K3QubWFyZ2luLnRvRml4ZWQoMSk7fSk7CiAgaE1rQ2hhcnQoJ2hfY19kYWlseScse3R5cGU6J2JhcicsZGF0YTp7bGFiZWxzOmxhYmVscyxkYXRhc2V0czpbe2xhYmVsOidGYWN0dXJhY2nDs24nLGRhdGE6ZmFjdCxiYWNrZ3JvdW5kQ29sb3I6J3JnYmEoNDYsODQsMTUwLC4zNSknLGJvcmRlckNvbG9yOicjMmU1NDk2JyxvcmRlcjoyfSx7bGFiZWw6J0dhbmFuY2lhJyxkYXRhOmdhbix0eXBlOidsaW5lJyxib3JkZXJDb2xvcjonIzE2YTM0YScsYmFja2dyb3VuZENvbG9yOicjMTZhMzRhJyx0ZW5zaW9uOi4yNSxvcmRlcjoxLHlBeGlzSUQ6J3knfV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLHBsdWdpbnM6e2xlZ2VuZDp7ZGlzcGxheTp0cnVlfX0sc2NhbGVzOnt4Ont0aWNrczp7bWF4Um90YXRpb246NjAsbWluUm90YXRpb246MH19fX19KTsKICBoTWtDaGFydCgnaF9jX21hcmdpbicse3R5cGU6J2xpbmUnLGRhdGE6e2xhYmVsczpsYWJlbHMsZGF0YXNldHM6W3tsYWJlbDonTWFyZ2VuICUnLGRhdGE6bWFyZyxib3JkZXJDb2xvcjonI2Q5NzcwNicsYmFja2dyb3VuZENvbG9yOicjZDk3NzA2Jyx0ZW5zaW9uOi4yNSxzcGFuR2Fwczp0cnVlfV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLHBsdWdpbnM6e2xlZ2VuZDp7ZGlzcGxheTpmYWxzZX19fX0pOwogIHZhciBkb3c9WzAsMCwwLDAsMCwwLDBdLGRvd0xibD1bJ0RPTScsJ0xVTicsJ01BUicsJ01Jw4knLCdKVUUnLCdWSUUnLCdTw4FCJ107CiAgcGVyRGF5LmZvckVhY2goZnVuY3Rpb24oZCl7dmFyIHA9ZC5kYXRlLnNwbGl0KCctJykubWFwKE51bWJlcik7dmFyIGc9bmV3IERhdGUoRGF0ZS5VVEMocFswXSxwWzFdLTEscFsyXSkpLmdldFVUQ0RheSgpO2Rvd1tnXSs9YWdnU2FsZXMoZC5zYWxlcykub3JkZXJzO30pOwogIGhNa0NoYXJ0KCdoX2NfZG93Jyx7dHlwZTonYmFyJyxkYXRhOntsYWJlbHM6ZG93TGJsLGRhdGFzZXRzOlt7bGFiZWw6J1ZlbnRhcycsZGF0YTpkb3csYmFja2dyb3VuZENvbG9yOicjMmU1NDk2J31dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxwbHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6ZmFsc2V9fX19KTsKICB2YXIgYWNjPTAsY3VtPWdhbi5tYXAoZnVuY3Rpb24oZyl7YWNjKz1nO3JldHVybiBhY2M7fSk7CiAgaE1rQ2hhcnQoJ2hfY19jdW0nLHt0eXBlOidsaW5lJyxkYXRhOntsYWJlbHM6bGFiZWxzLGRhdGFzZXRzOlt7bGFiZWw6J0dhbmFuY2lhIGFjdW11bGFkYScsZGF0YTpjdW0sYm9yZGVyQ29sb3I6JyMxNmEzNGEnLGJhY2tncm91bmRDb2xvcjoncmdiYSgyMiwxNjMsNzQsLjE1KScsZmlsbDp0cnVlLHRlbnNpb246LjI1fV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLHBsdWdpbnM6e2xlZ2VuZDp7ZGlzcGxheTpmYWxzZX19fX0pOwp9CmZ1bmN0aW9uIGhpc3RHcm91cEJ5KHNhbGVzLGtleUZuKXt2YXIgbT17fTtzYWxlcy5mb3JFYWNoKGZ1bmN0aW9uKHMpe3ZhciBrPWtleUZuKHMpO2lmKCFtW2tdKW1ba109e2tleTprLHRpdGxlOnMudGl0bGV8fGsscXR5OjAscmV2OjAsbmV0OjAsa25vd246MH07bVtrXS5xdHkrPXMucXR5fHwwO21ba10ucmV2Kz1zLnJldmVudWV8fDA7aWYocy5rbm93bil7bVtrXS5uZXQrPXMubmV0fHwwO21ba10ua25vd24rPXMucmV2ZW51ZXx8MDt9fSk7cmV0dXJuIE9iamVjdC5rZXlzKG0pLm1hcChmdW5jdGlvbihrKXtyZXR1cm4gbVtrXTt9KTt9CmZ1bmN0aW9uIGhpc3RSZW5kZXJSYW5raW5ncyhzYWxlcyl7CiAgdmFyIGc9aGlzdEdyb3VwQnkoc2FsZXMsZnVuY3Rpb24ocyl7cmV0dXJuIHMuaXRlbV9pZHx8cy50aXRsZTt9KTsKICB2YXIgc29sZD1nLnNsaWNlKCkuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiBiLnF0eS1hLnF0eTt9KS5zbGljZSgwLDEyKTsKICAkKCdoX3RvcF9zb2xkJykuaW5uZXJIVE1MPXNvbGQubGVuZ3RoP3NvbGQubWFwKGZ1bmN0aW9uKHgpe3JldHVybiAnPHRyPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2MoeC50aXRsZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicreC5xdHkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoeC5yZXYpKyc8L3RkPjwvdHI+Jzt9KS5qb2luKCcnKTonPHRyPjx0ZCBjb2xzcGFuPSIzIiBjbGFzcz0iZW1wdHkiPuKAlDwvdGQ+PC90cj4nOwogIC8vIE3DgVMgUkVOVEFCTEVTOiBwb3IgTUFSR0VOIChyZW50YWJpbGlkYWQpIGRlIG1heW9yIGEgbWVub3IuCiAgdmFyIHByb2Y9Zy5maWx0ZXIoZnVuY3Rpb24oeCl7cmV0dXJuIHgua25vd24+MDt9KS5tYXAoZnVuY3Rpb24oeCl7eC5tPXgubmV0L3gua25vd24qMTAwO3JldHVybiB4O30pLnNvcnQoZnVuY3Rpb24oYSxiKXtyZXR1cm4gYi5tLWEubTt9KS5zbGljZSgwLDEyKTsKICAkKCdoX3RvcF9wcm9maXQnKS5pbm5lckhUTUw9cHJvZi5sZW5ndGg/cHJvZi5tYXAoZnVuY3Rpb24oeCl7cmV0dXJuICc8dHI+PHRkIGNsYXNzPSJuYW1lIj4nK2VzYyh4LnRpdGxlKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKHgubmV0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykrJyI+JytmbXRNb25leSh4Lm5ldCkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10UGN0KHgubSkrJzwvdGQ+PC90cj4nO30pLmpvaW4oJycpOic8dHI+PHRkIGNvbHNwYW49IjMiIGNsYXNzPSJlbXB0eSI+4oCUPC90ZD48L3RyPic7CiAgLy8gQSBQw4lSRElEQSAvIE1BUkdFTiBGTEFDTzogU09MTyBsb3MgcXVlIHRpZW5lbiBtZW5vcyBkZSAxMCUgZGUgbWFyZ2VuLCBkZWwgcGVvciBhbCBtZWpvci4KICB2YXIgbG9zcz1nLmZpbHRlcihmdW5jdGlvbih4KXtyZXR1cm4geC5rbm93bj4wO30pLm1hcChmdW5jdGlvbih4KXt4Lm09eC5uZXQveC5rbm93bioxMDA7cmV0dXJuIHg7fSkuZmlsdGVyKGZ1bmN0aW9uKHgpe3JldHVybiB4Lm08MTA7fSkuc29ydChmdW5jdGlvbihhLGIpe3JldHVybiBhLm0tYi5tO30pLnNsaWNlKDAsMTIpOwogICQoJ2hfdG9wX2xvc3MnKS5pbm5lckhUTUw9bG9zcy5sZW5ndGg/bG9zcy5tYXAoZnVuY3Rpb24oeCl7cmV0dXJuICc8dHInKyh4Lm5ldDwwPycgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVkYmcpIic6JycpKyc+PHRkIGNsYXNzPSJuYW1lIj4nK2VzYyh4LnRpdGxlKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKHgubmV0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykrJyI+JytmbXRNb25leSh4Lm5ldCkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKyh4Lm08MD8ndmFyKC0tcmVkKSc6KHgubTw1Pyd2YXIoLS1hbWJlciknOicnKSkrJyI+JytmbXRQY3QoeC5tKSsnPC90ZD48L3RyPic7fSkuam9pbignJyk6Jzx0cj48dGQgY29sc3Bhbj0iMyIgY2xhc3M9ImVtcHR5Ij5OaW5ndW5vIGNvbiBtYXJnZW4gJmx0OzEwJTwvdGQ+PC90cj4nOwogIHZhciBwcm92PWhpc3RHcm91cEJ5KHNhbGVzLGZ1bmN0aW9uKHMpe3JldHVybiAocy5wcm92ZWVkb3J8fCcoc2luIHByb3ZlZWRvciknKTt9KS5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIGIubmV0LWEubmV0O30pLnNsaWNlKDAsMTUpOwogICQoJ2hfYnlfcHJvdicpLmlubmVySFRNTD1wcm92Lmxlbmd0aD9wcm92Lm1hcChmdW5jdGlvbih4KXtyZXR1cm4gJzx0cj48dGQ+Jytlc2MoeC5rZXkpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK3gucXR5Kyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6JysoeC5uZXQ+PTA/J3ZhcigtLWdyZWVuKSc6J3ZhcigtLXJlZCknKSsnIj4nK2ZtdE1vbmV5KHgubmV0KSsnPC90ZD48L3RyPic7fSkuam9pbignJyk6Jzx0cj48dGQgY29sc3Bhbj0iMyIgY2xhc3M9ImVtcHR5Ij7igJQ8L3RkPjwvdHI+JzsKfQpmdW5jdGlvbiBoaXN0UmVuZGVyRGFpbHkocGVyRGF5KXsKICBpZighcGVyRGF5Lmxlbmd0aCl7JCgnaF9kYWlseV9yb3dzJykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjEzIiBjbGFzcz0iZW1wdHkiPk5vIGhheSBkw61hcyBndWFyZGFkb3MgZW4gZWwgcmFuZ28uIEd1YXJkw6EgZMOtYXMgZGVzZGUgbGEgc29sYXBhIEdlc3Rpw7NuLjwvdGQ+PC90cj4nO3JldHVybjt9CiAgJCgnaF9kYWlseV9yb3dzJykuaW5uZXJIVE1MPXBlckRheS5tYXAoZnVuY3Rpb24oZCl7dmFyIHQ9YWdnU2FsZXMoZC5zYWxlcyk7CiAgICByZXR1cm4gJzx0cj48dGQ+JytkLmRhdGUrJzwvdGQ+PHRkPicrZG93TGFiZWwoZC5kYXRlKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh0LmZhY3R1cmFjaW9uKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh0LnF1ZWRhVG90YWwpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHQuY29zdFRvdGFsKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh0LmNvc3RUb3RhbCt0LmVudmlvVG90YWwpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHQuZmFjdHVyYVRvdGFsKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDtjb2xvcjonKyh0LmdhbmFuY2lhPj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykrJyI+JytmbXRNb25leSh0LmdhbmFuY2lhKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JysodC5tYXJnaW49PW51bGw/J+KAlCc6Zm10UGN0KHQubWFyZ2luKSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkodC5nYW5hbmNpYVNpbkZsZXgpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHQuY29zdFN0b2NrVG90YWwpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK3QuY3VvdGFzQ291bnQrJzwvdGQ+PHRkPjxidXR0b24gY2xhc3M9Im1pbmkiIHRpdGxlPSJCb3JyYXIgZXN0ZSBkw61hIiBvbmNsaWNrPSJoaXN0RGVsZXRlRGF5KFwnJytkLmRhdGUrJ1wnKSI+8J+Xke+4jzwvYnV0dG9uPjwvdGQ+PC90cj4nOwogIH0pLmpvaW4oJycpOwp9CmZ1bmN0aW9uIGhpc3RSZW5kZXJEZXRhaWwoc2FsZXMpewogIHZhciByb3dzPXNhbGVzLnNsaWNlKDAsNjAwKTsKICBpZighcm93cy5sZW5ndGgpeyQoJ2hfZGV0YWlsX3Jvd3MnKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTciIGNsYXNzPSJlbXB0eSI+U2luIHZlbnRhcyBjb24gZXN0b3MgZmlsdHJvcy48L3RkPjwvdHI+JztyZXR1cm47fQogICQoJ2hfZGV0YWlsX3Jvd3MnKS5pbm5lckhUTUw9cm93cy5tYXAoZnVuY3Rpb24ocyl7dmFyIGxvc3M9cy5uZXQhPW51bGwmJnMubmV0PDA7CiAgICByZXR1cm4gJzx0cicrKGxvc3M/JyBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1yZWRiZykiJzonJykrJz48dGQ+Jysocy5kYXRlfHwnJykrJzwvdGQ+PHRkIGNsYXNzPSJuYW1lIj4nKyhzLnBhY2s/JzxzcGFuIHRpdGxlPSJWZW50YSBlbiBjYXJyaXRvIiBzdHlsZT0iZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1ibHVlYmcpO2NvbG9yOnZhcigtLWJsdWUpO2ZvbnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OjcwMDtwYWRkaW5nOjFweCA1cHg7Ym9yZGVyLXJhZGl1czo4cHg7bWFyZ2luLXJpZ2h0OjVweCI+8J+bkjwvc3Bhbj4nOicnKStlc2Mocy50aXRsZXx8cy5pdGVtX2lkKSsnPC90ZD48dGQ+Jytlc2Mocy5hY2NvdW50X25hbWV8fCcnKSsnPC90ZD48dGQ+Jytlc2Moc3RhdHVzTGFiZWwocy5zdGF0dXMpKSsnPC90ZD48dGQ+Jysocy5zdG9jaz8nU8OtJzon4oCUJykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkocy5yZXZlbnVlKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPuKIkicrZm10TW9uZXkocy5mZWUpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysocy5lbnZpbz8oJ+KIkicrZm10TW9uZXkocy5lbnZpbykpOifigJQnKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrKHMudGF4Pygn4oiSJytmbXRNb25leShzLnRheCkpOickMCcpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIGIiPicrZm10TW9uZXkocy5xdWVkYSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyhzLmNvc3Q9PW51bGw/J3MvY29zdG8nOign4oiSJytmbXRNb25leShzLmNvc3QpKSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyhzLmZhY3R1cmE/KCfiiJInK2ZtdE1vbmV5KHMuZmFjdHVyYSkpOifigJQnKSsnPC90ZD48dGQgY2xhc3M9Im51bSIgc3R5bGU9ImZvbnQtd2VpZ2h0OjcwMDtjb2xvcjonKyhzLm5ldD09bnVsbD8ndmFyKC0tbXV0KSc6KHMubmV0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykpKyciPicrKHMubmV0PT1udWxsPyfigJQnOmZtdE1vbmV5KHMubmV0KSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHMubWFyZ2luUGN0PT1udWxsPyfigJQnOmZtdFBjdChzLm1hcmdpblBjdCkpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhzLmN1b3Rhc3x8MCkrJzwvdGQ+PHRkPicrZXNjKHMuc2t1fHwnJykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrKHMucGFja19pZHx8cy5vcmRlcl9pZHx8JycpKyc8L3RkPjwvdHI+JzsKICB9KS5qb2luKCcnKSsoc2FsZXMubGVuZ3RoPjYwMD8oJzx0cj48dGQgY29sc3Bhbj0iMTciIGNsYXNzPSJtdXRlZCIgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyIj7igKYgJysoc2FsZXMubGVuZ3RoLTYwMCkrJyB2ZW50YXMgbcOhcyAoYWZpbsOhIGxvcyBmaWx0cm9zIG8gZGVzY2FyZ8OhIGVsIFhMU1ggcGFyYSB2ZXJsYXMgdG9kYXMpPC90ZD48L3RyPicpOicnKTsKfQphc3luYyBmdW5jdGlvbiBoaXN0RGVsZXRlRGF5KGRhdGUpewogIGlmKCFjb25maXJtKCfCv0JvcnJhciBlbCBkw61hICcrZGF0ZSsnIGRlbCBoaXN0w7NyaWNvPyAobm8gYm9ycmEgbGFzIHZlbnRhcyBlbiBNTCwgc29sbyBlbCBzbmFwc2hvdCBndWFyZGFkbyknKSlyZXR1cm47CiAgdHJ5e2F3YWl0IGFwaSgnL2FwaS9nZXN0aW9uL2RlbGV0ZS1kYXknLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2RhdGU6ZGF0ZX0pfSk7dG9hc3QoJ0TDrWEgJytkYXRlKycgYm9ycmFkbycpO0hJU1RfTE9BREVEPWZhbHNlO2F3YWl0IGhpc3RMb2FkKCk7fQogIGNhdGNoKGUpe3RvYXN0KCdFcnJvcjogJysodHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKSk7fQp9CmFzeW5jIGZ1bmN0aW9uIGhpc3RSZXZhbGlkYXRlKCl7CiAgaWYoIWNvbmZpcm0oJ8K/UmV2YWxpZGFyIGxvcyBkw61hcyBndWFyZGFkb3MgZGVsIHJhbmdvIGNvbnRyYSBNTD8gU2FjYSB2ZW50YXMgY2FuY2VsYWRhcyBvIGNvbiBkZXZvbHVjacOzbiBhbCBjb21wcmFkb3IuIFB1ZWRlIHRhcmRhciB1bm9zIG1pbnV0b3MuJykpcmV0dXJuOwogIHZhciBmcm9tPSQoJ2hfZnJvbScpLnZhbHVlLHRvPSQoJ2hfdG8nKS52YWx1ZTskKCdoX21ldGEnKS50ZXh0Q29udGVudD0nUmV2YWxpZGFuZG8gZMOtYXMgY29udHJhIE1M4oCmIChwdWVkZSB0YXJkYXIpJzsKICB0cnl7dmFyIHI9YXdhaXQgYXBpKCcvYXBpL2dlc3Rpb24vcmV2YWxpZGF0ZScse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7ZnJvbTpmcm9tLHRvOnRvfSl9KTt0b2FzdCgn4pyFIFJldmFsaWRhZG9zICcrci5kYXlzKycgZMOtYShzKSDCtyAnK3IucmVtb3ZlZCsnIHZlbnRhKHMpIHJlbW92aWRhKHMpJyk7SElTVF9MT0FERUQ9ZmFsc2U7YXdhaXQgaGlzdExvYWQoKTt9CiAgY2F0Y2goZSl7dG9hc3QoJ0Vycm9yIGFsIHJldmFsaWRhcjogJysodHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKSk7JCgnaF9tZXRhJykudGV4dENvbnRlbnQ9J0Vycm9yIGFsIHJldmFsaWRhci4nO30KfQpmdW5jdGlvbiBoaXN0RG93bmxvYWRYbHN4KCl7CiAgaWYoIUhGSUxUfHwhSEZJTFQucGVyRGF5Lmxlbmd0aCl7dG9hc3QoJ05vIGhheSBkw61hcyBwYXJhIGV4cG9ydGFyJyk7cmV0dXJuO30KICB2YXIgd2I9WExTWC51dGlscy5ib29rX25ldygpOwogIHZhciByZXN1bWVuPUhGSUxULnBlckRheS5tYXAoZnVuY3Rpb24oZCl7dmFyIHQ9YWdnU2FsZXMoZC5zYWxlcyk7cmV0dXJuIHtGRUNIQTpkLmRhdGUsRElBOmRvd0xhYmVsKGQuZGF0ZSksJ1ZFTlRBUyBCUlVUQVMnOk1hdGgucm91bmQodC5mYWN0dXJhY2lvbiksJ1FVRURPIEVOIENVRU5UQSc6TWF0aC5yb3VuZCh0LnF1ZWRhVG90YWwpLCdDT1NUTyBGQUNUVVJBJzpNYXRoLnJvdW5kKHQuY29zdFRvdGFsKSwnQ09TVE8gQ09OIEZMRVgnOk1hdGgucm91bmQodC5jb3N0VG90YWwrdC5lbnZpb1RvdGFsKSwnRkFDVFVSQSc6TWF0aC5yb3VuZCh0LmZhY3R1cmFUb3RhbCksJ0dBTkFOQ0lBIENPTiBGTEVYJzpNYXRoLnJvdW5kKHQuZ2FuYW5jaWEpLCdQT1JDRU5UQUpFJzp0Lm1hcmdpbj09bnVsbD8nJzordC5tYXJnaW4udG9GaXhlZCgyKSwnR0FOQU5DSUEgU0lOIEZMRVgnOk1hdGgucm91bmQodC5nYW5hbmNpYVNpbkZsZXgpLCdRVUVETyBWRU5UQSBTVE9DSyc6TWF0aC5yb3VuZCh0LmNvc3RTdG9ja1RvdGFsKSwnQ1VPVEFTJzp0LmN1b3Rhc0NvdW50fTt9KTsKICB2YXIgVFQ9YWdnU2FsZXMoSEZJTFQuc2FsZXMpOwogIHJlc3VtZW4ucHVzaCh7RkVDSEE6J1JFU1VNRU4nLERJQTonJywnVkVOVEFTIEJSVVRBUyc6TWF0aC5yb3VuZChUVC5mYWN0dXJhY2lvbiksJ1FVRURPIEVOIENVRU5UQSc6TWF0aC5yb3VuZChUVC5xdWVkYVRvdGFsKSwnQ09TVE8gRkFDVFVSQSc6TWF0aC5yb3VuZChUVC5jb3N0VG90YWwpLCdDT1NUTyBDT04gRkxFWCc6TWF0aC5yb3VuZChUVC5jb3N0VG90YWwrVFQuZW52aW9Ub3RhbCksJ0ZBQ1RVUkEnOk1hdGgucm91bmQoVFQuZmFjdHVyYVRvdGFsKSwnR0FOQU5DSUEgQ09OIEZMRVgnOk1hdGgucm91bmQoVFQuZ2FuYW5jaWEpLCdQT1JDRU5UQUpFJzpUVC5tYXJnaW49PW51bGw/Jyc6K1RULm1hcmdpbi50b0ZpeGVkKDIpLCdHQU5BTkNJQSBTSU4gRkxFWCc6TWF0aC5yb3VuZChUVC5nYW5hbmNpYVNpbkZsZXgpLCdRVUVETyBWRU5UQSBTVE9DSyc6TWF0aC5yb3VuZChUVC5jb3N0U3RvY2tUb3RhbCksJ0NVT1RBUyc6VFQuY3VvdGFzQ291bnR9KTsKICBYTFNYLnV0aWxzLmJvb2tfYXBwZW5kX3NoZWV0KHdiLFhMU1gudXRpbHMuanNvbl90b19zaGVldChyZXN1bWVuKSwnUkVTVU1FTiBESUFSSU8nKTsKICB2YXIgdXNlZD17fTsKICBIRklMVC5wZXJEYXkuZm9yRWFjaChmdW5jdGlvbihkKXsKICAgIHZhciByb3dzPWQuc2FsZXMubWFwKGZ1bmN0aW9uKHMpe3JldHVybiB7J05VTUVSTyBERSBWRU5UQSc6U3RyaW5nKHMucGFja19pZHx8cy5vcmRlcl9pZHx8JycpLCdFU1RBRE8nOnN0YXR1c0xhYmVsKHMuc3RhdHVzKSwnU0tVJzpzLnNrdXx8JycsJ0RFU0NSSVBDSU9OJzpzLnRpdGxlfHwnJywnUFJPVkVFRE9SJzpzLnByb3ZlZWRvcnx8JycsJ0NBTlRJREFEJzpzLnF0eXx8MSwnRkxFWCc6cy5mbGV4PydGbGV4JzonJywnUFJFQ0lPIFZFTlRBJzpNYXRoLnJvdW5kKHMucmV2ZW51ZXx8MCksJ1FVRURBJzpNYXRoLnJvdW5kKHMucXVlZGF8fDApLCdQUkVDSU8gQ09TVE8nOnMuY29zdD09bnVsbD8nJzpNYXRoLnJvdW5kKHMuY29zdCksJ0NPU1RPJzpzLmNvc3Q9PW51bGw/Jyc6TWF0aC5yb3VuZCgocy5jb3N0fHwwKSsocy5lbnZpb3x8MCkpLCdGQUNUVVJBJzpNYXRoLnJvdW5kKHMuZmFjdHVyYXx8MCksJ0dBTkFOQ0lBJzpzLm5ldD09bnVsbD8nJzpNYXRoLnJvdW5kKHMubmV0KSwnUE9SQ0VOVEFKRSc6cy5tYXJnaW5QY3Q9PW51bGw/Jyc6K3MubWFyZ2luUGN0LnRvRml4ZWQoMiksJ0NVRU5UQSc6cy5hY2NvdW50X25hbWV8fCcnLCdTVE9DSyc6cy5zdG9jaz8nU8OtJzonJywnQ1VPVEFTJzpzLmN1b3Rhc3x8MCwnRkVDSEEnOmQuZGF0ZX07fSk7CiAgICB2YXIgbm09U3RyaW5nKHBhcnNlSW50KGQuZGF0ZS5zbGljZSg4LDEwKSwxMCkpO2lmKHVzZWRbbm1dKW5tPWQuZGF0ZTt1c2VkW25tXT0xO25tPW5tLnNsaWNlKDAsMzEpOwogICAgWExTWC51dGlscy5ib29rX2FwcGVuZF9zaGVldCh3YixYTFNYLnV0aWxzLmpzb25fdG9fc2hlZXQocm93cy5sZW5ndGg/cm93czpbeydOVU1FUk8gREUgVkVOVEEnOicoc2luIHZlbnRhcyBjb24gZXN0b3MgZmlsdHJvcyknfV0pLG5tKTsKICB9KTsKICBYTFNYLndyaXRlRmlsZSh3YiwnZ2VzdGlvbl9oaXN0b3JpY29fJysoJCgnaF9mcm9tJykudmFsdWV8fCcnKSsnXycrKCQoJ2hfdG8nKS52YWx1ZXx8JycpKycueGxzeCcpOwp9CgovLyA9PT09PT09PT09PT09PT09PT09PSBTT0xBUEEgRkxFWCAoY29udHJvbCBkZSBib25pZmljYWNpb25lcykgPT09PT09PT09PT09PT09PT09PT0KdmFyIEZMRVhfTE9BREVEPWZhbHNlLCBGTEVYREFUQT1udWxsOwphc3luYyBmdW5jdGlvbiBmbGV4TG9hZCgpewogIGNvbnN0IGlkPSQoJ2FjY291bnQnKS52YWx1ZXx8J2FsbCc7CiAgY29uc3QgZnJvbT0kKCdmX2Zyb20nKS52YWx1ZSwgdG89JCgnZl90bycpLnZhbHVlOwogIGNvbnN0IGlzQWxsPShpZD09PSdhbGwnKTsKICAkKCdmX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iOSIgY2xhc3M9ImxvYWRpbmciPlRyYXllbmRvIHZlbnRhcyBGbGV4IGRlIE1lcmNhZG8gTGlicmXigKYgKHB1ZWRlIHRhcmRhcik8L3RkPjwvdHI+JzsKICB0cnl7CiAgICBjb25zdCB1cmw9aXNBbGw/KCcvYXBpL2Fkcy92ZW50YXMtYWxsPycrKGZyb20/KCdmcm9tPScrZnJvbSk6JycpKyh0bz8oJyZ0bz0nK3RvKTonJykpOignL2FwaS9hZHMvdmVudGFzP2FjY291bnRfaWQ9JytpZCsoZnJvbT8oJyZmcm9tPScrZnJvbSk6JycpKyh0bz8oJyZ0bz0nK3RvKTonJykpOwogICAgY29uc3QgZD1hd2FpdCBhcGkodXJsKTsgRkxFWERBVEE9ZDsgRkxFWF9MT0FERUQ9dHJ1ZTsKICAgIGZsZXhSZW5kZXIoKTsKICB9Y2F0Y2goZSl7ICQoJ2ZfYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSI5IiBjbGFzcz0ibG9hZGluZyI+RXJyb3I6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkrJzwvdGQ+PC90cj4nOyB9Cn0KZnVuY3Rpb24gZmxleFJvd3MoKXsKICBpZighRkxFWERBVEEpcmV0dXJuIFtdOwogIGxldCByb3dzPShGTEVYREFUQS52ZW50YXN8fFtdKS5maWx0ZXIoZnVuY3Rpb24odil7cmV0dXJuIHYuZmxleDt9KTsKICB2YXIgb3E9KCgkKCdmX29yZGVyJykudmFsdWUpfHwnJykudHJpbSgpOwogIGlmKG9xKSByb3dzPXJvd3MuZmlsdGVyKGZ1bmN0aW9uKHYpe3JldHVybiBTdHJpbmcodi5wYWNrX2lkfHwnJykuaW5kZXhPZihvcSk+PTB8fFN0cmluZyh2Lm9yZGVyX2lkfHwnJykuaW5kZXhPZihvcSk+PTA7fSk7CiAgcmV0dXJuIHJvd3M7Cn0KZnVuY3Rpb24gZmxleFJlbmRlcigpewogIGlmKCFGTEVYREFUQSl7cmV0dXJuO30KICBjb25zdCBkPUZMRVhEQVRBOwogIGNvbnN0IHZ0PSQoJ2ZsZXhUYWJsZScpOyBpZih2dCkgdnQuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZS1hY2MnLCFkLmFsbCk7CiAgY29uc3Qgcm93cz1mbGV4Um93cygpOwogIHZhciBib25vPTAsIGVudmlvPTAsIHByZWNpbz0wOwogIHJvd3MuZm9yRWFjaChmdW5jdGlvbih2KXsgYm9ubys9KHYuYm9ub3x8MCk7IGVudmlvKz0odi5lbnZpb3x8MCk7IHByZWNpbys9KHYucmV2ZW51ZXx8MCk7IH0pOwogIGNvbnN0IHRpbGVzPVtbJ1ZlbnRhcyBGbGV4Jyxyb3dzLmxlbmd0aCwnJ10sWydCb25pZmljYWNpw7NuIHRvdGFsJyxmbXRNb25leShib25vKSwnZ29vZCddLFsnRW52w61vIEZsZXggdG90YWwnLGZtdE1vbmV5KGVudmlvKSwnJ10sWydGYWN0dXJhY2nDs24gRmxleCcsZm10TW9uZXkocHJlY2lvKSwnJ11dOwogICQoJ2Zfa3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAoZnVuY3Rpb24odCl7cmV0dXJuICc8ZGl2IGNsYXNzPSJrcGkgJyt0WzJdKyciPjxkaXYgY2xhc3M9ImsiPicrdFswXSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+Jyt0WzFdKyc8L2Rpdj48L2Rpdj4nO30pLmpvaW4oJycpOwogICQoJ2ZfbWV0YScpLmlubmVySFRNTD0n4pyI77iPIDxiPicrcm93cy5sZW5ndGgrJzwvYj4gdmVudGFzIEZsZXggwrcgYm9uaWZpY2FjacOzbiB0b3RhbCA8YiBzdHlsZT0iY29sb3I6dmFyKC0tZ3JlZW4pIj4nK2ZtdE1vbmV5KGJvbm8pKyc8L2I+IMK3IHBlcsOtb2RvICcrZXNjKGQuZnJvbXx8JycpKycgYSAnK2VzYyhkLnRvfHwnJyk7CiAgaWYoIXJvd3MubGVuZ3RoKXsgJCgnZl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjkiIGNsYXNzPSJlbXB0eSI+U2luIHZlbnRhcyBGbGV4IGVuIGVsIHBlcsOtb2RvLjwvdGQ+PC90cj4nOyByZXR1cm47IH0KICAkKCdmX2JvZHknKS5pbm5lckhUTUw9cm93cy5tYXAoZnVuY3Rpb24odil7CiAgICByZXR1cm4gJzx0cj4nKwogICAgICAnPHRkIGNsYXNzPSJuYW1lIj4nK2VzYyh2LnRpdGxlfHx2Lml0ZW1faWQpKyc8c3BhbiBjbGFzcz0iaWQiPicrKHYuaXRlbV9pZHx8JycpKycgwrcgJysodi5kYXRlfHwnJykrJzwvc3Bhbj48L3RkPicrCiAgICAgICc8dGQgY2xhc3M9ImFjY29sIj4nK2VzYyh2LmFjY291bnRfbmFtZXx8JycpKyc8L3RkPicrCiAgICAgICc8dGQ+JytzdGF0dXNQaWxsKHYuc3RhdHVzKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkodi5yZXZlbnVlKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj4nKyh2LmVudmlvPygn4oiSJytmbXRNb25leSh2LmVudmlvKSk6J+KAlCcpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLWdyZWVuKTtmb250LXdlaWdodDo3MDAiPicrKHYuYm9ubz8oJysnK2ZtdE1vbmV5KHYuYm9ubykpOifigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKHYuY3VvdGFzfHwwKSsnPC90ZD4nKwogICAgICAnPHRkPicrZXNjKHYuc2t1fHwnJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyh2LnBhY2tfaWR8fHYub3JkZXJfaWR8fCcnKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJyk7Cn0KZnVuY3Rpb24gZmxleERvd25sb2FkWGxzeCgpewogIGNvbnN0IHJvd3M9ZmxleFJvd3MoKTsKICBpZighcm93cy5sZW5ndGgpe3RvYXN0KCdObyBoYXkgdmVudGFzIEZsZXggcGFyYSBleHBvcnRhcicpO3JldHVybjt9CiAgY29uc3QgZGF0YT1yb3dzLm1hcChmdW5jdGlvbih2KXtyZXR1cm4ge0ZlY2hhOnYuZGF0ZSwgTl92ZW50YTp2LnBhY2tfaWR8fHYub3JkZXJfaWR8fCcnLCBDdWVudGE6di5hY2NvdW50X25hbWV8fCcnLCBQdWJsaWNhY2lvbjp2LnRpdGxlLCBDb2RfU0tVOnYuc2t1fHwnJywgRXN0YWRvOnN0YXR1c0xhYmVsKHYuc3RhdHVzKSwgUHJlY2lvOk1hdGgucm91bmQodi5yZXZlbnVlfHwwKSwgRW52aW86TWF0aC5yb3VuZCh2LmVudmlvfHwwKSwgQm9uaWZpY2FjaW9uX01MOk1hdGgucm91bmQodi5ib25vfHwwKSwgQ3VvdGFzOnYuY3VvdGFzfHwwfTt9KTsKICBjb25zdCB3cz1YTFNYLnV0aWxzLmpzb25fdG9fc2hlZXQoZGF0YSk7IGNvbnN0IHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTsgWExTWC51dGlscy5ib29rX2FwcGVuZF9zaGVldCh3Yix3cywnRkxFWCcpOwogIFhMU1gud3JpdGVGaWxlKHdiLCdmbGV4X2JvbmlmaWNhY2lvbmVzXycrKCQoJ2ZfZnJvbScpLnZhbHVlfHwnJykrJ18nKygkKCdmX3RvJykudmFsdWV8fCcnKSsnLnhsc3gnKTsKfQoKaW5pdCgpOwo8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg==", "base64").toString("utf8");
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
