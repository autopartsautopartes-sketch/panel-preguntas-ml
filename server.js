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
const DB_PATH = path.join(__dirname, 'data.json');
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
const SESSIONS_PATH = path.join(__dirname, 'sessions.json');
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
  const errors = [];
  for (const c of candidates) {
    if (!c.token) continue;
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
      errors.push({ tried: c.label, status: r.status, error: data.message || data.error || text.slice(0, 200) });
    } catch(e) {
      errors.push({ tried: c.label, error: e.message || String(e) });
    }
  }
  return { ok: false, removed: promotionId, type: promotionType, error: errors.map(e => `${e.tried}: ${e.status || ''} ${e.error}`).join(' | ') };
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
    // 1) Intento directo. La mayoría entra por acá y ahorra todas las llamadas de promociones.
    let errors = await attemptUpdateOnce();
    if (!errors.length) return { item_id: item.item_id, ok: true };
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
        errors = await attemptUpdateOnce();
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
            thumbnail: itemData.thumbnail,
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
      for (const q of questions) {
        allQuestions.push({
          ...q, account_name: account.name, account_id: account.id,
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
      // Fetch message packs in parallel (batches of 5 to avoid rate limits)
      for (let i = 0; i < uniqueOrders.length; i += 5) {
        const batch = uniqueOrders.slice(i, i + 5);
        const results = await Promise.allSettled(batch.map(async (order) => {
          const packId = order.pack_id || order.id;
          let msgData;
          try {
            msgData = await mlGet(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}`, token, {
              tag: 'post_sale', limit: 15
            });
          } catch (e) {
            // Retry once after a short delay — avoids transient rate-limit/network blips
            // causing a conversation to flicker in/out of the unread list between polls
            await new Promise(r => setTimeout(r, 400));
            msgData = await mlGet(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}`, token, {
              tag: 'post_sale', limit: 15
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
            return {
              id: m.id,
              from: fromRole,
              text: m.text || m.plain?.content || '',
              date: m.date_created || m.date || m.created_at || m.date_received || m.message_date?.created || '',
              mlUnread
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
  const { order_id, text, account_id } = await parseBody(req);
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
          return { id: itemId, thumbnail: itemData.thumbnail || '', sku };
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
    error_items: [], report: null, cancelled: false, created: Date.now(), username: 'api'
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
// Marcador de version: para confirmar que este deploy quedo live (sin auth, inofensivo)
route('GET', '/api/version', async (req, res) => {
  sendJSON(res, 200, { version: '2026-07-08-anto-upid-v11', features: ['anto_deposito', 'catalogo_gtin', 'prep_stats_admin'] });
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
function costsFilePath() { return _pathCosts.join(__dirname, 'ads_costs.json'); }
function loadCostsFile() { try { return JSON.parse(_fsCosts.readFileSync(costsFilePath(), 'utf8')) || {}; } catch (e) { return {}; } }
function saveCostsFile(obj) { _fsCosts.writeFileSync(costsFilePath(), JSON.stringify(obj)); }

// ---------------------------------------------------------------------------
// LEDGER HISTORICO DE VENTAS: congela el costo/margen al momento de cada venta.
// Estructura: { sales: { "<accountId>:<orderId>:<itemId>": { ...snapshot } }, updated }
// Asi el margen de una venta vieja NO se recalcula con el costo de hoy: queda fijo.
// ---------------------------------------------------------------------------
function histFilePath() { return _pathCosts.join(__dirname, 'ads_ventas_hist.json'); }
function loadHistFile() { try { return JSON.parse(_fsCosts.readFileSync(histFilePath(), 'utf8')) || { sales: {} }; } catch (e) { return { sales: {} }; } }
function saveHistFile(obj) { try { _fsCosts.writeFileSync(histFilePath(), JSON.stringify(obj)); } catch (e) {} }

// VENTAS por publicación de los ÚLTIMOS 90 DÍAS (para el "vende" de Estrategia).
// Estructura: { accounts: { <accountId>: { computedAt, days, map: { <itemId>: unidades } } } }
function sold90Path() { return _pathCosts.join(__dirname, 'ads_sold90.json'); }
function loadSold90File() { try { return JSON.parse(_fsCosts.readFileSync(sold90Path(), 'utf8')) || { accounts: {} }; } catch (e) { return { accounts: {} }; } }
function saveSold90File(obj) { try { _fsCosts.writeFileSync(sold90Path(), JSON.stringify(obj)); } catch (e) {} }
// Mapa item_id -> unidades vendidas (paid, sin canceladas) en [from,to].
async function fetchSold90Map(engine, account, from, to) {
  const orders = await engine.fetchSales(account, from, to);
  const map = {};
  for (const o of orders) {
    if (String(o.status || '').toLowerCase() === 'cancelled') continue;
    for (const it of (o.items || [])) { if (it.item_id) map[it.item_id] = (map[it.item_id] || 0) + (Number(it.qty) || 0); }
  }
  return map;
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

  // Visitas por publicación (demanda real). Batch al endpoint /visits/items, lotes EN PARALELO.
  async function fetchVisits(account, ids) {
    const token = await getValidToken(account);
    const out = {};
    const batches = [];
    for (let i = 0; i < ids.length; i += 50) batches.push(ids.slice(i, i + 50));
    await mapLimit(batches, 6, async (batch) => {
      try {
        const data = await mlGet('https://api.mercadolibre.com/visits/items', token, { ids: batch.join(',') });
        // La respuesta puede ser array [{item_id,total_visits}] u objeto { MLA..: n }.
        if (Array.isArray(data)) { for (const d of data) { if (d && d.item_id != null) out[d.item_id] = Number(d.total_visits) || 0; } }
        else if (data && typeof data === 'object') { for (const k in data) { const v = data[k]; out[k] = typeof v === 'number' ? v : Number(v && v.total_visits) || 0; } }
      } catch (e) {}
    });
    return out;
  }

  // Trae las VENTAS reales de ML por cuenta en el rango [from, to] (YYYY-MM-DD).
  // Devuelve órdenes con sus ítems y el shipment_id (para el envío real).
  async function fetchSales(account, from, to) {
    const token = await getValidToken(account);
    const p = { seller: account.seller_id, 'order.status': 'paid', sort: 'date_desc', limit: 50 };
    // Ventana en hora ARGENTINA (UTC-3), igual que el Dashboard, para que el día coincida.
    if (from) p['order.date_created.from'] = from + 'T00:00:00.000-03:00';
    if (to) p['order.date_created.to'] = to + 'T23:59:59.999-03:00';
    const orders = [];
    for (let offset = 0; offset < 3000; offset += 50) {
      let data;
      try { data = await mlGet('https://api.mercadolibre.com/orders/search', token, { ...p, offset }); }
      catch (e) { break; }
      const res = (data && data.results) || [];
      for (const o of res) {
        // Impuesto REAL que ML retiene en la venta (la línea "Impuestos" del resumen),
        // sumando lo que informan los pagos de la orden. Si no viene, queda null (usa fallback %).
        const pays = o.payments || [];
        let taxReal = null;
        for (const pm of pays) {
          const t = Number(pm.taxes_amount);
          if (!isNaN(t)) taxReal = (taxReal || 0) + t;
        }
        orders.push({
          order_id: o.id, date: argDate(o.date_created),   // fecha en hora argentina (consistente con el Dashboard)
          shipment_id: o.shipping && o.shipping.id,
          status: o.status, tags: o.tags || [],
          tax_real: taxReal,
          items: (o.order_items || []).map(it => ({
            item_id: it.item && it.item.id, title: (it.item && it.item.title) || '',
            qty: Number(it.quantity) || 0, unit_price: Number(it.unit_price) || 0, sale_fee: Number(it.sale_fee) || 0,
          })),
        });
      }
      if (res.length < 50) break;
    }
    return orders;
  }

  // Envío REAL de ML: costo que absorbió el vendedor + estado del envío.
  async function fetchShipping(account, shipmentId) {
    if (!shipmentId) return { cost: null, status: null };
    const token = await getValidToken(account);
    let cost = null, status = null, s = null;
    try { s = await mlGet(`https://api.mercadolibre.com/shipments/${shipmentId}`, token, {}, { 'x-format-new': 'true' }); status = s && (s.status || null); } catch (e) {}
    try {
      const c = await mlGet(`https://api.mercadolibre.com/shipments/${shipmentId}/costs`, token, {}, { 'x-format-new': 'true' });
      if (c) {
        if (Array.isArray(c.senders) && c.senders[0] && c.senders[0].cost != null) cost = Number(c.senders[0].cost) || 0;
        else if (c.gross_amount != null) cost = Math.max(0, Number(c.gross_amount) - (Number(c.receiver_shipping_cost) || 0));
      }
    } catch (e) {}
    if (cost == null && s && s.base_cost != null) cost = Number(s.base_cost) || 0;
    return { cost, status };
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

  return { getAdvertiser, getAdvertiserId, listCampaigns, listCampaignItems, setCampaignStatus, fetchItems, fetchSales, fetchShipping, simulateFee, fetchVisits, setItemPrice };
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
function saleNet(sale, costRow, cfg, realShip, realTax) {
  const qty = sale.qty || 0;
  const revenue = (sale.unit_price || 0) * qty;
  const fee = sale.sale_fee || 0;                                   // comisión real de ML ("Cargo por venta total")
  const taxReal = (realTax != null && !isNaN(realTax));
  const tax = taxReal ? realTax : 0;                                // impuesto REAL de ML por venta (0 si ML no lo informa)
  const factura = revenue * ((cfg.taxPct != null ? cfg.taxPct : 5) / 100); // "factura" mensual de ML → parte del costo
  const shipReal = (realShip != null && !isNaN(realShip));
  if (!costRow) { const e = shipReal ? realShip : 0; return { revenue, fee, envio: e, envioReal: shipReal, tax, taxReal, factura, queda: revenue - fee - e - tax, cost: null, net: null, marginPct: null, known: false }; }
  const pcost = Number(costRow.cost) || 0;
  let envio;
  if (shipReal) { envio = realShip; }                              // envío REAL de ML
  else { const rm = realMarginAtPrice(costRow, sale.unit_price, cfg.freeShipThreshold); const floor = rm ? rm.floorUsed : pcost; envio = Math.max(0, floor - pcost) * qty; }
  const cost = pcost * qty;                                        // costo del producto
  const queda = revenue - fee - envio - tax;                       // "cuánto queda" tras las retenciones por venta de ML
  const net = queda - cost - factura;                             // ganancia: descuenta costo Y la factura mensual
  return { revenue, fee, envio, envioReal: shipReal, tax, taxReal, factura, queda, cost, net, marginPct: revenue > 0 ? (net / revenue) * 100 : null, known: true };
}

async function analyzeVentas(engine, account, cfg, costs, from, to, hist) {
  const orders = await engine.fetchSales(account, from, to);
  const SHIP_CAP = cfg.shipCap || 200;                 // tope de envíos reales a consultar (por velocidad)
  let facturacion = 0, factConocida = 0, ganancia = 0, conocidas = 0, perdida = 0, sinCosto = 0, shipFetched = 0;
  let hidden = 0, savedCount = 0, freshCount = 0, taxRealCount = 0, keptOrders = 0;  // ocultas, congeladas, nuevas, con impuesto real, órdenes válidas
  const sales = (hist && hist.sales) || null;
  const nowIso = new Date().toISOString();
  const rows = [];
  let idx = 0;
  for (const o of orders) {
    let ship = null, status = null;
    if (idx < SHIP_CAP) { const sh = await engine.fetchShipping(account, o.shipment_id); ship = sh.cost; status = sh.status; if (ship != null) shipFetched++; }
    idx++;
    // Ocultar SOLO canceladas y reclamos cerrados con devolución: el resto (en camino, pendientes, entregadas) cuenta.
    if (isDeadOrder(o, status)) { hidden++; continue; }
    keptOrders++;
    const n = o.items.length || 1;
    const taxPart = (o.tax_real != null && !isNaN(o.tax_real)) ? o.tax_real / n : null;  // impuesto REAL de ML repartido entre ítems
    if (taxPart != null) taxRealCount++;
    for (const it of o.items) {
      const cr = costs[String(it.item_id)];
      const shipPart = (ship != null) ? ship / n : null;  // envío real de ML repartido entre ítems de la orden
      const key = account.id + ':' + o.order_id + ':' + it.item_id;
      const frozen = sales && sales[key];
      let r;
      if (frozen) {
        // Venta ya registrada: usamos el costo/margen CONGELADO al momento de la venta.
        r = { revenue: frozen.revenue, fee: frozen.fee, envio: frozen.envio, envioReal: frozen.envioReal, tax: frozen.tax, taxReal: frozen.taxReal, factura: frozen.factura, queda: frozen.queda, cost: frozen.cost, net: frozen.net, marginPct: frozen.marginPct, known: frozen.known };
        savedCount++;
      } else {
        r = saleNet(it, cr, cfg, shipPart, taxPart);
        if (sales) {
          sales[key] = { account_id: account.id, seller_id: account.seller_id, order_id: o.order_id, date: o.date, item_id: it.item_id, title: it.title, stock: !!(cr && cr.stock), savedAt: nowIso, ...r };
          freshCount++;
        }
      }
      facturacion += r.revenue;
      if (r.known) { ganancia += r.net; factConocida += r.revenue; conocidas++; if (r.net < 0) perdida++; } else sinCosto++;
      rows.push({ order_id: o.order_id, date: o.date, item_id: it.item_id, title: it.title, status, stock: !!(cr && cr.stock), frozen: !!frozen, ...r });
    }
  }
  return {
    from, to, days: daysBetween(from, to), count: rows.length, orders: keptOrders,
    facturacion, ganancia, margin: factConocida > 0 ? (ganancia / factConocida) * 100 : null,
    conocidas, sinCosto, perdida, shipFetched, hidden, savedCount, freshCount, taxRealCount, rows,
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
  const minVis = cfg.minVisits != null ? cfg.minVisits : 20;   // hay algo de demanda
  const hotVis = cfg.hotVisits != null ? cfg.hotVisits : 60;   // mucha demanda
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
  const minVis = cfg.minVisits != null ? cfg.minVisits : 20;
  const hotVis = cfg.hotVisits != null ? cfg.hotVisits : 60;
  const buen = it.margin != null && it.margin >= high;
  const sold = it.sold || 0, vis = it.visits || 0, conv = it.conv, age = it.ageDays;
  // 1) ANTI-CANIBALIZACIÓN: título repetido y NO es el líder → nunca ADS.
  if (it.duplicated && !it.isLeader) return { code: 'organico', label: '🌱 No anunciar — otra publicación del mismo título lidera (' + (it.leaderName || '—') + '). Dejala orgánica o subí precio para margen.', pri: 6 };
  // 2) MUERTA VIEJA: 0 visitas + creada hace más de 1 año → pausar/limpiar (no rankea ni suma).
  if (vis === 0 && age != null && age > 365) return { code: 'pausar', label: '⏸️ Pausar/limpiar — 0 visitas y +1 año publicada. No rankea; sacala del camino.', pri: 5 };
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
  const cargoVender = sim ? (Number(sim.sale_fee) || 0) : 0;                 // comisión + cargo fijo (exacto de ML)
  // Costo por ofrecer cuotas: el que informa ML, o un % configurable si ofrecés cuotas.
  const cuotas = sim && sim.financing ? Number(sim.financing) : (cfg.cuotasPct ? p * cfg.cuotasPct / 100 : 0);
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
  const objByAcc = {}; const nameByAcc = {};
  for (const a of (accountsMeta || [])) { objByAcc[a.id] = a.objetivo || 0; nameByAcc[a.id] = a.name; }

  // 2) Clasificamos cada producto.
  const items = [];
  let pausadas = 0;
  for (const id in costsTable) {
    const c = costsTable[id];
    // Solo publicaciones ACTIVAS. Si ya está enriquecida y NO está activa (pausada/cerrada/etc.), la salteamos.
    const st = String(c.status || '').toLowerCase();
    if (st && st !== 'active') { pausadas++; continue; }
    const agg = perItem[id];
    // MARGEN: SIEMPRE el del simulador de ML al precio real (con promo). Fallback: margen de lista.
    const simMargin = (c.simMargin != null && !isNaN(c.simMargin)) ? Number(c.simMargin) : null;
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
      price: c.price != null ? Number(c.price) : null, origPrice: c.origPrice != null ? Number(c.origPrice) : null, enPromo: !!c.enPromo,
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
  const getAccount = (req) => {
    const id = parseInt(new URL(req.url, 'http://localhost').searchParams.get('account_id'));
    return (loadDB().ml_accounts || []).find(a => a.id === id) || null;
  };

  route('GET', '/api/ads/accounts', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
    sendJSON(res, 200, { accounts: (loadDB().ml_accounts || []).map(a => ({ id: a.id, name: a.name, seller_id: a.seller_id })) });
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
    return { ...g, objetivo: a.objetivo != null ? a.objetivo : 100000000, taxPct: a.taxPct != null ? a.taxPct : 5 };
  }

  // RENTABILIDAD REAL: trae ventas de ML y calcula margen verdadero por cuenta.
  route('GET', '/api/ads/ventas', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
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
      if (v.freshCount > 0) { hist.updated = new Date().toISOString(); saveHistFile(hist); }  // persistimos las ventas nuevas congeladas
      const proyMensual = v.days > 0 ? v.facturacion / v.days * 30 : 0;
      sendJSON(res, 200, {
        account: account.name, objetivo: cfg.objetivo, taxPct: cfg.taxPct, from, to,
        proy_mensual: proyMensual, avance: cfg.objetivo > 0 ? proyMensual / cfg.objetivo * 100 : 0,
        resumen: { count: v.count, orders: v.orders, facturacion: v.facturacion, ganancia: v.ganancia, margin: v.margin, conocidas: v.conocidas, sinCosto: v.sinCosto, perdida: v.perdida, days: v.days, shipFetched: v.shipFetched, hidden: v.hidden, saved: v.savedCount, fresh: v.freshCount, taxReal: v.taxRealCount },
        ventas: v.rows.sort((a, b) => (a.net == null ? 1 : b.net == null ? -1 : a.net - b.net)).slice(0, 150),
      });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // RENTABILIDAD de TODAS las cuentas juntas, en un mismo rango de fechas.
  route('GET', '/api/ads/ventas-all', async (req, res) => {
    if (!requireAuth(req)) return sendJSON(res, 401, { error: 'No autorizado' });
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
      let shipFetched = 0, hidden = 0, saved = 0, fresh = 0, taxReal = 0, orders = 0, objetivoTotal = 0;
      const porCuenta = [];
      for (const account of accounts) {
        const cfg = getAccountCfg(account);
        objetivoTotal += cfg.objetivo || 0;
        const v = await analyzeVentas(engine, account, cfg, costs, from, to, hist);
        for (const r of v.rows) { r.account_name = account.name; allRows.push(r); if (r.known) factConocida += r.revenue; }
        facturacion += v.facturacion; ganancia += v.ganancia; orders += v.orders;
        conocidas += v.conocidas; perdida += v.perdida; sinCosto += v.sinCosto;
        shipFetched += v.shipFetched; hidden += v.hidden; saved += v.savedCount; fresh += v.freshCount; taxReal += v.taxRealCount;
        const proy = v.days > 0 ? v.facturacion / v.days * 30 : 0;
        porCuenta.push({ account_name: account.name, objetivo: cfg.objetivo, facturacion: v.facturacion, ganancia: v.ganancia, margin: v.margin, orders: v.orders, perdida: v.perdida, proy_mensual: proy });
      }
      if (fresh > 0) { hist.updated = new Date().toISOString(); saveHistFile(hist); }
      const days = daysBetween(from, to);
      const proyMensual = days > 0 ? facturacion / days * 30 : 0;
      sendJSON(res, 200, {
        account: 'Todas las cuentas', all: true, objetivo: objetivoTotal, from, to,
        proy_mensual: proyMensual, avance: objetivoTotal > 0 ? proyMensual / objetivoTotal * 100 : 0,
        por_cuenta: porCuenta,
        resumen: { count: allRows.length, orders, facturacion, ganancia, margin: factConocida > 0 ? (ganancia / factConocida) * 100 : null, conocidas, sinCosto, perdida, days, shipFetched, hidden, saved, fresh, taxReal },
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
    const costsTable = loadCostsFile().costs || {};
    if (!Object.keys(costsTable).length) return sendJSON(res, 200, { empty: true, note: 'Importá los _COMPLETO de tus cuentas primero (uno por cuenta).' });
    const hist = loadHistFile();
    const accountsMeta = (loadDB().ml_accounts || []).map(a => ({ id: a.id, name: a.name, seller_id: a.seller_id, objetivo: getAccountCfg(a).objetivo }));
    const cfg = { marginHigh: numP('marginHigh', 12), minSales: numP('minSales', 1),
      minVisits: numP('minVisits', 20), hotVisits: numP('hotVisits', 60), roas: numP('roas', 5), tieBand: 2 };
    // Mapa de ventas de los últimos 90 días, fusionado de todas las cuentas (item_ids únicos).
    const s90 = loadSold90File(); const sold90Map = {}; let s90At = null;
    for (const aid in (s90.accounts || {})) { const a = s90.accounts[aid]; if (a && a.map) { for (const k in a.map) sold90Map[k] = a.map[k]; if (a.computedAt && (!s90At || a.computedAt > s90At)) s90At = a.computedAt; } }
    try {
      const strat = buildStrategy(costsTable, hist, accountsMeta, cfg, sold90Map);
      strat.totals.sold90_desde = s90At;
      // Orden = PLAN DE ACCIÓN: por prioridad de acción, y dentro por potencial.
      const items = strat.items.slice().sort((a, b) =>
        ((a.priority || 9) - (b.priority || 9)) || ((b.score || 0) - (a.score || 0)) || ((b.margin || -999) - (a.margin || -999))
      ).slice(0, 500);
      sendJSON(res, 200, { config: cfg, totals: strat.totals, segmentos: strat.segmentos, plan: strat.plan, planMeta: strat.planMeta, duplicados: strat.duplicados, cuentas: strat.cuentas, items });
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
      let categoryId = u.searchParams.get('category_id') || null, listingType = u.searchParams.get('listing_type') || null, price = Number(u.searchParams.get('price')) || null;
      if (itemId) {
        const info = await engine.fetchItems(account, [itemId], 'id,price,category_id,listing_type_id,title');
        const it = info[itemId];
        if (it) { out.item = { id: itemId, title: it.title, price: it.price, category_id: it.category_id, listing_type_id: it.listing_type_id }; categoryId = categoryId || it.category_id; listingType = listingType || it.listing_type_id; price = price || Number(it.price); }
      }
      const token = await getValidToken(account);
      const params = { price: Math.round(price || 10000) };
      if (categoryId) params.category_id = categoryId;
      if (listingType) params.listing_type_id = listingType;
      out.request = params;
      out.raw = await mlGet('https://api.mercadolibre.com/sites/MLA/listing_prices', token, params);
      const sim = await engine.simulateFee(account, params.price, categoryId, listingType);
      out.simulateFee = sim;
      // Desglose "Recibís" para comparar con la web de ML. Costo del _COMPLETO si el item está cargado.
      const cRow = itemId ? ((loadCostsFile().costs || {})[itemId] || { cost: 0, costShip: 0 }) : { cost: 0, costShip: 0 };
      const cfgA = getAccountCfg(account);
      if (u.searchParams.get('cuotasPct') != null) cfgA.cuotasPct = Number(u.searchParams.get('cuotasPct')) || 0;
      if (u.searchParams.get('retencionPct') != null) cfgA.retencionPct = Number(u.searchParams.get('retencionPct')) || 0;
      out.desglose_recibis = simNet(cRow, params.price, sim, cfgA);
      sendJSON(res, 200, out);
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
    const u = new URL(req.url, 'http://x');
    const cap = Math.min(Number(u.searchParams.get('cap')) || 300, 800);
    const cfg = getAccountCfg(account);
    if (u.searchParams.get('cuotasPct') != null) cfg.cuotasPct = Number(u.searchParams.get('cuotasPct')) || 0;
    if (u.searchParams.get('retencionPct') != null) cfg.retencionPct = Number(u.searchParams.get('retencionPct')) || 0;
    const file = loadCostsFile();
    const table = file.costs || {};
    // SOLO ACTIVAS: excluyo las que ya sabemos pausadas/cerradas (no vuelven a pasar por ningún proceso).
    const mine = Object.keys(table).filter(id => {
      if (String(table[id].seller_id) !== String(account.seller_id) || !/^MLA/i.test(id)) return false;
      const st = String(table[id].status || '').toLowerCase();
      return !st || st === 'active';   // sin estado conocido (aún sin enriquecer) o activa
    });
    // Priorizo los que aún NO enriquecí (sin enrichAt), y dentro de esos por mayor margen de lista.
    const ids = mine
      .sort((a, b) => (table[a].enrichAt ? 1 : 0) - (table[b].enrichAt ? 1 : 0) || (Number(table[b].marginList) || 0) - (Number(table[a].marginList) || 0))
      .slice(0, cap);
    if (!ids.length) return sendJSON(res, 200, { refined: 0, note: 'No hay publicaciones activas para enriquecer en esta cuenta.' });
    try {
      // Ventas de los últimos 90 días de la cuenta (se recalcula si está vieja, > 6h). Una sola vez por corrida.
      const s90 = loadSold90File(); s90.accounts = s90.accounts || {};
      const cur90 = s90.accounts[account.id];
      const fresh = cur90 && cur90.computedAt && (Date.now() - new Date(cur90.computedAt).getTime()) < 6 * 3600 * 1000;
      if (!fresh) {
        try {
          const map90 = await fetchSold90Map(engine, account, ymd(daysAgo(90)), ymd(new Date()));
          s90.accounts[account.id] = { computedAt: new Date().toISOString(), days: 90, map: map90 };
          saveSold90File(s90);
        } catch (e) { /* si falla, seguimos; buildStrategy cae al ledger */ }
      }
      // Data en vivo de ML: título, precio (con promo), precio original, stock, ventas, tipo, categoría, health.
      // fetchItems (multiget de a 20) y fetchVisits (de a 50) van en paralelo.
      const [info, visits] = await Promise.all([
        engine.fetchItems(account, ids, 'id,title,price,original_price,available_quantity,sold_quantity,listing_type_id,category_id,health,permalink,status,date_created,start_time'),
        engine.fetchVisits(account, ids),
      ]);
      // ACELERACIÓN: las simulaciones de costo (listing_prices) se hacen EN PARALELO (concurrencia limitada),
      // en vez de una por una. Es el cuello de botella del enriquecimiento.
      const simMap = {};
      const simJobs = ids.filter(id => info[id]).map(id => { const it = info[id], c = table[id]; return { id, price: Number(it.price) || Number(c.listPrice) || 0, catId: it.category_id, lt: it.listing_type_id || c.listingType }; });
      await mapLimit(simJobs, 15, async (job) => { if (job.price > 0) { try { simMap[job.id] = await engine.simulateFee(account, job.price, job.catId, job.lt); } catch (e) {} } });
      let refined = 0, failed = 0;
      const nowIso = new Date().toISOString();
      for (const id of ids) {
        const c = table[id]; const it = info[id];
        if (!it) { failed++; continue; }
        const price = Number(it.price) || Number(c.listPrice) || 0;   // precio ACTUAL (con promo/tachado aplicado)
        const orig = Number(it.original_price) || null;                // precio tachado (antes de promo)
        const catId = it.category_id; const lt = it.listing_type_id || c.listingType;
        const sim = simMap[id];
        if (price > 0 && sim) {
          const nm = simNet(c, price, sim, cfg);
          c.simFee = sim.sale_fee; c.simFixed = sim.fixed_fee; c.simCuotas = nm ? nm.cuotas : 0; c.simEnvio = nm ? nm.envio : 0;
          c.simImp = nm ? nm.impuestos : 0; c.simRecibis = nm ? nm.recibis : null; c.simMargin = nm ? nm.marginPct : null;
        }
        // Data real de la publicación (título de ML = autoridad para el cruce por título).
        if (it.title) c.title = it.title;
        c.price = price; c.origPrice = orig; c.enPromo = !!(orig && price && orig > price);
        c.sold = Number(it.sold_quantity) || 0;
        c.stockAvail = Number(it.available_quantity) || 0;
        c.visits = visits[id] != null ? visits[id] : (c.visits || 0);
        c.listingType = lt || c.listingType; c.category_id = catId || c.category_id;
        c.health = it.health != null ? Number(it.health) : c.health;
        c.status = it.status || c.status; c.permalink = it.permalink || c.permalink;
        c.created = it.date_created || it.start_time || c.created;   // antigüedad (para pausar muertas viejas)
        c.enrichAt = nowIso;
        refined++;
      }
      saveCostsFile({ ...file, costs: table, updated: new Date().toISOString() });
      const enrichedTotal = mine.filter(id => table[id].enrichAt).length;
      sendJSON(res, 200, { refined, failed, scanned: ids.length, cap, account: account.name, enriched_total: enrichedTotal, account_total: mine.length,
        note: enrichedTotal < mine.length ? `Enriquecí ${enrichedTotal} de ${mine.length} productos de la cuenta. Volvé a tocar 🎯 para seguir con el resto.` : 'Enriquecí TODOS los productos de la cuenta con data real de ML.' });
    } catch (e) {
      sendJSON(res, 500, { error: (e && e.response && e.response.data) || String(e.message || e) });
    }
  });

  // Helpers compartidos por el actualizador de precios.
  function strategyCfgFrom(u) {
    const numP = (k, def) => { const v = u.searchParams.get(k); if (v == null || v === '') return def; const n = Number(v); return isNaN(n) ? def : n; };
    return { marginHigh: numP('marginHigh', 12), minSales: numP('minSales', 1), minVisits: numP('minVisits', 20), hotVisits: numP('hotVisits', 60), roas: numP('roas', 5), tieBand: 2 };
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
    const accountsMeta = (loadDB().ml_accounts || []).map(a => ({ id: a.id, name: a.name, seller_id: a.seller_id, objetivo: getAccountCfg(a).objetivo }));
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
    const file = loadCostsFile(); const table = file.costs || {};
    const results = []; let ok = 0, err = 0;
    for (const ch of changes) {
      const acc = accById[ch.account_id]; const price = Math.round(Number(ch.price));
      if (!acc || !ch.item_id || !price || price <= 0) { results.push({ item_id: ch.item_id, ok: false, error: 'datos inválidos' }); err++; continue; }
      try {
        await engine.setItemPrice(acc, ch.item_id, price);
        if (table[ch.item_id]) { table[ch.item_id].price = price; table[ch.item_id].priceUpdatedAt = new Date().toISOString(); }
        results.push({ item_id: ch.item_id, ok: true, price }); ok++;
      } catch (e) { results.push({ item_id: ch.item_id, ok: false, error: (e && e.response && e.response.data && (e.response.data.message || JSON.stringify(e.response.data))) || String(e.message || e) }); err++; }
    }
    saveCostsFile({ ...file, costs: table, updated: new Date().toISOString() });
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
    const arr = Array.isArray(body.costs) ? body.costs : [];
    // Cuenta a la que pertenece este _COMPLETO (para que las 6 cuentas coexistan y se pueda cruzar por título).
    const account = (loadDB().ml_accounts || []).find(a => a.id === parseInt(body.account_id));
    const sellerId = account ? account.seller_id : null;
    const accName = account ? account.name : null;
    const table = loadCostsFile().costs || {};
    // Reemplazo: si viene account_id, borro SOLO los items de esa cuenta (no piso las demás).
    // Sin account_id, se mantiene el viejo comportamiento (reemplazo total) para no romper.
    if (body.replace) {
      if (sellerId != null) { for (const id in table) { if (String(table[id].seller_id) === String(sellerId)) delete table[id]; } }
      else { for (const id in table) delete table[id]; }
    }
    let n = 0;
    for (const r of arr) {
      const id = String(r.item_id || r.id || '').trim();
      if (!id) continue;
      table[id] = {
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
        seller_id: sellerId,                             // cuenta dueña de esta publicación
        account_id: account ? account.id : null,
        account_name: accName,
      };
      n++;
    }
    saveCostsFile({ costs: table, updated: new Date().toISOString() });
    sendJSON(res, 200, { ok: true, imported: n, total: Object.keys(table).length, account: accName, by_account: countByAccount(table) });
  });
  route('GET', '/api/ads/costs', async (req, res) => {
    if (!isAdmin(req)) return sendJSON(res, 403, { error: 'Solo admin' });
    const f = loadCostsFile();
    const table = f.costs || {};
    sendJSON(res, 200, { total: Object.keys(table).length, updated: f.updated || null, by_account: countByAccount(table) });
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
    for (const k of ['margin', 'acosTarget', 'minClicks', 'windowDays', 'freeShipThreshold']) {
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


const ADS_PANEL_HTML = Buffer.from("PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVzIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+UGFuZWwgRXN0cmF0w6lnaWNvIMK3IEF1dG9jaGFwPC90aXRsZT4KPHNjcmlwdD53aW5kb3cuX19QQU5FTF9NT0RFX189JyUlTU9ERSUlJzs8L3NjcmlwdD4KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL3hsc3gvMC4xOC41L3hsc3guZnVsbC5taW4uanMiPjwvc2NyaXB0Pgo8c3R5bGU+CiAgOnJvb3R7LS1uYXZ5OiMxZjM4NjQ7LS1ibHVlOiMyZTU0OTY7LS1iZzojZjRmNmZiOy0tY2FyZDojZmZmOy0tbGluZTojZTJlOGYwOy0taW5rOiMxZTI5M2I7LS1tdXQ6IzY0NzQ4YjsKICAtLWdyZWVuOiMxNmEzNGE7LS1ncmVlbmJnOiNkY2ZjZTc7LS1hbWJlcjojZDk3NzA2Oy0tYW1iZXJiZzojZmVmM2M3Oy0tcmVkOiNkYzI2MjY7LS1yZWRiZzojZmVlMmUyOy0tYmx1ZWJnOiNkYmVhZmU7fQogICp7Ym94LXNpemluZzpib3JkZXItYm94fQogIGJvZHl7bWFyZ2luOjA7Zm9udC1mYW1pbHk6LWFwcGxlLXN5c3RlbSxCbGlua01hY1N5c3RlbUZvbnQsIlNlZ29lIFVJIixSb2JvdG8sQXJpYWwsc2Fucy1zZXJpZjtiYWNrZ3JvdW5kOnZhcigtLWJnKTtjb2xvcjp2YXIoLS1pbmspO2ZvbnQtc2l6ZToxNHB4fQogIC53cmFwe21heC13aWR0aDoxMzYwcHg7bWFyZ2luOjAgYXV0bztwYWRkaW5nOjE4cHh9CiAgaGVhZGVyLnRvcHtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMnB4O21hcmdpbi1ib3R0b206MTRweH0KICBoZWFkZXIudG9wIGgxe2ZvbnQtc2l6ZToyMHB4O21hcmdpbjowO2NvbG9yOnZhcigtLW5hdnkpO2ZvbnQtd2VpZ2h0OjgwMH0KICBoZWFkZXIudG9wIC5zdWJ7Y29sb3I6dmFyKC0tbXV0KTtmb250LXNpemU6MTJweH0KICAuc3BhY2Vye2ZsZXg6MX0KICBzZWxlY3QsaW5wdXQsYnV0dG9ue2ZvbnQ6aW5oZXJpdDtjb2xvcjp2YXIoLS1pbmspfQogIHNlbGVjdCxpbnB1dFt0eXBlPXRleHRdLGlucHV0W3R5cGU9bnVtYmVyXXtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6OHB4IDEwcHg7YmFja2dyb3VuZDojZmZmfQogIGJ1dHRvbntjdXJzb3I6cG9pbnRlcjtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6OXB4O3BhZGRpbmc6OHB4IDEzcHg7YmFja2dyb3VuZDojZmZmO2ZvbnQtd2VpZ2h0OjYwMDt0cmFuc2l0aW9uOi4xMnN9CiAgYnV0dG9uOmhvdmVye2JhY2tncm91bmQ6I2YxZjVmOX0KICBidXR0b24ucHJpbWFyeXtiYWNrZ3JvdW5kOnZhcigtLW5hdnkpO2NvbG9yOiNmZmY7Ym9yZGVyLWNvbG9yOnZhcigtLW5hdnkpfSBidXR0b24ucHJpbWFyeTpob3ZlcntiYWNrZ3JvdW5kOiMxNjJhNGR9CiAgLnBpbGx7ZGlzcGxheTppbmxpbmUtZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjZweDtib3JkZXItcmFkaXVzOjk5OXB4O3BhZGRpbmc6NHB4IDExcHg7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NzAwO2JvcmRlcjoxcHggc29saWQgdHJhbnNwYXJlbnR9CiAgLnAtZ3JlZW57YmFja2dyb3VuZDp2YXIoLS1ncmVlbmJnKTtjb2xvcjojMTY2NTM0fSAucC1hbWJlcntiYWNrZ3JvdW5kOnZhcigtLWFtYmVyYmcpO2NvbG9yOiM5MjQwMGV9CiAgLnAtcmVke2JhY2tncm91bmQ6dmFyKC0tcmVkYmcpO2NvbG9yOiM5OTFiMWJ9IC5wLWJsdWV7YmFja2dyb3VuZDp2YXIoLS1ibHVlYmcpO2NvbG9yOiMxZTQwYWZ9IC5wLWdyZXl7YmFja2dyb3VuZDojZjFmNWY5O2NvbG9yOiM0NzU1Njl9CiAgLyogVGFicyAqLwogIC50YWJze2Rpc3BsYXk6ZmxleDtnYXA6NnB4O2JvcmRlci1ib3R0b206MnB4IHNvbGlkIHZhcigtLWxpbmUpO21hcmdpbi1ib3R0b206MTZweDtmbGV4LXdyYXA6d3JhcH0KICAudGFie3BhZGRpbmc6MTBweCAxOHB4O2JvcmRlcjowO2JhY2tncm91bmQ6dHJhbnNwYXJlbnQ7Ym9yZGVyLXJhZGl1czoxMHB4IDEwcHggMCAwO2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS1tdXQpO2N1cnNvcjpwb2ludGVyO2JvcmRlci1ib3R0b206M3B4IHNvbGlkIHRyYW5zcGFyZW50O21hcmdpbi1ib3R0b206LTJweH0KICAudGFiLmFjdGl2ZXtjb2xvcjp2YXIoLS1uYXZ5KTtib3JkZXItYm90dG9tLWNvbG9yOnZhcigtLW5hdnkpfQogIC50YWI6aG92ZXJ7YmFja2dyb3VuZDojZWVmMmY3fQogIC5wYW5lbHtkaXNwbGF5Om5vbmV9IC5wYW5lbC5hY3RpdmV7ZGlzcGxheTpibG9ja30KICAvKiBDb3N0IGJhciAqLwogIC5jb3N0YmFye2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxMnB4IDE2cHg7bWFyZ2luLWJvdHRvbToxNHB4O2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3JhcDtnYXA6MTJweDthbGlnbi1pdGVtczpjZW50ZXJ9CiAgLmJhbm5lcntiYWNrZ3JvdW5kOiNmZmY3ZWQ7Ym9yZGVyOjFweCBzb2xpZCAjZmVkN2FhO2NvbG9yOiM5YTM0MTI7Ym9yZGVyLXJhZGl1czoxMnB4O3BhZGRpbmc6MTRweCAxNnB4O21hcmdpbi1ib3R0b206MTRweDtkaXNwbGF5Om5vbmV9CiAgLmJhbm5lci5zaG93e2Rpc3BsYXk6YmxvY2t9IC5iYW5uZXIgYntjb2xvcjojN2MyZDEyfSAuYmFubmVyIG9se21hcmdpbjo4cHggMCAwO3BhZGRpbmctbGVmdDoyMHB4fQogIC5jYXJke2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7cGFkZGluZzoxNHB4IDE2cHg7bWFyZ2luLWJvdHRvbToxNHB4fQogIC5jYXJkIGgze21hcmdpbjowIDAgMTBweDtmb250LXNpemU6MTNweDtjb2xvcjp2YXIoLS1tdXQpO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouNnB4fQogIC5jZmdyaWR7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDoxNHB4O2FsaWduLWl0ZW1zOmZsZXgtZW5kfQogIC5maWVsZHtkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2dhcDo0cHh9CiAgLmZpZWxkIGxhYmVse2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7Zm9udC13ZWlnaHQ6NjAwfQogIC5maWVsZCBpbnB1dHt3aWR0aDoxMTBweH0gLmZpZWxkIC5oaW50e2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLW11dCl9CiAgLmF1dG90YWd7bWFyZ2luLWxlZnQ6YXV0bztmb250LXNpemU6MTJweH0KICAua3Bpc3tkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCg2LDFmcik7Z2FwOjEycHg7bWFyZ2luLWJvdHRvbToxNHB4fQogIC5rcGl7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEzcHggMTRweH0KICAua3BpIC5re2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7Zm9udC13ZWlnaHQ6NjAwO3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtsZXR0ZXItc3BhY2luZzouNHB4fQogIC5rcGkgLnZ7Zm9udC1zaXplOjIxcHg7Zm9udC13ZWlnaHQ6ODAwO21hcmdpbi10b3A6NXB4O2NvbG9yOnZhcigtLW5hdnkpfSAua3BpIC52LnNtYWxse2ZvbnQtc2l6ZToxNnB4fQogIC5rcGkuZ29vZCAudntjb2xvcjp2YXIoLS1ncmVlbil9IC5rcGkud2FybiAudntjb2xvcjp2YXIoLS1hbWJlcil9IC5rcGkuYmFkIC52e2NvbG9yOnZhcigtLXJlZCl9CiAgQG1lZGlhKG1heC13aWR0aDo5ODBweCl7LmtwaXN7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcil9fQogIEBtZWRpYShtYXgtd2lkdGg6NTYwcHgpey5rcGlze2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfS5maWVsZCBpbnB1dHt3aWR0aDo5MHB4fX0KICAubGVnZW5ke2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7ZGlzcGxheTpmbGV4O2dhcDoxMnB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbjoycHggMnB4IDEycHh9CiAgLmxlZ2VuZCBzcGFue2Rpc3BsYXk6aW5saW5lLWZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo1cHh9IC5kb3R7d2lkdGg6OXB4O2hlaWdodDo5cHg7Ym9yZGVyLXJhZGl1czo1MCV9CiAgLmZpbHRlcnN7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjEycHggMTRweDttYXJnaW4tYm90dG9tOjEycHg7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDoxMHB4O2FsaWduLWl0ZW1zOmNlbnRlcn0KICAuZmlsdGVycyAuY2hpcHtjdXJzb3I6cG9pbnRlcjt1c2VyLXNlbGVjdDpub25lO2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czo5OTlweDtwYWRkaW5nOjVweCAxMnB4O2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjYwMDtiYWNrZ3JvdW5kOiNmZmY7Y29sb3I6dmFyKC0tbXV0KX0KICAuZmlsdGVycyAuY2hpcC5vbntiYWNrZ3JvdW5kOnZhcigtLW5hdnkpO2NvbG9yOiNmZmY7Ym9yZGVyLWNvbG9yOnZhcigtLW5hdnkpfQogIC5maWx0ZXJzIGlucHV0W3R5cGU9dGV4dF17ZmxleDoxO21pbi13aWR0aDoxODBweH0KICAudGFibGVjYXJke2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEycHg7b3ZlcmZsb3c6aGlkZGVufQogIC50YWJsZXNjcm9sbHtvdmVyZmxvdy14OmF1dG99CiAgdGFibGV7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO3dpZHRoOjEwMCU7bWluLXdpZHRoOjkwMHB4fQogIHRoLHRke3BhZGRpbmc6MTBweCAxMnB4O3RleHQtYWxpZ246bGVmdDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTt3aGl0ZS1zcGFjZTpub3dyYXB9CiAgdGh7YmFja2dyb3VuZDojZjhmYWZjO2ZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLW11dCk7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlO2xldHRlci1zcGFjaW5nOi40cHg7Y3Vyc29yOnBvaW50ZXI7cG9zaXRpb246c3RpY2t5O3RvcDowfQogIHRoLm51bSx0ZC5udW17dGV4dC1hbGlnbjpyaWdodH0KICB0Ym9keSB0cjpob3ZlcntiYWNrZ3JvdW5kOiNmOGZhZmN9CiAgdGQubmFtZXt3aGl0ZS1zcGFjZTpub3JtYWw7bWluLXdpZHRoOjIyMHB4O2ZvbnQtd2VpZ2h0OjYwMH0KICB0ZC5uYW1lIC5pZHtkaXNwbGF5OmJsb2NrO2ZvbnQtd2VpZ2h0OjQwMDtjb2xvcjp2YXIoLS1tdXQpO2ZvbnQtc2l6ZToxMXB4fQogIC5hY29zY2VsbHtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7anVzdGlmeS1jb250ZW50OmZsZXgtZW5kfQogIC5hY29zYmFye3dpZHRoOjU0cHg7aGVpZ2h0OjdweDtib3JkZXItcmFkaXVzOjRweDtiYWNrZ3JvdW5kOiNlZWYyZjc7b3ZlcmZsb3c6aGlkZGVuO2ZsZXg6bm9uZX0gLmFjb3NiYXI+aXtkaXNwbGF5OmJsb2NrO2hlaWdodDoxMDAlfQogIC5yb3didG57cGFkZGluZzo1cHggMTBweDtmb250LXNpemU6MTJweDtib3JkZXItcmFkaXVzOjdweH0KICAucm93YnRuLnBhdXNle2NvbG9yOiM5OTFiMWI7Ym9yZGVyLWNvbG9yOiNmY2E1YTV9IC5yb3didG4ucGF1c2U6aG92ZXJ7YmFja2dyb3VuZDp2YXIoLS1yZWRiZyl9CiAgLnJvd2J0bi5wbGF5e2NvbG9yOiMxNjY1MzQ7Ym9yZGVyLWNvbG9yOiM4NmVmYWN9IC5yb3didG4ucGxheTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLWdyZWVuYmcpfQogIC5lbXB0eSwubG9hZGluZ3twYWRkaW5nOjM4cHg7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tbXV0KX0KICAuYWN0aW9uc3tkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjEwcHg7YWxpZ24taXRlbXM6Y2VudGVyO21hcmdpbjoxNHB4IDB9CiAgLmJhcntiYWNrZ3JvdW5kOiNlZWYyZjc7Ym9yZGVyLXJhZGl1czo2cHg7aGVpZ2h0OjE0cHg7b3ZlcmZsb3c6aGlkZGVufS5iYXI+aXtkaXNwbGF5OmJsb2NrO2hlaWdodDoxMDAlO2JhY2tncm91bmQ6dmFyKC0tYmx1ZSl9CiAgLmxvZ2NhcmR7YmFja2dyb3VuZDp2YXIoLS1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1yYWRpdXM6MTJweDtwYWRkaW5nOjE0cHggMTZweDttYXJnaW4tdG9wOjZweDtkaXNwbGF5Om5vbmV9CiAgLmxvZ2NhcmQuc2hvd3tkaXNwbGF5OmJsb2NrfQogIC5sb2dyb3d7Zm9udC1zaXplOjEycHg7Ym9yZGVyLWJvdHRvbToxcHggZGFzaGVkIHZhcigtLWxpbmUpO3BhZGRpbmc6N3B4IDA7ZGlzcGxheTpmbGV4O2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwfQogIC50b2FzdHtwb3NpdGlvbjpmaXhlZDtib3R0b206MjBweDtsZWZ0OjUwJTt0cmFuc2Zvcm06dHJhbnNsYXRlWCgtNTAlKTtiYWNrZ3JvdW5kOnZhcigtLW5hdnkpO2NvbG9yOiNmZmY7cGFkZGluZzoxMXB4IDE4cHg7Ym9yZGVyLXJhZGl1czoxMHB4O2ZvbnQtc2l6ZToxM3B4O29wYWNpdHk6MDtwb2ludGVyLWV2ZW50czpub25lO3RyYW5zaXRpb246LjI1czt6LWluZGV4OjUwfQogIC50b2FzdC5zaG93e29wYWNpdHk6MX0KICAubXV0ZWR7Y29sb3I6dmFyKC0tbXV0KX0gLmJ7Zm9udC13ZWlnaHQ6NzAwfQogICN2ZW5UYWJsZS5oaWRlLWFjYyAuYWNjb2x7ZGlzcGxheTpub25lfQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5Pgo8ZGl2IGNsYXNzPSJ3cmFwIj4KCiAgPGhlYWRlciBjbGFzcz0idG9wIj4KICAgIDxkaXY+CiAgICAgIDxoMT7wn5OKIFBhbmVsIEVzdHJhdMOpZ2ljbyDCtyBBdXRvY2hhcDwvaDE+CiAgICAgIDxkaXYgY2xhc3M9InN1YiI+UmVudGFiaWxpZGFkIHJlYWwsIHB1YmxpY2lkYWQgeSBjcmVjaW1pZW50byDigJQgbXVsdGljdWVudGE8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0ic3BhY2VyIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZpZWxkIiBzdHlsZT0ibWluLXdpZHRoOjIxMHB4Ij48bGFiZWw+Q3VlbnRhPC9sYWJlbD4KICAgICAgPHNlbGVjdCBpZD0iYWNjb3VudCIgb25jaGFuZ2U9Im9uQWNjb3VudENoYW5nZSgpIj48L3NlbGVjdD4KICAgIDwvZGl2PgogICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0icmVmcmVzaFRhYigpIj7ihrsgQWN0dWFsaXphcjwvYnV0dG9uPgogIDwvaGVhZGVyPgoKICA8IS0tIEJhcnJhIGRlIGNvc3RvczogdW4gY2FzaWxsZXJvIHBvciBjdWVudGEgKGNhZGEgX0NPTVBMRVRPIGxpbmtlYWRvIGEgc3UgY3VlbnRhKSAtLT4KICA8ZGl2IGNsYXNzPSJjb3N0YmFyIiBzdHlsZT0iZmxleC1kaXJlY3Rpb246Y29sdW1uO2FsaWduLWl0ZW1zOnN0cmV0Y2g7Z2FwOjhweCI+CiAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O2ZsZXgtd3JhcDp3cmFwIj4KICAgICAgPGRpdiBjbGFzcz0iYiIgc3R5bGU9ImZvbnQtc2l6ZToxM3B4Ij7wn5KwIENvc3RvcyBwb3IgcHJvZHVjdG8gKF9DT01QTEVUTykg4oCUIHVuIGFyY2hpdm8gcG9yIGN1ZW50YTwvZGl2PgogICAgICA8c3BhbiBpZD0iY29zdHN0YXR1cyIgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLWxlZnQ6YXV0byI+PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4Ij5DYWRhIGN1ZW50YSB0aWVuZSBzdSBjYXNpbGxlcm8uIEltcG9ydMOhIGVsIF9DT01QTEVUTyBkZSBjYWRhIHVuYTogcXVlZGFuIGxhcyA2IGd1YXJkYWRhcyB5IGxpbmtlYWRhcyBwYXJhIGVsIGNydWNlIHBvciB0w610dWxvIGRlIEVzdHJhdGVnaWEuIFJlaW1wb3J0YXIgdW5hIGN1ZW50YSBzb2xvIGFjdHVhbGl6YSBlc2EuPC9kaXY+CiAgICA8ZGl2IGlkPSJjb3N0c2xvdHMiIHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGwsbWlubWF4KDIzMHB4LDFmcikpO2dhcDo4cHgiPjwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJiYW5uZXIiIGlkPSJiYW5uZXIiPgogICAgPGI+4pqZ77iPIEZhbHRhIGFjdGl2YXIgZWwgYWNjZXNvIGEgUHVibGljaWRhZCBwb3IgQVBJLjwvYj4KICAgIDxkaXYgaWQ9ImJhbm5lck1zZyIgc3R5bGU9Im1hcmdpbi10b3A6NHB4Ij48L2Rpdj4KICAgIDxvbD4KICAgICAgPGxpPkFjdGl2w6EgPGI+UHJvZHVjdCBBZHM8L2I+IGVuIGxhIGN1ZW50YSAoR2VzdGnDs24gZGUgcHVibGljYWNpb25lcyDigLogUHVibGljaWRhZCkuPC9saT4KICAgICAgPGxpPkVuIHR1IGFwcCBkZSBNZXJjYWRvIExpYnJlIERldmVsb3BlcnMsIGhhYmlsaXTDoSBlbCBwZXJtaXNvIGRlIDxiPnB1YmxpY2lkYWQgKGFkdmVydGlzaW5nKTwvYj4uPC9saT4KICAgICAgPGxpPjxiPlJlY29uZWN0w6EgbGEgY3VlbnRhPC9iPiBkZXNkZSBDb25maWd1cmFjacOzbiDihpIgQ3VlbnRhcy48L2xpPgogICAgPC9vbD4KICA8L2Rpdj4KCiAgPCEtLSBQRVNUQcORQVMgLS0+CiAgPGRpdiBjbGFzcz0idGFicyI+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIgYWN0aXZlIiBpZD0idGFiLXJlbnQiIG9uY2xpY2s9InNob3dUYWIoJ3JlbnQnKSI+8J+Xgu+4jyBHZXN0acOzbjwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiIiBpZD0idGFiLWVzdHIiIG9uY2xpY2s9InNob3dUYWIoJ2VzdHInKSI+8J+noCBFc3RyYXRlZ2lhPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItcHViIiBvbmNsaWNrPSJzaG93VGFiKCdwdWInKSI+8J+ToiBQdWJsaWNpZGFkIChBRFMpPC9idXR0b24+CiAgICA8YnV0dG9uIGNsYXNzPSJ0YWIiIGlkPSJ0YWItd2luIiBvbmNsaWNrPSJzaG93VGFiKCd3aW4nKSI+8J+PhiBHYW5hZG9yYXM8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPCEtLSA9PT09PSBUQUIgUkVOVEFCSUxJREFEID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIGFjdGl2ZSIgaWQ9InBhbmVsLXJlbnQiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5PYmpldGl2byBtZW5zdWFsICQ8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJ2ZW5fb2JqIiBzdGVwPSIxMDAwMDAwIiBzdHlsZT0id2lkdGg6MTUwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij4xMDBNIGdyYW5kZXMgwrcgNU0gY2hpY2FzPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+RmFjdHVyYSAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0idmVuX3RheCIgc3RlcD0iMC41IiBzdHlsZT0id2lkdGg6ODBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPmNhcmdvIG1lbnN1YWwgZGUgTUwgKHBhcnRlIGRlbCBjb3N0byk8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5EZXNkZTwvbGFiZWw+PGlucHV0IHR5cGU9ImRhdGUiIGlkPSJ2ZW5fZnJvbSIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkhhc3RhPC9sYWJlbD48aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9InZlbl90byIgc3R5bGU9IndpZHRoOjE1MHB4Ij48L2Rpdj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9InNhdmVWZW50YXNDZmcoKSI+R3VhcmRhciBvYmpldGl2bzwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImxvYWRWZW50YXMoKSIgdGl0bGU9IkFwbGljYXIgZWwgZmlsdHJvIHkgdHJhZXIgbGFzIHZlbnRhcyI+8J+UjSBCdXNjYXI8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImRvd25sb2FkVmVudGFzWGxzeCgpIj7irIcgRGVzY2FyZ2FyIFhMU1g8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjEycHg7bWFyZ2luLXRvcDo4cHgiPkVsZWfDrSBlbCBwZXLDrW9kbyB5IHRvY8OhIDxiPvCflI0gQnVzY2FyPC9iPiAobm8gYnVzY2Egc29sbykuIEdhbmFuY2lhID0gcHJlY2lvIOKIkiBjb21pc2nDs24gcmVhbCDiiJIgZW52w61vIHJlYWwg4oiSIDxiPmltcHVlc3RvIHJlYWwgZGUgTUw8L2I+IOKIkiBjb3N0byDiiJIgPGI+ZmFjdHVyYTwvYj4uIEVsIDxiPmltcHVlc3RvPC9iPiBlcyBsbyBxdWUgTUwgcmV0aWVuZSBlbiBjYWRhIHZlbnRhOyBsYSA8Yj5mYWN0dXJhPC9iPiAoJSBkZSBhcnJpYmEpIGVzIGVsIGNhcmdvIG1lbnN1YWwgZGUgTUwgeSBjdWVudGEgY29tbyBwYXJ0ZSBkZWwgY29zdG8uIFRyYWUgPGI+dG9kYXM8L2I+IGxhcyB2ZW50YXMgbWVub3MgY2FuY2VsYWRhcyB5IHJlY2xhbW9zIGNlcnJhZG9zIGNvbiBkZXZvbHVjacOzbi4gRWwgY29zdG8gcXVlZGEgPGI+Y29uZ2VsYWRvPC9iPiBhbCBtb21lbnRvIGRlIGxhIHZlbnRhLjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJrcGlzIiBpZD0idmVuX2twaXMiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9InZlbl9wcm9ncmVzc19jYXJkIiBzdHlsZT0iZGlzcGxheTpub25lIj48ZGl2IGlkPSJ2ZW5fcHJvZ3Jlc3MiPjwvZGl2PjwvZGl2PgogICAgPGRpdiBjbGFzcz0idGFibGVjYXJkIj48ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+CiAgICAgIDx0YWJsZSBpZD0idmVuVGFibGUiIGNsYXNzPSJoaWRlLWFjYyIgc3R5bGU9Im1pbi13aWR0aDoxMjAwcHgiPgogICAgICAgIDx0aGVhZD48dHI+CiAgICAgICAgICA8dGggZGF0YS1rPSJ0aXRsZSIgb25jbGljaz0ic29ydFZlbigndGl0bGUnKSI+VmVudGE8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJhY2NvbCIgZGF0YS1rPSJhY2NvdW50X25hbWUiIG9uY2xpY2s9InNvcnRWZW4oJ2FjY291bnRfbmFtZScpIj5DdWVudGE8L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0ic3RhdHVzIiBvbmNsaWNrPSJzb3J0VmVuKCdzdGF0dXMnKSI+RXN0YWRvIGVudsOtbzwvdGg+CiAgICAgICAgICA8dGggZGF0YS1rPSJzdG9jayIgb25jbGljaz0ic29ydFZlbignc3RvY2snKSI+U3RvY2s8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0icmV2ZW51ZSIgb25jbGljaz0ic29ydFZlbigncmV2ZW51ZScpIj5QcmVjaW88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iZmVlIiBvbmNsaWNrPSJzb3J0VmVuKCdmZWUnKSI+Q29taXNpw7NuPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImVudmlvIiBvbmNsaWNrPSJzb3J0VmVuKCdlbnZpbycpIj5FbnbDrW88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0idGF4IiBvbmNsaWNrPSJzb3J0VmVuKCd0YXgnKSIgdGl0bGU9IkltcHVlc3RvIHJlYWwgcXVlIE1MIHJldGllbmUgZW4gbGEgdmVudGEgKHJlc3BhbGRvOiAlIHNpIG5vIHZpZW5lKSI+SW1wdWVzdG9zPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9InF1ZWRhIiBvbmNsaWNrPSJzb3J0VmVuKCdxdWVkYScpIiB0aXRsZT0iUHJlY2lvIOKIkiBjb21pc2nDs24g4oiSIGVudsOtbyDiiJIgaW1wdWVzdG9zIj5DdcOhbnRvIHF1ZWRhPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9ImNvc3QiIG9uY2xpY2s9InNvcnRWZW4oJ2Nvc3QnKSI+Q29zdG88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iZmFjdHVyYSIgb25jbGljaz0ic29ydFZlbignZmFjdHVyYScpIiB0aXRsZT0iQ2FyZ28gbWVuc3VhbCBkZSBNTCAocGFydGUgZGVsIGNvc3RvKSI+RmFjdHVyYTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJuZXQiIG9uY2xpY2s9InNvcnRWZW4oJ25ldCcpIj5HYW5hbmNpYTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJtYXJnaW5QY3QiIG9uY2xpY2s9InNvcnRWZW4oJ21hcmdpblBjdCcpIj5NYXJnZW48L3RoPgogICAgICAgIDwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9InZlbl9ib2R5Ij48dHI+PHRkIGNvbHNwYW49IjEyIiBjbGFzcz0ibG9hZGluZyI+RWxlZ8OtIGVsIHBlcsOtb2RvIHkgdG9jw6Eg8J+UjSBCdXNjYXIgcGFyYSB0cmFlciBsYXMgdmVudGFzIGRlIGVzdGEgY3VlbnRhLjwvdGQ+PC90cj48L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+PC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIEVTVFJBVEVHSUEgKGVsIGNlcmVicm8pID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIiBpZD0icGFuZWwtZXN0ciI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGRpdiBjbGFzcz0iY2ZncmlkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk1hcmdlbiAiYnVlbm8iIOKJpSAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZXN0cl9oaWdoIiBzdGVwPSIwLjUiIHZhbHVlPSIxMiIgc3R5bGU9IndpZHRoOjkwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij5idWVuIG1hcmdlbjwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPlZlbmRlIHNpIHZlbnRhcyDiiaU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJlc3RyX21pbnNhbGVzIiBzdGVwPSIxIiB2YWx1ZT0iMSIgc3R5bGU9IndpZHRoOjgwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij52ZWxvY2lkYWQ8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5EZW1hbmRhIHNpIHZpc2l0YXMg4omlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZXN0cl9taW52aXMiIHN0ZXA9IjUiIHZhbHVlPSIyMCIgc3R5bGU9IndpZHRoOjkwcHgiPjxzcGFuIGNsYXNzPSJoaW50Ij5oYXkgaW50ZXLDqXM8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5NdWNobyB0csOhZmljbyDiiaU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJlc3RyX2hvdHZpcyIgc3RlcD0iNSIgdmFsdWU9IjYwIiBzdHlsZT0id2lkdGg6OTBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPm5vIGNvbnZpZXJ0ZeKGkmFqdXN0YXI8L3NwYW4+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5ST0FTIG9iamV0aXZvPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iZXN0cl9yb2FzIiBzdGVwPSIwLjUiIHZhbHVlPSI1IiBzdHlsZT0id2lkdGg6ODBweCI+PHNwYW4gY2xhc3M9ImhpbnQiPnBhcmEgY2FsY3VsYXIgQURTPC9zcGFuPjwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImxvYWRFc3RyYXRlZ2lhKCkiPvCfp6AgQ2FsY3VsYXIgZXN0cmF0ZWdpYTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0icmVmaW5hck1hcmdlbmVzKCkiIHRpdGxlPSJUcmFlIGxhIGRhdGEgcmVhbCBkZSBjYWRhIHB1YmxpY2FjacOzbiBkZXNkZSBNTDogdMOtdHVsbywgcHJlY2lvIGNvbiBwcm9tbywgdmVudGFzLCB2aXNpdGFzLCBleHBvc2ljacOzbiB5IGVsIGNvc3RvIGV4YWN0byAoc2ltdWxhciBjb3N0b3MpIj7wn46vIEVucmlxdWVjZXIgY29uIGRhdG9zIGRlIE1MPC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJkb3dubG9hZEVzdHJhdGVnaWFYbHN4KCkiPuKshyBEZXNjYXJnYXIgWExTWDwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tdG9wOjhweCI+TW90b3IgZGUgcG9zaWNpb25hbWllbnRvOiBjcnV6YSA8Yj50b2RhcyBsYXMgY3VlbnRhczwvYj4gcG9yIHTDrXR1bG8geSBjbGFzaWZpY2EgY2FkYSBwdWJsaWNhY2nDs24gcG9yIDxiPm1hcmdlbiDDlyB2ZW50YXMgw5cgdmlzaXRhcyDDlyBjb252ZXJzacOzbjwvYj4sIGNvbiBsYSBqdWdhZGEgcGFyYSBjb252ZXJ0aXJsYSBlbiB2ZW50YS4gRWwgbWFyZ2VuIHNhbGUgZGVsIDxiPnNpbXVsYWRvciBkZSBNTDwvYj4gYWwgPGI+cHJlY2lvIHJlYWwgY29uIHByb21vPC9iPiAo8J+UtSksIGZhbGxiYWNrIGRlIGxpc3RhICjwn5+gKS4gPGI+SW1wb3J0YW50ZTo8L2I+IGxvcyBkYXRvcyByZWFsZXMgKHTDrXR1bG8sIHZlbnRhcywgdmlzaXRhcywgcHJlY2lvIGNvbiBwcm9tbykgc2FsZW4gZGUgTUwgc8OzbG8gY3VhbmRvIHRvY8OhcyA8Yj7wn46vIEVucmlxdWVjZXI8L2I+IOKAlCBoYWNlbG8gcG9yIGN1ZW50YS4gRWwgPGI+InZlbmRlIjwvYj4gbWlyYSBsYXMgPGI+dmVudGFzIGRlIGxvcyDDumx0aW1vcyAzIG1lc2VzPC9iPi48L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxoMz7impnvuI8gT2JqZXRpdm8geSBmYWN0dXJhIHBvciBjdWVudGE8L2gzPgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206MTBweCI+RWwgPGI+b2JqZXRpdm8gbWVuc3VhbDwvYj4gZGUgY2FkYSBjdWVudGEgeSBzdSA8Yj4lIGRlIGZhY3R1cmE8L2I+IChjYXJnbyBtZW5zdWFsIGRlIE1MIHF1ZSBjdWVudGEgY29tbyBjb3N0bykuIENvbiBlc3RvIGVsIHNpc3RlbWEgY2FsY3VsYSBlbCBtYXJnZW4gcmVhbCwgZWwgYXZhbmNlIG1lcyBjb3JyaWRvIHkgY3XDoW50byBpbnZlcnRpciBlbiBBRFMuPC9kaXY+CiAgICAgIDxkaXYgaWQ9ImVzdHJfYWNjdGNmZyIgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMzAwcHgsMWZyKSk7Z2FwOjEwcHgiPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0iZXN0cl9wcm9ncmVzc19jYXJkIiBzdHlsZT0iZGlzcGxheTpub25lO2JvcmRlci1jb2xvcjp2YXIoLS1uYXZ5KSI+CiAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7ZmxleC13cmFwOndyYXAiPgogICAgICAgIDxiIHN0eWxlPSJmb250LXNpemU6MTNweDtjb2xvcjp2YXIoLS1uYXZ5KSIgaWQ9ImVzdHJfcHJvZ190eHQiPkVucmlxdWVjaWVuZG/igKY8L2I+CiAgICAgICAgPHNwYW4gY2xhc3M9Im11dGVkIiBpZD0iZXN0cl9wcm9nX3N1YiIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4Ij48L3NwYW4+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJzdG9wRW5yaXF1ZWNlcigpIiBzdHlsZT0ibWFyZ2luLWxlZnQ6YXV0byIgaWQ9ImVzdHJfc3RvcF9idG4iPuKPuSBEZXRlbmVyPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJiYXIiIHN0eWxlPSJtYXJnaW4tdG9wOjhweCI+PGkgaWQ9ImVzdHJfcHJvZ19iYXIiIHN0eWxlPSJ3aWR0aDowJTtiYWNrZ3JvdW5kOnZhcigtLW5hdnkpIj48L2k+PC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImtwaXMiIGlkPSJlc3RyX2twaXMiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9ImVzdHJfcGxhbl9jYXJkIiBzdHlsZT0iZGlzcGxheTpub25lIj4KICAgICAgPGgzPvCfk4sgUGxhbiBkZSBhY2Npw7NuIOKAlCBxdcOpIGhhY2VyLCBwb3IgcHJpb3JpZGFkPC9oMz4KICAgICAgPGRpdiBpZD0iZXN0cl9wbGFuIiBzdHlsZT0iZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoYXV0by1maWxsLG1pbm1heCgyMjBweCwxZnIpKTtnYXA6MTBweCI+PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjExcHg7bWFyZ2luLXRvcDo4cHgiPlRvY8OhIHVuYSBhY2Npw7NuIHBhcmEgZmlsdHJhciBsYSB0YWJsYSBkZSBhYmFqby4gRWwgb3JkZW4gZXMgcG9yIGltcGFjdG86IHByaW1lcm8gZXNjYWxhciB5IHByb21vdmVyLjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0iZXN0cl9hY2N0c19jYXJkIiBzdHlsZT0iZGlzcGxheTpub25lIj4KICAgICAgPGgzPkN1ZW50YXMgaGFjaWEgc3Ugb2JqZXRpdm88L2gzPgogICAgICA8ZGl2IGNsYXNzPSJ0YWJsZXNjcm9sbCI+PHRhYmxlIHN0eWxlPSJtaW4td2lkdGg6MTAwMHB4IiBpZD0iZXN0ckFjY3RUYWJsZSI+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+Q3VlbnRhPC90aD48dGggY2xhc3M9Im51bSI+T2JqZXRpdm8vbWVzPC90aD48dGggY2xhc3M9Im51bSI+UHJveS4gbWVzIGNvcnJpZG88L3RoPjx0aCBjbGFzcz0ibnVtIj5BdmFuY2U8L3RoPjx0aCBjbGFzcz0ibnVtIj5GYWx0YW50ZTwvdGg+PHRoIGNsYXNzPSJudW0iPvCfkrAgQURTIHN1Z2VyaWRvL21lczwvdGg+PHRoIGNsYXNzPSJudW0iPkVucmlxdWVjLjwvdGg+PHRoIGNsYXNzPSJudW0iPuKtkDwvdGg+PHRoIGNsYXNzPSJudW0iPvCfjq88L3RoPjx0aCBjbGFzcz0ibnVtIj7wn5GRPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJlc3RyX2FjY3RzIj48L3Rib2R5PgogICAgICA8L3RhYmxlPjwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJsZWdlbmQiIGlkPSJlc3RyX2xlZ2VuZCIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+CiAgICAgIDxzcGFuPjxiPuKtkCBFc3RyZWxsYTo8L2I+IHZlbmRpw7MgKMO6bHRpbW9zIDMgbWVzZXMpICsgYnVlbiBtYXJnZW4g4oaSIGVzY2FsYXIgQURTPC9zcGFuPgogICAgICA8c3Bhbj48Yj7wn5qAIFByb21lc2E6PC9iPiBidWVuIG1hcmdlbiArIGRlbWFuZGEsIG5vIHZlbmRlIOKGkiBBRFMgKyBwcm9tbzwvc3Bhbj4KICAgICAgPHNwYW4+PGI+8J+UpyBBanVzdGFyOjwvYj4gbXVjaG8gdHLDoWZpY28sIG5vIGNvbnZpZXJ0ZSDihpIgcHJlY2lvL3B1YmxpY2FjacOzbiAoTk8gQURTKTwvc3Bhbj4KICAgICAgPHNwYW4+PGI+8J+QhCBWYWNhOjwvYj4gdmVuZGUgKyBtYXJnZW4gZmxhY28g4oaSIG9wdGltaXphciBwcmVjaW88L3NwYW4+CiAgICAgIDxzcGFuPjxiPvCfkqQgRHVybWllbnRlOjwvYj4gc2luIGRlbWFuZGEg4oaSIHN0b2NrIDAgbyBzdWJpciBwcmVjaW88L3NwYW4+CiAgICAgIDxzcGFuPjxiPvCfjLEgT3Jnw6FuaWNvOjwvYj4gZHVwbGljYWRvLCBvdHJhIGN1ZW50YSBsaWRlcmE8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImZpbHRlcnMiIGlkPSJlc3RyX2ZpbHRlcnMiIHN0eWxlPSJkaXNwbGF5Om5vbmU7bWFyZ2luLWJvdHRvbToxMHB4Ij4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtc2VnPSJlc3RyZWxsYSIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIj7irZAgRXN0cmVsbGE8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLXNlZz0icHJvbWVzYSIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIj7wn5qAIFByb21lc2E8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLXNlZz0iYWp1c3RhciIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIj7wn5SnIEFqdXN0YXI8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLXNlZz0idmFjYSIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIj7wn5CEIFZhY2E8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLXNlZz0iZHVybWllbnRlIiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiPvCfkqQgRHVybWllbnRlPC9zcGFuPgogICAgICA8c3BhbiBjbGFzcz0iY2hpcCIgZGF0YS1zZWc9ImVucmljaGVkT25seSIgb25jbGljaz0idG9nZ2xlU2VnKHRoaXMpIiB0aXRsZT0iU29sbyBsb3MgZW5yaXF1ZWNpZG9zIGNvbiBkYXRhIHJlYWwgZGUgTUwiPuKchSBTb2xvIGVucmlxdWVjaWRvczwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAiIGRhdGEtc2VnPSJkdXBPbmx5IiBvbmNsaWNrPSJ0b2dnbGVTZWcodGhpcykiIHRpdGxlPSJTb2xvIHByb2R1Y3RvcyByZXBldGlkb3MgZW50cmUgY3VlbnRhcyI+8J+UgSBTb2xvIGR1cGxpY2Fkb3M8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRhYmxlY2FyZCI+PGRpdiBjbGFzcz0idGFibGVzY3JvbGwiPgogICAgICA8dGFibGUgaWQ9ImVzdHJUYWJsZSIgc3R5bGU9Im1pbi13aWR0aDoxMjgwcHgiPgogICAgICAgIDx0aGVhZD48dHI+CiAgICAgICAgICA8dGggZGF0YS1rPSJ0aXRsZSIgb25jbGljaz0ic29ydEVzdHIoJ3RpdGxlJykiPlByb2R1Y3RvPC90aD4KICAgICAgICAgIDx0aCBkYXRhLWs9ImFjY291bnRfbmFtZSIgb25jbGljaz0ic29ydEVzdHIoJ2FjY291bnRfbmFtZScpIj5DdWVudGE8L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0ic2VnbWVudCIgb25jbGljaz0ic29ydEVzdHIoJ3NlZ21lbnQnKSI+U2VnbWVudG88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ic2NvcmUiIG9uY2xpY2s9InNvcnRFc3RyKCdzY29yZScpIiB0aXRsZT0iUG90ZW5jaWFsIGRlIGFjY2nDs24gKG1hcmdlbiDDlyBkZW1hbmRhIMOXIGNvbnZlcnNpw7NuKSI+UG90ZW5jaWFsPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBkYXRhLWs9Im1hcmdpbiIgb25jbGljaz0ic29ydEVzdHIoJ21hcmdpbicpIj5NYXJnZW48L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0icHJpY2UiIG9uY2xpY2s9InNvcnRFc3RyKCdwcmljZScpIj5QcmVjaW88L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0ic29sZCIgb25jbGljaz0ic29ydEVzdHIoJ3NvbGQnKSIgdGl0bGU9IlVuaWRhZGVzIHZlbmRpZGFzIGVuIGxvcyDDumx0aW1vcyAzIG1lc2VzIChkZWZpbmUgc2kgJ3ZlbmRlJykiPlZlbnRhcyAzbTwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgZGF0YS1rPSJ2aXNpdHMiIG9uY2xpY2s9InNvcnRFc3RyKCd2aXNpdHMnKSIgdGl0bGU9IlZpc2l0YXMgYWN1bXVsYWRhcyBkZSBsYSBwdWJsaWNhY2nDs24iPlZpc2l0YXM8L3RoPgogICAgICAgICAgPHRoIGNsYXNzPSJudW0iIGRhdGEtaz0iY29udiIgb25jbGljaz0ic29ydEVzdHIoJ2NvbnYnKSIgdGl0bGU9IkNvbnZlcnNpw7NuID0gdmVudGFzIC8gdmlzaXRhcyI+Q29udi48L3RoPgogICAgICAgICAgPHRoIGRhdGEtaz0iaXNMZWFkZXIiIG9uY2xpY2s9InNvcnRFc3RyKCdpc0xlYWRlcicpIj5Mw61kZXI8L3RoPgogICAgICAgICAgPHRoPkFjY2nDs248L3RoPgogICAgICAgIDwvdHI+PC90aGVhZD4KICAgICAgICA8dGJvZHkgaWQ9ImVzdHJfYm9keSI+PHRyPjx0ZCBjb2xzcGFuPSIxMSIgY2xhc3M9ImxvYWRpbmciPlRvY8OhICLwn6egIENhbGN1bGFyIGVzdHJhdGVnaWEiIHBhcmEgY3J1emFyIGxhcyBjdWVudGFzLjwvdGQ+PC90cj48L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+PC9kaXY+CgogICAgPCEtLSA9PT09PSBBQ1RVQUxJWkFET1IgREUgUFJFQ0lPUyBNQVNJVk8gPT09PT0gLS0+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0iZXN0cl9wcmVjaW9zX2NhcmQiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ym9yZGVyOjJweCBzb2xpZCB2YXIoLS1uYXZ5KSI+CiAgICAgIDxoMz7wn5KyIEFjdHVhbGl6YWRvciBkZSBwcmVjaW9zIG1hc2l2byDigJQgcG9yIGVzdHJhdGVnaWE8L2gzPgogICAgICA8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206MTBweCI+RGVmaW7DrSB1bmEgcmVnbGEgcG9yIGFjY2nDs24uIDxiPk1hcmdlbiBvYmpldGl2bzwvYj46IGVsIHNpc3RlbWEgY2FsY3VsYSBlbCBwcmVjaW8gY29uIGVsIGNvc3RvIGV4YWN0byBkZSBNTC4gPGI+QWp1c3RlICU8L2I+OiBzdWJlL2JhamEgZWwgcHJlY2lvIGFjdHVhbCBlc2UgcG9yY2VudGFqZS4gRGVzcHXDqXMgdmVzIGxhIDxiPnZpc3RhIHByZXZpYTwvYj4geSBhcHJvYsOhcyBhbnRlcyBkZSBtYW5kYXIgYSBNTC4gU29sbyBmdW5jaW9uYSBjb24gcHJvZHVjdG9zIDxiPmVucmlxdWVjaWRvczwvYj4uPC9kaXY+CiAgICAgIDxkaXYgaWQ9InByZWNpb19ydWxlcyIgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KGF1dG8tZmlsbCxtaW5tYXgoMzIwcHgsMWZyKSk7Z2FwOjEwcHgiPjwvZGl2PgogICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7ZmxleC13cmFwOndyYXA7bWFyZ2luLXRvcDoxMnB4O2FsaWduLWl0ZW1zOmNlbnRlciI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icHJpbWFyeSIgb25jbGljaz0icHJldmlld1ByZWNpb3MoKSI+8J+RgSBWaXN0YSBwcmV2aWE8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImFwbGljYXJQcmVjaW9zKCkiIGlkPSJwcmVjaW9fYXBwbHlfYnRuIiBzdHlsZT0iZGlzcGxheTpub25lO2JvcmRlci1jb2xvcjp2YXIoLS1ncmVlbik7Y29sb3I6IzE2NjUzNCI+4pyFIEFwbGljYXIgYSBNTCAoPHNwYW4gaWQ9InByZWNpb19hcHBseV9uIj4wPC9zcGFuPik8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImRvd25sb2FkUHJlY2lvc1hsc3goKSIgaWQ9InByZWNpb194bHN4X2J0biIgc3R5bGU9ImRpc3BsYXk6bm9uZSI+4qyHIFhMU1g8L2J1dHRvbj4KICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiIGlkPSJwcmVjaW9fcHJldl9pbmZvIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPjwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIiBzdHlsZT0ibWFyZ2luLXRvcDoxMnB4Ij48dGFibGUgaWQ9InByZWNpb1RhYmxlIiBzdHlsZT0ibWluLXdpZHRoOjkwMHB4O2Rpc3BsYXk6bm9uZSI+CiAgICAgICAgPHRoZWFkPjx0cj48dGg+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0icHJlY2lvX2FsbCIgY2hlY2tlZCBvbmNsaWNrPSJ0b2dnbGVQcmVjaW9BbGwodGhpcykiPjwvdGg+PHRoPlByb2R1Y3RvPC90aD48dGg+Q3VlbnRhPC90aD48dGg+QWNjacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbyBhY3R1YWw8L3RoPjx0aCBjbGFzcz0ibnVtIj5QcmVjaW8gbnVldm88L3RoPjx0aCBjbGFzcz0ibnVtIj7OlCU8L3RoPjx0aCBjbGFzcz0ibnVtIj5NYXJnZW4gYWN0dWFsPC90aD48dGggY2xhc3M9Im51bSI+TWFyZ2VuIG51ZXZvPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJwcmVjaW9fYm9keSI+PC90Ym9keT4KICAgICAgPC90YWJsZT48L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tID09PT09IFRBQiBQVUJMSUNJREFEID09PT09IC0tPgogIDxkaXYgY2xhc3M9InBhbmVsIiBpZD0icGFuZWwtcHViIj4KICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICA8aDM+Q29uZmlndXJhY2nDs24gZGUgZGVjaXNpw7NuICh0dSBtYXJnZW4gbWFuZGEpPC9oMz4KICAgICAgPGRpdiBjbGFzcz0iY2ZncmlkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk1hcmdlbiBuZXRvICU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJjZmdfbWFyZ2luIiBzdGVwPSIwLjUiIG1pbj0iMCI+PHNwYW4gY2xhc3M9ImhpbnQiPmVxdWlsaWJyaW8gZGUgQUNPUzwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkFDT1Mgb2JqZXRpdm8gJTwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImNmZ190YXJnZXQiIHN0ZXA9IjAuNSIgbWluPSIwIj48c3BhbiBjbGFzcz0iaGludCI+bWV0YSByZW50YWJsZTwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPk3DrW4uIGNsaWNzPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iY2ZnX2NsaWNrcyIgc3RlcD0iMSIgbWluPSIwIj48c3BhbiBjbGFzcz0iaGludCI+cGFyYSBkZWNpZGlyPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+VmVudGFuYSAoZMOtYXMpPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iY2ZnX3dpbmRvdyIgc3RlcD0iMSIgbWluPSIxIiBtYXg9IjkwIj48c3BhbiBjbGFzcz0iaGludCI+bcOheCA5MDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkVudsOtbyBncmF0aXMgZGVzZGUgJDwvbGFiZWw+PGlucHV0IHR5cGU9Im51bWJlciIgaWQ9ImNmZ19zaGlwIiBzdGVwPSIxMDAwIiBtaW49IjAiPjxzcGFuIGNsYXNzPSJoaW50Ij51bWJyYWw8L3NwYW4+PC9kaXY+CiAgICAgICAgPGJ1dHRvbiBvbmNsaWNrPSJzYXZlQ29uZmlnKCkiPkd1YXJkYXI8L2J1dHRvbj4KICAgICAgICA8ZGl2IGNsYXNzPSJhdXRvdGFnIHBpbGwgcC1ncmV5IiBpZD0iYXV0b3RhZyI+QXV0by1wYXVzYTog4oCUPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJrcGlzIiBpZD0ia3BpcyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJsZWdlbmQiPgogICAgICA8c3Bhbj48aSBjbGFzcz0iZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1ncmVlbikiPjwvaT4gPGI+RXNjYWxhcjwvYj48L3NwYW4+CiAgICAgIDxzcGFuPjxpIGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLWFtYmVyKSI+PC9pPiA8Yj5NYW50ZW5lcjwvYj48L3NwYW4+CiAgICAgIDxzcGFuPjxpIGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOiMzYjgyZjYiPjwvaT4gPGI+SnVudGFyIGRhdG9zPC9iPjwvc3Bhbj4KICAgICAgPHNwYW4+PGkgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVkKSI+PC9pPiA8Yj5QYXVzYXI8L2I+PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJmaWx0ZXJzIj4KICAgICAgPHNwYW4gY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS1tdXQpIj5GaWx0cmFyOjwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtYWN0PSJFU0NBTEFSIiBvbmNsaWNrPSJ0b2dnbGVDaGlwKHRoaXMpIj7wn5+iIEVzY2FsYXI8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLWFjdD0iTUFOVEVORVIiIG9uY2xpY2s9InRvZ2dsZUNoaXAodGhpcykiPvCfn6EgTWFudGVuZXI8L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGlwIG9uIiBkYXRhLWFjdD0iSlVOVEFSX0RBVE9TIiBvbmNsaWNrPSJ0b2dnbGVDaGlwKHRoaXMpIj7wn5S1IEp1bnRhciBkYXRvczwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImNoaXAgb24iIGRhdGEtYWN0PSJQQVVTQVIiIG9uY2xpY2s9InRvZ2dsZUNoaXAodGhpcykiPvCflLQgUGF1c2FyPC9zcGFuPgogICAgICA8c2VsZWN0IGlkPSJzdGF0dXNGaWx0ZXIiIG9uY2hhbmdlPSJyZW5kZXIoKSI+PG9wdGlvbiB2YWx1ZT0iYWxsIj5Ub2RvcyBsb3MgZXN0YWRvczwvb3B0aW9uPjxvcHRpb24gdmFsdWU9ImFjdGl2ZSI+U29sbyBhY3RpdmFzPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0icGF1c2VkIj5Tb2xvIHBhdXNhZGFzPC9vcHRpb24+PC9zZWxlY3Q+CiAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0ic2VhcmNoIiBwbGFjZWhvbGRlcj0iQnVzY2FyIHBvciBub21icmUgbyBJRCBkZSBjYW1wYcOxYeKApiIgb25pbnB1dD0icmVuZGVyKCkiPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiPjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj4KICAgICAgPHRhYmxlPgogICAgICAgIDx0aGVhZD48dHI+CiAgICAgICAgICA8dGggb25jbGljaz0ic29ydEJ5KCduYW1lJykiPkNhbXBhw7FhPC90aD48dGggb25jbGljaz0ic29ydEJ5KCdzdGF0dXMnKSI+RXN0YWRvPC90aD4KICAgICAgICAgIDx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ2Nvc3QnKSI+SW52ZXJzacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iIG9uY2xpY2s9InNvcnRCeSgncmV2ZW51ZScpIj5WZW50YXMgcHViLjwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCdhY29zJykiPkFDT1M8L3RoPjx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ2JyZWFrZXZlbkFjb3MnKSI+RXF1aWxpYnJpbzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCduZXRQcm9maXQnKSI+R2FuYW5jaWE8L3RoPjx0aCBjbGFzcz0ibnVtIiBvbmNsaWNrPSJzb3J0QnkoJ3JvYXMnKSI+Uk9BUzwvdGg+CiAgICAgICAgICA8dGggY2xhc3M9Im51bSIgb25jbGljaz0ic29ydEJ5KCdjbGlja3MnKSI+Q2xpY3M8L3RoPjx0aCBvbmNsaWNrPSJzb3J0QnkoJ2FjdGlvbicpIj5BY2Npw7NuPC90aD48dGg+TW90aXZvPC90aD48dGg+PC90aD4KICAgICAgICA8L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJ0Ym9keSI+PHRyPjx0ZCBjb2xzcGFuPSIxMiIgY2xhc3M9ImxvYWRpbmciPkVsZWfDrSB1bmEgY3VlbnRh4oCmPC90ZD48L3RyPjwvdGJvZHk+CiAgICAgIDwvdGFibGU+CiAgICA8L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJwcmltYXJ5IiBvbmNsaWNrPSJydW5Ob3coKSI+4pa2IENvcnJlciBhbsOhbGlzaXMgQURTPC9idXR0b24+CiAgICAgIDxidXR0b24gb25jbGljaz0idG9nZ2xlTG9nKCkiPvCfk5wgw5psdGltYXMgY29ycmlkYXM8L2J1dHRvbj4KICAgICAgPHNwYW4gY2xhc3M9Im11dGVkIiBpZD0ibGFzdFJ1biI+PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJsb2djYXJkIiBpZD0ibG9nY2FyZCI+PC9kaXY+CiAgPC9kaXY+CgogIDwhLS0gPT09PT0gVEFCIEdBTkFET1JBUyA9PT09PSAtLT4KICA8ZGl2IGNsYXNzPSJwYW5lbCIgaWQ9InBhbmVsLXdpbiI+CiAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTJweDttYXJnaW4tYm90dG9tOjEwcHgiPkNydXphIHR1IG1hcmdlbiAoZGVsIEV4Y2VsKSBjb24gZGF0b3MgZW4gdml2byBkZSBNTDogc29sbyBhY3RpdmFzLCBjb24gc3RvY2sgeSBjb24gdmVudGFzLiBDb3Bpw6FzIGxvcyBJRHMgeSBsb3MgcGVnw6FzIGFsIGNyZWFyIGxhIGNhbXBhw7FhIGVuIE1lcmNhZG8gTGlicmUuPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNmZ3JpZCI+CiAgICAgICAgPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5NYXJnZW4gbcOtbmltbyAlPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0id2luX21hcmdpbiIgdmFsdWU9IjEyIiBzdGVwPSIxIiBzdHlsZT0id2lkdGg6MTAwcHgiPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWw+VmVudGFzIG3DrW5pbWFzPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0id2luX3NhbGVzIiB2YWx1ZT0iMSIgc3RlcD0iMSIgc3R5bGU9IndpZHRoOjEwMHB4Ij48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWVsZCI+PGxhYmVsPkNhbnRpZGFkPC9sYWJlbD48aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0id2luX2xpbWl0IiB2YWx1ZT0iNDAiIHN0ZXA9IjEwIiBzdHlsZT0id2lkdGg6MTAwcHgiPjwvZGl2PgogICAgICAgIDxidXR0b24gY2xhc3M9InByaW1hcnkiIG9uY2xpY2s9ImxvYWRXaW5uZXJzKCkiPkJ1c2NhciBnYW5hZG9yYXM8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIG9uY2xpY2s9ImNvcHlXaW5uZXJzKCkiPvCfk4sgQ29waWFyIElEczwvYnV0dG9uPgogICAgICAgIDxidXR0b24gb25jbGljaz0iY3N2V2lubmVycygpIj7irIcgQ1NWPC9idXR0b24+CiAgICAgICAgPHNwYW4gY2xhc3M9Im11dGVkIiBpZD0id2luU3RhdHVzIj48L3NwYW4+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ0YWJsZWNhcmQiPjxkaXYgY2xhc3M9InRhYmxlc2Nyb2xsIj4KICAgICAgPHRhYmxlIHN0eWxlPSJtaW4td2lkdGg6NjQwcHgiPgogICAgICAgIDx0aGVhZD48dHI+PHRoPlB1YmxpY2FjacOzbjwvdGg+PHRoIGNsYXNzPSJudW0iPk1hcmdlbjwvdGg+PHRoIGNsYXNzPSJudW0iPlByZWNpbzwvdGg+PHRoIGNsYXNzPSJudW0iPlN0b2NrPC90aD48dGggY2xhc3M9Im51bSI+VmVudGFzPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgPHRib2R5IGlkPSJ3aW5Cb2R5Ij48dHI+PHRkIGNvbHNwYW49IjUiIGNsYXNzPSJsb2FkaW5nIj5FbGVnw60gY3JpdGVyaW9zIHkgdG9jw6EgIkJ1c2NhciBnYW5hZG9yYXMiLjwvdGQ+PC90cj48L3Rib2R5PgogICAgICA8L3RhYmxlPgogICAgPC9kaXY+PC9kaXY+CiAgPC9kaXY+Cgo8L2Rpdj4KPGRpdiBjbGFzcz0idG9hc3QiIGlkPSJ0b2FzdCI+PC9kaXY+Cgo8c2NyaXB0PgondXNlIHN0cmljdCc7CmxldCBTVEFURT17cm93czpbXSxjZmc6e30sc29ydEtleTonY29zdCcsc29ydERpcjotMSxhY3RzOntFU0NBTEFSOjEsTUFOVEVORVI6MSxKVU5UQVJfREFUT1M6MSxQQVVTQVI6MX19OwpsZXQgVkVOPW51bGwsIFdJTk5FUlM9W10sIFNUUkFUPW51bGwsIENVUlRBQj0ncmVudCc7CmNvbnN0ICQ9aWQ9PmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKY29uc3QgZm10TW9uZXk9bj0+KG49PW51bGx8fGlzTmFOKG4pKT8n4oCUJzonJCcrTWF0aC5yb3VuZChuKS50b0xvY2FsZVN0cmluZygnZXMtQVInKTsKY29uc3QgZm10UGN0PW49PihuPT1udWxsfHxpc05hTihuKSk/J+KAlCc6bi50b0ZpeGVkKDEpKyclJzsKY29uc3QgZm10WD1uPT4obj09bnVsbHx8aXNOYU4obikpPyfigJQnOm4udG9GaXhlZCgxKSsneCc7CmZ1bmN0aW9uIHRvYXN0KG0pe2NvbnN0IHQ9JCgndG9hc3QnKTt0LnRleHRDb250ZW50PW07dC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7c2V0VGltZW91dCgoKT0+dC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93JyksMjYwMCk7fQpmdW5jdGlvbiBlc2Mocyl7cmV0dXJuIFN0cmluZyhzPT1udWxsPycnOnMpLnJlcGxhY2UoL1smPD4iXS9nLGM9Pih7JyYnOicmYW1wOycsJzwnOicmbHQ7JywnPic6JyZndDsnLCciJzonJnF1b3Q7J31bY10pKTt9CmFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLG9wdHMpewogIGNvbnN0IHI9YXdhaXQgZmV0Y2gocGF0aCxPYmplY3QuYXNzaWduKHtoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9fSxvcHRzKSk7CiAgaWYoci5zdGF0dXM9PT00MDEpe2xvY2F0aW9uLmhyZWY9Jy8nO3JldHVybiBuZXcgUHJvbWlzZSgoKT0+e30pO30KICBjb25zdCBkPWF3YWl0IHIuanNvbigpLmNhdGNoKCgpPT4oe30pKTsKICBpZighci5vaykgdGhyb3cgKGQuZXJyb3I/ZDp7ZXJyb3I6J0hUVFAgJytyLnN0YXR1c30pOwogIHJldHVybiBkOwp9CgpmdW5jdGlvbiBzaG93VGFiKHQpewogIENVUlRBQj10OwogIFsncmVudCcsJ3B1YicsJ3dpbicsJ2VzdHInXS5mb3JFYWNoKHg9PnskKCd0YWItJyt4KS5jbGFzc0xpc3QudG9nZ2xlKCdhY3RpdmUnLHg9PT10KTskKCdwYW5lbC0nK3gpLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScseD09PXQpO30pOwogIGlmKHQhPT0ncHViJyl7Y29uc3QgYj0kKCdiYW5uZXInKTtpZihiKWIuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpO30gIC8vIGVsIGJhbm5lciBkZSBBRFMgc29sbyB2YSBlbiBQdWJsaWNpZGFkCiAgcmVmcmVzaFRhYigpOwp9CmZ1bmN0aW9uIHJlZnJlc2hUYWIoKXsKICBpZighJCgnYWNjb3VudCcpLnZhbHVlKSByZXR1cm47CiAgaWYoQ1VSVEFCPT09J3JlbnQnKXsgLyogUmVudGFiaWxpZGFkIE5PIGJ1c2NhIHNvbGE6IGVsIHVzdWFyaW8gdG9jYSDwn5SNIEJ1c2NhciAqLyB9CiAgZWxzZSBpZihDVVJUQUI9PT0ncHViJyl7IGxvYWRDYW1wYWlnbnMoKTsgfQogIGVsc2UgaWYoQ1VSVEFCPT09J3dpbicpeyAvKiBvbiBkZW1hbmQgKi8gfQogIGVsc2UgaWYoQ1VSVEFCPT09J2VzdHInKXsgaWYoIVNUUkFUKSBsb2FkRXN0cmF0ZWdpYSgpOyB9Cn0KZnVuY3Rpb24gb25BY2NvdW50Q2hhbmdlKCl7IFZFTj1udWxsOyBXSU5ORVJTPVtdOyBpZihDVVJUQUIhPT0nZXN0cicpU1RSQVQ9bnVsbDsgcmVmcmVzaFRhYigpOyB9CgpsZXQgQUNDT1VOVFM9W107CmZ1bmN0aW9uIHJlbmRlckNvc3RTbG90cygpewogIGNvbnN0IGJveD0kKCdjb3N0c2xvdHMnKTtpZighYm94KXJldHVybjsKICBib3guaW5uZXJIVE1MPUFDQ09VTlRTLm1hcChhPT4KICAgICc8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo4cHg7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzo4cHggMTBweDtiYWNrZ3JvdW5kOiNmZmYiPicrCiAgICAgICc8ZGl2IHN0eWxlPSJtaW4td2lkdGg6MDtmbGV4OjEiPjxkaXYgY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweDt3aGl0ZS1zcGFjZTpub3dyYXA7b3ZlcmZsb3c6aGlkZGVuO3RleHQtb3ZlcmZsb3c6ZWxsaXBzaXMiPicrZXNjKGEubmFtZSkrJzwvZGl2PicrCiAgICAgICc8ZGl2IGNsYXNzPSJtdXRlZCIgaWQ9InNsb3Rjb3VudC0nK2EuaWQrJyIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4Ij7igJQgc2luIGNvc3RvczwvZGl2PjwvZGl2PicrCiAgICAgICc8bGFiZWwgY2xhc3M9InBpbGwgcC1ibHVlIiBzdHlsZT0iY3Vyc29yOnBvaW50ZXI7d2hpdGUtc3BhY2U6bm93cmFwIj7wn5OlIEltcG9ydGFyJysKICAgICAgICAnPGlucHV0IHR5cGU9ImZpbGUiIGFjY2VwdD0iLnhsc3gsLnhscyIgc3R5bGU9ImRpc3BsYXk6bm9uZSIgb25jaGFuZ2U9ImltcG9ydENvc3RzKHRoaXMsJythLmlkKycsXCcnK2VzYyhhLm5hbWUpLnJlcGxhY2UoLycvZywiXFwnIikrJ1wnKSI+PC9sYWJlbD4nKwogICAgJzwvZGl2PicpLmpvaW4oJycpOwp9Ci8vIE1vZG8gZGVsIHBhbmVsOiAnZ2VzdGlvbicgKHNvbG8gR2VzdGnDs24pIG8gJ2VzdHJhdGVnaWEnIChFc3RyYXRlZ2lhK1B1YmxpY2lkYWQrR2FuYWRvcmFzKS4KY29uc3QgUEFORUxfTU9ERT0od2luZG93Ll9fUEFORUxfTU9ERV9fPT09J2dlc3Rpb24nKT8nZ2VzdGlvbic6J2VzdHJhdGVnaWEnOwpmdW5jdGlvbiBhcHBseU1vZGUoKXsKICBjb25zdCBzaG93UmVudD0oUEFORUxfTU9ERT09PSdnZXN0aW9uJyk7CiAgY29uc3QgZXN0clRhYnM9Wydlc3RyJywncHViJywnd2luJ107CiAgJCgndGFiLXJlbnQnKS5zdHlsZS5kaXNwbGF5PXNob3dSZW50PycnOidub25lJzsKICBlc3RyVGFicy5mb3JFYWNoKHQ9Pntjb25zdCBiPSQoJ3RhYi0nK3QpO2lmKGIpYi5zdHlsZS5kaXNwbGF5PXNob3dSZW50Pydub25lJzonJzt9KTsKICAvLyBUw610dWxvIHNlZ8O6biBtb2RvCiAgY29uc3QgaDE9ZG9jdW1lbnQucXVlcnlTZWxlY3RvcignaGVhZGVyLnRvcCBoMScpLCBzdWI9ZG9jdW1lbnQucXVlcnlTZWxlY3RvcignaGVhZGVyLnRvcCAuc3ViJyk7CiAgaWYoc2hvd1JlbnQpeyBpZihoMSloMS50ZXh0Q29udGVudD0n8J+Xgu+4jyBHZXN0acOzbiDCtyBBdXRvY2hhcCc7IGlmKHN1YilzdWIudGV4dENvbnRlbnQ9J1JlbnRhYmlsaWRhZCBkaWFyaWEgcG9yIGN1ZW50YSDigJQgY3XDoW50byBnYW7DoXMgcG9yIGTDrWEnOyB9CiAgZWxzZSB7IGlmKGgxKWgxLnRleHRDb250ZW50PSfwn6egIEVzdHJhdGVnaWEgwrcgQXV0b2NoYXAnOyBpZihzdWIpc3ViLnRleHRDb250ZW50PSdTZWdtZW50YWNpw7NuLCBjdWVudGEgbMOtZGVyIHkgY3JlY2ltaWVudG8gcG9yIGN1ZW50YSc7IH0KICBzaG93VGFiKHNob3dSZW50PydyZW50JzonZXN0cicpOwp9CmFzeW5jIGZ1bmN0aW9uIGluaXQoKXsKICB0cnl7CiAgICBjb25zdCBhY2NzPWF3YWl0IGFwaSgnL2FwaS9hZHMvYWNjb3VudHMnKTsKICAgIEFDQ09VTlRTPWFjY3MuYWNjb3VudHN8fFtdOwogICAgY29uc3Qgc2VsPSQoJ2FjY291bnQnKTsgc2VsLmlubmVySFRNTD0nJzsKICAgIGNvbnN0IG9BbGw9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnb3B0aW9uJyk7b0FsbC52YWx1ZT0nYWxsJztvQWxsLnRleHRDb250ZW50PSfwn5eC77iPIFRvZGFzIGxhcyBjdWVudGFzJztzZWwuYXBwZW5kQ2hpbGQob0FsbCk7CiAgICBBQ0NPVU5UUy5mb3JFYWNoKGE9Pntjb25zdCBvPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ29wdGlvbicpO28udmFsdWU9YS5pZDtvLnRleHRDb250ZW50PWEubmFtZSsnICgnK2Euc2VsbGVyX2lkKycpJztzZWwuYXBwZW5kQ2hpbGQobyk7fSk7CiAgICByZW5kZXJDb3N0U2xvdHMoKTsKICB9Y2F0Y2goZSl7fQogIGF3YWl0IGxvYWRDb25maWcoKTsgbG9hZENvc3RTdGF0dXMoKTsKICAvLyBGZWNoYXMgcG9yIGRlZmVjdG8gZW4gaG9yYSBhcmdlbnRpbmEgKFVUQy0zKSwgY29uc2lzdGVudGUgY29uIGVsIERhc2hib2FyZC4KICBjb25zdCBhcmdUb2RheT1uZXcgRGF0ZShEYXRlLm5vdygpLTMqMzYwMCoxMDAwKSwgYXJnQWdvPW5ldyBEYXRlKERhdGUubm93KCktMyozNjAwKjEwMDAtMzAqODY0MDAwMDApOwogICQoJ3Zlbl90bycpLnZhbHVlPWFyZ1RvZGF5LnRvSVNPU3RyaW5nKCkuc2xpY2UoMCwxMCk7CiAgJCgndmVuX2Zyb20nKS52YWx1ZT1hcmdBZ28udG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKTsKICBhcHBseU1vZGUoKTsgLy8gbXVlc3RyYSBsYXMgcGVzdGHDsWFzIHNlZ8O6biAvZ2VzdGlvbiBvIC9wdWJsaWNpZGFkCn0KYXN5bmMgZnVuY3Rpb24gbG9hZENvbmZpZygpewogIHRyeXsKICAgIGNvbnN0IGM9YXdhaXQgYXBpKCcvYXBpL2Fkcy9jb25maWcnKTsgU1RBVEUuY2ZnPWM7CiAgICAkKCdjZmdfbWFyZ2luJykudmFsdWU9Yy5tYXJnaW47JCgnY2ZnX3RhcmdldCcpLnZhbHVlPWMuYWNvc1RhcmdldDskKCdjZmdfY2xpY2tzJykudmFsdWU9Yy5taW5DbGlja3M7JCgnY2ZnX3dpbmRvdycpLnZhbHVlPWMud2luZG93RGF5czsKICAgICQoJ2NmZ19zaGlwJykudmFsdWU9Yy5mcmVlU2hpcFRocmVzaG9sZCE9bnVsbD9jLmZyZWVTaGlwVGhyZXNob2xkOjMzMDAwOwogICAgY29uc3QgdGFnPSQoJ2F1dG90YWcnKTt0YWcudGV4dENvbnRlbnQ9J0F1dG8tcGF1c2E6ICcrKGMuYXV0b1BhdXNlPydBQ1RJVkEnOidEUlktUlVOIChubyBwYXVzYSknKTt0YWcuY2xhc3NOYW1lPSdhdXRvdGFnIHBpbGwgJysoYy5hdXRvUGF1c2U/J3AtcmVkJzoncC1ncmV5Jyk7CiAgfWNhdGNoKGUpe30KfQphc3luYyBmdW5jdGlvbiBzYXZlQ29uZmlnKCl7CiAgdHJ5e2NvbnN0IGJvZHk9e21hcmdpbjorJCgnY2ZnX21hcmdpbicpLnZhbHVlLGFjb3NUYXJnZXQ6KyQoJ2NmZ190YXJnZXQnKS52YWx1ZSxtaW5DbGlja3M6KyQoJ2NmZ19jbGlja3MnKS52YWx1ZSx3aW5kb3dEYXlzOiskKCdjZmdfd2luZG93JykudmFsdWUsZnJlZVNoaXBUaHJlc2hvbGQ6KyQoJ2NmZ19zaGlwJykudmFsdWV9OwogIGNvbnN0IHI9YXdhaXQgYXBpKCcvYXBpL2Fkcy9jb25maWcnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoYm9keSl9KTtTVEFURS5jZmc9ci5jb25maWc7dG9hc3QoJ0NvbmZpZ3VyYWNpw7NuIGd1YXJkYWRhJyk7bG9hZENhbXBhaWducygpO30KICBjYXRjaChlKXt0b2FzdCgnRXJyb3I6ICcrKGUuZXJyb3J8fGUpKTt9Cn0KCi8vIC0tLS0gQ29zdG9zIC0tLS0KZnVuY3Rpb24gcGljayhyb3csbmFtZXMpe2Zvcihjb25zdCBuIG9mIG5hbWVzKXtmb3IoY29uc3QgayBpbiByb3cpe2lmKFN0cmluZyhrKS50cmltKCkudG9Mb3dlckNhc2UoKT09PW4pcmV0dXJuIHJvd1trXTt9fXJldHVybiB1bmRlZmluZWQ7fQpmdW5jdGlvbiBpbXBvcnRDb3N0cyhpbnB1dCxhY2NJZCxhY2NOYW1lKXsKICBjb25zdCBmaWxlPWlucHV0LmZpbGVzJiZpbnB1dC5maWxlc1swXTtpZighZmlsZSlyZXR1cm47CiAgaWYodHlwZW9mIFhMU1g9PT0ndW5kZWZpbmVkJyl7dG9hc3QoJ05vIGNhcmfDsyBsYSBsaWJyZXLDrWEgZGUgRXhjZWwnKTtyZXR1cm47fQogIGlmKCFhY2NJZCl7dG9hc3QoJ0Nhc2lsbGVybyBzaW4gY3VlbnRhJyk7aW5wdXQudmFsdWU9Jyc7cmV0dXJuO30KICBjb25zdCBjbnQ9JCgnc2xvdGNvdW50LScrYWNjSWQpO2lmKGNudCljbnQudGV4dENvbnRlbnQ9J2ltcG9ydGFuZG/igKYnOwogIGNvbnN0IHJlYWRlcj1uZXcgRmlsZVJlYWRlcigpOwogIHJlYWRlci5vbmxvYWQ9YXN5bmMgZT0+ewogICAgdHJ5ewogICAgICBjb25zdCB3Yj1YTFNYLnJlYWQoZS50YXJnZXQucmVzdWx0LHt0eXBlOidhcnJheSd9KTtjb25zdCB3cz13Yi5TaGVldHNbJ1NoZWV0MSddfHx3Yi5TaGVldHNbd2IuU2hlZXROYW1lc1swXV07CiAgICAgIGNvbnN0IHJvd3M9WExTWC51dGlscy5zaGVldF90b19qc29uKHdzLHtkZWZ2YWw6Jyd9KTtjb25zdCBjb3N0cz1bXTsKICAgICAgZm9yKGNvbnN0IHIgb2Ygcm93cyl7Y29uc3QgaXRlbV9pZD1TdHJpbmcocGljayhyLFsnaXRlbV9pZCddKXx8JycpLnRyaW0oKTtpZighL15NTEFcZCsvaS50ZXN0KGl0ZW1faWQpKWNvbnRpbnVlOwogICAgICAgIGNvc3RzLnB1c2goe2l0ZW1faWQsY29zdDpwaWNrKHIsWydwcmVjaW8gY29zdG8nXSksY29zdFNoaXA6cGljayhyLFsnY29zdG8vZ2FzdG9zJ10pLHNoaXA6cGljayhyLFsnc2hpcHBpbmcnXSksY29tbWlzc2lvbjpwaWNrKHIsWydjb3N0byBwb3IgdmVuZGVyJ10pLGxpc3RpbmdUeXBlOnBpY2socixbJ2xpc3RpbmdfdHlwZV9pZCddKSxsaXN0UHJpY2U6cGljayhyLFsncHJlY2lvIGZpbmFsJ10pLG1hcmdpbkxpc3Q6cGljayhyLFsnbWFyZ2VuIGRlIGdhbmFuY2lhJ10pLG9mZXJ0YTpwaWNrKHIsWydvZmVydGEnXSksdGl0bGU6cGljayhyLFsndGl0dWxvJywndMOtdHVsbycsJ3RpdGxlJywncHVibGljYWNpb24nLCdwdWJsaWNhY2nDs24nLCdub21icmUnXSksc2t1OnBpY2socixbJ3NrdScsJ2NvZGlnbycsJ2PDs2RpZ28nLCdjb2RpZ28gcHJvdmVlZG9yJywnY8OzZGlnbyBwcm92ZWVkb3InLCdza3UgcHJvdmVlZG9yJ10pfSk7fQogICAgICBpZighY29zdHMubGVuZ3RoKXt0b2FzdCgnTm8gZW5jb250csOpIGZpbGFzIGNvbiBpdGVtX2lkIHbDoWxpZG8nKTtjb25zdCBjMD0kKCdzbG90Y291bnQtJythY2NJZCk7aWYoYzApYzAudGV4dENvbnRlbnQ9J+KAlCBzaW4gZmlsYXMgdsOhbGlkYXMnO3JldHVybjt9CiAgICAgIGNvbnN0IHJlcz1hd2FpdCBhcGkoJy9hcGkvYWRzL2Nvc3RzJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtjb3N0cyxhY2NvdW50X2lkOmFjY0lkLHJlcGxhY2U6dHJ1ZX0pfSk7CiAgICAgIHRvYXN0KCdDb3N0b3MgaW1wb3J0YWRvcyAoJysoYWNjTmFtZXx8cmVzLmFjY291bnR8fCdjdWVudGEnKSsnKTogJytyZXMuaW1wb3J0ZWQpO2xvYWRDb3N0U3RhdHVzKCk7CiAgICB9Y2F0Y2goZXJyKXt0b2FzdCgnRXJyb3IgaW1wb3J0YW5kbzogJysoZXJyLmVycm9yfHxlcnIubWVzc2FnZXx8ZXJyKSk7fQogICAgaW5wdXQudmFsdWU9Jyc7CiAgfTsKICByZWFkZXIucmVhZEFzQXJyYXlCdWZmZXIoZmlsZSk7Cn0KYXN5bmMgZnVuY3Rpb24gbG9hZENvc3RTdGF0dXMoKXsKICB0cnl7Y29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL2Nvc3RzJyk7CiAgICBjb25zdCBieT1BcnJheS5pc0FycmF5KGQuYnlfYWNjb3VudCk/ZC5ieV9hY2NvdW50OltdOwogICAgY29uc3QgbkFjYz1ieS5maWx0ZXIoeD0+eC5jb3VudD4wKS5sZW5ndGg7CiAgICAkKCdjb3N0c3RhdHVzJykuaW5uZXJIVE1MPWQudG90YWw/KCfinIUgPGI+JytkLnRvdGFsLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2I+IHByb2R1Y3RvcyDCtyAnK25BY2MrJyBkZSAnKyhBQ0NPVU5UUy5sZW5ndGh8fDYpKycgY3VlbnRhcyBjYXJnYWRhcycpOifimqDvuI8gU2luIGNvc3RvczogaW1wb3J0w6EgZWwgX0NPTVBMRVRPIGRlIGNhZGEgY3VlbnRhLic7CiAgICAvLyBSZXNldGVvIGxvcyBjb250YWRvcmVzIGRlIGNhZGEgY2FzaWxsZXJvIHkgbHVlZ28gbG9zIGxsZW5vLgogICAgQUNDT1VOVFMuZm9yRWFjaChhPT57Y29uc3QgYz0kKCdzbG90Y291bnQtJythLmlkKTtpZihjKWMudGV4dENvbnRlbnQ9J+KAlCBzaW4gY29zdG9zJzt9KTsKICAgIGJ5LmZvckVhY2goeD0+e2NvbnN0IGM9JCgnc2xvdGNvdW50LScreC5hY2NvdW50X2lkKTtpZihjKWMuaW5uZXJIVE1MPSfinIUgPGI+Jyt4LmNvdW50LnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2I+IHByb2R1Y3Rvcyc7fSk7CiAgfWNhdGNoKGUpe30KfQoKLy8gLS0tLSBSRU5UQUJJTElEQUQgLS0tLQpsZXQgVlNPUlQ9e2tleTonbmV0JyxkaXI6MX07CmZ1bmN0aW9uIHN0YXR1c0xhYmVsKHMpe2NvbnN0IG09e3BlbmRpbmc6J1BlbmRpZW50ZScsaGFuZGxpbmc6J1ByZXBhcmFuZG8nLHJlYWR5X3RvX3NoaXA6J0xpc3RvIHAvZW52aWFyJyxyZWFkeV90b19wcmludDonTGlzdG8gcC9pbXByaW1pcicsc2hpcHBlZDonRW52aWFkbycsZGVsaXZlcmVkOidFbnRyZWdhZG8nLG5vdF9kZWxpdmVyZWQ6J05vIGVudHJlZ2FkbycsY2FuY2VsbGVkOidDYW5jZWxhZG8nLHRvX2JlX2FncmVlZDonQSBjb252ZW5pcid9O3JldHVybiBtW3NdfHwoc3x8J+KAlCcpO30KZnVuY3Rpb24gc3RhdHVzUGlsbChzKXtjb25zdCBjbHM9KHtkZWxpdmVyZWQ6J3AtZ3JlZW4nLHNoaXBwZWQ6J3AtYmx1ZScscmVhZHlfdG9fc2hpcDoncC1hbWJlcicscmVhZHlfdG9fcHJpbnQ6J3AtYW1iZXInLGhhbmRsaW5nOidwLWFtYmVyJyxwZW5kaW5nOidwLWdyZXknLGNhbmNlbGxlZDoncC1yZWQnLG5vdF9kZWxpdmVyZWQ6J3AtcmVkJ30pW3NdfHwncC1ncmV5JztyZXR1cm4gJzxzcGFuIGNsYXNzPSJwaWxsICcrY2xzKyciPicrc3RhdHVzTGFiZWwocykrJzwvc3Bhbj4nO30KZnVuY3Rpb24gc29ydFZlbihrKXsgaWYoVlNPUlQua2V5PT09aylWU09SVC5kaXIqPS0xOyBlbHNle1ZTT1JULmtleT1rO1ZTT1JULmRpcj0oaz09PSd0aXRsZSd8fGs9PT0nc3RhdHVzJ3x8az09PSdzdG9jaycpPzE6LTE7fSBpZihWRU4pcmVuZGVyVmVudGFzKFZFTik7IH0KZnVuY3Rpb24gdXBkYXRlVmVuQXJyb3dzKCl7ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnI3ZlblRhYmxlIHRoZWFkIHRoJykuZm9yRWFjaCh0aD0+e2NvbnN0IGE9dGgucXVlcnlTZWxlY3RvcignLmFycicpO2lmKGEpYS5yZW1vdmUoKTtpZih0aC5kYXRhc2V0Lms9PT1WU09SVC5rZXkpe2NvbnN0IHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc3BhbicpO3MuY2xhc3NOYW1lPSdhcnInO3MudGV4dENvbnRlbnQ9VlNPUlQuZGlyPjA/JyDilrInOicg4pa8Jzt0aC5hcHBlbmRDaGlsZChzKTt9fSk7fQpmdW5jdGlvbiBkb3dubG9hZFZlbnRhc1hsc3goKXsKICBpZighVkVOfHwhVkVOLnZlbnRhc3x8IVZFTi52ZW50YXMubGVuZ3RoKXt0b2FzdCgnQW5hbGl6w6EgdmVudGFzIHByaW1lcm8nKTtyZXR1cm47fQogIGNvbnN0IGRhdGE9VkVOLnZlbnRhcy5tYXAodj0+e2NvbnN0IG89e0ZlY2hhOnYuZGF0ZX07aWYoVkVOLmFsbClvLkN1ZW50YT12LmFjY291bnRfbmFtZXx8Jyc7cmV0dXJuIE9iamVjdC5hc3NpZ24obyx7UHVibGljYWNpb246di50aXRsZSxJdGVtSUQ6di5pdGVtX2lkLEVzdGFkb19lbnZpbzpzdGF0dXNMYWJlbCh2LnN0YXR1cyksU3RvY2s6di5zdG9jaz8nU8OtJzonJyxQcmVjaW86di5yZXZlbnVlLENvbWlzaW9uOnYuZmVlLEVudmlvOnYuZW52aW8sSW1wdWVzdG9zOk1hdGgucm91bmQodi50YXh8fDApLEN1YW50b19xdWVkYTpNYXRoLnJvdW5kKHYucXVlZGEpLENvc3RvOnYuY29zdCxGYWN0dXJhOk1hdGgucm91bmQodi5mYWN0dXJhfHwwKSxHYW5hbmNpYTp2Lm5ldD09bnVsbD8nJzpNYXRoLnJvdW5kKHYubmV0KSxNYXJnZW5fcGN0OnYubWFyZ2luUGN0PT1udWxsPycnOit2Lm1hcmdpblBjdC50b0ZpeGVkKDEpfSk7fSk7CiAgY29uc3Qgd3M9WExTWC51dGlscy5qc29uX3RvX3NoZWV0KGRhdGEpO2NvbnN0IHdiPVhMU1gudXRpbHMuYm9va19uZXcoKTtYTFNYLnV0aWxzLmJvb2tfYXBwZW5kX3NoZWV0KHdiLHdzLCdWZW50YXMnKTsKICBYTFNYLndyaXRlRmlsZSh3YiwndmVudGFzXycrKFZFTi5hbGw/J1RPREFTJzooJCgnYWNjb3VudCcpLnNlbGVjdGVkT3B0aW9uc1swXT8kKCdhY2NvdW50Jykuc2VsZWN0ZWRPcHRpb25zWzBdLnRleHRDb250ZW50LnNwbGl0KCcgJylbMF06J2N1ZW50YScpKSsnXycrKFZFTi5mcm9tfHwnJykrJ18nKyhWRU4udG98fCcnKSsnLnhsc3gnKTsKfQphc3luYyBmdW5jdGlvbiBsb2FkVmVudGFzKCl7CiAgY29uc3QgaWQ9JCgnYWNjb3VudCcpLnZhbHVlO2lmKCFpZCl7dG9hc3QoJ0VsZWfDrSB1bmEgY3VlbnRhJyk7cmV0dXJuO30KICBjb25zdCBmcm9tPSQoJ3Zlbl9mcm9tJykudmFsdWUsIHRvPSQoJ3Zlbl90bycpLnZhbHVlOwogIGNvbnN0IGlzQWxsPShpZD09PSdhbGwnKTsKICAkKCd2ZW5fYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMyIgY2xhc3M9ImxvYWRpbmciPicrKGlzQWxsPydUcmF5ZW5kbyB2ZW50YXMgZGUgPGI+dG9kYXMgbGFzIGN1ZW50YXM8L2I+IOKAlCBwdWVkZSB0YXJkYXIgYmFzdGFudGXigKYnOidUcmF5ZW5kbyB2ZW50YXMgeSBlbnbDrW9zIHJlYWxlcyBkZSBNZXJjYWRvIExpYnJl4oCmIChwdWVkZSB0YXJkYXIgdW5vcyBzZWd1bmRvcyknKSsnPC90ZD48L3RyPic7CiAgdHJ5ewogICAgY29uc3QgdXJsPWlzQWxsPygnL2FwaS9hZHMvdmVudGFzLWFsbD8nKyhmcm9tPygnZnJvbT0nK2Zyb20pOicnKSsodG8/KCcmdG89Jyt0byk6JycpKTooJy9hcGkvYWRzL3ZlbnRhcz9hY2NvdW50X2lkPScraWQrKGZyb20/KCcmZnJvbT0nK2Zyb20pOicnKSsodG8/KCcmdG89Jyt0byk6JycpKTsKICAgIGNvbnN0IGQ9YXdhaXQgYXBpKHVybCk7VkVOPWQ7CiAgICBpZihkLm9iamV0aXZvIT1udWxsKSQoJ3Zlbl9vYmonKS52YWx1ZT1kLm9iamV0aXZvOwogICAgaWYoIWlzQWxsJiZkLnRheFBjdCE9bnVsbCYmJCgndmVuX3RheCcpLnZhbHVlPT09JycpJCgndmVuX3RheCcpLnZhbHVlPWQudGF4UGN0OwogICAgcmVuZGVyVmVudGFzKGQpOwogIH1jYXRjaChlKXskKCd2ZW5fYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMyIgY2xhc3M9ImxvYWRpbmciPkVycm9yOiAnKyh0eXBlb2YgZS5lcnJvcj09PSdzdHJpbmcnP2UuZXJyb3I6SlNPTi5zdHJpbmdpZnkoZS5lcnJvcikpKyc8L3RkPjwvdHI+Jzt9Cn0KZnVuY3Rpb24gcmVuZGVyVmVudGFzKGQpewogIGNvbnN0IHI9ZC5yZXN1bWVuOwogIGNvbnN0IHZ0PSQoJ3ZlblRhYmxlJyk7aWYodnQpdnQuY2xhc3NMaXN0LnRvZ2dsZSgnaGlkZS1hY2MnLCFkLmFsbCk7ICAvLyBtdWVzdHJhIGxhIGNvbHVtbmEgQ3VlbnRhIHNvbG8gZW4gIlRvZGFzIGxhcyBjdWVudGFzIgogIGNvbnN0IG1DbHM9ci5tYXJnaW49PW51bGw/Jyc6KHIubWFyZ2luPj0xMD8nZ29vZCc6KHIubWFyZ2luPj01Pyd3YXJuJzonYmFkJykpOwogIGNvbnN0IHRpbGVzPVtbJ1ZlbnRhcycsKHIub3JkZXJzIT1udWxsP3Iub3JkZXJzOnIuY291bnQpLCcnXSxbJ0ZhY3R1cmFjacOzbiAoJytyLmRheXMrJ2QpJyxmbXRNb25leShyLmZhY3R1cmFjaW9uKSwnJ10sWydHYW5hbmNpYSByZWFsJyxmbXRNb25leShyLmdhbmFuY2lhKSxyLmdhbmFuY2lhPj0wPydnb29kJzonYmFkJ10sWydNYXJnZW4gcmVhbCcsci5tYXJnaW49PW51bGw/J+KAlCc6Zm10UGN0KHIubWFyZ2luKSxtQ2xzXSxbJ0EgcMOpcmRpZGEnLHIucGVyZGlkYSsoci5wZXJkaWRhPycg4pqg77iPJzonJyksci5wZXJkaWRhPydiYWQnOidnb29kJ10sWydQcm95LiBtZW5zdWFsJyxmbXRNb25leShkLnByb3lfbWVuc3VhbCksJyddXTsKICAkKCd2ZW5fa3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAodD0+JzxkaXYgY2xhc3M9ImtwaSAnK3RbMl0rJyI+PGRpdiBjbGFzcz0iayI+Jyt0WzBdKyc8L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3RbMV0rJzwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogICQoJ3Zlbl9wcm9ncmVzc19jYXJkJykuc3R5bGUuZGlzcGxheT0nYmxvY2snOwogIGNvbnN0IHBjdD1NYXRoLm1pbigxMDAsZC5hdmFuY2V8fDApOwogIGNvbnN0IGhpZGRlbk5vdGU9ci5oaWRkZW4/KCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6NHB4Ij7wn5qrICcrci5oaWRkZW4rJyBvcmRlbicrKHIuaGlkZGVuPjE/J2VzJzonJykrJyBvY3VsdGEnKyhyLmhpZGRlbj4xPydzJzonJykrJyAoY2FuY2VsYWRhcyBvIGNvbiBkZXZvbHVjacOzbiBhbCBjb21wcmFkb3IpPC9kaXY+Jyk6Jyc7CiAgY29uc3Qgc2F2ZWROb3RlPShyLnNhdmVkIT1udWxsfHxyLmZyZXNoIT1udWxsKT8oJzxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjExcHg7bWFyZ2luLXRvcDo0cHgiPvCfkr4gJysoci5zYXZlZHx8MCkrJyBjb24gY29zdG8gY29uZ2VsYWRvIMK3ICcrKHIuZnJlc2h8fDApKycgbnVldmEnKygoci5mcmVzaHx8MCk9PT0xPycnOidzJykrJyBndWFyZGFkYScrKChyLmZyZXNofHwwKT09PTE/Jyc6J3MnKSsnPC9kaXY+Jyk6Jyc7CiAgY29uc3QgdGF4Tm90ZT1yLnRheFJlYWwhPW51bGw/KCc8ZGl2IGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O21hcmdpbi10b3A6NHB4Ij7wn6e+IEltcHVlc3RvIHJlYWwgZGUgTUwgZW4gJytyLnRheFJlYWwrJyBkZSAnKyhyLm9yZGVyc3x8ci5jb3VudCkrJyDDs3JkZW5lcycrKHIudGF4UmVhbDwoci5vcmRlcnN8fHIuY291bnQpPygnIMK3IGVuIGVsIHJlc3RvIE1MIG5vIGluZm9ybcOzIGltcHVlc3RvIChxdWVkYSAkMCknKTonJykrJyDCtyBsYSBmYWN0dXJhICglIG1lbnN1YWwpIHZhIGFwYXJ0ZSwgZW4gbGEgY29sdW1uYSBGYWN0dXJhPC9kaXY+Jyk6Jyc7CiAgY29uc3Qgc2hpcE5vdGU9ci5zaGlwRmV0Y2hlZCE9bnVsbD8oJzxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0iZm9udC1zaXplOjExcHg7bWFyZ2luLXRvcDo2cHgiPvCfmpogRW52w61vIHJlYWwgZGUgTUwgZW4gJytyLnNoaXBGZXRjaGVkKycgZGUgJysoci5vcmRlcnN8fHIuY291bnQpKycgw7NyZGVuZXMnKyhyLnNoaXBGZXRjaGVkPChyLm9yZGVyc3x8ci5jb3VudCk/JyDCtyBlbCByZXN0byB1c2EgbGEgZXN0aW1hY2nDs24gZGVsIEV4Y2VsJzonJykrJyDCtyBwZXLDrW9kbyAnK2QuZnJvbSsnIGEgJytkLnRvKyc8L2Rpdj4nKTonJzsKICAkKCd2ZW5fcHJvZ3Jlc3MnKS5pbm5lckhUTUw9JzxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxM3B4O21hcmdpbi1ib3R0b206NnB4Ij48Yj5BdmFuY2UgaGFjaWEgZWwgb2JqZXRpdm8gbWVuc3VhbDwvYj4gKCcrZm10TW9uZXkoZC5vYmpldGl2bykrJyk6IDxiIHN0eWxlPSJjb2xvcjonKyhkLmF2YW5jZT49MTAwPyd2YXIoLS1ncmVlbiknOid2YXIoLS1uYXZ5KScpKyciPicrKGQuYXZhbmNlfHwwKS50b0ZpeGVkKDApKyclPC9iPiA8c3BhbiBjbGFzcz0ibXV0ZWQiPsK3IHByb3llY2Npw7NuICcrZm10TW9uZXkoZC5wcm95X21lbnN1YWwpKyc8L3NwYW4+PC9kaXY+PGRpdiBjbGFzcz0iYmFyIj48aSBzdHlsZT0id2lkdGg6JytwY3QrJyU7YmFja2dyb3VuZDonKyhkLmF2YW5jZT49MTAwPyd2YXIoLS1ncmVlbiknOid2YXIoLS1ibHVlKScpKyciPjwvaT48L2Rpdj4nK3NhdmVkTm90ZSt0YXhOb3RlK2hpZGRlbk5vdGUrc2hpcE5vdGU7CiAgY29uc3Qgcm93cz0oZC52ZW50YXN8fFtdKS5zbGljZSgpOwogIGNvbnN0IGs9VlNPUlQua2V5LGRpcj1WU09SVC5kaXI7CiAgcm93cy5zb3J0KChhLGIpPT57bGV0IHg9YVtrXSx5PWJba107aWYoaz09PSd0aXRsZSd8fGs9PT0nc3RhdHVzJ3x8az09PSdhY2NvdW50X25hbWUnKXt4PVN0cmluZyh4fHwnJyk7eT1TdHJpbmcoeXx8JycpO3JldHVybiBkaXIqeC5sb2NhbGVDb21wYXJlKHkpO31pZihrPT09J3N0b2NrJyl7cmV0dXJuIGRpciooKHg/MTowKS0oeT8xOjApKTt9eD0oeD09bnVsbD8tSW5maW5pdHk6eCk7eT0oeT09bnVsbD8tSW5maW5pdHk6eSk7cmV0dXJuIGRpciooeC15KTt9KTsKICB1cGRhdGVWZW5BcnJvd3MoKTsKICBpZighcm93cy5sZW5ndGgpeyQoJ3Zlbl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjEzIiBjbGFzcz0iZW1wdHkiPlNpbiB2ZW50YXMgZW4gZWwgcGVyw61vZG8uPC90ZD48L3RyPic7cmV0dXJuO30KICAkKCd2ZW5fYm9keScpLmlubmVySFRNTD1yb3dzLm1hcCh2PT57Y29uc3QgbG9zcz12Lm5ldCE9bnVsbCYmdi5uZXQ8MDsKICAgIHJldHVybiAnPHRyJysobG9zcz8nIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXJlZGJnKSInOicnKSsnPicrCiAgICAgICc8dGQgY2xhc3M9Im5hbWUiPicrZXNjKHYudGl0bGV8fHYuaXRlbV9pZCkrJzxzcGFuIGNsYXNzPSJpZCI+Jysodi5pdGVtX2lkfHwnJykrJyDCtyAnKyh2LmRhdGV8fCcnKSsnPC9zcGFuPjwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0iYWNjb2wiPicrZXNjKHYuYWNjb3VudF9uYW1lfHwnJykrJzwvdGQ+JysKICAgICAgJzx0ZD4nK3N0YXR1c1BpbGwodi5zdGF0dXMpKyc8L3RkPicrCiAgICAgICc8dGQ+Jysodi5zdG9jaz8nPHNwYW4gY2xhc3M9InBpbGwgcC1hbWJlciI+U8OtPC9zcGFuPic6JzxzcGFuIGNsYXNzPSJtdXRlZCI+4oCUPC9zcGFuPicpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JytmbXRNb25leSh2LnJldmVudWUpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPuKIkicrZm10TW9uZXkodi5mZWUpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrKHYuZW52aW8/KCfiiJInK2ZtdE1vbmV5KHYuZW52aW8pKTon4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysodi50YXg/KCfiiJInK2ZtdE1vbmV5KHYudGF4KSk6KHYudGF4UmVhbD09PWZhbHNlPyc8c3BhbiBjbGFzcz0ibXV0ZWQiIHRpdGxlPSJNTCBubyBpbmZvcm3DsyBpbXB1ZXN0byBlbiBlc3RhIG9yZGVuIj7igJQ8L3NwYW4+JzonJDAnKSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIGIiPicrZm10TW9uZXkodi5xdWVkYSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+Jysodi5jb3N0PT1udWxsPyc8c3BhbiBjbGFzcz0ibXV0ZWQiPnMvY29zdG88L3NwYW4+JzooJ+KIkicrZm10TW9uZXkodi5jb3N0KSkpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrKHYuZmFjdHVyYT8oJ+KIkicrZm10TW9uZXkodi5mYWN0dXJhKSk6J+KAlCcpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImZvbnQtd2VpZ2h0OjgwMDtjb2xvcjonKyh2Lm5ldD09bnVsbD8ndmFyKC0tbXV0KSc6KHYubmV0Pj0wPyd2YXIoLS1ncmVlbiknOid2YXIoLS1yZWQpJykpKyciPicrKHYubmV0PT1udWxsPyfigJQnOmZtdE1vbmV5KHYubmV0KSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyh2Lm1hcmdpblBjdD09bnVsbD8n4oCUJzpmbXRQY3Qodi5tYXJnaW5QY3QpKSsnPC90ZD48L3RyPic7fSkuam9pbignJyk7Cn0KYXN5bmMgZnVuY3Rpb24gc2F2ZVZlbnRhc0NmZygpewogIGNvbnN0IGlkPSQoJ2FjY291bnQnKS52YWx1ZTtpZighaWQpcmV0dXJuOwogIGlmKGlkPT09J2FsbCcpe3RvYXN0KCdFbGVnw60gdW5hIGN1ZW50YSBwdW50dWFsIHBhcmEgZ3VhcmRhciBzdSBvYmpldGl2bycpO3JldHVybjt9CiAgdHJ5e2F3YWl0IGFwaSgnL2FwaS9hZHMvYWNjb3VudC1jb25maWcnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2FjY291bnRfaWQ6aWQsb2JqZXRpdm86KyQoJ3Zlbl9vYmonKS52YWx1ZSx0YXhQY3Q6KyQoJ3Zlbl90YXgnKS52YWx1ZX0pfSk7dG9hc3QoJ09iamV0aXZvIGd1YXJkYWRvIMK3IHRvY8OhIPCflI0gQnVzY2FyIHBhcmEgcmVjYWxjdWxhcicpO30KICBjYXRjaChlKXt0b2FzdCgnRXJyb3I6ICcrKGUuZXJyb3J8fGUpKTt9Cn0KCi8vIC0tLS0gRVNUUkFURUdJQSAoZWwgY2VyZWJybykgLS0tLQpsZXQgRVNPUlQ9e2tleTonc2NvcmUnLGRpcjotMX0sIEVTRUc9e2VzdHJlbGxhOjEscHJvbWVzYToxLGFqdXN0YXI6MSx2YWNhOjEsZHVybWllbnRlOjEsZHVwT25seTowLGVucmljaGVkT25seTowfTsKY29uc3QgU0VHTUVUQT17ZXN0cmVsbGE6WydwLWdyZWVuJywn4q2QIEVzdHJlbGxhJ10scHJvbWVzYTpbJ3AtYmx1ZScsJ/CfmoAgUHJvbWVzYSddLGFqdXN0YXI6WydwLXJlZCcsJ/CflKcgQWp1c3RhciddLHZhY2E6WydwLWFtYmVyJywn8J+QhCBWYWNhJ10sZHVybWllbnRlOlsncC1ncmV5Jywn8J+SpCBEdXJtaWVudGUnXX07CmZ1bmN0aW9uIHNlZ1BpbGwocyl7Y29uc3QgbT1TRUdNRVRBW3NdfHxbJ3AtZ3JleScsc107cmV0dXJuICc8c3BhbiBjbGFzcz0icGlsbCAnK21bMF0rJyI+JyttWzFdKyc8L3NwYW4+Jzt9CmZ1bmN0aW9uIHRvZ2dsZVNlZyhlbCl7ZWwuY2xhc3NMaXN0LnRvZ2dsZSgnb24nKTtFU0VHW2VsLmRhdGFzZXQuc2VnXT1lbC5jbGFzc0xpc3QuY29udGFpbnMoJ29uJyk/MTowO2lmKFNUUkFUKXJlbmRlckVzdHJhdGVnaWEoU1RSQVQpO30KZnVuY3Rpb24gc29ydEVzdHIoayl7aWYoRVNPUlQua2V5PT09aylFU09SVC5kaXIqPS0xO2Vsc2V7RVNPUlQua2V5PWs7RVNPUlQuZGlyPShrPT09J3RpdGxlJ3x8az09PSdhY2NvdW50X25hbWUnfHxrPT09J3NlZ21lbnQnKT8xOi0xO31pZihTVFJBVClyZW5kZXJFc3RyYXRlZ2lhKFNUUkFUKTt9CmxldCBFTlJJQ0hJTkc9ZmFsc2U7CmZ1bmN0aW9uIHN0b3BFbnJpcXVlY2VyKCl7IEVOUklDSElORz1mYWxzZTsgJCgnZXN0cl9zdG9wX2J0bicpLnRleHRDb250ZW50PSdEZXRlbmllbmRv4oCmJzsgfQpmdW5jdGlvbiBzZXRQcm9nKHR4dCxzdWIscGN0KXsgJCgnZXN0cl9wcm9nX3R4dCcpLnRleHRDb250ZW50PXR4dDsgaWYoc3ViIT1udWxsKSQoJ2VzdHJfcHJvZ19zdWInKS50ZXh0Q29udGVudD1zdWI7IGlmKHBjdCE9bnVsbCkkKCdlc3RyX3Byb2dfYmFyJykuc3R5bGUud2lkdGg9TWF0aC5taW4oMTAwLE1hdGgubWF4KDAscGN0KSkrJyUnOyB9CmFzeW5jIGZ1bmN0aW9uIHJlZmluYXJNYXJnZW5lcygpewogIGlmKEVOUklDSElORykgcmV0dXJuOyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8geWEgZXN0w6EgY29ycmllbmRvCiAgY29uc3Qgc2VsPSQoJ2FjY291bnQnKS52YWx1ZTsKICBjb25zdCB0YXJnZXRzPShzZWw9PT0nYWxsJ3x8IXNlbCk/QUNDT1VOVFMubWFwKGE9PmEuaWQpOltzZWxdOwogIEVOUklDSElORz10cnVlOwogICQoJ2VzdHJfcHJvZ3Jlc3NfY2FyZCcpLnN0eWxlLmRpc3BsYXk9J2Jsb2NrJzsKICAkKCdlc3RyX3N0b3BfYnRuJykudGV4dENvbnRlbnQ9J+KPuSBEZXRlbmVyJzsKICBzZXRQcm9nKCdJbmljaWFuZG8gZW5yaXF1ZWNpbWllbnRvIGNvbiBkYXRvcyByZWFsZXMgZGUgTUzigKYnLCcnLDApOwogIGxldCBncmFuZD0wLCBiYXRjaGVzPTA7CiAgdHJ5ewogICAgZm9yKGNvbnN0IHRpZCBvZiB0YXJnZXRzKXsKICAgICAgaWYoIUVOUklDSElORykgYnJlYWs7CiAgICAgIGNvbnN0IGFjYz1BQ0NPVU5UUy5maW5kKGE9PlN0cmluZyhhLmlkKT09PVN0cmluZyh0aWQpKTsKICAgICAgY29uc3QgYWNjTmFtZT1hY2M/YWNjLm5hbWU6J2N1ZW50YSc7CiAgICAgIHdoaWxlKEVOUklDSElORyl7CiAgICAgICAgbGV0IHI7CiAgICAgICAgdHJ5eyByPWF3YWl0IGFwaSgnL2FwaS9hZHMvZXN0cmF0ZWdpYS9yZWZpbmFyP2FjY291bnRfaWQ9Jyt0aWQpOyB9CiAgICAgICAgY2F0Y2goZSl7IHNldFByb2coJ0Vycm9yIGVuICcrYWNjTmFtZSxTdHJpbmcoZS5lcnJvcnx8ZSksMCk7IGJyZWFrOyB9CiAgICAgICAgZ3JhbmQrPXIucmVmaW5lZHx8MDsgYmF0Y2hlcysrOwogICAgICAgIGNvbnN0IGRvbmU9ci5lbnJpY2hlZF90b3RhbHx8MCwgdG90PXIuYWNjb3VudF90b3RhbHx8MDsKICAgICAgICBzZXRQcm9nKCdFbnJpcXVlY2llbmRvICcrYWNjTmFtZSsnOiAnK2RvbmUudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyAvICcrdG90LnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLAogICAgICAgICAgICAgICAgJ/Cfk6YgJytncmFuZC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIGVuIGVzdGEgY29ycmlkYSDCtyBsb3RlICcrYmF0Y2hlcysnIMK3IHRyYWUgdMOtdHVsbywgcHJlY2lvIGNvbiBwcm9tbywgdmVudGFzIHkgdmlzaXRhcyBkZSBNTCcsCiAgICAgICAgICAgICAgICB0b3Q/ZG9uZS90b3QqMTAwOjEwMCk7CiAgICAgICAgaWYoYmF0Y2hlcyUzPT09MCkgYXdhaXQgbG9hZEVzdHJhdGVnaWEoKTsgICAgICAgICAgLy8gcmVmcmVzY2EgbG9zIG7Dum1lcm9zIGNhZGEgMyBsb3RlcwogICAgICAgIGlmKCFyLnJlZmluZWQgfHwgZG9uZT49dG90KSBicmVhazsgICAgICAgICAgICAgICAgIC8vIGN1ZW50YSB0ZXJtaW5hZGEgbyBzaW4gbcOhcyBwYXJhIGVucmlxdWVjZXIKICAgICAgfQogICAgfQogIH0gZmluYWxseSB7CiAgICBjb25zdCBzdG9wcGVkPSFFTlJJQ0hJTkc7CiAgICBFTlJJQ0hJTkc9ZmFsc2U7CiAgICBzZXRQcm9nKHN0b3BwZWQ/KCdEZXRlbmlkbyDCtyAnK2dyYW5kLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgZW5yaXF1ZWNpZG9zJyk6KCfinIUgTGlzdG8gwrcgJytncmFuZC50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIHByb2R1Y3RvcyBlbnJpcXVlY2lkb3MgY29uIGRhdGEgcmVhbCBkZSBNTCcpLCcnLDEwMCk7CiAgICBhd2FpdCBsb2FkRXN0cmF0ZWdpYSgpOwogICAgc2V0VGltZW91dCgoKT0+eyBpZighRU5SSUNISU5HKSAkKCdlc3RyX3Byb2dyZXNzX2NhcmQnKS5zdHlsZS5kaXNwbGF5PSdub25lJzsgfSw1MDAwKTsKICB9Cn0KZnVuY3Rpb24gbWFyZ2luU3JjRG90KHNyYyl7cmV0dXJuIHNyYz09PSdzaW0nPyfwn5S1Jzon8J+foCc7fQpmdW5jdGlvbiBlc3RyUGFyYW1zKCl7Y29uc3QgZz0kKCdlc3RyX2hpZ2gnKS52YWx1ZSxtcz0kKCdlc3RyX21pbnNhbGVzJykudmFsdWUsbXY9JCgnZXN0cl9taW52aXMnKS52YWx1ZSxodj0kKCdlc3RyX2hvdHZpcycpLnZhbHVlLHJvPSQoJ2VzdHJfcm9hcycpLnZhbHVlO3JldHVybiAnbWFyZ2luSGlnaD0nKyhnfHwxMikrJyZtaW5TYWxlcz0nKyhtc3x8MSkrJyZtaW5WaXNpdHM9JysobXZ8fDIwKSsnJmhvdFZpc2l0cz0nKyhodnx8NjApKycmcm9hcz0nKyhyb3x8NSk7fQphc3luYyBmdW5jdGlvbiBsb2FkRXN0cmF0ZWdpYSgpewogICQoJ2VzdHJfYm9keScpLmlubmVySFRNTD0nPHRyPjx0ZCBjb2xzcGFuPSIxMSIgY2xhc3M9ImxvYWRpbmciPkNydXphbmRvIGN1ZW50YXMgcG9yIHTDrXR1bG8geSBjbGFzaWZpY2FuZG/igKY8L3RkPjwvdHI+JzsKICB0cnl7CiAgICBjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvZXN0cmF0ZWdpYT8nK2VzdHJQYXJhbXMoKSk7CiAgICBpZihkLmVtcHR5KXskKCdlc3RyX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTEiIGNsYXNzPSJlbXB0eSI+Jytlc2MoZC5ub3RlfHwnSW1wb3J0w6EgbG9zIF9DT01QTEVUTyBwcmltZXJvLicpKyc8L3RkPjwvdHI+JzskKCdlc3RyX2twaXMnKS5pbm5lckhUTUw9Jyc7U1RSQVQ9bnVsbDtyZXR1cm47fQogICAgU1RSQVQ9ZDtyZW5kZXJFc3RyYXRlZ2lhKGQpOwogIH1jYXRjaChlKXskKCdlc3RyX2JvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTEiIGNsYXNzPSJlbXB0eSI+RXJyb3I6ICcrZXNjKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSkrJzwvdGQ+PC90cj4nO30KfQpmdW5jdGlvbiByZW5kZXJFc3RyYXRlZ2lhKGQpewogIGNvbnN0IHM9ZC5zZWdtZW50b3N8fHt9LHQ9ZC50b3RhbHN8fHt9LGR1PWQuZHVwbGljYWRvc3x8e307CiAgY29uc3QgZW5yPShkLmN1ZW50YXN8fFtdKS5yZWR1Y2UoKGEsYyk9PmErKGMuZW5yaWNoZWR8fDApLDApOwogIGNvbnN0IHRpbGVzPVsKICAgIFsnQWN0aXZhcycsKHQucHJvZHVjdG9zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsodC5wYXVzYWRhcz8oJyDCtyAnK3QucGF1c2FkYXMudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJyBwYXVzYWRhcyBmdWVyYScpOicnKSwnJ10sCiAgICBbJ+KchSBFbnJpcXVlY2lkb3MnLGVuci50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIC8gJysodC5wcm9kdWN0b3N8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLGVucj4wPyhlbnI+PSh0LnByb2R1Y3Rvc3x8MCk/J2dvb2QnOid3YXJuJyk6J2JhZCddLAogICAgWyfirZAgRXN0cmVsbGFzJywocy5lc3RyZWxsYXx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJyksJ2dvb2QnXSwKICAgIFsn8J+agCBQcm9tZXNhcycsKHMucHJvbWVzYXx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJyksJyddLAogICAgWyfwn5SnIEFqdXN0YXInLChzLmFqdXN0YXJ8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLChzLmFqdXN0YXJ8fDApPyd3YXJuJzonJ10sCiAgICBbJ/CfkIQgVmFjYXMnLChzLnZhY2F8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpLCd3YXJuJ10sCiAgICBbJ/CfkqQgRHVybWllbnRlcycsKHMuZHVybWllbnRlfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSwnJ10sCiAgICBbJ/CflIEgRHVwbGljYWRvcycsKGR1Lml0ZW1zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsoZHUuZ3J1cG9zPygnIMK3ICcrZHUuZ3J1cG9zKycgZ3InKTonJyksZHUuaXRlbXM/J2JhZCc6J2dvb2QnXSwKICBdOwogICQoJ2VzdHJfa3BpcycpLmlubmVySFRNTD10aWxlcy5tYXAoeD0+JzxkaXYgY2xhc3M9ImtwaSAnK3hbMl0rJyI+PGRpdiBjbGFzcz0iayI+Jyt4WzBdKyc8L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3hbMV0rJzwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogIHJlbmRlclBsYW4oZCk7CiAgcmVuZGVyQWNjdENmZyhkLmN1ZW50YXN8fFtdKTsKICByZW5kZXJQcmVjaW9SdWxlcygpOwogICQoJ2VzdHJfcGxhbl9jYXJkJykuc3R5bGUuZGlzcGxheT0nYmxvY2snOyQoJ2VzdHJfcHJlY2lvc19jYXJkJykuc3R5bGUuZGlzcGxheT0nYmxvY2snOwogIC8vIEN1ZW50YXMgaGFjaWEgc3Ugb2JqZXRpdm8gKG1lcyBjb3JyaWRvICsgQURTIHN1Z2VyaWRvKQogIGNvbnN0IGFjY3RzPWQuY3VlbnRhc3x8W107CiAgJCgnZXN0cl9hY2N0c19jYXJkJykuc3R5bGUuZGlzcGxheT1hY2N0cy5sZW5ndGg/J2Jsb2NrJzonbm9uZSc7CiAgJCgnZXN0cl9sZWdlbmQnKS5zdHlsZS5kaXNwbGF5PSdmbGV4JzskKCdlc3RyX2ZpbHRlcnMnKS5zdHlsZS5kaXNwbGF5PSdmbGV4JzsKICAkKCdlc3RyX2FjY3RzJykuaW5uZXJIVE1MPWFjY3RzLm1hcChhPT57CiAgICBjb25zdCBhdj1hLmF2YW5jZXx8MDsKICAgIHJldHVybiAnPHRyPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2MoYS5hY2NvdW50X25hbWV8fCfigJQnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrZm10TW9uZXkoYS5vYmpldGl2bykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KGEucHJveV9tZW5zdWFsKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo3MDA7Y29sb3I6JysoYXY+PTEwMD8ndmFyKC0tZ3JlZW4pJzphdj49NjA/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLXJlZCknKSsnIj4nK2F2LnRvRml4ZWQoMCkrJyU8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSIgc3R5bGU9ImNvbG9yOicrKGEuZmFsdGFudGU+MD8ndmFyKC0tcmVkKSc6J3ZhcigtLWdyZWVuKScpKyciPicrKGEuZmFsdGFudGU+MD9mbXRNb25leShhLmZhbHRhbnRlKTon4pyTJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIGIiIHN0eWxlPSJjb2xvcjp2YXIoLS1uYXZ5KSI+JysoYS5hZHNfYnVkZ2V0PjA/Zm10TW9uZXkoYS5hZHNfYnVkZ2V0KTon4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiBzdHlsZT0iY29sb3I6JysoKGEuZW5yaWNoZWR8fDApPj0oYS5pdGVtc3x8MCk/J3ZhcigtLWdyZWVuKSc6KGEuZW5yaWNoZWQ/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLXJlZCknKSkrJyI+JysoYS5lbnJpY2hlZHx8MCkudG9Mb2NhbGVTdHJpbmcoJ2VzLUFSJykrJy8nKyhhLml0ZW1zfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKGEuZXN0cmVsbGF8fDApKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nKyhhLnByb21vdmVyfHwwKSsnPC90ZD48dGQgY2xhc3M9Im51bSBiIj4nKyhhLmxpZGVyfHwwKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJyk7CiAgLy8gVGFibGEgZGUgcHJvZHVjdG9zIChmaWx0cmFkYSArIG9yZGVuYWRhKQogIGxldCByb3dzPShkLml0ZW1zfHxbXSkuZmlsdGVyKGk9PkVTRUdbaS5zZWdtZW50XSk7CiAgaWYoRVNFRy5kdXBPbmx5KXJvd3M9cm93cy5maWx0ZXIoaT0+aS5kdXBsaWNhdGVkKTsKICBpZihFU0VHLmVucmljaGVkT25seSlyb3dzPXJvd3MuZmlsdGVyKGk9PmkuZW5yaWNoZWQpOwogIGlmKEVBQ1RJT04pcm93cz1yb3dzLmZpbHRlcihpPT5pLmFjdGlvbkNvZGU9PT1FQUNUSU9OKTsKICBjb25zdCBrPUVTT1JULmtleSxkaXI9RVNPUlQuZGlyOwogIHJvd3M9cm93cy5zbGljZSgpLnNvcnQoKGEsYik9PntsZXQgeD1hW2tdLHk9YltrXTsKICAgIGlmKGs9PT0ndGl0bGUnfHxrPT09J2FjY291bnRfbmFtZSd8fGs9PT0nc2VnbWVudCcpe3g9U3RyaW5nKHh8fCcnKTt5PVN0cmluZyh5fHwnJyk7cmV0dXJuIGRpcip4LmxvY2FsZUNvbXBhcmUoeSk7fQogICAgaWYoaz09PSdpc0xlYWRlcicpe3JldHVybiBkaXIqKCh4PzE6MCktKHk/MTowKSk7fQogICAgeD0oeD09bnVsbD8tSW5maW5pdHk6eCk7eT0oeT09bnVsbD8tSW5maW5pdHk6eSk7cmV0dXJuIGRpciooeC15KTt9KTsKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcjZXN0clRhYmxlIHRoZWFkIHRoJykuZm9yRWFjaCh0aD0+e2NvbnN0IGE9dGgucXVlcnlTZWxlY3RvcignLmFycicpO2lmKGEpYS5yZW1vdmUoKTtpZih0aC5kYXRhc2V0Lms9PT1FU09SVC5rZXkpe2NvbnN0IHNwPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3NwYW4nKTtzcC5jbGFzc05hbWU9J2Fycic7c3AudGV4dENvbnRlbnQ9RVNPUlQuZGlyPjA/JyDilrInOicg4pa8Jzt0aC5hcHBlbmRDaGlsZChzcCk7fX0pOwogIGlmKCFyb3dzLmxlbmd0aCl7JCgnZXN0cl9ib2R5JykuaW5uZXJIVE1MPSc8dHI+PHRkIGNvbHNwYW49IjExIiBjbGFzcz0iZW1wdHkiPlNpbiBwcm9kdWN0b3MgY29uIGVzb3MgZmlsdHJvcy48L3RkPjwvdHI+JztyZXR1cm47fQogICQoJ2VzdHJfYm9keScpLmlubmVySFRNTD1yb3dzLnNsaWNlKDAsNDAwKS5tYXAoaT0+ewogICAgY29uc3QgbGVhZD1pLmR1cGxpY2F0ZWQ/KGkuaXNMZWFkZXI/JzxzcGFuIGNsYXNzPSJwaWxsIHAtZ3JlZW4iPvCfkZEgTMOtZGVyPC9zcGFuPic6JzxzcGFuIGNsYXNzPSJwaWxsIHAtZ3JleSI+8J+MsSBPcmfDoW5pY288L3NwYW4+Jyk6JzxzcGFuIGNsYXNzPSJtdXRlZCI+w7puaWNvPC9zcGFuPic7CiAgICBjb25zdCBzYz1pLnNjb3JlfHwwLCBzY0NvbD1zYz49NjY/J3ZhcigtLWdyZWVuKSc6c2M+PTMzPyd2YXIoLS1hbWJlciknOid2YXIoLS1tdXQpJzsKICAgIGNvbnN0IHByb21vVGFnPWkuZW5Qcm9tbz8nIDxzcGFuIGNsYXNzPSJwaWxsIHAtcmVkIiBzdHlsZT0iZm9udC1zaXplOjlweDtwYWRkaW5nOjFweCA2cHgiPnByb21vPC9zcGFuPic6Jyc7CiAgICByZXR1cm4gJzx0cicrKChpLmR1cGxpY2F0ZWQmJiFpLmlzTGVhZGVyKT8nIHN0eWxlPSJiYWNrZ3JvdW5kOiNmOGZhZmMiJzonJykrJz4nKwogICAgICAnPHRkIGNsYXNzPSJuYW1lIj4nK2VzYyhpLnRpdGxlfHxpLml0ZW1faWQpK3Byb21vVGFnKyc8c3BhbiBjbGFzcz0iaWQiPicrKGkuaXRlbV9pZHx8JycpKyhpLmVucmljaGVkPycnOicgwrcgc2luIGVucmlxdWVjZXInKSsoaS5kdXBsaWNhdGVkPygnIMK3IHJlcGV0aWRvJyk6JycpKyc8L3NwYW4+PC90ZD4nKwogICAgICAnPHRkPicrZXNjKGkuYWNjb3VudF9uYW1lfHwn4oCUJykrJzwvdGQ+JysKICAgICAgJzx0ZD4nK3NlZ1BpbGwoaS5zZWdtZW50KSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0gYiIgc3R5bGU9ImNvbG9yOicrc2NDb2wrJyI+JytzYysnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKygoaS5tYXJnaW4hPW51bGwmJmkubWFyZ2luPj0oKyQoJ2VzdHJfaGlnaCcpLnZhbHVlfHwxMikpPyd2YXIoLS1ncmVlbiknOid2YXIoLS1hbWJlciknKSsnIiB0aXRsZT0iJysoaS5tYXJnaW5TcmM9PT0nc2ltJz8nc2ltdWxhZG8gY29uIGVsIGNvc3RvIGV4YWN0byBkZSBNTCBhbCBwcmVjaW8gcmVhbCc6J21hcmdlbiBkZSBsaXN0YSAoZW5yaXF1ZWPDqSBwYXJhIGVsIGV4YWN0byknKSsnIj4nKyhpLm1hcmdpbj09bnVsbD8n4oCUJzpmbXRQY3QoaS5tYXJnaW4pKSsnIDxzcGFuIHN0eWxlPSJmb250LXNpemU6OXB4Ij4nK21hcmdpblNyY0RvdChpLm1hcmdpblNyYykrJzwvc3Bhbj48L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JysoaS5wcmljZT09bnVsbD8n4oCUJzpmbXRNb25leShpLnByaWNlKSkrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIiB0aXRsZT0iJysoKGkuc29sZFRvdGFsIT1udWxsKT8oJ2FjdW11bGFkbyBoaXN0w7NyaWNvOiAnK2kuc29sZFRvdGFsKTonJykrJyI+JysoaS5zb2xkfHwwKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iPicrKGkudmlzaXRzfHwwKS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKyhpLmNvbnY9PW51bGw/J3ZhcigtLW11dCknOihpLmNvbnY+PTM/J3ZhcigtLWdyZWVuKSc6aS5jb252Pj0xPyd2YXIoLS1hbWJlciknOid2YXIoLS1yZWQpJykpKyciPicrKGkuY29udj09bnVsbD8n4oCUJzppLmNvbnYudG9GaXhlZCgxKSsnJScpKyc8L3RkPicrCiAgICAgICc8dGQ+JytsZWFkKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im11dGVkIiBzdHlsZT0id2hpdGUtc3BhY2U6bm9ybWFsO21heC13aWR0aDozMjBweCI+Jytlc2MoaS5hY3Rpb258fCcnKSsnPC90ZD48L3RyPic7CiAgfSkuam9pbignJyk7Cn0KZnVuY3Rpb24gZG93bmxvYWRFc3RyYXRlZ2lhWGxzeCgpewogIGlmKCFTVFJBVHx8IVNUUkFULml0ZW1zfHwhU1RSQVQuaXRlbXMubGVuZ3RoKXt0b2FzdCgnQ2FsY3Vsw6EgbGEgZXN0cmF0ZWdpYSBwcmltZXJvJyk7cmV0dXJuO30KICBjb25zdCBkYXRhPVNUUkFULml0ZW1zLm1hcChpPT4oe1Byb2R1Y3RvOmkudGl0bGUsSXRlbUlEOmkuaXRlbV9pZCxDdWVudGE6aS5hY2NvdW50X25hbWUsU2VnbWVudG86aS5zZWdtZW50LFBvdGVuY2lhbDppLnNjb3JlfHwwLE1hcmdlbl9wY3Q6aS5tYXJnaW49PW51bGw/Jyc6K2kubWFyZ2luLnRvRml4ZWQoMSksTWFyZ2VuX29yaWdlbjooaS5tYXJnaW5TcmM9PT0nc2ltJz8nc2ltdWxhZG8gTUwnOidsaXN0YScpLFByZWNpbzppLnByaWNlPT1udWxsPycnOmkucHJpY2UsRW5fcHJvbW86aS5lblByb21vPydTw60nOicnLFZlbnRhc18zbTppLnNvbGR8fDAsVmVudGFzX3RvdGFsOmkuc29sZFRvdGFsPT1udWxsPycnOmkuc29sZFRvdGFsLFZpc2l0YXM6aS52aXNpdHN8fDAsQ29udmVyc2lvbl9wY3Q6aS5jb252PT1udWxsPycnOitpLmNvbnYudG9GaXhlZCgyKSxFeHBvc2ljaW9uOmkubGlzdGluZ1R5cGV8fCcnLEVucmlxdWVjaWRvOmkuZW5yaWNoZWQ/J1PDrSc6JycsRHVwbGljYWRvOmkuZHVwbGljYXRlZD8nU8OtJzonJyxMaWRlcjppLmR1cGxpY2F0ZWQ/KGkuaXNMZWFkZXI/J0zDrWRlcic6J1NvbG8gb3Jnw6FuaWNvJyk6J8O6bmljbycsTGlkZXJfY3VlbnRhOmkubGVhZGVyTmFtZXx8JycsU3RvY2tfb2ZlcnRhOmkuc3RvY2s/J1PDrSc6JycsQWNjaW9uOmkuYWN0aW9ufSkpOwogIGNvbnN0IHdzPVhMU1gudXRpbHMuanNvbl90b19zaGVldChkYXRhKTtjb25zdCB3Yj1YTFNYLnV0aWxzLmJvb2tfbmV3KCk7WExTWC51dGlscy5ib29rX2FwcGVuZF9zaGVldCh3Yix3cywnRXN0cmF0ZWdpYScpOwogIFhMU1gud3JpdGVGaWxlKHdiLCdlc3RyYXRlZ2lhX211bHRpY3VlbnRhXycrKG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKSkrJy54bHN4Jyk7Cn0KCi8vIC0tLS0gUExBTiBERSBBQ0NJw5NOICh0aWxlcyBjbGlja2VhYmxlcyBxdWUgZmlsdHJhbiBsYSB0YWJsYSkgLS0tLQpsZXQgRUFDVElPTj1udWxsOwpjb25zdCBBQ1RfQ09MT1I9e2VzY2FsYXI6J2dvb2QnLHByb21vdmVyOidnb29kJyxhanVzdGFyOid3YXJuJyxwcmVjaW86J3dhcm4nLHBhdXNhcjonYmFkJyxvcmdhbmljbzonJyxyZXZpc2FyOicnfTsKZnVuY3Rpb24gZmlsdGVyQWN0aW9uKGNvZGUpeyBFQUNUSU9OPShFQUNUSU9OPT09Y29kZSk/bnVsbDpjb2RlOyBpZihTVFJBVClyZW5kZXJFc3RyYXRlZ2lhKFNUUkFUKTsgfQpmdW5jdGlvbiByZW5kZXJQbGFuKGQpewogIGNvbnN0IHBsYW49ZC5wbGFufHx7fSwgbWV0YT1kLnBsYW5NZXRhfHx7fTsKICBjb25zdCBvcmRlcj1PYmplY3Qua2V5cyhtZXRhKS5zb3J0KChhLGIpPT4obWV0YVthXS5wcml8fDkpLShtZXRhW2JdLnByaXx8OSkpOwogICQoJ2VzdHJfcGxhbicpLmlubmVySFRNTD1vcmRlci5tYXAoY29kZT0+ewogICAgY29uc3QgbT1tZXRhW2NvZGVdLCBuPXBsYW5bY29kZV18fDAsIG9uPShFQUNUSU9OPT09Y29kZSk7CiAgICByZXR1cm4gJzxkaXYgb25jbGljaz0iZmlsdGVyQWN0aW9uKFwnJytjb2RlKydcJykiIGNsYXNzPSJrcGkgJysoQUNUX0NPTE9SW2NvZGVdfHwnJykrJyIgc3R5bGU9ImN1cnNvcjpwb2ludGVyOycrKG9uPydvdXRsaW5lOjJweCBzb2xpZCB2YXIoLS1uYXZ5KSc6JycpKyciPicrCiAgICAgICc8ZGl2IGNsYXNzPSJrIj4nK2VzYyhtLmxhYmVsKSsnPC9kaXY+PGRpdiBjbGFzcz0idiBzbWFsbCI+JytuLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKyc8L2Rpdj4nKwogICAgICAnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJmb250LXNpemU6MTBweDttYXJnaW4tdG9wOjRweDt3aGl0ZS1zcGFjZTpub3JtYWwiPicrZXNjKG0uaGludCkrJzwvZGl2PjwvZGl2Pic7CiAgfSkuam9pbignJyk7Cn0KLy8gLS0tLSBDT05GSUcgUE9SIENVRU5UQSAob2JqZXRpdm8gKyBmYWN0dXJhKSAtLS0tCmZ1bmN0aW9uIHJlbmRlckFjY3RDZmcoY3VlbnRhcyl7CiAgY29uc3QgYnlJZD17fTsgKGN1ZW50YXN8fFtdKS5mb3JFYWNoKGM9PmJ5SWRbYy5hY2NvdW50X2lkXT1jKTsKICAkKCdlc3RyX2FjY3RjZmcnKS5pbm5lckhUTUw9QUNDT1VOVFMubWFwKGE9PnsKICAgIGNvbnN0IGM9YnlJZFthLmlkXXx8e307CiAgICByZXR1cm4gJzxkaXYgc3R5bGU9ImJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9yZGVyLXJhZGl1czoxMHB4O3BhZGRpbmc6MTBweCAxMnB4O2JhY2tncm91bmQ6I2ZmZiI+JysKICAgICAgJzxkaXYgY2xhc3M9ImIiIHN0eWxlPSJmb250LXNpemU6MTJweDt3aGl0ZS1zcGFjZTpub3dyYXA7b3ZlcmZsb3c6aGlkZGVuO3RleHQtb3ZlcmZsb3c6ZWxsaXBzaXMiPicrZXNjKGEubmFtZSkrJzwvZGl2PicrCiAgICAgICc8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDttYXJnaW4tdG9wOjZweDthbGlnbi1pdGVtczpmbGV4LWVuZCI+JysKICAgICAgICAnPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5PYmpldGl2by9tZXM8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJvYmotJythLmlkKyciIHN0ZXA9IjEwMDAwMDAiIHZhbHVlPSInKyhjLm9iamV0aXZvfHwxMDAwMDAwMDApKyciIHN0eWxlPSJ3aWR0aDoxMzBweCI+PC9kaXY+JysKICAgICAgICAnPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5GYWN0dXJhICU8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJmYWMtJythLmlkKyciIHN0ZXA9IjAuNSIgdmFsdWU9IicrKGMuZmFjdHVyYSE9bnVsbD9jLmZhY3R1cmE6NSkrJyIgc3R5bGU9IndpZHRoOjcwcHgiPjwvZGl2PicrCiAgICAgICAgJzxidXR0b24gb25jbGljaz0ic2F2ZUFjY3RDZmcoJythLmlkKycpIj5HdWFyZGFyPC9idXR0b24+JysKICAgICAgJzwvZGl2PjwvZGl2Pic7CiAgfSkuam9pbignJyk7Cn0KYXN5bmMgZnVuY3Rpb24gc2F2ZUFjY3RDZmcoaWQpewogIGNvbnN0IG9iamV0aXZvPSskKCdvYmotJytpZCkudmFsdWUsIHRheFBjdD0rJCgnZmFjLScraWQpLnZhbHVlOwogIHRyeXsgYXdhaXQgYXBpKCcvYXBpL2Fkcy9hY2NvdW50LWNvbmZpZycse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeSh7YWNjb3VudF9pZDppZCxvYmpldGl2byx0YXhQY3R9KX0pOwogICAgdG9hc3QoJ0N1ZW50YSBndWFyZGFkYSDCtyByZWNhbGN1bMOhIG8gcmUtZW5yaXF1ZWPDqSBwYXJhIGFwbGljYXIgbGEgZmFjdHVyYSBhbCBtYXJnZW4nKTsgfQogIGNhdGNoKGUpeyB0b2FzdCgnRXJyb3I6ICcrKGUuZXJyb3J8fGUpKTsgfQp9Ci8vIC0tLS0gQUNUVUFMSVpBRE9SIERFIFBSRUNJT1MgTUFTSVZPIC0tLS0KY29uc3QgUFJJQ0VfQUNUSU9OUz1bCiAge2NvZGU6J29yZ2FuaWNvJyxsYWJlbDon8J+MsSBObyBhbnVuY2lhciAodMOtdHVsbyByZXBldGlkbyknLG1vZGU6J21hcmdpbicsdmFsOjI1fSwKICB7Y29kZToncmV2aXNhcicsbGFiZWw6J/CfkqQgRHVybWllbnRlIChzaW4gZGVtYW5kYSknLG1vZGU6J21hcmdpbicsdmFsOjIwfSwKICB7Y29kZToncHJlY2lvJyxsYWJlbDon8J+QhCBWYWNhIChtYXJnZW4gZmxhY28pJyxtb2RlOidtYXJnaW4nLHZhbDoxNX0sCiAge2NvZGU6J2FqdXN0YXInLGxhYmVsOifwn5SnIEFqdXN0YXIgKG5vIGNvbnZpZXJ0ZSknLG1vZGU6J3BjdCcsdmFsOi04fSwKICB7Y29kZToncHJvbW92ZXInLGxhYmVsOifwn46vIFByb21vdmVyIChnYW5hciB2ZW50YSknLG1vZGU6J3BjdCcsdmFsOi01fSwKICB7Y29kZTonZXNjYWxhcicsbGFiZWw6J+KtkCBFc2NhbGFyIChlc3RyZWxsYSknLG1vZGU6J25vbmUnLHZhbDowfSwKXTsKZnVuY3Rpb24gcmVuZGVyUHJlY2lvUnVsZXMoKXsKICBpZigkKCdwcmVjaW9fcnVsZXMnKS5kYXRhc2V0LmRvbmUpcmV0dXJuOyAvLyBzb2xvIGxhIHByaW1lcmEgdmV6IChubyBwaXNhciBsbyBxdWUgZWwgdXN1YXJpbyB0b2PDsykKICAkKCdwcmVjaW9fcnVsZXMnKS5pbm5lckhUTUw9UFJJQ0VfQUNUSU9OUy5tYXAocj0+CiAgICAnPGRpdiBzdHlsZT0iYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVzOjEwcHg7cGFkZGluZzoxMHB4IDEycHg7YmFja2dyb3VuZDojZmZmIj4nKwogICAgICAnPGRpdiBjbGFzcz0iYiIgc3R5bGU9ImZvbnQtc2l6ZToxMnB4Ij4nK3IubGFiZWwrJzwvZGl2PicrCiAgICAgICc8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjhweDttYXJnaW4tdG9wOjZweDthbGlnbi1pdGVtczpmbGV4LWVuZCI+JysKICAgICAgICAnPGRpdiBjbGFzcz0iZmllbGQiPjxsYWJlbD5SZWdsYTwvbGFiZWw+PHNlbGVjdCBpZD0icHItbW9kZS0nK3IuY29kZSsnIiBvbmNoYW5nZT0icHJNb2RlQ2hhbmdlKFwnJytyLmNvZGUrJ1wnKSI+JysKICAgICAgICAgICc8b3B0aW9uIHZhbHVlPSJub25lIicrKHIubW9kZT09PSdub25lJz8nIHNlbGVjdGVkJzonJykrJz5TaW4gY2FtYmlvPC9vcHRpb24+JysKICAgICAgICAgICc8b3B0aW9uIHZhbHVlPSJtYXJnaW4iJysoci5tb2RlPT09J21hcmdpbic/JyBzZWxlY3RlZCc6JycpKyc+TWFyZ2VuIG9iamV0aXZvICU8L29wdGlvbj4nKwogICAgICAgICAgJzxvcHRpb24gdmFsdWU9InBjdCInKyhyLm1vZGU9PT0ncGN0Jz8nIHNlbGVjdGVkJzonJykrJz5BanVzdGUgJTwvb3B0aW9uPicrCiAgICAgICAgJzwvc2VsZWN0PjwvZGl2PicrCiAgICAgICAgJzxkaXYgY2xhc3M9ImZpZWxkIj48bGFiZWwgaWQ9InByLWxibC0nK3IuY29kZSsnIj4nKyhyLm1vZGU9PT0nbWFyZ2luJz8nTWFyZ2VuICUnOidBanVzdGUgJScpKyc8L2xhYmVsPjxpbnB1dCB0eXBlPSJudW1iZXIiIGlkPSJwci12YWwtJytyLmNvZGUrJyIgc3RlcD0iMC41IiB2YWx1ZT0iJytyLnZhbCsnIiBzdHlsZT0id2lkdGg6ODBweCInKyhyLm1vZGU9PT0nbm9uZSc/JyBkaXNhYmxlZCc6JycpKyc+PC9kaXY+JysKICAgICAgJzwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwogICQoJ3ByZWNpb19ydWxlcycpLmRhdGFzZXQuZG9uZT0nMSc7Cn0KZnVuY3Rpb24gcHJNb2RlQ2hhbmdlKGNvZGUpe2NvbnN0IG09JCgncHItbW9kZS0nK2NvZGUpLnZhbHVlOyQoJ3ByLXZhbC0nK2NvZGUpLmRpc2FibGVkPShtPT09J25vbmUnKTskKCdwci1sYmwtJytjb2RlKS50ZXh0Q29udGVudD0obT09PSdtYXJnaW4nPydNYXJnZW4gJSc6J0FqdXN0ZSAlJyk7fQpmdW5jdGlvbiBjdXJyZW50UHJpY2VSdWxlcygpe2NvbnN0IHJ1bGVzPXt9O1BSSUNFX0FDVElPTlMuZm9yRWFjaChyPT57Y29uc3QgbW9kZT0kKCdwci1tb2RlLScrci5jb2RlKS52YWx1ZTtjb25zdCB2YWx1ZT0rJCgncHItdmFsLScrci5jb2RlKS52YWx1ZTtydWxlc1tyLmNvZGVdPXttb2RlLHZhbHVlfTt9KTtyZXR1cm4gcnVsZXM7fQpsZXQgUFJFVklFVz1bXTsKYXN5bmMgZnVuY3Rpb24gcHJldmlld1ByZWNpb3MoKXsKICBjb25zdCBzZWw9JCgnYWNjb3VudCcpLnZhbHVlOwogICQoJ3ByZWNpb19wcmV2X2luZm8nKS50ZXh0Q29udGVudD0nQ2FsY3VsYW5kbyBwcmVjaW9z4oCmJzsKICB0cnl7CiAgICBjb25zdCBib2R5PXtydWxlczpjdXJyZW50UHJpY2VSdWxlcygpLGFjY291bnRfaWQ6c2VsfTsKICAgIGNvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9wcmVjaW9zL3BsYW4/Jytlc3RyUGFyYW1zKCkse21ldGhvZDonUE9TVCcsYm9keTpKU09OLnN0cmluZ2lmeShib2R5KX0pOwogICAgUFJFVklFVz1kLmNoYW5nZXN8fFtdOwogICAgY29uc3Qgc2s9ZC5za2lwcGVkfHx7fTsKICAgICQoJ3ByZWNpb19wcmV2X2luZm8nKS5pbm5lckhUTUw9KGQuY291bnR8fDApLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKycgY2FtYmlvcycrKChzay5zaW5fZW5yaXF1ZWNlcnx8c2subWFyZ2VuX2ltcG9zaWJsZSk/KCcgwrcgPHNwYW4gY2xhc3M9Im11dGVkIj4nKyhzay5zaW5fZW5yaXF1ZWNlcnx8MCkrJyBzaW4gZW5yaXF1ZWNlciwgJysoc2subWFyZ2VuX2ltcG9zaWJsZXx8MCkrJyBtYXJnZW4gaW1wb3NpYmxlPC9zcGFuPicpOicnKTsKICAgIHJlbmRlclByZXZpZXcoKTsKICB9Y2F0Y2goZSl7JCgncHJlY2lvX3ByZXZfaW5mbycpLnRleHRDb250ZW50PSdFcnJvcjogJysodHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKTt9Cn0KZnVuY3Rpb24gcmVuZGVyUHJldmlldygpewogIGNvbnN0IHRiPSQoJ3ByZWNpb19ib2R5Jyk7CiAgaWYoIVBSRVZJRVcubGVuZ3RoKXskKCdwcmVjaW9UYWJsZScpLnN0eWxlLmRpc3BsYXk9J25vbmUnOyQoJ3ByZWNpb19hcHBseV9idG4nKS5zdHlsZS5kaXNwbGF5PSdub25lJzskKCdwcmVjaW9feGxzeF9idG4nKS5zdHlsZS5kaXNwbGF5PSdub25lJztyZXR1cm47fQogICQoJ3ByZWNpb1RhYmxlJykuc3R5bGUuZGlzcGxheT0nJzskKCdwcmVjaW9feGxzeF9idG4nKS5zdHlsZS5kaXNwbGF5PScnOwogIHRiLmlubmVySFRNTD1QUkVWSUVXLnNsaWNlKDAsMzAwKS5tYXAoKGMsaWR4KT0+ewogICAgY29uc3QgdXA9KGMuZGVsdGFQY3R8fDApPj0wOwogICAgcmV0dXJuICc8dHI+PHRkPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgY2xhc3M9InByLWNoayIgZGF0YS1pZHg9IicraWR4KyciIGNoZWNrZWQgb25jbGljaz0idXBkYXRlQXBwbHlDb3VudCgpIj48L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im5hbWUiPicrZXNjKGMudGl0bGV8fGMuaXRlbV9pZCkrJzxzcGFuIGNsYXNzPSJpZCI+JytjLml0ZW1faWQrJzwvc3Bhbj48L3RkPicrCiAgICAgICc8dGQ+Jytlc2MoYy5hY2NvdW50X25hbWV8fCcnKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJtdXRlZCIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4Ij4nK2VzYygoYy5hY3Rpb25Db2RlfHwnJykpKyc8L3RkPicrCiAgICAgICc8dGQgY2xhc3M9Im51bSI+JytmbXRNb25leShjLnByaWNlTm93KSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0gYiI+JytmbXRNb25leShjLnByaWNlTmV3KSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0iIHN0eWxlPSJjb2xvcjonKyh1cD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKyciPicrKGMuZGVsdGFQY3Q9PW51bGw/J+KAlCc6KHVwPycrJzonJykrYy5kZWx0YVBjdC50b0ZpeGVkKDEpKyclJykrJzwvdGQ+JysKICAgICAgJzx0ZCBjbGFzcz0ibnVtIj4nKyhjLm1hcmdpbk5vdz09bnVsbD8n4oCUJzpmbXRQY3QoYy5tYXJnaW5Ob3cpKSsnPC90ZD4nKwogICAgICAnPHRkIGNsYXNzPSJudW0gYiIgc3R5bGU9ImNvbG9yOnZhcigtLWdyZWVuKSI+JysoYy5tYXJnaW5OZXc9PW51bGw/J+KAlCc6Zm10UGN0KGMubWFyZ2luTmV3KSkrJzwvdGQ+PC90cj4nOwogIH0pLmpvaW4oJycpOwogIHVwZGF0ZUFwcGx5Q291bnQoKTsKfQpmdW5jdGlvbiB0b2dnbGVQcmVjaW9BbGwoZWwpe2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5wci1jaGsnKS5mb3JFYWNoKGM9PmMuY2hlY2tlZD1lbC5jaGVja2VkKTt1cGRhdGVBcHBseUNvdW50KCk7fQpmdW5jdGlvbiBzZWxlY3RlZENoYW5nZXMoKXtjb25zdCBvdXQ9W107ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnByLWNoaycpLmZvckVhY2goYz0+e2lmKGMuY2hlY2tlZCl7Y29uc3QgaXQ9UFJFVklFV1srYy5kYXRhc2V0LmlkeF07aWYoaXQpb3V0LnB1c2goe2l0ZW1faWQ6aXQuaXRlbV9pZCxhY2NvdW50X2lkOml0LmFjY291bnRfaWQscHJpY2U6aXQucHJpY2VOZXd9KTt9fSk7cmV0dXJuIG91dDt9CmZ1bmN0aW9uIHVwZGF0ZUFwcGx5Q291bnQoKXtjb25zdCBuPXNlbGVjdGVkQ2hhbmdlcygpLmxlbmd0aDskKCdwcmVjaW9fYXBwbHlfbicpLnRleHRDb250ZW50PW47JCgncHJlY2lvX2FwcGx5X2J0bicpLnN0eWxlLmRpc3BsYXk9bj8nJzonbm9uZSc7fQphc3luYyBmdW5jdGlvbiBhcGxpY2FyUHJlY2lvcygpewogIGNvbnN0IGNoYW5nZXM9c2VsZWN0ZWRDaGFuZ2VzKCk7CiAgaWYoIWNoYW5nZXMubGVuZ3RoKXt0b2FzdCgnTm8gaGF5IGNhbWJpb3Mgc2VsZWNjaW9uYWRvcycpO3JldHVybjt9CiAgaWYoIWNvbmZpcm0oJ1ZhcyBhIGNhbWJpYXIgZWwgcHJlY2lvIGRlICcrY2hhbmdlcy5sZW5ndGgrJyBwdWJsaWNhY2lvbmVzIGVuIE1lcmNhZG8gTGlicmUuIMK/Q29uZmlybcOhcz8nKSlyZXR1cm47CiAgJCgncHJlY2lvX2FwcGx5X2J0bicpLmRpc2FibGVkPXRydWU7JCgncHJlY2lvX3ByZXZfaW5mbycpLnRleHRDb250ZW50PSdBcGxpY2FuZG8gJytjaGFuZ2VzLmxlbmd0aCsnIGNhbWJpb3MgZW4gTUzigKYnOwogIHRyeXsKICAgIGxldCBvaz0wLGVycj0wOwogICAgZm9yKGxldCBpPTA7aTxjaGFuZ2VzLmxlbmd0aDtpKz0yMDApewogICAgICBjb25zdCBkPWF3YWl0IGFwaSgnL2FwaS9hZHMvcHJlY2lvcy9hcGxpY2FyJyx7bWV0aG9kOidQT1NUJyxib2R5OkpTT04uc3RyaW5naWZ5KHtjaGFuZ2VzOmNoYW5nZXMuc2xpY2UoaSxpKzIwMCl9KX0pOwogICAgICBvays9ZC5hcHBsaWVkfHwwO2Vycis9ZC5mYWlsZWR8fDA7CiAgICAgICQoJ3ByZWNpb19wcmV2X2luZm8nKS50ZXh0Q29udGVudD0nQXBsaWNhZG9zICcrb2srJyDCtyBlcnJvcmVzICcrZXJyKyfigKYnOwogICAgfQogICAgdG9hc3QoJ+KchSBQcmVjaW9zIGFwbGljYWRvczogJytvaysnIMK3IGVycm9yZXM6ICcrZXJyKTsKICAgICQoJ3ByZWNpb19wcmV2X2luZm8nKS50ZXh0Q29udGVudD0nTGlzdG86ICcrb2srJyBhcGxpY2Fkb3MsICcrZXJyKycgZXJyb3Jlcy4gUmUtZW5yaXF1ZWPDqSBwYXJhIHZlciBsb3MgbnVldm9zIG3DoXJnZW5lcy4nOwogIH1jYXRjaChlKXt0b2FzdCgnRXJyb3I6ICcrKGUuZXJyb3J8fGUpKTt9CiAgZmluYWxseXskKCdwcmVjaW9fYXBwbHlfYnRuJykuZGlzYWJsZWQ9ZmFsc2U7fQp9CmZ1bmN0aW9uIGRvd25sb2FkUHJlY2lvc1hsc3goKXsKICBpZighUFJFVklFVy5sZW5ndGgpe3RvYXN0KCdIYWPDqSBsYSB2aXN0YSBwcmV2aWEgcHJpbWVybycpO3JldHVybjt9CiAgY29uc3QgZGF0YT1QUkVWSUVXLm1hcChjPT4oe1Byb2R1Y3RvOmMudGl0bGUsSXRlbUlEOmMuaXRlbV9pZCxDdWVudGE6Yy5hY2NvdW50X25hbWUsQWNjaW9uOmMuYWN0aW9uQ29kZSxQcmVjaW9fYWN0dWFsOmMucHJpY2VOb3csUHJlY2lvX251ZXZvOmMucHJpY2VOZXcsRGVsdGFfcGN0OmMuZGVsdGFQY3Q9PW51bGw/Jyc6K2MuZGVsdGFQY3QudG9GaXhlZCgxKSxNYXJnZW5fYWN0dWFsOmMubWFyZ2luTm93PT1udWxsPycnOitjLm1hcmdpbk5vdy50b0ZpeGVkKDEpLE1hcmdlbl9udWV2bzpjLm1hcmdpbk5ldz09bnVsbD8nJzorYy5tYXJnaW5OZXcudG9GaXhlZCgxKX0pKTsKICBjb25zdCB3cz1YTFNYLnV0aWxzLmpzb25fdG9fc2hlZXQoZGF0YSk7Y29uc3Qgd2I9WExTWC51dGlscy5ib29rX25ldygpO1hMU1gudXRpbHMuYm9va19hcHBlbmRfc2hlZXQod2Isd3MsJ1ByZWNpb3MnKTsKICBYTFNYLndyaXRlRmlsZSh3YiwncGxhbl9wcmVjaW9zXycrKG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKS5zbGljZSgwLDEwKSkrJy54bHN4Jyk7Cn0KCi8vIC0tLS0gUFVCTElDSURBRCAtLS0tCmFzeW5jIGZ1bmN0aW9uIGxvYWRDYW1wYWlnbnMoKXsKICBjb25zdCBpZD0kKCdhY2NvdW50JykudmFsdWU7aWYoIWlkKXJldHVybjsKICAkKCdiYW5uZXInKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgJCgndGJvZHknKS5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTIiIGNsYXNzPSJsb2FkaW5nIj5DYXJnYW5kbyBjYW1wYcOxYXPigKY8L3RkPjwvdHI+JzsKICB0cnl7Y29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL2NhbXBhaWducz9hY2NvdW50X2lkPScraWQpO1NUQVRFLmNmZz1kLmNvbmZpZ3x8U1RBVEUuY2ZnO1NUQVRFLnJvd3M9KGQuY2FtcGFpZ25zfHxbXSkubWFwKGVucmljaCk7cmVuZGVyKCk7fQogIGNhdGNoKGUpe1NUQVRFLnJvd3M9W107cmVuZGVyKCk7JCgnYmFubmVyTXNnJykudGV4dENvbnRlbnQ9dHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpOyQoJ2Jhbm5lcicpLmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTt9Cn0KZnVuY3Rpb24gZW5yaWNoKHIpe2NvbnN0IG09ci5tZXRyaWNzfHx7fTtjb25zdCBjdHI9bS5wcmludHM+MD8obS5jbGlja3MvbS5wcmludHMqMTAwKTpudWxsO3JldHVybiB7Li4ucixjb3N0Om0uY29zdHx8MCxyZXZlbnVlOm0ucmV2ZW51ZXx8MCxhY29zOm0uYWNvcyxyb2FzOm0ucm9hcyxjbGlja3M6bS5jbGlja3N8fDAscHJpbnRzOm0ucHJpbnRzfHwwLHVuaXRzOm0udW5pdHN8fDAsY3RyfTt9CmZ1bmN0aW9uIHRvZ2dsZUNoaXAoZWwpe2VsLmNsYXNzTGlzdC50b2dnbGUoJ29uJyk7U1RBVEUuYWN0c1tlbC5kYXRhc2V0LmFjdF09ZWwuY2xhc3NMaXN0LmNvbnRhaW5zKCdvbicpPzE6MDtyZW5kZXIoKTt9CmZ1bmN0aW9uIHNvcnRCeShrKXtpZihTVEFURS5zb3J0S2V5PT09aylTVEFURS5zb3J0RGlyKj0tMTtlbHNle1NUQVRFLnNvcnRLZXk9aztTVEFURS5zb3J0RGlyPS0xO31yZW5kZXIoKTt9CmZ1bmN0aW9uIGFjdGlvblBpbGwoYSl7Y29uc3QgbWFwPXtFU0NBTEFSOlsncC1ncmVlbicsJ/Cfn6IgRXNjYWxhciddLE1BTlRFTkVSOlsncC1hbWJlcicsJ/Cfn6EgTWFudGVuZXInXSxKVU5UQVJfREFUT1M6WydwLWJsdWUnLCfwn5S1IEp1bnRhciBkYXRvcyddLFBBVVNBUjpbJ3AtcmVkJywn8J+UtCBQYXVzYXInXX07Y29uc3RbY2xzLHR4dF09bWFwW2FdfHxbJ3AtZ3JleScsYV07cmV0dXJuICc8c3BhbiBjbGFzcz0icGlsbCAnK2NscysnIj4nK3R4dCsnPC9zcGFuPic7fQpmdW5jdGlvbiBhY29zQmFyKGFjb3MsYmUpe2NvbnN0IGJlMj0oYmUhPW51bGwpP2JlOigrU1RBVEUuY2ZnLm1hcmdpbnx8MTIpO2NvbnN0IHRhcmdldD0oYmUhPW51bGwpP2JlKjAuNjooK1NUQVRFLmNmZy5hY29zVGFyZ2V0fHw3KTtpZihhY29zPT1udWxsKXJldHVybiAnPHNwYW4gY2xhc3M9Im11dGVkIj5zL3ZlbnRhPC9zcGFuPic7Y29uc3QgcGN0PU1hdGgubWluKDEwMCxhY29zLyhiZTIqMS42KSoxMDApO2xldCBjb2w9YWNvczw9dGFyZ2V0Pyd2YXIoLS1ncmVlbiknOihhY29zPD1iZTI/J3ZhcigtLWFtYmVyKSc6J3ZhcigtLXJlZCknKTtyZXR1cm4gJzxkaXYgY2xhc3M9ImFjb3NjZWxsIj48c3Bhbj4nK2ZtdFBjdChhY29zKSsnPC9zcGFuPjxkaXYgY2xhc3M9ImFjb3NiYXIiPjxpIHN0eWxlPSJ3aWR0aDonK3BjdCsnJTtiYWNrZ3JvdW5kOicrY29sKyciPjwvaT48L2Rpdj48L2Rpdj4nO30KZnVuY3Rpb24gZmlsdGVyZWRSb3dzKCl7Y29uc3QgcT0oJCgnc2VhcmNoJykudmFsdWV8fCcnKS50b0xvd2VyQ2FzZSgpLnRyaW0oKTtjb25zdCBzdD0kKCdzdGF0dXNGaWx0ZXInKS52YWx1ZTtsZXQgcm93cz1TVEFURS5yb3dzLmZpbHRlcihyPT5TVEFURS5hY3RzW3IuYWN0aW9uXSk7aWYoc3QhPT0nYWxsJylyb3dzPXJvd3MuZmlsdGVyKHI9PlN0cmluZyhyLnN0YXR1cykudG9Mb3dlckNhc2UoKT09PXN0KTtpZihxKXJvd3M9cm93cy5maWx0ZXIocj0+KHIubmFtZXx8JycpLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMocSl8fFN0cmluZyhyLmNhbXBhaWduX2lkKS5pbmNsdWRlcyhxKSk7Y29uc3Qgaz1TVEFURS5zb3J0S2V5LGRpcj1TVEFURS5zb3J0RGlyO3Jvd3Muc29ydCgoYSxiKT0+e2xldCB4PWFba10seT1iW2tdO2lmKGs9PT0nbmFtZSd8fGs9PT0nc3RhdHVzJ3x8az09PSdhY3Rpb24nKXt4PVN0cmluZyh4fHwnJyk7eT1TdHJpbmcoeXx8JycpO3JldHVybiBkaXIqeC5sb2NhbGVDb21wYXJlKHkpO314PSh4PT1udWxsPy0xOngpO3k9KHk9PW51bGw/LTE6eSk7cmV0dXJuIGRpciooeC15KTt9KTtyZXR1cm4gcm93czt9CmZ1bmN0aW9uIHJlbmRlcigpewogIGNvbnN0IHJvd3M9ZmlsdGVyZWRSb3dzKCk7cmVuZGVyS3BpcygpO2NvbnN0IHRiPSQoJ3Rib2R5Jyk7CiAgaWYoIXJvd3MubGVuZ3RoKXt0Yi5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iMTIiIGNsYXNzPSJlbXB0eSI+Tm8gaGF5IGNhbXBhw7FhcyBxdWUgY29pbmNpZGFuLjwvdGQ+PC90cj4nO3JldHVybjt9CiAgdGIuaW5uZXJIVE1MPXJvd3MubWFwKHI9Pntjb25zdCBpc0E9U3RyaW5nKHIuc3RhdHVzKS50b0xvd2VyQ2FzZSgpPT09J2FjdGl2ZSc7Y29uc3Qgc3RQaWxsPWlzQT8nPHNwYW4gY2xhc3M9InBpbGwgcC1ncmVlbiI+QWN0aXZhPC9zcGFuPic6JzxzcGFuIGNsYXNzPSJwaWxsIHAtZ3JleSI+Jysoci5zdGF0dXN8fCfigJQnKSsnPC9zcGFuPic7CiAgICBjb25zdCBidG49aXNBPyc8YnV0dG9uIGNsYXNzPSJyb3didG4gcGF1c2UiIG9uY2xpY2s9InNldFN0YXR1cyhcJycrci5jYW1wYWlnbl9pZCsnXCcsXCdwYXVzZWRcJykiPlBhdXNhcjwvYnV0dG9uPic6JzxidXR0b24gY2xhc3M9InJvd2J0biBwbGF5IiBvbmNsaWNrPSJzZXRTdGF0dXMoXCcnK3IuY2FtcGFpZ25faWQrJ1wnLFwnYWN0aXZlXCcpIj5BY3RpdmFyPC9idXR0b24+JzsKICAgIHJldHVybiAnPHRyPjx0ZCBjbGFzcz0ibmFtZSI+Jytlc2Moci5uYW1lKSsnPHNwYW4gY2xhc3M9ImlkIj4nK3IuY2FtcGFpZ25faWQrJzwvc3Bhbj48L3RkPjx0ZD4nK3N0UGlsbCsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRNb25leShyLmNvc3QpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHIucmV2ZW51ZSkrJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrYWNvc0JhcihyLmFjb3Msci5icmVha2V2ZW5BY29zKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+Jysoci5icmVha2V2ZW5BY29zIT1udWxsP2ZtdFBjdChyLmJyZWFrZXZlbkFjb3MpOic8c3BhbiBjbGFzcz0ibXV0ZWQiPnMvY29zdG88L3NwYW4+JykrJzwvdGQ+PHRkIGNsYXNzPSJudW0iIHN0eWxlPSJmb250LXdlaWdodDo3MDA7Y29sb3I6Jysoci5uZXRQcm9maXQ9PW51bGw/J3ZhcigtLW11dCknOihyLm5ldFByb2ZpdD49MD8ndmFyKC0tZ3JlZW4pJzondmFyKC0tcmVkKScpKSsnIj4nKyhyLm5ldFByb2ZpdD09bnVsbD8n4oCUJzpmbXRNb25leShyLm5ldFByb2ZpdCkpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdFgoci5yb2FzKSsnPC90ZD48dGQgY2xhc3M9Im51bSI+JytyLmNsaWNrcy50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnPC90ZD48dGQ+JythY3Rpb25QaWxsKHIuYWN0aW9uKSsnPC90ZD48dGQgY2xhc3M9Im11dGVkIiBzdHlsZT0id2hpdGUtc3BhY2U6bm9ybWFsO21heC13aWR0aDoyMDBweCI+Jytlc2Moci5yZWFzb258fCcnKSsnPC90ZD48dGQ+JytidG4rJzwvdGQ+PC90cj4nO30pLmpvaW4oJycpOwp9CmZ1bmN0aW9uIHJlbmRlcktwaXMoKXsKICBjb25zdCByb3dzPVNUQVRFLnJvd3M7Y29uc3QgY29zdD1yb3dzLnJlZHVjZSgocyxyKT0+cysoci5jb3N0fHwwKSwwKTtjb25zdCByZXY9cm93cy5yZWR1Y2UoKHMscik9PnMrKHIucmV2ZW51ZXx8MCksMCk7CiAgY29uc3QgYWNvcz1yZXY+MD9jb3N0L3JldioxMDA6bnVsbDtjb25zdCByb2FzPWNvc3Q+MD9yZXYvY29zdDpudWxsO2NvbnN0IG1hcmdpbj0rU1RBVEUuY2ZnLm1hcmdpbnx8MTI7CiAgY29uc3QgY250PWE9PnJvd3MuZmlsdGVyKHI9PnIuYWN0aW9uPT09YSkubGVuZ3RoOwogIGNvbnN0IHJlYWxSb3dzPXJvd3MuZmlsdGVyKHI9PnIubmV0UHJvZml0IT1udWxsKTtjb25zdCByZWFsTmV0PXJlYWxSb3dzLnJlZHVjZSgocyxyKT0+cytyLm5ldFByb2ZpdCwwKTtjb25zdCBoYXNSZWFsPXJlYWxSb3dzLmxlbmd0aD4wOwogIGNvbnN0IGFjb3NDbHM9YWNvcz09bnVsbD8nJzooYWNvczw9KCtTVEFURS5jZmcuYWNvc1RhcmdldHx8Nyk/J2dvb2QnOihhY29zPD1tYXJnaW4/J3dhcm4nOidiYWQnKSk7CiAgY29uc3QgdGlsZXM9W1snSW52ZXJzacOzbicsZm10TW9uZXkoY29zdCksJyddLFsnVmVudGFzIHBvciBwdWIuJyxmbXRNb25leShyZXYpLCcnXSxbJ0FDT1MgZ2xvYmFsJyxmbXRQY3QoYWNvcyksYWNvc0Nsc10sWydST0FTIGdsb2JhbCcsZm10WChyb2FzKSxyb2FzJiZyb2FzPj0xLyhtYXJnaW4vMTAwKT8nZ29vZCc6J3dhcm4nXSxbaGFzUmVhbD8nR2FuYW5jaWEgbmV0YSByZWFsJzonR2FuYW5jaWEgZXN0aW0uJyxmbXRNb25leShoYXNSZWFsP3JlYWxOZXQ6cmV2KihtYXJnaW4vMTAwKS1jb3N0KSwoaGFzUmVhbD9yZWFsTmV0OnJldioobWFyZ2luLzEwMCktY29zdCk+PTA/J2dvb2QnOidiYWQnXSxbJ/Cfn6InK2NudCgnRVNDQUxBUicpKycg8J+foScrY250KCdNQU5URU5FUicpKycg8J+UtCcrY250KCdQQVVTQVInKSwnJywnJ11dOwogICQoJ2twaXMnKS5pbm5lckhUTUw9dGlsZXMubWFwKCh0LGkpPT5pPT09NT8nPGRpdiBjbGFzcz0ia3BpIj48ZGl2IGNsYXNzPSJrIj5TZW3DoWZvcm88L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3RbMF0rJzwvZGl2PjwvZGl2Pic6JzxkaXYgY2xhc3M9ImtwaSAnK3RbMl0rJyI+PGRpdiBjbGFzcz0iayI+Jyt0WzBdKyc8L2Rpdj48ZGl2IGNsYXNzPSJ2IHNtYWxsIj4nK3RbMV0rJzwvZGl2PjwvZGl2PicpLmpvaW4oJycpOwp9CmFzeW5jIGZ1bmN0aW9uIHNldFN0YXR1cyhjaWQsc3RhdHVzKXsKICBjb25zdCBhY2NvdW50X2lkPSQoJ2FjY291bnQnKS52YWx1ZTsKICB0cnl7YXdhaXQgYXBpKCcvYXBpL2Fkcy9jYW1wYWlnbi1zdGF0dXMnLHttZXRob2Q6J1BPU1QnLGJvZHk6SlNPTi5zdHJpbmdpZnkoe2FjY291bnRfaWQsY2FtcGFpZ25faWQ6Y2lkLHN0YXR1c30pfSk7Y29uc3Qgcm93PVNUQVRFLnJvd3MuZmluZChyPT5TdHJpbmcoci5jYW1wYWlnbl9pZCk9PT1TdHJpbmcoY2lkKSk7aWYocm93KXJvdy5zdGF0dXM9c3RhdHVzO3RvYXN0KCdDYW1wYcOxYSAnKyhzdGF0dXM9PT0ncGF1c2VkJz8ncGF1c2FkYSc6J2FjdGl2YWRhJykpO3JlbmRlcigpO30KICBjYXRjaChlKXt0b2FzdCgnTm8gc2UgcHVkbzogJysodHlwZW9mIGUuZXJyb3I9PT0nc3RyaW5nJz9lLmVycm9yOkpTT04uc3RyaW5naWZ5KGUuZXJyb3IpKSk7fQp9CmFzeW5jIGZ1bmN0aW9uIHJ1bk5vdygpewogIHRyeXt0b2FzdCgnQ29ycmllbmRvIGFuw6FsaXNpc+KApicpO2NvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy9ydW4tbm93Jyx7bWV0aG9kOidQT1NUJ30pO2NvbnN0IHBhdXNlZD1kLnJlc3VsdHMuZmlsdGVyKHI9PnIucGF1c2VkKS5sZW5ndGgsd291bGQ9ZC5yZXN1bHRzLmZpbHRlcihyPT5yLndvdWxkX3BhdXNlKS5sZW5ndGg7dG9hc3QoZC5kcnlfcnVuPygnRFJZLVJVTjogcGF1c2Fyw61hICcrd291bGQpOignTGlzdG86ICcrcGF1c2VkKycgcGF1c2FkYXMnKSk7bG9hZENhbXBhaWducygpO2xvYWRMb2coKTt9CiAgY2F0Y2goZSl7dG9hc3QoJ0Vycm9yOiAnKyhlLmVycm9yfHxlKSk7fQp9CmFzeW5jIGZ1bmN0aW9uIGxvYWRMb2coKXsKICB0cnl7Y29uc3QgZD1hd2FpdCBhcGkoJy9hcGkvYWRzL2xvZycpOyQoJ2xhc3RSdW4nKS50ZXh0Q29udGVudD1kLmxhc3RfcnVuPygnw5psdGltYSBjb3JyaWRhOiAnK25ldyBEYXRlKGQubGFzdF9ydW4pLnRvTG9jYWxlU3RyaW5nKCdlcy1BUicpKTonU2luIGNvcnJpZGFzIGHDum4nOwogIGNvbnN0IHJ1bnM9ZC5ydW5zfHxbXTskKCdsb2djYXJkJykuaW5uZXJIVE1MPXJ1bnMubGVuZ3RoP3J1bnMubWFwKHJ1bj0+e2NvbnN0IGhlYWQ9JzxkaXYgY2xhc3M9ImIiPicrbmV3IERhdGUocnVuLmF0KS50b0xvY2FsZVN0cmluZygnZXMtQVInKSsnIMK3ICcrKHJ1bi5kcnlfcnVuPydEUlktUlVOJzonTElWRScpKyc8L2Rpdj4nO2NvbnN0IGl0ZW1zPShydW4ucmVzdWx0c3x8W10pLmZpbHRlcihyPT5yLndvdWxkX3BhdXNlfHxyLnBhdXNlZHx8ci5lcnJvcikubWFwKHI9Pic8ZGl2IGNsYXNzPSJsb2dyb3ciPjxzcGFuIGNsYXNzPSJwaWxsICcrKHIucGF1c2VkPydwLXJlZCc6KHIuZXJyb3I/J3AtZ3JleSc6J3AtYW1iZXInKSkrJyI+Jysoci5wYXVzZWQ/J3BhdXNhZGEnOihyLmVycm9yPydlcnJvcic6J2EgcGF1c2FyJykpKyc8L3NwYW4+IDxzcGFuIGNsYXNzPSJiIj4nK2VzYyhyLm5hbWV8fHIuYWNjb3VudHx8JycpKyc8L3NwYW4+IDxzcGFuIGNsYXNzPSJtdXRlZCI+Jytlc2Moci5yZWFzb258fHIuZXJyb3J8fCcnKSsnPC9zcGFuPjwvZGl2PicpLmpvaW4oJycpfHwnPGRpdiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJwYWRkaW5nOjZweCAwIj5TaW4gY2FtYmlvcy48L2Rpdj4nO3JldHVybiBoZWFkK2l0ZW1zO30pLmpvaW4oJzxociBzdHlsZT0iYm9yZGVyOm5vbmU7Ym9yZGVyLXRvcDoxcHggc29saWQgdmFyKC0tbGluZSk7bWFyZ2luOjEwcHggMCI+Jyk6JzxkaXYgY2xhc3M9Im11dGVkIj5TaW4gY29ycmlkYXMuPC9kaXY+Jzt9Y2F0Y2goZSl7fQp9CmZ1bmN0aW9uIHRvZ2dsZUxvZygpe2NvbnN0IGM9JCgnbG9nY2FyZCcpO2MuY2xhc3NMaXN0LnRvZ2dsZSgnc2hvdycpO2lmKGMuY2xhc3NMaXN0LmNvbnRhaW5zKCdzaG93JykpbG9hZExvZygpO30KCi8vIC0tLS0gR0FOQURPUkFTIC0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZFdpbm5lcnMoKXsKICBjb25zdCBpZD0kKCdhY2NvdW50JykudmFsdWU7aWYoIWlkKXt0b2FzdCgnRWxlZ8OtIHVuYSBjdWVudGEnKTtyZXR1cm47fQogIGNvbnN0IG09JCgnd2luX21hcmdpbicpLnZhbHVlfHwxMixzPSQoJ3dpbl9zYWxlcycpLnZhbHVlfHwwLGw9JCgnd2luX2xpbWl0JykudmFsdWV8fDQwOwogICQoJ3dpblN0YXR1cycpLnRleHRDb250ZW50PSdCdXNjYW5kb+KApic7CiAgdHJ5e2NvbnN0IGQ9YXdhaXQgYXBpKCcvYXBpL2Fkcy93aW5uZXJzP2FjY291bnRfaWQ9JytpZCsnJm1pbk1hcmdpbj0nK20rJyZtaW5TYWxlcz0nK3MrJyZsaW1pdD0nK2wpO1dJTk5FUlM9ZC53aW5uZXJzfHxbXTsKICAkKCd3aW5TdGF0dXMnKS5pbm5lckhUTUw9JzxiPicrV0lOTkVSUy5sZW5ndGgrJzwvYj4gZ2FuYWRvcmFzJysoZC5zY2FubmVkPygnIChkZSAnK2Quc2Nhbm5lZCsnIHJldmlzYWRhcyknKTonJykrKGQubm90ZT8oJyDCtyAnK2VzYyhkLm5vdGUpKTonJyk7cmVuZGVyV2lubmVycygpO30KICBjYXRjaChlKXskKCd3aW5TdGF0dXMnKS50ZXh0Q29udGVudD0nRXJyb3I6ICcrKHR5cGVvZiBlLmVycm9yPT09J3N0cmluZyc/ZS5lcnJvcjpKU09OLnN0cmluZ2lmeShlLmVycm9yKSk7fQp9CmZ1bmN0aW9uIHJlbmRlcldpbm5lcnMoKXsKICBjb25zdCB0Yj0kKCd3aW5Cb2R5Jyk7aWYoIVdJTk5FUlMubGVuZ3RoKXt0Yi5pbm5lckhUTUw9Jzx0cj48dGQgY29sc3Bhbj0iNSIgY2xhc3M9ImVtcHR5Ij5TaW4gcmVzdWx0YWRvcy48L3RkPjwvdHI+JztyZXR1cm47fQogIHRiLmlubmVySFRNTD1XSU5ORVJTLm1hcCh3PT4nPHRyPjx0ZCBjbGFzcz0ibmFtZSI+PGEgaHJlZj0iJysody5wZXJtYWxpbmt8fCcjJykrJyIgdGFyZ2V0PSJfYmxhbmsiPicrZXNjKHcudGl0bGV8fHcuaXRlbV9pZCkrJzwvYT48c3BhbiBjbGFzcz0iaWQiPicrdy5pdGVtX2lkKyc8L3NwYW4+PC90ZD48dGQgY2xhc3M9Im51bSI+JytmbXRQY3Qody5tYXJnaW4pKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK2ZtdE1vbmV5KHcucHJpY2UpKyc8L3RkPjx0ZCBjbGFzcz0ibnVtIj4nK3cuc3RvY2srJzwvdGQ+PHRkIGNsYXNzPSJudW0iPicrdy5zb2xkKyc8L3RkPjwvdHI+Jykuam9pbignJyk7Cn0KZnVuY3Rpb24gY29weVdpbm5lcnMoKXtpZighV0lOTkVSUy5sZW5ndGgpe3RvYXN0KCdCdXNjw6EgZ2FuYWRvcmFzIHByaW1lcm8nKTtyZXR1cm47fWNvbnN0IGlkcz1XSU5ORVJTLm1hcCh3PT53Lml0ZW1faWQpLmpvaW4oJywgJyk7aWYobmF2aWdhdG9yLmNsaXBib2FyZCl7bmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoaWRzKS50aGVuKCgpPT50b2FzdCgnQ29waWFkb3MgJytXSU5ORVJTLmxlbmd0aCsnIElEcycpKS5jYXRjaCgoKT0+cHJvbXB0KCdDb3Bpw6EgbG9zIElEczonLGlkcykpO31lbHNlIHByb21wdCgnQ29wacOhIGxvcyBJRHM6JyxpZHMpO30KZnVuY3Rpb24gY3N2V2lubmVycygpe2lmKCFXSU5ORVJTLmxlbmd0aCl7dG9hc3QoJ0J1c2PDoSBnYW5hZG9yYXMgcHJpbWVybycpO3JldHVybjt9Y29uc3Qgcm93cz1bWydpdGVtX2lkJywndGl0dWxvJywnbWFyZ2VuXyUnLCdwcmVjaW8nLCdzdG9jaycsJ3ZlbnRhcyddXTtXSU5ORVJTLmZvckVhY2godz0+cm93cy5wdXNoKFt3Lml0ZW1faWQsJyInK1N0cmluZyh3LnRpdGxlfHwnJykucmVwbGFjZSgvIi9nLCcnKSsnIicsdy5tYXJnaW4udG9GaXhlZCgxKSx3LnByaWNlLHcuc3RvY2ssdy5zb2xkXSkpO2NvbnN0IGNzdj1yb3dzLm1hcChyPT5yLmpvaW4oJywnKSkuam9pbignXG4nKTtjb25zdCBhPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2EnKTthLmhyZWY9J2RhdGE6dGV4dC9jc3Y7Y2hhcnNldD11dGYtOCwnK2VuY29kZVVSSUNvbXBvbmVudChjc3YpO2EuZG93bmxvYWQ9J2dhbmFkb3Jhcy5jc3YnO2EuY2xpY2soKTt9Cgppbml0KCk7Cjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K", "base64").toString("utf8");
// El mismo panel se sirve en dos modos: /publicidad = Estrategia, /gestion = Gestión (rentabilidad diaria).
function servePanel(mode, req, res) {
  const sess = requireAuth(req);
  if (!sess) { res.writeHead(302, { Location: '/' }); return res.end(); }
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
