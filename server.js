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

// ==================== JSON DATABASE ====================

const DB_PATH = path.join(__dirname, 'data.json');

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) {
    return { users: [], ml_accounts: [], nextUserId: 1, nextAccountId: 1 };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Init admin
const dbInit = loadDB();
if (dbInit.users.length === 0) {
  dbInit.users.push({
    id: dbInit.nextUserId++,
    username: 'admin',
    password: hashPassword('admin123'),
    role: 'admin',
    created_at: new Date().toISOString()
  });
  saveDB(dbInit);
  console.log('Usuario admin creado: admin / admin123');
}

// ==================== SESSION STORE ====================

const sessions = {};

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function getSession(req) {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (sid && sessions[sid]) return sessions[sid];
  return null;
}

function createSession(res) {
  const sid = generateSessionId();
  sessions[sid] = {};
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`);
  return sessions[sid];
}

function destroySession(req, res) {
  const cookies = parseCookies(req);
  if (cookies.sid) delete sessions[cookies.sid];
  res.setHeader('Set-Cookie', `sid=; HttpOnly; Path=/; Max-Age=0`);
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [key, ...vals] = c.trim().split('=');
    if (key) cookies[key] = vals.join('=');
  });
  return cookies;
}

// ==================== HTTP HELPERS ====================

async function mlGet(url, token, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const fullUrl = qs ? `${url}?${qs}` : url;
  const res = await fetch(fullUrl, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
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

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); } catch (e) { resolve({}); }
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
  const { username, password } = await parseBody(req);
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !verifyPassword(password, user.password)) {
    return sendJSON(res, 401, { error: 'Usuario o contraseña incorrectos' });
  }
  const sess = createSession(res);
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
  sendJSON(res, 200, { username: sess.username, role: sess.role });
});

// USERS
route('GET', '/api/users', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const db = loadDB();
  sendJSON(res, 200, db.users.map(u => ({ id: u.id, username: u.username, role: u.role, created_at: u.created_at })));
});

route('POST', '/api/users', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { username, password } = await parseBody(req);
  if (!username || !password) return sendJSON(res, 400, { error: 'Faltan datos' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return sendJSON(res, 400, { error: 'El usuario ya existe' });
  db.users.push({ id: db.nextUserId++, username, password: hashPassword(password), role: 'user', created_at: new Date().toISOString() });
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
});route('GET', '/callback', async (req, res) => {
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
  const db = loadDB();
  let allQuestions = [];

  const targets = accountFilter ? db.ml_accounts.filter(a => a.id === parseInt(accountFilter)) : db.ml_accounts;

  for (const account of targets) {
    const token = await getValidToken(account);
    if (!token) continue;
    try {
      const data = await mlGet('https://api.mercadolibre.com/questions/search', token, {
        seller_id: account.seller_id, status, sort_fields: 'date_created', sort_types: 'DESC', limit: 50
      });
      const questions = data.questions || [];

      const itemIds = [...new Set(questions.map(q => q.item_id))];
      const itemDetails = {};
      for (const itemId of itemIds) {
        try {
          const itemData = await mlGet(`https://api.mercadolibre.com/items/${itemId}`, token);
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
          // Determine listing type label
          let listingType = '';
          const lt = itemData.listing_type_id || '';
          if (lt === 'gold_special' || lt === 'gold_pro') listingType = 'Premium';
          else if (lt === 'gold') listingType = 'Clásica';
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
        } catch (e){console.error(`Error fetching item ${itemId}:`, e.response?.data || e.message || e);
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
  if (!token) return sendJSON(res, 500, { error: 'Token inválido' });

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
  const db = loadDB();
  let allMessages = [];

  const targets = accountFilter ? db.ml_accounts.filter(a => a.id === parseInt(accountFilter)) : db.ml_accounts;

  for (const account of targets) {
    const token = await getValidToken(account);
    if (!token) continue;
    try {
      const ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, {
        seller: account.seller_id, sort: 'date_desc', limit: 20
      });

      for (const order of (ordersData.results || [])) {
        try {
          const msgData = await mlGet(`https://api.mercadolibre.com/messages/orders/${order.id}`, token, {
            seller: account.seller_id, limit: 10
          });
          const messages = msgData.messages || [];
          if (messages.length === 0) continue;

          allMessages.push({
            order_id: order.id, account_name: account.name, account_id: account.id,
            seller_id: account.seller_id, buyer_name: order.buyer?.nickname || 'Comprador',
            item_title: order.order_items?.[0]?.item?.title || 'Producto',
            messages: messages.map(m => ({
              id: m.id, from: m.from?.user_id?.toString() === account.seller_id ? 'seller' : 'buyer',
              text: m.text, date: m.date
            })),
            last_message_date: messages[messages.length - 1]?.date || order.date_created
          });
        } catch (e) {}
      }
    } catch (err) {
      console.error(`Error messages ${account.name}:`, err.response?.data || err.message || err);
    }
  }

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
  if (!token) return sendJSON(res, 500, { error: 'Token inválido' });

  try {
    const orderData = await mlGet(`https://api.mercadolibre.com/orders/${order_id}`, token);
    const buyerId = orderData.buyer.id;
    await mlPost(`https://api.mercadolibre.com/messages/packs/${orderData.pack_id || order_id}/sellers/${account.seller_id}`, {
      from: { user_id: account.seller_id }, to: { user_id: buyerId }, text
    }, token);
    sendJSON(res, 200, { ok: true });
  } catch (err) {
    console.error('Error sending message:', err.response?.data || err.message || err);
    sendJSON(res, 500, { error: err.response?.data?.message || 'Error al enviar mensaje' });
  }
});

// STATS
route('GET', '/api/stats', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });
  const db = loadDB();
  let totalUnanswered = 0, totalAnswered = 0;

  for (const account of db.ml_accounts) {
    const token = await getValidToken(account);
    if (!token) continue;
    try {
      const u = await mlGet('https://api.mercadolibre.com/questions/search', token, { seller_id: account.seller_id, status: 'UNANSWERED', limit: 0 });
      totalUnanswered += u.total || 0;
      const a = await mlGet('https://api.mercadolibre.com/questions/search', token, { seller_id: account.seller_id, status: 'ANSWERED', limit: 0 });
      totalAnswered += a.total || 0;
    } catch (e) {}
  }

  sendJSON(res, 200, { accounts: db.ml_accounts.length, unanswered: totalUnanswered, answered: totalAnswered });
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

// ==================== STATIC FILES ====================

const MIME_TYPES = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
};

function serveStatic(req, res) {
  let filePath = path.join(__dirname, 'public', req.url === '/' ? 'index.html' : req.url.split('?')[0]);
  const ext = path.extname(filePath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Serve index.html for SPA routes
      fs.readFile(path.join(__dirname, 'public', 'index.html'), (err2, data2) => {
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

// ==================== SERVER ====================

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  const method = req.method;

  // Match route
  const routeKey = `${method}:${pathname}`;
  if (routes[routeKey]) {
    try {
      await routes[routeKey](req, res);
    } catch (err) {
      console.error('Server error:', err);
      sendJSON(res, 500, { error: 'Error interno del servidor' });
    }
    return;
  }

  // Static files
  if (method === 'GET') {
    serveStatic(req, res);
    return;
  }

  sendJSON(res, 404, { error: 'Ruta no encontrada' });
});

server.listen(PORT, () => {
  console.log(`Panel de preguntas corriendo en ${BASE_URL}`);
  console.log(`Puerto: ${PORT}`);
});
