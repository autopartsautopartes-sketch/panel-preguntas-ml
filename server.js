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
const DB_BACKUP_ENV = process.env.DB_BACKUP; // base64-encoded backup from env var

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
console.log(`[STARTUP] Sesiones restauradas: ${Object.keys(sessions).length}`);

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
  sessions[sid] = { created: Date.now() };
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax`);
  saveSessions();
  return sessions[sid];
}

function destroySession(req, res) {
  const cookies = parseCookies(req);
  if (cookies.sid) delete sessions[cookies.sid];
  res.setHeader('Set-Cookie', `sid=; HttpOnly; Path=/; Max-Age=0`);
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
  const db = loadDB();
  const user = db.users.find(u => u.id === sess.userId);
  sendJSON(res, 200, {
    username: sess.username, role: sess.role,
    alerts_questions: user?.alerts_questions ?? true,
    alerts_messages: user?.alerts_messages ?? true,
    view_dashboard: user?.view_dashboard !== false
  });
});

// USERS
route('GET', '/api/users', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const db = loadDB();
  sendJSON(res, 200, db.users.map(u => ({ id: u.id, username: u.username, role: u.role, alerts_questions: u.alerts_questions ?? true, alerts_messages: u.alerts_messages ?? true, view_dashboard: u.view_dashboard !== false, created_at: u.created_at })));
});

route('POST', '/api/users/alerts', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { id, alerts_questions, alerts_messages, view_dashboard } = await parseBody(req);
  const db = loadDB();
  const user = db.users.find(u => u.id === parseInt(id));
  if (!user) return sendJSON(res, 404, { error: 'Usuario no encontrado' });
  if (alerts_questions !== undefined) user.alerts_questions = !!alerts_questions;
  if (alerts_messages !== undefined) user.alerts_messages = !!alerts_messages;
  if (view_dashboard !== undefined) user.view_dashboard = !!view_dashboard;
  saveDB(db);
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/users', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });
  const { username, password } = await parseBody(req);
  if (!username || !password) return sendJSON(res, 400, { error: 'Faltan datos' });
  const db = loadDB();
  if (db.users.find(u => u.username === username)) return sendJSON(res, 400, { error: 'El usuario ya existe' });
  db.users.push({ id: db.nextUserId++, username, password: hashPassword(password), role: 'user', alerts_questions: true, alerts_messages: true, view_dashboard: true, created_at: new Date().toISOString() });
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
          seller: account.seller_id, sort: 'date_desc', limit: 20
        });
        ordersResults = ordersData.results || [];
      }

      const seenPacks = new Set();
      const uniqueOrders = [];
      for (const order of ordersResults) {
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
          const msgData = await mlGet(`https://api.mercadolibre.com/messages/packs/${packId}/sellers/${account.seller_id}`, token, {
            tag: 'post_sale', limit: 15
          });
          const messages = msgData.messages || [];
          if (messages.length === 0) return null;

          const mappedMessages = messages.map(m => ({
            id: m.id, from: m.from?.user_id?.toString() === account.seller_id ? 'seller' : 'buyer',
            text: m.text || m.plain?.content || '', date: m.date_created || m.date || m.created_at || m.date_received || m.message_date?.created || ''
          }));

          const lastMsg = mappedMessages[mappedMessages.length - 1];
          const isUnread = lastMsg.from === 'buyer';

          if (!buyerFilter && !orderFilter) {
            if ((statusFilter === 'unread' && !isUnread) || (statusFilter === 'answered' && isUnread)) return null;
          }

          return {
            order_id: order.id, pack_id: packId, account_name: account.name, account_id: account.id,
            seller_id: account.seller_id, buyer_name: order.buyer?.nickname || 'Comprador',
            buyer_id: order.buyer?.id?.toString() || '',
            item_title: order.order_items?.[0]?.item?.title || 'Producto',
            messages: mappedMessages, is_unread: isUnread,
            last_message_date: messages[messages.length - 1]?.date_created || messages[messages.length - 1]?.date || order.date_created
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

    console.log('[MSG REPLY] pack:', packId, 'seller:', sellerId, 'buyer:', buyerId);

    // ML messages API requires application_id param and x-client-id header
    const msgUrl = `https://api.mercadolibre.com/messages/packs/${packId}/sellers/${sellerId}?application_id=${ML_CLIENT_ID}`;
    console.log('[MSG REPLY] POST to:', msgUrl);

    const msgBody = {
      from: { user_id: String(sellerId), email: "test" },
      to: { user_id: String(buyerId) },
      text: text
    };

    const msgRes = await fetch(msgUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'x-client-id': ML_CLIENT_ID
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

// SALES
// In-memory caches to speed up repeated requests
const itemCache = {}; // cache item thumbnail/sku by item id (rarely changes)
const shipmentCacheGlobal = {}; // cache shipment info by shipping_id

route('GET', '/api/sales', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess) return sendJSON(res, 401, { error: 'No autorizado' });

  const url = new URL(req.url, 'http://localhost');
  const accountFilter = url.searchParams.get('account_id');
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
      const params = { seller: account.seller_id, sort: 'date_desc', limit: 50 };
      if (dateFrom) params['order.date_created.from'] = dateFrom + 'T00:00:00.000-00:00';
      if (dateTo) params['order.date_created.to'] = dateTo + 'T23:59:59.999-00:00';
      const ordersData = await mlGet('https://api.mercadolibre.com/orders/search', token, params);
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
  const b64 = Buffer.from(JSON.stringify(db)).toString('base64');
  sendJSON(res, 200, {
    instructions: 'Copia este valor y pegalo en Render > Environment > DB_BACKUP. Asi tus datos se restauran automaticamente en cada deploy.',
    base64: b64,
    users: db.users.length,
    accounts: (db.ml_accounts || []).length
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
  console.log('[SHUTDOWN] Guardando sesiones...');
  saveSessions();
  console.log('[SHUTDOWN] Listo. Cerrando servidor.');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
});
