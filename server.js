route('GET', '/api/promotion-items-stream', async (req, res) => {
  const sess = requireAuth(req);
  if (!sess || sess.role !== 'admin') return sendJSON(res, 403, { error: 'Acceso denegado' });

  const urlObj = new URL(req.url, 'http://localhost');
  const accountId = parseInt(urlObj.searchParams.get('account_id'));
  const promoId = urlObj.searchParams.get('promo_id');
  if (!promoId) return sendJSON(res, 400, { error: 'Falta promo_id' });

  const db = loadDB();
  const account = db.ml_accounts.find(a => a.id === accountId);
  if (!account) return sendJSON(res, 404, { error: 'Cuenta no encontrada' });

  const userToken = await getValidToken(account);
  const appTok = await getAppToken();

  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson',
    'Transfer-Encoding': 'chunked',
    'Cache-Control': 'no-cache'
  });

  const candidates = [
    {
      label: 'marketplace_app',
      token: appTok,
      headers: promoH(),
      buildUrl: (searchAfter) => {
        let u = `${PROMO_BASE}/promotions/${promoId}/items?user_id=${account.seller_id}&limit=50`;
        if (searchAfter) u += `&search_after=${encodeURIComponent(searchAfter)}`;
        return u;
      }
    },
    {
      label: 'marketplace_user',
      token: userToken,
      headers: promoH(),
      buildUrl: (searchAfter) => {
        let u = `${PROMO_BASE}/promotions/${promoId}/items?user_id=${account.seller_id}&limit=50`;
        if (searchAfter) u += `&search_after=${encodeURIComponent(searchAfter)}`;
        return u;
      }
    },
    {
      label: 'old_user',
      token: userToken,
      headers: {},
      buildUrl: (searchAfter) => {
        let u = `https://api.mercadolibre.com/seller-promotions/promotions/${promoId}/items?app_id=${ML_CLIENT_ID}&app_version=2.0.0&user_id=${account.seller_id}&limit=50`;
        if (searchAfter) u += `&search_after=${encodeURIComponent(searchAfter)}`;
        return u;
      }
    }
  ];

  for (const c of candidates) {
    if (!c.token) continue;

    let total = null, sent = 0, searchAfter = null;
    let hadSuccess = false;

    try {
      do {
        const r = await mlGet(c.buildUrl(searchAfter), c.token, {}, c.headers);
        const items = r.results || r.items || r.data || (Array.isArray(r) ? r : []);

        if (total === null) {
          total = r.paging?.total ?? r.total ?? items.length;
          res.write(JSON.stringify({ type: 'debug', winner: c.label, total, sample: r }) + '\n');
          res.write(JSON.stringify({ type: 'total', total }) + '\n');
        }

        for (const it of items) {
          res.write(JSON.stringify({ type: 'item', data: it }) + '\n');
          sent++;
        }

        searchAfter = r.paging?.search_after || null;
        hadSuccess = true;
      } while (searchAfter);

      if (hadSuccess && sent > 0) {
        res.write(JSON.stringify({ type: 'done', total: sent }) + '\n');
        return res.end();
      }
    } catch (e) {
      res.write(JSON.stringify({
        type: 'debug_error',
        tried: c.label,
        status: e?.response?.status,
        error: e?.response?.data || e?.message || e
      }) + '\n');
    }
  }

  res.write(JSON.stringify({ type: 'done', total: 0 }) + '\n');
  res.end();
});
