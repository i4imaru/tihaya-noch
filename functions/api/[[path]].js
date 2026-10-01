// Тихая ночь — серверная часть (Cloudflare Pages Functions).
// Нужно: привязка D1 с именем DB и секрет ADMIN_TOKEN (не короче 12 символов). Таблицы создаются сами.
//   GET  /api/geo                      страна посетителя по IP (Cloudflare)
//   GET  /api/doc?p=…   PUT /api/doc?p=…   документы: visits/<vid>, notes/<vid> (свои), public/notes (читают все, пишет владелец)
//   GET  /api/list?c=visits|notes&n=…  все документы коллекции (только владелец)
//   GET  /api/admin/ping               проверка токена владельца

const J = (o, s = 200) => new Response(JSON.stringify(o), {
  status: s,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
});
const VID = /^v_[a-z0-9]{20}$/;
let ready = false;

async function ensure(db) {
  if (ready) return;
  await db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS docs (path TEXT PRIMARY KEY, col TEXT NOT NULL, body TEXT NOT NULL, updated INTEGER NOT NULL)'),
    db.prepare('CREATE INDEX IF NOT EXISTS docs_col ON docs (col, updated)'),
  ]);
  ready = true;
}

function isAdmin(req, env) {
  const t = String(env.ADMIN_TOKEN || '');
  if (t.length < 12) return false;
  const h = req.headers.get('authorization') || '';
  const g = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (g.length !== t.length) return false;
  let x = 0;
  for (let i = 0; i < t.length; i++) x |= g.charCodeAt(i) ^ t.charCodeAt(i);
  return x === 0;
}

function parsePath(p) {
  const m = /^(visits|notes)\/(v_[a-z0-9]{20})$/.exec(p || '');
  if (m) return { col: m[1], id: m[2] };
  if (p === 'public/notes') return { col: 'public', id: 'notes' };
  return null;
}

const str = (v, n) => String(v == null ? '' : v).slice(0, n);

function cleanNotes(b) {
  if (!Array.isArray(b.items) || b.items.length > 10) return null;
  return {
    items: b.items
      .map(n => ({ id: str(n && n.id, 16), text: str(n && n.text, 400), at: Number(n && n.at) || Date.now(), lang: str(n && n.lang, 5), room: n && n.room ? str(n.room, 12) : null }))
      .filter(n => n.id && n.text.trim()),
  };
}

function cleanPublic(b) {
  const items = (Array.isArray(b.items) ? b.items : []).slice(-300)
    .map(n => ({ id: str(n && n.id, 16), text: str(n && n.text, 400), at: Number(n && n.at) || Date.now(), lang: str(n && n.lang, 5) }))
    .filter(n => n.id && n.text.trim());
  const hidden = (Array.isArray(b.hidden) ? b.hidden : []).slice(-500).map(x => str(x, 16)).filter(Boolean);
  return { items, hidden };
}

export async function onRequest({ request, env, params }) {
  const route = [].concat(params.path || []).join('/');
  const url = new URL(request.url);

  if (route === 'geo') return J({ cc: (request.cf && request.cf.country) || null });
  if (!env.DB) return J({ error: 'no_db' }, 503);
  await ensure(env.DB);

  const admin = isAdmin(request, env);
  const vid = request.headers.get('x-tn-vid') || '';

  if (route === 'admin/ping') return admin ? J({ ok: true }) : J({ error: 'forbidden' }, 403);

  if (route === 'doc') {
    const P = parsePath(url.searchParams.get('p'));
    if (!P) return J({ error: 'bad_path' }, 400);
    const key = P.col + '/' + P.id;
    const own = P.col !== 'public' && VID.test(vid) && P.id === vid;

    if (request.method === 'GET') {
      if (!(own || admin || P.col === 'public')) return J({ body: null });
      const r = await env.DB.prepare('SELECT body FROM docs WHERE path = ?').bind(key).first();
      return J({ body: r ? JSON.parse(r.body) : null });
    }
    if (request.method === 'PUT') {
      const txt = await request.text();
      if (txt.length > 65536) return J({ error: 'too_large' }, 413);
      let b;
      try { b = JSON.parse(txt); } catch (e) { return J({ error: 'bad_json' }, 400); }
      if (!b || typeof b !== 'object' || Array.isArray(b)) return J({ error: 'bad_body' }, 400);
      if (P.col === 'public') {
        if (!admin) return J({ error: 'forbidden' }, 403);
        b = cleanPublic(b);
      } else {
        if (!own) return J({ error: 'forbidden' }, 403);
        if (P.col === 'notes') { b = cleanNotes(b); if (!b) return J({ error: 'bad_body' }, 400); }
        else if (admin) b.owner = true;
        else delete b.owner;
      }
      await env.DB.prepare('INSERT INTO docs (path, col, body, updated) VALUES (?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET body = excluded.body, updated = excluded.updated')
        .bind(key, P.col, JSON.stringify(b), Date.now()).run();
      return J({ ok: true });
    }
    return J({ error: 'method' }, 405);
  }

  if (route === 'list') {
    if (!admin) return J({ error: 'forbidden' }, 403);
    const c = url.searchParams.get('c');
    if (c !== 'visits' && c !== 'notes') return J({ error: 'bad_col' }, 400);
    const n = Math.min(2000, Math.max(1, Number(url.searchParams.get('n')) || 1000));
    const r = await env.DB.prepare('SELECT path, body FROM docs WHERE col = ? ORDER BY updated DESC LIMIT ?').bind(c, n).all();
    return J({ docs: (r.results || []).map(x => ({ id: x.path.split('/')[1], body: JSON.parse(x.body) })) });
  }

  return J({ error: 'not_found' }, 404);
}
