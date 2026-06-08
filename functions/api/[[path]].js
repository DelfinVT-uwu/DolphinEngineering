/* ═══════════════════════════════════════════════════════
   DolphinEngineering — Cloudflare Pages API
   Powered by D1 + JWT (HMAC-SHA256 via Web Crypto)
   ═══════════════════════════════════════════════════════ */

/* ─── JWT helpers ──────────────────────────────────── */
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function createJWT(payload, secret) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`))));
  return `${header}.${body}.${sig}`;
}
async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

/* ─── password helpers ──────────────────────────────── */
async function hashPw(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return `${b64url(salt)}:${b64url(bits)}`;
}
async function verifyPw(password, stored) {
  const [saltB64, hashB64] = stored.split(':');
  const salt = b64urlDecode(saltB64);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return b64url(bits) === hashB64;
}

/* ─── helpers ───────────────────────────────────────── */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }
  });
}
function sanitize(v) {
  if (typeof v !== 'string') return '';
  return v.replace(/<[^>]*>/g, '').trim();
}
function getToken(req) {
  const c = req.headers.get('Cookie') || '';
  const m = c.match(/(?:^|;\s*)token=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}
function setCookie(token) {
  return `token=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400`;
}
function clearCookie() {
  return `token=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`;
}
function getIP(req) {
  return req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';
}

/* ─── rate limit ────────────────────────────────────── */
async function checkRateLimit(env, ip, endpoint, max, windowMin) {
  const row = await env.DB.prepare(
    `SELECT count, window_start FROM rate_limits WHERE ip = ? AND endpoint = ?`
  ).bind(ip, endpoint).first();
  const now = Date.now();
  if (!row) {
    await env.DB.prepare(
      `INSERT INTO rate_limits (ip, endpoint, count, window_start) VALUES (?, ?, 1, ?)`
    ).bind(ip, endpoint, now).run();
    return true;
  }
  if (now - row.window_start > windowMin * 60 * 1000) {
    await env.DB.prepare(
      `UPDATE rate_limits SET count = 1, window_start = ? WHERE ip = ? AND endpoint = ?`
    ).bind(now, ip, endpoint).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare(
    `UPDATE rate_limits SET count = count + 1 WHERE ip = ? AND endpoint = ?`
  ).bind(ip, endpoint).run();
  return true;
}

/* ─── seed admin ────────────────────────────────────── */
async function ensureAdmin(env) {
  const existing = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind('admin@dolphin.sec').first();
  if (!existing) {
    const hash = await hashPw('Admin123!');
    await env.DB.prepare(
      `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')`
    ).bind('Administrador', 'admin@dolphin.sec', hash).run();
  }
}

/* ═══════════════════════════════════════════════════════
   REQUEST HANDLER
   ═══════════════════════════════════════════════════════ */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\//, '').replace(/\/$/, '');
  const method = request.method;

  /* CORS preflight */
  if (method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Credentials': 'true' } });
  }

  try {
    /* seed admin on first request */
    await ensureAdmin(env);
  } catch {}

  try {
    /* ─── REGISTER ──────────────────────────────────── */
    if (path === 'register' && method === 'POST') {
      const ip = getIP(request);
      if (!await checkRateLimit(env, ip, 'register', 5, 15))
        return json({ success: false, message: 'Demasiados intentos. Intenta en 15 minutos.' }, 429);

      const body = await request.json();
      const name = sanitize(body.name);
      const email = sanitize(body.email);
      const password = body.password;
      const org = sanitize(body.organization);

      if (!name || !email || !password) return json({ success: false, message: 'Todos los campos obligatorios' }, 400);
      if (password.length < 6) return json({ success: false, message: 'Mínimo 6 caracteres' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ success: false, message: 'Email inválido' }, 400);

      const existing = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
      if (existing) return json({ success: false, message: 'El email ya está registrado' }, 400);

      const hash = await hashPw(password);
      await env.DB.prepare(
        `INSERT INTO users (name, email, password, organization) VALUES (?, ?, ?, ?)`
      ).bind(name, email, hash, org || '').run();

      const user = await env.DB.prepare(`SELECT id, name, role FROM users WHERE email = ?`).bind(email).first();
      const token = await createJWT({ sub: user.id, name: user.name, role: user.role, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 }, env.JWT_SECRET);

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': setCookie(token), 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }
      });
    }

    /* ─── LOGIN ─────────────────────────────────────── */
    if (path === 'login' && method === 'POST') {
      const ip = getIP(request);
      if (!await checkRateLimit(env, ip, 'login', 10, 15))
        return json({ success: false, message: 'Demasiados intentos. Intenta en 15 minutos.' }, 429);

      const body = await request.json();
      const email = sanitize(body.email);
      const password = body.password;

      if (!email || !password) return json({ success: false, message: 'Email y contraseña requeridos' }, 400);

      const user = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
      if (!user || !(await verifyPw(password, user.password)))
        return json({ success: false, message: 'Credenciales inválidas' }, 401);

      const token = await createJWT({ sub: user.id, name: user.name, role: user.role, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 }, env.JWT_SECRET);

      return new Response(JSON.stringify({ success: true, role: user.role }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': setCookie(token), 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }
      });
    }

    /* ─── LOGOUT ────────────────────────────────────── */
    if (path === 'logout' && method === 'POST') {
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearCookie(), 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }
      });
    }

    /* ─── SESSION ───────────────────────────────────── */
    if (path === 'session' && method === 'GET') {
      const token = getToken(request);
      if (!token) return json({ authenticated: false });
      const payload = await verifyJWT(token, env.JWT_SECRET);
      if (!payload) return json({ authenticated: false });
      return json({ authenticated: true, name: payload.name, role: payload.role });
    }

    /* ─── CONTACT ────────────────────────────────────── */
    if (path === 'contact' && method === 'POST') {
      const ip = getIP(request);
      if (!await checkRateLimit(env, ip, 'contact', 5, 60))
        return json({ success: false, message: 'Demasiados mensajes. Intenta en 1 hora.' }, 429);

      const body = await request.json();
      const name = sanitize(body.name);
      const email = sanitize(body.email);
      const org = sanitize(body.organization);
      const service = sanitize(body.service);
      const message = sanitize(body.message);

      if (!name || !email || !message) return json({ success: false, message: 'Nombre, email y mensaje requeridos' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ success: false, message: 'Email inválido' }, 400);

      await env.DB.prepare(
        `INSERT INTO messages (name, email, organization, service, message) VALUES (?, ?, ?, ?, ?)`
      ).bind(name, email, org || '', service || '', message).run();

      return json({ success: true, message: 'Mensaje recibido correctamente' });
    }

    /* ─── ADMIN AUTH ──────────────────────────────────── */
    function requireAdmin(req) {
      const t = getToken(req);
      if (!t) return null;
      return verifyJWT(t, env.JWT_SECRET);
    }

    /* ─── ADMIN: STATS ───────────────────────────────── */
    if (path === 'admin/stats' && method === 'GET') {
      const payload = await requireAdmin(request);
      if (!payload || payload.role !== 'admin') return json({ error: 'No autorizado' }, 403);
      const totalUsers = (await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first()).c;
      const totalMessages = (await env.DB.prepare(`SELECT COUNT(*) as c FROM messages`).first()).c;
      const unreadMessages = (await env.DB.prepare(`SELECT COUNT(*) as c FROM messages WHERE read = 0`).first()).c;
      const recentUsers = (await env.DB.prepare(`SELECT COUNT(*) as c FROM users WHERE created_at > datetime('now', '-7 days')`).first()).c;
      return json({ totalUsers, totalMessages, unreadMessages, recentUsers });
    }

    /* ─── ADMIN: USERS LIST ───────────────────────────── */
    if (path === 'admin/users' && method === 'GET') {
      const payload = await requireAdmin(request);
      if (!payload || payload.role !== 'admin') return json({ error: 'No autorizado' }, 403);
      const users = await env.DB.prepare(`SELECT id, name, email, organization, role, created_at FROM users ORDER BY created_at DESC`).all();
      return json(users.results);
    }

    /* ─── ADMIN: MESSAGES LIST ────────────────────────── */
    if (path === 'admin/messages' && method === 'GET') {
      const payload = await requireAdmin(request);
      if (!payload || payload.role !== 'admin') return json({ error: 'No autorizado' }, 403);
      const msgs = await env.DB.prepare(`SELECT * FROM messages ORDER BY created_at DESC`).all();
      return json(msgs.results);
    }

    /* ─── ADMIN: MARK READ ────────────────────────────── */
    const markMatch = path.match(/^admin\/messages\/(\d+)\/read$/);
    if (markMatch && method === 'PUT') {
      const payload = await requireAdmin(request);
      if (!payload || payload.role !== 'admin') return json({ error: 'No autorizado' }, 403);
      await env.DB.prepare(`UPDATE messages SET read = 1 WHERE id = ?`).bind(Number(markMatch[1])).run();
      return json({ success: true });
    }

    /* ─── ADMIN: DELETE MESSAGE ───────────────────────── */
    const delMsgMatch = path.match(/^admin\/messages\/(\d+)$/);
    if (delMsgMatch && method === 'DELETE') {
      const payload = await requireAdmin(request);
      if (!payload || payload.role !== 'admin') return json({ error: 'No autorizado' }, 403);
      await env.DB.prepare(`DELETE FROM messages WHERE id = ?`).bind(Number(delMsgMatch[1])).run();
      return json({ success: true });
    }

    /* ─── ADMIN: DELETE USER ──────────────────────────── */
    const delUserMatch = path.match(/^admin\/users\/(\d+)$/);
    if (delUserMatch && method === 'DELETE') {
      const payload = await requireAdmin(request);
      if (!payload || payload.role !== 'admin') return json({ error: 'No autorizado' }, 403);
      await env.DB.prepare(`DELETE FROM users WHERE id = ? AND role != 'admin'`).bind(Number(delUserMatch[1])).run();
      return json({ success: true });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    console.error('API error:', e);
    return json({ error: 'Error interno del servidor' }, 500);
  }
}
