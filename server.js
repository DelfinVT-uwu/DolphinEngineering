require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const isDev = process.env.NODE_ENV !== 'production';

/* DB — stored outside public */
const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    organization TEXT DEFAULT '',
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    organization TEXT DEFAULT '',
    service TEXT DEFAULT '',
    message TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

/* seed admin user (safe: only if not exists, password hashed) */
const admin = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@dolphin.sec');
if (!admin) {
  const hash = bcrypt.hashSync('Admin123!', 10);
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run('Administrador', 'admin@dolphin.sec', hash, 'admin');
}

/* ─── helper: sanitize strings ─────────────────────── */
function sanitize(v) {
  if (typeof v !== 'string') return '';
  return v.replace(/<[^>]*>/g, '').trim();
}

/* ─── rate limiters ─────────────────────────────────── */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Demasiados intentos. Intenta en 15 minutos.' },
  standardHeaders: true, legacyHeaders: false,
});
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Demasiados mensajes. Intenta en 1 hora.' },
  standardHeaders: true, legacyHeaders: false,
});

/* ─── session secret ───────────────────────────────── */
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
if (!process.env.SESSION_SECRET && !isDev) {
  console.warn('⚠  SESSION_SECRET no está definido. Usando valor aleatorio (las sesiones se perderán al reiniciar).');
}

/* ─── middleware ────────────────────────────────────── */
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: !isDev,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

/* security headers */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (!isDev) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});

app.use('/client', express.static(path.join(__dirname, 'public')));

/* ─── auth middleware ───────────────────────────────── */
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'No autorizado' });
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
  next();
}

/* ─── API ───────────────────────────────────────────── */

/* register */
app.post('/api/register', authLimiter, (req, res) => {
  const name = sanitize(req.body.name);
  const email = sanitize(req.body.email);
  const password = req.body.password;
  const organization = sanitize(req.body.organization);
  if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Todos los campos obligatorios' });
  if (password.length < 6) return res.status(400).json({ success: false, message: 'Mínimo 6 caracteres' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, message: 'Email inválido' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(400).json({ success: false, message: 'El email ya está registrado' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (name, email, password, organization) VALUES (?, ?, ?, ?)').run(name, email, hash, organization || '');
  const user = db.prepare('SELECT id, name, email, role FROM users WHERE email = ?').get(email);
  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.userRole = user.role;
  res.json({ success: true });
});

/* login */
app.post('/api/login', authLimiter, (req, res) => {
  const email = sanitize(req.body.email);
  const password = req.body.password;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email y contraseña requeridos' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
  req.session.userId = user.id;
  req.session.userName = user.name;
  req.session.userRole = user.role;
  res.json({ success: true, role: user.role });
});

/* logout */
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

/* session check */
app.get('/api/session', (req, res) => {
  if (!req.session.userId) return res.json({ authenticated: false });
  res.json({ authenticated: true, name: req.session.userName, role: req.session.userRole });
});

/* contact form */
app.post('/api/contact', contactLimiter, (req, res) => {
  const name = sanitize(req.body.name);
  const email = sanitize(req.body.email);
  const organization = sanitize(req.body.organization);
  const service = sanitize(req.body.service);
  const message = sanitize(req.body.message);
  if (!name || !email || !message) return res.status(400).json({ success: false, message: 'Nombre, email y mensaje requeridos' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, message: 'Email inválido' });
  db.prepare('INSERT INTO messages (name, email, organization, service, message) VALUES (?, ?, ?, ?, ?)').run(name, email, organization || '', service || '', message);
  res.json({ success: true, message: 'Mensaje recibido correctamente' });
});

/* ─── DASHBOARD API (admin only) ────────────────────── */

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, name, email, organization, role, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.get('/api/admin/messages', requireAdmin, (req, res) => {
  const messages = db.prepare('SELECT * FROM messages ORDER BY created_at DESC').all();
  res.json(messages);
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const totalMessages = db.prepare('SELECT COUNT(*) as c FROM messages').get().c;
  const unreadMessages = db.prepare('SELECT COUNT(*) as c FROM messages WHERE read = 0').get().c;
  const recentUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE created_at > datetime("now", "-7 days")').get().c;
  res.json({ totalUsers, totalMessages, unreadMessages, recentUsers });
});

app.put('/api/admin/messages/:id/read', requireAdmin, (req, res) => {
  db.prepare('UPDATE messages SET read = 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.delete('/api/admin/messages/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM messages WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ? AND role != "admin"').run(req.params.id);
  res.json({ success: true });
});

/* ─── PAGES ─────────────────────────────────────────── */

app.get('/client/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/client/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});
app.get('/client/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/client/login');
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).sendFile(path.join(__dirname, 'public', '403.html'));
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

/* serve main page */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`▶ DolphinEngineering server running at http://localhost:${PORT}`);
  if (isDev) console.log('   Modo desarrollo — las cookies NO usan Secure flag');
  if (!process.env.SESSION_SECRET) console.log('   ℹ Define SESSION_SECRET en .env para sesiones persistentes');
});
