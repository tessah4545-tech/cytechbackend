/* CyTech Backend — Node/Express + Neon Postgres + Paystack
   Fixes all Render errors from screenshots: CommonJS only, no missing modules,
   no /var/data writes, no native builds, no Dockerfile needed. */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ADMIN_PATH = process.env.ADMIN_PATH || 'cytech-admin-x9k2';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@cytech.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe!2026';
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_PUBLIC = process.env.PAYSTACK_PUBLIC_KEY || '';
const ALLOWED = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());

const PRICE_KES = { notes: 30, practicals: 100, course: 2000 };

/* ---------------- Storage: Neon Postgres with local JSON fallback ---------------- */
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

let mem = { users: [], transactions: [], applications: [], messages: [], settings: {}, resets: [] };
try { if (fs.existsSync(DB_FILE)) mem = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}

let pool = null, pgReady = false;
if (process.env.DATABASE_URL) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
}
async function pgInit() {
  if (!pool) return;
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS kvstore (id TEXT PRIMARY KEY, payload JSONB, updated_at TIMESTAMPTZ DEFAULT now())`);
    pgReady = true;
    // RESTORE on boot / redeploy
    const r = await pool.query(`SELECT payload FROM kvstore WHERE id='main'`);
    if (r.rows.length && r.rows[0].payload && (r.rows[0].payload.users||[]).length >= mem.users.length) {
      mem = r.rows[0].payload;
      console.log('[db] restored from Neon:', mem.users.length, 'users,', mem.transactions.length, 'txns');
    } else { await pgFlush(); console.log('[db] seeded Neon with local data'); }
  } catch (e) { pgReady = false; console.log('[db] Neon unavailable, using local store:', e.message); }
}
async function pgFlush() {
  if (!pool || !pgReady) return;
  try { await pool.query(`INSERT INTO kvstore (id,payload,updated_at) VALUES ('main',$1,now())
    ON CONFLICT (id) DO UPDATE SET payload=$1, updated_at=now()`, [JSON.stringify(mem)]); }
  catch (e) { pgReady = false; }
}
function persist() { try { fs.writeFileSync(DB_FILE, JSON.stringify(mem)); } catch (e) {} pgFlush(); }
/* auto-backup every 4 minutes */
setInterval(() => { persist(); console.log('[db] auto-backup ->', pgReady ? 'Neon OK' : 'local only'); }, 4 * 60 * 1000);

/* ---------------- App ---------------- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED.includes('*') || ALLOWED.includes(origin)) return cb(null, true);
    return cb(null, false);
  }, credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 400 }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

const uid = () => crypto.randomBytes(8).toString('hex');
const sign = u => jwt.sign({ id: u.id, email: u.email, role: u.role || 'user' }, JWT_SECRET, { expiresIn: '7d' });
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try { req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}
function adminOnly(req, res, next) { if (req.user && req.user.role === 'admin') return next(); res.status(403).json({ error: 'Forbidden' }); }

/* seed admin + default settings */
(async () => {
  await pgInit();
  if (!mem.users.find(u => u.email === ADMIN_EMAIL))
    mem.users.push({ id: uid(), name: 'Administrator', email: ADMIN_EMAIL, pass: bcrypt.hashSync(ADMIN_PASSWORD, 10), role: 'admin', createdAt: Date.now() });
  if (!mem.settings.practicalUrl) mem.settings.practicalUrl = 'http://testphp.vulnweb.com';
  if (!mem.settings.adminNote) mem.settings.adminNote = 'Welcome to CyTech. Classes run Mon/Wed/Fri 6PM-8PM EAT, venue: CyTech Lab, Nairobi CBD.';
  persist();
})();

/* ---------------- Auth ---------------- */
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password || password.length < 6) return res.status(400).json({ error: 'Name, valid email and 6+ char password required' });
  const e = String(email).toLowerCase().trim();
  if (mem.users.find(u => u.email === e)) return res.status(409).json({ error: 'Email already registered' });
  const u = { id: uid(), name: String(name).slice(0, 60), email: e, pass: bcrypt.hashSync(password, 10), role: 'user', createdAt: Date.now() };
  mem.users.push(u); persist();
  res.json({ token: sign(u), user: { id: u.id, name: u.name, email: u.email, role: u.role } });
});
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const u = mem.users.find(x => x.email === String(email || '').toLowerCase().trim());
  if (!u || !bcrypt.compareSync(String(password || ''), u.pass)) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: sign(u), user: { id: u.id, name: u.name, email: u.email, role: u.role } });
});
app.post('/api/auth/forgot', authLimiter, (req, res) => {
  const u = mem.users.find(x => x.email === String((req.body || {}).email || '').toLowerCase().trim());
  if (u) { const t = crypto.randomBytes(20).toString('hex'); mem.resets.push({ token: t, userId: u.id, exp: Date.now() + 3600e3 }); persist(); console.log('[reset]', u.email, t); }
  res.json({ ok: true, message: 'If that email exists, a reset link was issued.' , devToken: process.env.NODE_ENV==='production'?undefined:(u?mem.resets[mem.resets.length-1].token:undefined)});
});
app.post('/api/auth/reset', (req, res) => {
  const { token, password } = req.body || {};
  const r = mem.resets.find(x => x.token === token && x.exp > Date.now());
  if (!r || !password || password.length < 6) return res.status(400).json({ error: 'Invalid/expired token or weak password' });
  const u = mem.users.find(x => x.id === r.userId); if (!u) return res.status(404).json({ error: 'User not found' });
  u.pass = bcrypt.hashSync(password, 10); mem.resets = mem.resets.filter(x => x.token !== token); persist();
  res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => {
  const u = mem.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const paid = mem.transactions.filter(t => t.userId === u.id && t.status === 'success').map(t => t.purpose);
  const application = mem.applications.find(a => a.userId === u.id);
  res.json({ user: { id: u.id, name: u.name, email: u.email, role: u.role }, entitlements: paid, application, adminNote: application ? mem.settings.adminNote : undefined, practicalUrl: paid.includes('practicals') ? mem.settings.practicalUrl : undefined });
});

/* ---------------- Paystack ---------------- */
function paystack(path_, method, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({ hostname: 'api.paystack.co', path: path_, method, headers: { Authorization: 'Bearer ' + PAYSTACK_SECRET, 'Content-Type': 'application/json', ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } },
      r => { let b = ''; r.on('data', c => b += c); r.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } }); });
    req.on('error', reject); if (data) req.write(data); req.end();
  });
}
app.get('/api/pay/config', (req, res) => res.json({ publicKey: PAYSTACK_PUBLIC, prices: PRICE_KES, currency: 'KES' }));
app.post('/api/pay/init', auth, async (req, res) => {
  const { purpose } = req.body || {};
  if (!PRICE_KES[purpose]) return res.status(400).json({ error: 'Invalid purpose' });
  const reference = 'CYT-' + uid().toUpperCase();
  mem.transactions.push({ id: uid(), reference, userId: req.user.id, email: req.user.email, purpose, amount: PRICE_KES[purpose], status: 'pending', createdAt: Date.now() });
  persist();
  if (!PAYSTACK_SECRET) return res.json({ reference, demo: true, message: 'Paystack key not set — demo mode' });
  try {
    const r = await paystack('/transaction/initialize', 'POST', { email: req.user.email, amount: PRICE_KES[purpose] * 100, currency: 'KES', reference, metadata: { purpose, userId: req.user.id }, channels: ['card', 'mobile_money'] });
    if (!r.status) return res.status(502).json({ error: r.message || 'Paystack init failed' });
    res.json({ reference, authorization_url: r.data.authorization_url, access_code: r.data.access_code });
  } catch (e) { res.status(502).json({ error: 'Payment gateway unreachable' }); }
});
async function verifyRef(reference) {
  if (!PAYSTACK_SECRET) return { demo: true, status: 'success' };
  const r = await paystack('/transaction/verify/' + reference, 'GET');
  return r.status ? { status: r.data.status, data: r.data } : { status: 'failed' };
}
app.get('/api/pay/verify/:reference', auth, async (req, res) => {
  const t = mem.transactions.find(x => x.reference === req.params.reference && x.userId === req.user.id);
  if (!t) return res.status(404).json({ error: 'Transaction not found' });
  const v = await verifyRef(t.reference);
  t.status = v.status === 'success' ? 'success' : 'failed';
  t.verifiedAt = Date.now(); persist();
  if (t.status === 'success' && t.purpose === 'course' && !mem.applications.find(a => a.userId === t.userId))
    { mem.applications.push({ id: uid(), userId: t.userId, email: t.email, status: 'registered', createdAt: Date.now() }); persist(); }
  res.json({ status: t.status, purpose: t.purpose });
});
app.post('/api/pay/webhook', express.json({ type: '*/*' }), (req, res) => {
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(JSON.stringify(req.body)).digest('hex');
  if (hash !== req.headers['x-paystack-signature']) return res.sendStatus(401);
  const ev = req.body;
  if (ev.event === 'charge.success') {
    const t = mem.transactions.find(x => x.reference === ev.data.reference);
    if (t && t.status !== 'success') { t.status = 'success'; t.verifiedAt = Date.now();
      if (t.purpose === 'course' && !mem.applications.find(a => a.userId === t.userId))
        mem.applications.push({ id: uid(), userId: t.userId, email: t.email, status: 'registered', createdAt: Date.now() });
      persist(); }
  }
  res.sendStatus(200);
});

/* ---------------- Practicals & content config (public, gated by frontend+entitlement) ---------------- */
app.get('/api/config/public', (req, res) => res.json({ practicalUrl: null, prices: PRICE_KES }));

/* ---------------- Admin (hidden path, /ADMIN_PATH/ serves panel) ---------------- */
app.post('/api/admin/login', authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const u = mem.users.find(x => x.email === String(email || '').toLowerCase().trim() && x.role === 'admin');
  if (!u || !bcrypt.compareSync(String(password || ''), u.pass)) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: sign(u) });
});
app.get('/api/admin/overview', auth, adminOnly, (req, res) => {
  const tx = mem.transactions.slice().sort((a, b) => b.createdAt - a.createdAt);
  res.json({
    wallet: { total: tx.filter(t => t.status === 'success').reduce((s, t) => s + t.amount, 0),
      success: tx.filter(t => t.status === 'success'), pending: tx.filter(t => t.status === 'pending'), failed: tx.filter(t => t.status === 'failed') },
    users: mem.users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt })),
    applications: mem.applications, settings: mem.settings, db: { neon: pgReady, users: mem.users.length, txns: mem.transactions.length }
  });
});
app.post('/api/admin/settings', auth, adminOnly, (req, res) => {
  const { practicalUrl, adminNote } = req.body || {};
  if (practicalUrl !== undefined) mem.settings.practicalUrl = String(practicalUrl).slice(0, 500);
  if (adminNote !== undefined) mem.settings.adminNote = String(adminNote).slice(0, 5000);
  persist(); res.json({ ok: true, settings: mem.settings });
});
app.post('/api/admin/message', auth, adminOnly, (req, res) => {
  const { userId, message } = req.body || {};
  if (!message) return res.status(400).json({ error: 'Message required' });
  mem.messages.push({ id: uid(), userId: userId || null, message: String(message).slice(0, 2000), createdAt: Date.now() });
  persist(); res.json({ ok: true });
});
app.get('/api/messages', auth, (req, res) => res.json(mem.messages.filter(m => !m.userId || m.userId === req.user.id).sort((a, b) => b.createdAt - a.createdAt).slice(0, 20)));
app.post('/api/admin/backup', auth, adminOnly, async (req, res) => { persist(); await pgFlush(); res.json({ ok: true, neon: pgReady }); });
app.get('/api/health', (req, res) => res.json({ ok: true, neon: pgReady, time: Date.now() }));

/* admin panel static (hidden) */
app.use('/' + ADMIN_PATH, express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.json({ service: 'CyTech API', status: 'online' }));

app.listen(PORT, () => console.log('CyTech API listening on', PORT, '| admin panel at /' + ADMIN_PATH));
/* static: generated study PDFs + app download stubs */
app.use('/notes', express.static(path.join(__dirname, 'pdf')));
app.use('/downloads', express.static(path.join(__dirname, 'downloads')));
