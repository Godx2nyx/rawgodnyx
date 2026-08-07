const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();

const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!DATABASE_URL) {
    console.error('FATAL: DATABASE_URL environment variable is not set.');
    process.exit(1);
}
if (!SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET environment variable is not set.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(helmet());
app.disable('x-powered-by');
app.set('trust proxy', 1);

const MAX_CONTENT_LENGTH = 50000;
const KEY_PREFIX = 'gdx_';
const DAILY_API_LIMIT = 14;
const COOKIE_NAME = 'gdx_session';

// ---------- Schema ----------
async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            api_key_hash TEXT,
            api_daily_count INTEGER NOT NULL DEFAULT 0,
            api_usage_date DATE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS raws (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_raws_owner ON raws(owner_id);`);
}

// ---------- Hashing helpers (scrypt, no extra native deps) ----------
function hashSecret(plaintext) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(plaintext, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}
function verifySecret(plaintext, stored) {
    if (!stored) return false;
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return false;
    const check = crypto.scryptSync(plaintext, salt, 64).toString('hex');
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(check, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function generateApiKey() {
    return KEY_PREFIX + crypto.randomBytes(24).toString('base64url');
}
function generateRawId() {
    return crypto.randomBytes(16).toString('base64url');
}

// ---------- Auth helpers ----------
function setSessionCookie(res, user) {
    const token = jwt.sign({ id: user.id, username: user.username }, SESSION_SECRET, { expiresIn: '30d' });
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000
    });
}

// เติม req.user ถ้ามี session ที่ valid (ไม่บังคับ ใช้เพื่อผูกความเป็นเจ้าของตอนสร้าง raw)
function attachUserIfLoggedIn(req, res, next) {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return next();
    try {
        req.user = jwt.verify(token, SESSION_SECRET);
    } catch {
        // token ไม่ valid/หมดอายุ ถือว่าไม่ได้ login
    }
    next();
}

function requireLogin(req, res, next) {
    if (!req.user) return res.status(401).json({ success: false, message: 'Login required' });
    next();
}

function isToday(dateVal) {
    const d = new Date(dateVal);
    const now = new Date();
    return d.getUTCFullYear() === now.getUTCFullYear() &&
           d.getUTCMonth() === now.getUTCMonth() &&
           d.getUTCDate() === now.getUTCDate();
}

// ---------- Rate limiters ----------
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true, legacyHeaders: false,
    message: { success: false, message: 'Too many attempts, try again later.' }
});

const publicCreateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true, legacyHeaders: false,
    message: { success: false, message: 'Too many requests, please try again later.' }
});

const viewLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    standardHeaders: true, legacyHeaders: false,
    message: { success: false, message: 'Rate limit exceeded' }
});

// ---------- Static ----------
app.use(express.static(path.join(__dirname, 'public'), {
    dotfiles: 'deny', index: false, redirect: false
}));

// ===================== AUTH =====================

app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({ success: false, message: 'Username ต้องเป็น a-z A-Z 0-9 _ ยาว 3-20 ตัว' });
    }
    if (typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ success: false, message: 'Password ต้องยาวอย่างน้อย 8 ตัว' });
    }

    try {
        const exists = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (exists.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'Username นี้มีคนใช้แล้ว' });
        }

        const passwordHash = hashSecret(password);
        const { rows } = await pool.query(
            'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
            [username, passwordHash]
        );

        setSessionCookie(res, rows[0]);
        res.json({ success: true, username: rows[0].username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ success: false, message: 'Missing credentials' });
    }

    try {
        const { rows } = await pool.query('SELECT id, username, password_hash FROM users WHERE username = $1', [username]);
        const user = rows[0];

        if (!user || !verifySecret(password, user.password_hash)) {
            return res.status(401).json({ success: false, message: 'Username หรือ password ไม่ถูกต้อง' });
        }

        setSessionCookie(res, user);
        res.json({ success: true, username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie(COOKIE_NAME);
    res.json({ success: true });
});

app.get('/api/auth/me', attachUserIfLoggedIn, (req, res) => {
    if (!req.user) return res.json({ success: true, loggedIn: false });
    res.json({ success: true, loggedIn: true, username: req.user.username });
});

// ===================== API KEY MANAGEMENT (ต้อง login) =====================

app.get('/api/keys/status', attachUserIfLoggedIn, requireLogin, async (req, res) => {
    const { rows } = await pool.query('SELECT api_key_hash, api_daily_count, api_usage_date FROM users WHERE id = $1', [req.user.id]);
    const u = rows[0];
    res.json({
        success: true,
        hasKey: !!u.api_key_hash,
        usageToday: u.api_usage_date && isToday(u.api_usage_date) ? u.api_daily_count : 0,
        dailyLimit: DAILY_API_LIMIT
    });
});

// ปุ่มเดียวใช้ทั้ง Generate ครั้งแรก และ Reset (สร้างใหม่ทับของเดิม)
app.post('/api/keys/generate', authLimiter, attachUserIfLoggedIn, requireLogin, async (req, res) => {
    const plainKey = generateApiKey();
    const keyHash = hashSecret(plainKey);

    try {
        await pool.query(
            'UPDATE users SET api_key_hash = $1, api_daily_count = 0, api_usage_date = NULL WHERE id = $2',
            [keyHash, req.user.id]
        );
        res.json({
            success: true,
            api_key: plainKey,
            warning: 'เก็บคีย์นี้ไว้ให้ดี ระบบจะไม่แสดงซ้ำอีก — ถ้าลืมให้กด Reset เพื่อสร้างใหม่'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to generate key' });
    }
});

// ===================== RAW CREATE =====================
// - มี session (login จากหน้าเว็บ) -> ผูกความเป็นเจ้าของ ไม่หักโควต้า API
// - ไม่มี session แต่ส่ง api_key -> เรียกผ่าน API ภายนอก, หักโควต้า 14 ครั้ง/วัน
// - ไม่มีทั้งคู่ -> สร้างแบบ anonymous เปิดให้ทุกคน (จำกัดด้วย IP rate limit เท่านั้น)
app.post('/api/create', publicCreateLimiter, attachUserIfLoggedIn, async (req, res) => {
    const { content, api_key } = req.body || {};

    if (typeof content !== 'string' || content.trim().length === 0) {
        return res.status(400).json({ success: false, message: 'Content is required and must be a non-empty string' });
    }
    if (content.length > MAX_CONTENT_LENGTH) {
        return res.status(413).json({ success: false, message: `Content exceeds maximum length of ${MAX_CONTENT_LENGTH} characters` });
    }

    let ownerId = null;

    try {
        if (req.user) {
            ownerId = req.user.id;
        } else if (typeof api_key === 'string' && api_key.startsWith(KEY_PREFIX)) {
            const { rows } = await pool.query(
                'SELECT id, api_key_hash, api_daily_count, api_usage_date FROM users WHERE api_key_hash IS NOT NULL'
            );
            const match = rows.find(r => verifySecret(api_key, r.api_key_hash));

            if (!match) {
                return res.status(403).json({ success: false, message: 'Invalid API key' });
            }

            const usedToday = match.api_usage_date && isToday(match.api_usage_date) ? match.api_daily_count : 0;
            if (usedToday >= DAILY_API_LIMIT) {
                return res.status(429).json({ success: false, message: `Daily API limit reached (${DAILY_API_LIMIT}/day)` });
            }

            await pool.query(
                'UPDATE users SET api_daily_count = $1, api_usage_date = CURRENT_DATE WHERE id = $2',
                [usedToday + 1, match.id]
            );
            ownerId = match.id;
        }

        const rawId = generateRawId();
        await pool.query(
            'INSERT INTO raws (id, content, owner_id) VALUES ($1, $2, $3)',
            [rawId, content, ownerId]
        );

        const rawUrl = `${req.protocol}://${req.get('host')}/r/${rawId}`;
        res.json({ success: true, url: rawUrl, id: rawId, owned: ownerId !== null });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to save content' });
    }
});

// ===================== RAW VIEW / EDIT / DELETE =====================

app.get('/r/:id', viewLimiter, (req, res) => {
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(req.params.id)) {
        return res.status(404).send('Not found');
    }
    res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

app.get('/api/raw/:id', viewLimiter, attachUserIfLoggedIn, async (req, res) => {
    const rawId = req.params.id;
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(rawId)) {
        return res.status(400).json({ success: false, message: 'Invalid id format' });
    }

    try {
        const { rows } = await pool.query(
            'SELECT id, content, owner_id, created_at, updated_at FROM raws WHERE id = $1',
            [rawId]
        );
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Not found' });
        }

        const raw = rows[0];
        const isOwner = !!(req.user && raw.owner_id === req.user.id);

        res.json({
            success: true,
            id: raw.id,
            content: raw.content,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            isOwner
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.patch('/api/raw/:id', publicCreateLimiter, attachUserIfLoggedIn, requireLogin, async (req, res) => {
    const rawId = req.params.id;
    const { content } = req.body || {};

    if (typeof content !== 'string' || content.trim().length === 0) {
        return res.status(400).json({ success: false, message: 'Content is required' });
    }
    if (content.length > MAX_CONTENT_LENGTH) {
        return res.status(413).json({ success: false, message: `Content exceeds maximum length of ${MAX_CONTENT_LENGTH} characters` });
    }

    try {
        const { rows } = await pool.query('SELECT owner_id FROM raws WHERE id = $1', [rawId]);
        if (rows.length === 0) return res.status(404).json({ success: false, message: 'Not found' });
        if (rows[0].owner_id !== req.user.id) return res.status(403).json({ success: false, message: 'Not your raw' });

        await pool.query('UPDATE raws SET content = $1, updated_at = now() WHERE id = $2', [content, rawId]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.delete('/api/raw/:id', publicCreateLimiter, attachUserIfLoggedIn, requireLogin, async (req, res) => {
    const rawId = req.params.id;
    try {
        const { rows } = await pool.query('SELECT owner_id FROM raws WHERE id = $1', [rawId]);
        if (rows.length === 0) return res.status(404).json({ success: false, message: 'Not found' });
        if (rows[0].owner_id !== req.user.id) return res.status(403).json({ success: false, message: 'Not your raw' });

        await pool.query('DELETE FROM raws WHERE id = $1', [rawId]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/api/raws/mine', attachUserIfLoggedIn, requireLogin, async (req, res) => {
    const { rows } = await pool.query(
        'SELECT id, LEFT(content, 80) AS preview, created_at, updated_at FROM raws WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 100',
        [req.user.id]
    );
    res.json({ success: true, raws: rows });
});

app.use((req, res) => res.status(404).json({ success: false, message: 'Not found' }));
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

initDb()
    .then(() => app.listen(PORT, () => console.log(`Server is running on port ${PORT}`)))
    .catch(err => { console.error('Failed to initialize database:', err); process.exit(1); });
