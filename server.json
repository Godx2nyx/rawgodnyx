const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
    console.error('FATAL: DATABASE_URL environment variable is not set.');
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false } // จำเป็นสำหรับ Render Postgres
});

app.use(express.json({ limit: '100kb' }));
app.use(helmet());
app.disable('x-powered-by');
app.set('trust proxy', 1);

const TTL_MS = 24 * 60 * 60 * 1000; // อายุ raw แต่ละอัน (24 ชม.)
const MAX_CONTENT_LENGTH = 50000;
const KEY_PREFIX = 'gdx_';

// ---------- Schema ----------
async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            label TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_used_at TIMESTAMPTZ,
            revoked BOOLEAN NOT NULL DEFAULT false
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS raws (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL
        );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_raws_expires ON raws(expires_at);`);
}

// ลบ raw ที่หมดอายุ (เรียกเป็นระยะ)
async function cleanupExpired() {
    try {
        await pool.query(`DELETE FROM raws WHERE expires_at < now();`);
    } catch (err) {
        console.error('Cleanup error:', err);
    }
}
setInterval(cleanupExpired, 10 * 60 * 1000);

// ---------- Key hashing (scrypt, ไม่ต้องพึ่ง native dependency เพิ่ม) ----------
function hashKey(plaintext) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(plaintext, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyKey(plaintext, stored) {
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

// ---------- Rate limiters ----------
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5, // สร้างได้ 5 คีย์ต่อ IP ต่อชั่วโมง กันการปั่นคีย์จำนวนมาก
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many key registrations. Try again later.' }
});

const createLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests, please try again later.' }
});

const viewLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Rate limit exceeded' }
});

// ---------- Middleware: ตรวจ API key จาก DB ----------
async function requireApiKey(req, res, next) {
    const apiKey = req.body?.secret_key || req.headers['x-api-key'];

    if (typeof apiKey !== 'string' || !apiKey.startsWith(KEY_PREFIX)) {
        return res.status(403).json({ success: false, message: 'Unauthorized: Invalid API Key' });
    }

    try {
        const { rows } = await pool.query(
            `SELECT id, key_hash, revoked FROM api_keys WHERE revoked = false`
        );

        // ตรวจทีละ record ด้วย verifyKey (จำนวนคีย์ปกติไม่เยอะพอจะเป็นคอขวด)
        const match = rows.find(r => verifyKey(apiKey, r.key_hash));

        if (!match) {
            return res.status(403).json({ success: false, message: 'Unauthorized: Invalid API Key' });
        }

        await pool.query(`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, [match.id]);
        req.apiKeyId = match.id;
        next();
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}

// ---------- Static ----------
app.use(express.static(path.join(__dirname, 'public'), {
    dotfiles: 'deny',
    index: false,
    redirect: false
}));

// ---------- API: สมัครคีย์ใหม่ (self-service) ----------
app.post('/api/keys', registerLimiter, async (req, res) => {
    const { label } = req.body || {};

    if (label !== undefined && (typeof label !== 'string' || label.length > 100)) {
        return res.status(400).json({ success: false, message: 'Invalid label' });
    }

    const plainKey = generateApiKey();
    const keyHash = hashKey(plainKey);

    try {
        const { rows } = await pool.query(
            `INSERT INTO api_keys (key_hash, label) VALUES ($1, $2) RETURNING id, created_at`,
            [keyHash, label || null]
        );

        // แสดงคีย์ plaintext ให้ผู้ใช้ "ครั้งเดียว" เท่านั้น เก็บใน DB แค่ hash
        return res.json({
            success: true,
            api_key: plainKey,
            key_id: rows[0].id,
            created_at: rows[0].created_at,
            warning: 'เก็บคีย์นี้ไว้ให้ดี ระบบจะไม่แสดงซ้ำอีก'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to create key' });
    }
});

// ---------- API: เพิกถอนคีย์ตัวเอง (ต้องส่งคีย์มายืนยันความเป็นเจ้าของ) ----------
app.post('/api/keys/revoke', createLimiter, async (req, res) => {
    const { secret_key } = req.body || {};
    if (typeof secret_key !== 'string' || !secret_key.startsWith(KEY_PREFIX)) {
        return res.status(400).json({ success: false, message: 'Invalid key' });
    }

    try {
        const { rows } = await pool.query(`SELECT id, key_hash FROM api_keys WHERE revoked = false`);
        const match = rows.find(r => verifyKey(secret_key, r.key_hash));
        if (!match) {
            return res.status(404).json({ success: false, message: 'Key not found' });
        }
        await pool.query(`UPDATE api_keys SET revoked = true WHERE id = $1`, [match.id]);
        res.json({ success: true, message: 'Key revoked' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// ---------- API: สร้าง raw ----------
app.post('/api/create', createLimiter, requireApiKey, async (req, res) => {
    const { content } = req.body || {};

    if (typeof content !== 'string' || content.trim().length === 0) {
        return res.status(400).json({ success: false, message: 'Content is required and must be a non-empty string' });
    }
    if (content.length > MAX_CONTENT_LENGTH) {
        return res.status(413).json({ success: false, message: `Content exceeds maximum length of ${MAX_CONTENT_LENGTH} characters` });
    }

    const rawId = generateRawId();
    const expiresAt = new Date(Date.now() + TTL_MS);

    try {
        await pool.query(
            `INSERT INTO raws (id, content, key_id, expires_at) VALUES ($1, $2, $3, $4)`,
            [rawId, content, req.apiKeyId, expiresAt]
        );
        const rawUrl = `${req.protocol}://${req.get('host')}/r/${rawId}`;
        res.json({ success: true, url: rawUrl, id: rawId, expires_at: expiresAt });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to save content' });
    }
});

// ---------- หน้าแสดง raw ----------
app.get('/r/:id', viewLimiter, (req, res) => {
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(req.params.id)) {
        return res.status(404).send('Not found');
    }
    res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// ---------- API ดึง content ของ raw (frontend fetch แล้ว escape เอง) ----------
app.get('/api/raw/:id', viewLimiter, async (req, res) => {
    const rawId = req.params.id;
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(rawId)) {
        return res.status(400).json({ success: false, message: 'Invalid id format' });
    }

    try {
        const { rows } = await pool.query(
            `SELECT content, created_at, expires_at FROM raws WHERE id = $1 AND expires_at > now()`,
            [rawId]
        );
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Not found or expired' });
        }
        res.json({ success: true, ...rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Not found' });
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

initDb()
    .then(() => {
        app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
    })
    .catch(err => {
        console.error('Failed to initialize database:', err);
        process.exit(1);
    });
