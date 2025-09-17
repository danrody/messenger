import express from 'express';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me-in-production';
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const timestamp = Date.now();
    const safeOriginal = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_');
    cb(null, `${timestamp}_${safeOriginal}`);
  }
});

const upload = multer({ storage });

async function createDb() {
  const db = await open({ filename: path.join(__dirname, 'data.sqlite'), driver: sqlite3.Database });
  await db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL,
      recipient_id INTEGER NOT NULL,
      content TEXT,
      file_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_messages_participants ON messages (sender_id, recipient_id, created_at);
  `);
  
  // Лёгкая миграция схемы: добавляем is_admin, если его нет в существующей базе
  try {
    const userColumns = await db.all("PRAGMA table_info(users)");
    const hasIsAdmin = Array.isArray(userColumns) && userColumns.some(c => c.name === 'is_admin');
    if (!hasIsAdmin) {
      await db.exec("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0");
    }
  } catch (e) {
    console.warn('Schema migration check failed:', e);
  }
  
  // Создаем админ-аккаунт если его нет
  const adminExists = await db.get('SELECT id FROM users WHERE username = ?', 'admin');
  if (!adminExists) {
    const adminPasswordHash = await bcrypt.hash('admin123', 10);
    await db.run('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', 'admin', adminPasswordHash, 1);
    console.log('Admin account created: username=admin, password=admin123');
  }
  
  return db;
}

function createAuthMiddleware() {
  return function auth(req, res, next) {
    const token = req.cookies.token || (req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : null);
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload; // { id, username }
      next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

function issueToken(res, user) {
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  return token;
}

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: true,
    credentials: true
  }
});

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));

const socketsByUserId = new Map();

let db; // initialized later

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const usernameTrimmed = String(username).trim();
    if (usernameTrimmed.length < 3) return res.status(400).json({ error: 'username too short' });
    if (String(password).length < 6) return res.status(400).json({ error: 'password too short' });

    const existing = await db.get('SELECT id FROM users WHERE username = ?', usernameTrimmed);
    if (existing) return res.status(409).json({ error: 'username already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', usernameTrimmed, passwordHash);
    const user = { id: result.lastID, username: usernameTrimmed };
    issueToken(res, user);
    return res.json({ user });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE username = ?', String(username).trim());
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    issueToken(res, user);
    return res.json({ user: { id: user.id, username: user.username } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

const auth = createAuthMiddleware();

app.get('/api/me', auth, async (req, res) => {
  const user = await db.get('SELECT id, username, is_admin FROM users WHERE id = ?', req.user.id);
  return res.json({ user: { id: user.id, username: user.username, is_admin: user.is_admin } });
});

app.get('/api/users', auth, async (req, res) => {
  const users = await db.all('SELECT id, username FROM users WHERE id != ? ORDER BY username ASC', req.user.id);
  res.json({ users });
});

// Админ-панель
app.get('/api/admin/users', auth, async (req, res) => {
  const user = await db.get('SELECT is_admin FROM users WHERE id = ?', req.user.id);
  if (!user || !user.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  const users = await db.all(`
    SELECT id, username, is_admin, created_at,
           (SELECT COUNT(*) FROM messages WHERE sender_id = users.id) as message_count
    FROM users 
    ORDER BY created_at DESC
  `);
  res.json({ users });
});

app.get('/api/admin/stats', auth, async (req, res) => {
  const user = await db.get('SELECT is_admin FROM users WHERE id = ?', req.user.id);
  if (!user || !user.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  const stats = await db.get(`
    SELECT 
      (SELECT COUNT(*) FROM users) as total_users,
      (SELECT COUNT(*) FROM messages) as total_messages,
      (SELECT COUNT(*) FROM messages WHERE created_at > datetime('now', '-24 hours')) as messages_today
  `);
  res.json({ stats });
});

app.get('/api/messages/:otherUserId', auth, async (req, res) => {
  const otherUserId = Number(req.params.otherUserId);
  if (!otherUserId) return res.status(400).json({ error: 'invalid user id' });
  const messages = await db.all(
    `SELECT * FROM messages
     WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
     ORDER BY created_at ASC`,
    req.user.id, otherUserId, otherUserId, req.user.id
  );
  res.json({ messages });
});

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no file' });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({ fileUrl });
});

io.use((socket, next) => {
  try {
    // Try to read token from cookie
    const cookieHeader = socket.handshake.headers.cookie || '';
    const tokenFromCookie = cookieHeader.split(';').map(s => s.trim()).find(s => s.startsWith('token='))?.split('=')[1];
    const bearer = socket.handshake.headers['authorization']?.replace('Bearer ', '');
    const token = tokenFromCookie || socket.handshake.auth?.token || bearer;
    if (!token) return next(new Error('Unauthorized'));
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload; // { id, username }
    next();
  } catch (e) {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  if (!socketsByUserId.has(userId)) socketsByUserId.set(userId, new Set());
  socketsByUserId.get(userId).add(socket);

  socket.on('disconnect', () => {
    const set = socketsByUserId.get(userId);
    if (set) {
      set.delete(socket);
      if (set.size === 0) socketsByUserId.delete(userId);
    }
  });

  socket.on('direct_message', async (payload, ack) => {
    try {
      const { toUserId, content, fileUrl } = payload || {};
      if (!toUserId || (!content && !fileUrl)) {
        if (ack) ack({ ok: false, error: 'invalid payload' });
        return;
      }
      const result = await db.run(
        'INSERT INTO messages (sender_id, recipient_id, content, file_url) VALUES (?, ?, ?, ?)',
        userId, toUserId, content || null, fileUrl || null
      );
      const message = {
        id: result.lastID,
        sender_id: userId,
        recipient_id: toUserId,
        content: content || null,
        file_url: fileUrl || null,
        created_at: new Date().toISOString()
      };

      const recipientSockets = socketsByUserId.get(toUserId);
      if (recipientSockets) {
        for (const s of recipientSockets) {
          s.emit('direct_message', message);
        }
      }
      const senderSockets = socketsByUserId.get(userId);
      if (senderSockets) {
        for (const s of senderSockets) {
          if (s !== socket) s.emit('direct_message', message);
        }
      }
      if (ack) ack({ ok: true, message });
    } catch (e) {
      console.error(e);
      if (ack) ack({ ok: false, error: 'server error' });
    }
  });
});

const PORT = process.env.PORT || 8080;

createDb().then((database) => {
  db = database;
  server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
});