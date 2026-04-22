require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const https = require('https');
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const FRONTEND_URL = String(process.env.FRONTEND_URL || '').trim();
const BOT_TOKEN = String(process.env.BOT_TOKEN || '').trim();
const BOT_POLLING = process.env.BOT_POLLING === 'true';
const WEBHOOK_URL = String(process.env.WEBHOOK_URL || '').trim();
const TELEGRAM_WEBHOOK_SECRET = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const ANTHROPIC_API_KEY = String(process.env.ANTHROPIC_API_KEY || '').trim();
const FIREBASE_API_KEY = String(process.env.FIREBASE_API_KEY || '').trim();
const FIREBASE_PROJECT_ID = String(process.env.FIREBASE_PROJECT_ID || '').trim();
const SESSION_COOKIE_NAME = 'mdh_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const SESSION_REFRESH_MS = 1000 * 60 * 30;
const AUTH_CODE_TTL_MS = 1000 * 60 * 5;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ADMIN_TELEGRAM_IDS = new Set(
  String(process.env.ADMIN_TELEGRAM_IDS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
);

const FIREBASE = {
  apiKey: FIREBASE_API_KEY,
  projectId: FIREBASE_PROJECT_ID,
};

const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${FIREBASE.projectId}/databases/(default)/documents`;
const httpsAgent = new https.Agent({ keepAlive: false });
const httpClient = axios.create({
  httpsAgent,
  timeout: 30000,
});

if (!FIREBASE.apiKey || !FIREBASE.projectId) {
  throw new Error('FIREBASE_API_KEY va FIREBASE_PROJECT_ID majburiy.');
}

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!FRONTEND_URL) return callback(null, true);
    if (!origin || origin === FRONTEND_URL) return callback(null, true);
    return callback(new Error('CORS ruxsat berilmadi'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString('hex')}`;
}

function nowIso() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function createSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, item) => {
    const index = item.indexOf('=');
    if (index < 0) return acc;
    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();
    if (!key) return acc;
    acc[key] = decodeURIComponent(value);
    return acc;
  }, {});
}

function setSessionCookie(res, token, expiresAt) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Expires=${new Date(expiresAt).toUTCString()}`,
  ];
  if (IS_PRODUCTION) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res) {
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];
  if (IS_PRODUCTION) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

function createRateLimiter({ limit, windowMs, keyFn }) {
  const store = new Map();
  return (req, res, next) => {
    const key = keyFn(req);
    const entry = store.get(key);
    const current = nowMs();
    if (!entry || entry.resetAt <= current) {
      store.set(key, { count: 1, resetAt: current + windowMs });
      return next();
    }
    if (entry.count >= limit) {
      res.setHeader('Retry-After', Math.ceil((entry.resetAt - current) / 1000));
      return res.status(429).json({ error: 'Juda ko‘p urinish. Keyinroq qayta urinib ko‘ring.' });
    }
    entry.count += 1;
    next();
  };
}

const authVerifyLimiter = createRateLimiter({
  limit: 5,
  windowMs: 1000 * 60 * 10,
  keyFn: (req) => `auth:${clientIp(req)}`,
});

const writeLimiter = createRateLimiter({
  limit: 30,
  windowMs: 1000 * 60,
  keyFn: (req) => `write:${req.user?._id || clientIp(req)}`,
});

const aiLimiter = createRateLimiter({
  limit: 10,
  windowMs: 1000 * 60 * 10,
  keyFn: (req) => `ai:${req.user?._id || clientIp(req)}`,
});

function sanitizeUser(user) {
  if (!user) return null;
  const copy = { ...withAdminFlag(user) };
  delete copy.telegramId;
  delete copy.phone;
  return copy;
}

function encodeValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (Array.isArray(value)) {
    return { arrayValue: { values: value.map(encodeValue) } };
  }
  if (typeof value === 'boolean') return { booleanValue: value };
  if (typeof value === 'number') {
    if (Number.isInteger(value)) return { integerValue: String(value) };
    return { doubleValue: value };
  }
  if (typeof value === 'object') {
    return {
      mapValue: {
        fields: Object.fromEntries(Object.entries(value).map(([k, v]) => [k, encodeValue(v)])),
      },
    };
  }
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    return { timestampValue: value };
  }
  return { stringValue: String(value) };
}

function sanitizePayload(payload) {
  const copy = { ...payload };
  delete copy._id;
  delete copy.id;
  delete copy.author;
  delete copy.post;
  return copy;
}

function decodeValue(value) {
  if ('stringValue' in value) return value.stringValue;
  if ('integerValue' in value) return Number(value.integerValue);
  if ('doubleValue' in value) return Number(value.doubleValue);
  if ('booleanValue' in value) return value.booleanValue;
  if ('timestampValue' in value) return value.timestampValue;
  if ('nullValue' in value) return null;
  if ('arrayValue' in value) return (value.arrayValue.values || []).map(decodeValue);
  if ('mapValue' in value) {
    const fields = value.mapValue.fields || {};
    return Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, decodeValue(v)]));
  }
  return null;
}

function decodeDoc(doc) {
  const id = doc.name.split('/').pop();
  const fields = doc.fields || {};
  const value = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, decodeValue(v)]));
  return { _id: id, id, ...value };
}

function isAdminUser(user) {
  if (!user) return false;
  return Boolean(user.isAdmin) || ADMIN_TELEGRAM_IDS.has(String(user.telegramId || ''));
}

function withAdminFlag(user) {
  if (!user) return user;
  return { ...user, isAdmin: isAdminUser(user) };
}

async function firestoreRequest(method, url, data, params) {
  const response = await httpClient({
    method,
    url,
    params: { key: FIREBASE.apiKey, ...params },
    data,
  });
  return response.data;
}

async function listCollection(name) {
  try {
    const data = await firestoreRequest('get', `${FIRESTORE_BASE}/${name}`);
    return (data.documents || []).map(decodeDoc);
  } catch (error) {
    if (error.response?.status === 404) return [];
    throw error;
  }
}

async function getDocument(collection, id) {
  try {
    const data = await firestoreRequest('get', `${FIRESTORE_BASE}/${collection}/${id}`);
    return decodeDoc(data);
  } catch (error) {
    if (error.response?.status === 404) return null;
    throw error;
  }
}

async function setDocument(collection, id, payload) {
  const fields = Object.fromEntries(Object.entries(sanitizePayload(payload)).map(([k, v]) => [k, encodeValue(v)]));
  const data = await firestoreRequest('patch', `${FIRESTORE_BASE}/${collection}/${id}`, { fields });
  return decodeDoc(data);
}

async function createDocument(collection, payload, id = makeId(collection.slice(0, 3))) {
  return setDocument(collection, id, payload);
}

async function deleteDocument(collection, id) {
  try {
    await firestoreRequest('delete', `${FIRESTORE_BASE}/${collection}/${id}`);
  } catch (error) {
    if (error.response?.status !== 404) throw error;
  }
}

async function findSessionByToken(token) {
  if (!token) return null;
  const sessions = await listCollection('sessions');
  const tokenHash = hashToken(token);
  const session = sessions.find((item) => item.tokenHash === tokenHash);
  if (!session) return null;
  if (Number(session.expiresAt || 0) <= nowMs()) {
    await deleteDocument('sessions', session._id);
    return null;
  }
  return session;
}

async function createSession(user, req, res) {
  const token = createSessionToken();
  const expiresAt = nowMs() + SESSION_TTL_MS;
  await createDocument('sessions', {
    userId: user._id,
    tokenHash: hashToken(token),
    createdAt: nowIso(),
    expiresAt,
    lastUsedAt: nowIso(),
    userAgent: String(req.headers['user-agent'] || '').slice(0, 512),
    ip: clientIp(req),
  }, makeId('ses'));
  setSessionCookie(res, token, expiresAt);
}

async function destroySession(req, res) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE_NAME];
  if (!token) {
    clearSessionCookie(res);
    return;
  }
  const session = await findSessionByToken(token);
  if (session) await deleteDocument('sessions', session._id);
  clearSessionCookie(res);
}

async function auth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Token kerak' });
  const session = await findSessionByToken(token);
  if (!session) {
    clearSessionCookie(res);
    return res.status(401).json({ error: "Sessiya yaroqsiz yoki muddati o'tgan" });
  }
  const user = await getDocument('users', session.userId);
  if (!user) return res.status(401).json({ error: 'Foydalanuvchi topilmadi' });
  if (user.isBlocked) return res.status(403).json({ error: 'Akkaunt bloklangan' });
  const updates = {
    ...session,
    lastUsedAt: nowIso(),
  };
  if (Number(session.expiresAt || 0) - nowMs() <= SESSION_REFRESH_MS) {
    updates.expiresAt = nowMs() + SESSION_TTL_MS;
    setSessionCookie(res, token, updates.expiresAt);
  }
  await setDocument('sessions', session._id, updates);
  req.user = withAdminFlag(user);
  req.session = updates;
  next();
}

async function getOptionalUser(req) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE_NAME];
  if (!token) return null;
  const session = await findSessionByToken(token);
  if (!session) return null;
  const user = await getDocument('users', session.userId);
  return withAdminFlag(user);
}

function adminAuth(req, res, next) {
  if (!req.user || !isAdminUser(req.user)) {
    return res.status(403).json({ error: 'Admin ruxsati kerak' });
  }
  next();
}

async function listFollowers() {
  return listCollection('followers');
}

async function getFollowRecord(followerId, followingId) {
  const followers = await listFollowers();
  return followers.find((item) => item.followerId === followerId && item.followingId === followingId) || null;
}

async function tg(method, data) {
  if (!BOT_TOKEN) return null;
  try {
    const response = await httpClient.post(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, data);
    return response.data;
  } catch (error) {
    console.error(`TG ${method}:`, error.response?.data?.description || error.message);
    return null;
  }
}

async function sendMsg(chatId, text, extra = {}) {
  return tg('sendMessage', { chat_id: chatId, text, parse_mode: 'HTML', ...extra });
}

async function notifyUser(user, text, extra = {}) {
  if (!user?.telegramId || !BOT_TOKEN) return;
  await sendMsg(user.telegramId, text, extra);
}

async function findBotSession(telegramId) {
  const sessions = await listCollection('botSessions');
  return sessions.find((item) => item.telegramId === String(telegramId)) || null;
}

async function saveBotSession(telegramId, payload) {
  const existing = await findBotSession(telegramId);
  const base = {
    telegramId: String(telegramId),
    step: 'await_phone',
    phone: '',
    firstName: '',
    lastName: '',
    username: '',
    updatedAt: nowIso(),
  };
  if (existing) {
    return setDocument('botSessions', existing._id, { ...existing, ...payload, updatedAt: nowIso() });
  }
  return createDocument('botSessions', { ...base, ...payload, updatedAt: nowIso() }, `bts_${telegramId}`);
}

async function clearBotSession(telegramId) {
  const existing = await findBotSession(telegramId);
  if (existing) await deleteDocument('botSessions', existing._id);
}

async function askPhone(chatId) {
  await sendMsg(chatId, 'Davom etish uchun telefon raqamingizni yuboring:', {
    reply_markup: {
      keyboard: [[{ text: '📱 Telefon raqamni yuborish', request_contact: true }]],
      resize_keyboard: true,
      one_time_keyboard: true,
    },
  });
}

function normalizePhone(phone) {
  return String(phone || '').replace(/[^\d+]/g, '');
}

async function findUserByPhone(phone) {
  const users = await listCollection('users');
  const normalized = normalizePhone(phone);
  return users.find((user) => normalizePhone(user.phone) === normalized) || null;
}

async function findUserByTelegramId(telegramId) {
  const users = await listCollection('users');
  return users.find((user) => user.telegramId === String(telegramId) && user.registered) || null;
}

async function upsertUserByTelegram({ telegramId, name, username, phone }) {
  const users = await listCollection('users');
  const normalizedPhone = normalizePhone(phone);
  const existing = users.find((user) =>
    user.telegramId === String(telegramId) ||
    (normalizedPhone && normalizePhone(user.phone) === normalizedPhone)
  );
  if (existing) {
    return setDocument('users', existing._id, {
      ...existing,
      name: name || existing.name,
      username: username || existing.username || '',
      phone: phone || existing.phone || '',
      registered: true,
      isAdmin: isAdminUser({ ...existing, telegramId, isAdmin: existing.isAdmin }),
    });
  }
  return createDocument('users', {
    telegramId: String(telegramId),
    name,
    username: username || '',
    phone: phone || '',
    registered: true,
    isBlocked: false,
    isAdmin: ADMIN_TELEGRAM_IDS.has(String(telegramId)),
    postCount: 0,
    createdAt: nowIso(),
  }, makeId('usr'));
}

async function createLoginCode(telegramId, name, username) {
  const authCodes = await listCollection('authCodes');
  await Promise.all(
    authCodes
      .filter((item) => item.telegramId === String(telegramId))
      .map((item) => deleteDocument('authCodes', item._id))
  );

  const code = String(Math.floor(100000 + Math.random() * 900000));
  await createDocument('authCodes', {
    code,
    telegramId: String(telegramId),
    name,
    username: username || '',
    expiresAt: nowMs() + AUTH_CODE_TTL_MS,
    used: false,
  }, makeId('acd'));
  return code;
}

async function sendLoginCode(chatId, telegramId, name, username) {
  const code = await createLoginCode(telegramId, name, username);
  await sendMsg(
    chatId,
    `Tasdiqlash kodi: <code>${code}</code>`,
    {
      reply_markup: {
        inline_keyboard: [[
          {
            text: 'Kodni nusxalash',
            copy_text: { text: code },
          }
        ]],
      },
    }
  );
  return code;
}

async function getAdminStats() {
  const [users, posts, comments, followers, authCodes, botSessions] = await Promise.all([
    listCollection('users'),
    listCollection('posts'),
    listCollection('comments'),
    listCollection('followers'),
    listCollection('authCodes'),
    listCollection('botSessions'),
  ]);
  return {
    users: users.filter((item) => item.registered).length,
    posts: posts.filter((item) => !item.isHidden).length,
    comments: comments.filter((item) => !item.isHidden).length,
    followers: followers.length,
    authCodes: authCodes.length,
    botSessions: botSessions.length,
  };
}

async function sendAdminMenu(chatId) {
  await sendMsg(chatId, 'Admin panel', {
    reply_markup: {
      inline_keyboard: [
        [
          { text: 'Statistika', callback_data: 'admin_stats' },
          { text: 'Recent users', callback_data: 'admin_users' },
        ],
        [
          { text: 'Recent posts', callback_data: 'admin_posts' },
          { text: 'Broadcast yuborish', callback_data: 'admin_broadcast' },
        ],
      ],
    },
  });
}

async function getRecentAdminUsers(limit = 6) {
  const users = await listCollection('users');
  return users
    .filter((user) => user.registered)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .slice(0, limit)
    .map((user) => withAdminFlag(user));
}

async function getRecentAdminPosts(limit = 6) {
  const [posts, users] = await Promise.all([listCollection('posts'), listCollection('users')]);
  return posts
    .filter((post) => !post.isHidden)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .slice(0, limit)
    .map((post) => ({
      ...post,
      author: users.find((user) => user._id === post.authorId) || null,
    }));
}

async function sendAdminUsers(chatId) {
  const users = await getRecentAdminUsers();
  const lines = users.length
    ? users.map((user, index) => `${index + 1}. ${user.name || 'Noma’lum'}${user.username ? ` (@${user.username})` : ''}\nTG: ${user.telegramId || 'yo‘q'}\nStatus: ${user.isBlocked ? 'Bloklangan' : 'Faol'}`)
    : ['Hali foydalanuvchilar yo‘q.'];

  const keyboard = users.map((user) => [{
    text: `${user.isBlocked ? 'Ochish' : 'Bloklash'}: ${user.name || 'User'}`.slice(0, 32),
    callback_data: `admin_user_toggle_${user._id}`,
  }]);
  keyboard.push([{ text: 'Admin menyuga qaytish', callback_data: 'admin_home' }]);

  await sendMsg(chatId, `Recent users\n\n${lines.join('\n\n')}`, {
    reply_markup: { inline_keyboard: keyboard },
  });
}

async function sendAdminPosts(chatId) {
  const posts = await getRecentAdminPosts();
  const lines = posts.length
    ? posts.map((post, index) => `${index + 1}. ${post.title}\nMuallif: ${post.author?.name || 'Noma’lum'}\nLike: ${post.likes?.length || 0} | Ko‘rishlar: ${post.views || 0}`)
    : ['Hali postlar yo‘q.'];

  await sendMsg(chatId, `Recent posts\n\n${lines.join('\n\n')}`, {
    reply_markup: {
      inline_keyboard: [[{ text: 'Admin menyuga qaytish', callback_data: 'admin_home' }]],
    },
  });
}

async function sendBroadcastMessage(message) {
  const users = await listCollection('users');
  const targets = users.filter((user) => user.registered && user.telegramId && !user.isBlocked);
  let sent = 0;
  let failed = 0;

  for (const user of targets) {
    const result = await sendMsg(user.telegramId, message);
    if (result?.ok) sent++;
    else failed++;
  }

  return { total: targets.length, sent, failed };
}

async function handleTelegramUpdate(update) {
  const cb = update?.callback_query;
  if (cb) {
    await tg('answerCallbackQuery', { callback_query_id: cb.id });
    const telegramId = String(cb.from.id);
    const data = cb.data || '';
    if (data.startsWith('admin_')) {
      if (!ADMIN_TELEGRAM_IDS.has(telegramId)) {
        return;
      }
      if (data === 'admin_stats') {
        const stats = await getAdminStats();
        await sendMsg(
          cb.from.id,
          `Bot statistikasi\n\nFoydalanuvchilar: ${stats.users}\nPostlar: ${stats.posts}\nIzohlar: ${stats.comments}\nKuzatishlar: ${stats.followers}\nFaol kodlar: ${stats.authCodes}\nJarayondagi sessiyalar: ${stats.botSessions}`
        );
        await sendAdminMenu(cb.from.id);
        return;
      }
      if (data === 'admin_home') {
        await clearBotSession(telegramId);
        await sendAdminMenu(cb.from.id);
        return;
      }
      if (data === 'admin_users') {
        await clearBotSession(telegramId);
        await sendAdminUsers(cb.from.id);
        return;
      }
      if (data === 'admin_posts') {
        await clearBotSession(telegramId);
        await sendAdminPosts(cb.from.id);
        return;
      }
      if (data === 'admin_broadcast') {
        await saveBotSession(telegramId, { step: 'await_broadcast_text' });
        await sendMsg(cb.from.id, 'Yuboriladigan broadcast xabar matnini kiriting:');
        return;
      }
      if (data === 'admin_broadcast_cancel') {
        await clearBotSession(telegramId);
        await sendMsg(cb.from.id, 'Broadcast bekor qilindi.');
        await sendAdminMenu(cb.from.id);
        return;
      }
      if (data === 'admin_broadcast_confirm') {
        const currentSession = await findBotSession(telegramId);
        const message = String(currentSession?.broadcastDraft || '').trim();
        if (!message) {
          await sendMsg(cb.from.id, 'Broadcast matni topilmadi.');
          await sendAdminMenu(cb.from.id);
          return;
        }
        const result = await sendBroadcastMessage(message);
        await clearBotSession(telegramId);
        await sendMsg(cb.from.id, `Broadcast yakunlandi\n\nYuborildi: ${result.sent}\nXato: ${result.failed}\nJami: ${result.total}`);
        await sendAdminMenu(cb.from.id);
        return;
      }
      if (data.startsWith('admin_user_toggle_')) {
        const userId = data.replace('admin_user_toggle_', '');
        const user = await getDocument('users', userId);
        if (!user) {
          await sendMsg(cb.from.id, 'Foydalanuvchi topilmadi.');
          return;
        }
        const updated = await setDocument('users', user._id, {
          ...user,
          isBlocked: !user.isBlocked,
        });
        await sendMsg(cb.from.id, `${updated.name || 'Foydalanuvchi'} uchun holat yangilandi: ${updated.isBlocked ? 'bloklandi' : 'ochildi'}.`);
        await sendAdminUsers(cb.from.id);
        return;
      }
    }
    if (data === 'register' || data === 'get_code' || data === 'start_register') {
      const existingUser = await findUserByTelegramId(telegramId);
      if (existingUser) {
        await sendLoginCode(cb.from.id, telegramId, existingUser.name, cb.from.username || existingUser.username || '');
        await clearBotSession(telegramId);
        return;
      }
      await saveBotSession(telegramId, {
        step: 'await_phone',
        username: cb.from.username || '',
        firstName: cb.from.first_name || '',
        lastName: cb.from.last_name || '',
      });
      await askPhone(cb.from.id);
    }
    return;
  }

  const msg = update?.message;
  if (!msg) return;
  const telegramId = String(msg.from.id);
  const username = msg.from.username || '';
  const text = msg.text || '';
  const session = await findBotSession(telegramId);

  if (text.startsWith('/admin')) {
    if (!ADMIN_TELEGRAM_IDS.has(telegramId)) {
      return;
    }
    await clearBotSession(telegramId);
    await sendAdminMenu(msg.chat.id);
    return;
  }

  if (text.startsWith('/start')) {
    const existingUser = await findUserByTelegramId(telegramId);
    if (existingUser) {
      await sendLoginCode(msg.chat.id, telegramId, existingUser.name, username || existingUser.username || '');
      await clearBotSession(telegramId);
      return;
    }
    await saveBotSession(telegramId, {
      step: 'await_phone',
      username,
      firstName: msg.from.first_name || '',
      lastName: msg.from.last_name || '',
    });
    await askPhone(msg.chat.id);
    return;
  }

  if (msg.contact) {
    if (String(msg.contact.user_id || '') !== telegramId) {
      await sendMsg(msg.chat.id, 'Iltimos, faqat o‘zingizga tegishli telefon raqamini yuboring.');
      return;
    }
    const phone = msg.contact.phone_number || '';
    const existingUserByPhone = await findUserByPhone(phone);
    if (existingUserByPhone) {
      const updatedUser = await upsertUserByTelegram({
        telegramId,
        name: existingUserByPhone.name,
        username: username || existingUserByPhone.username || '',
        phone,
      });
      await sendLoginCode(msg.chat.id, telegramId, updatedUser.name, updatedUser.username || '');
      await clearBotSession(telegramId);
      return;
    }
    await saveBotSession(telegramId, {
      ...(session || {}),
      telegramId,
      username,
      phone,
      step: 'await_first_name',
    });
    await sendMsg(msg.chat.id, 'Ismingizni kiriting:', {
      reply_markup: { remove_keyboard: true },
    });
    return;
  }

  if (session?.step === 'await_phone') {
    await askPhone(msg.chat.id);
    return;
  }

  if (session?.step === 'await_broadcast_text') {
    const message = text.trim();
    if (!message) {
      await sendMsg(msg.chat.id, 'Broadcast matnini bo‘sh qoldirmang.');
      return;
    }
    await saveBotSession(telegramId, { ...session, step: 'await_broadcast_confirm', broadcastDraft: message });
    await sendMsg(msg.chat.id, `Broadcast preview\n\n${message}`, {
      reply_markup: {
        inline_keyboard: [
          [{ text: 'Tasdiqlash', callback_data: 'admin_broadcast_confirm' }],
          [{ text: 'Bekor qilish', callback_data: 'admin_broadcast_cancel' }],
        ],
      },
    });
    return;
  }

  if (session?.step === 'await_first_name') {
    const firstName = text.trim();
    if (!firstName) {
      await sendMsg(msg.chat.id, 'Ism maydonini bo‘sh qoldirmang.');
      return;
    }
    await saveBotSession(telegramId, {
      ...session,
      username,
      firstName,
      step: 'await_last_name',
    });
    await sendMsg(msg.chat.id, 'Familyangizni kiriting:');
    return;
  }

  if (session?.step === 'await_last_name') {
    const lastName = text.trim();
    if (!lastName) {
      await sendMsg(msg.chat.id, 'Familiya maydonini bo‘sh qoldirmang.');
      return;
    }
    const fullName = [session.firstName, lastName].filter(Boolean).join(' ').trim();
    await upsertUserByTelegram({ telegramId, name: fullName, username, phone: session.phone });
    await sendMsg(msg.chat.id, '✅ Ma’lumotlar qabul qilindi.');
    await sendLoginCode(msg.chat.id, telegramId, fullName, username);
    await clearBotSession(telegramId);
  }
}

let pollingOffset = 0;
let pollingActive = false;

async function ensureTelegramWebhook() {
  if (!BOT_TOKEN || !WEBHOOK_URL) return;
  const webhookUrl = `${WEBHOOK_URL.replace(/\/$/, '')}/bot/webhook`;
  try {
    const me = await tg('getMe', {});
    const botName = me?.result?.username ? `@${me.result.username}` : 'Telegram bot';
    const payload = { url: webhookUrl, drop_pending_updates: false };
    if (TELEGRAM_WEBHOOK_SECRET) payload.secret_token = TELEGRAM_WEBHOOK_SECRET;
    await tg('setWebhook', payload);
    console.log(`${botName} webhook o'rnatildi: ${webhookUrl}`);
  } catch (error) {
    console.error('Telegram webhookni o`rnatib bo`lmadi.');
  }
}

async function startTelegramPolling() {
  if (!BOT_TOKEN || !BOT_POLLING || pollingActive) return;
  pollingActive = true;
  try {
    const me = await tg('getMe', {});
    const botName = me?.result?.username ? `@${me.result.username}` : 'Telegram bot';
    console.log(`${botName} polling rejimida ishga tushdi`);
    await tg('deleteWebhook', { drop_pending_updates: false });
  } catch (error) {
    console.error('Telegram botni ishga tushirib bo`lmadi.');
  }

  const loop = async () => {
    try {
      const response = await httpClient.get(`https://api.telegram.org/bot${BOT_TOKEN}/getUpdates`, {
        params: { timeout: 25, offset: pollingOffset },
      });
      const updates = response.data?.result || [];
      for (const update of updates) {
        pollingOffset = update.update_id + 1;
        await handleTelegramUpdate(update);
      }
    } catch (error) {
      console.error('Telegram polling xato:', error.response?.data?.description || error.message);
    } finally {
      setTimeout(loop, 1000);
    }
  };

  loop();
}

async function hydratePost(post, users) {
  return {
    ...post,
    author: sanitizeUser(users.find((user) => user._id === post.authorId) || null),
  };
}

function attachCommentCounts(posts, comments) {
  const countMap = comments.reduce((acc, comment) => {
    if (!comment.isHidden) acc[comment.postId] = (acc[comment.postId] || 0) + 1;
    return acc;
  }, {});
  return posts.map((post) => ({ ...post, commentCount: countMap[post._id] || 0 }));
}

async function hydrateComment(comment, users, posts) {
  const post = posts.find((item) => item._id === comment.postId);
  return {
    ...comment,
    author: sanitizeUser(users.find((user) => user._id === comment.authorId) || null),
    post: post ? { _id: post._id, title: post.title } : null,
  };
}

app.post('/bot/webhook', async (req, res) => {
  if (TELEGRAM_WEBHOOK_SECRET) {
    const incomingSecret = String(req.headers['x-telegram-bot-api-secret-token'] || '').trim();
    if (incomingSecret !== TELEGRAM_WEBHOOK_SECRET) {
      return res.sendStatus(401);
    }
  }
  res.sendStatus(200);
  Promise.resolve(handleTelegramUpdate(req.body)).catch((error) => {
    console.error('Webhook update xato:', error.response?.data || error.message || error);
  });
});

app.get('/api/health', async (req, res) => {
  const [users, posts, comments] = await Promise.all([
    listCollection('users'),
    listCollection('posts'),
    listCollection('comments'),
  ]);
  res.json({ ok: true, storage: 'firestore', users: users.length, posts: posts.length, comments: comments.length });
});

app.post('/api/auth/verify', authVerifyLimiter, async (req, res) => {
  try {
    const code = String(req.body?.code || '').trim();
    if (code.length !== 6) return res.status(400).json({ error: "Noto'g'ri kod" });

    const authCodes = await listCollection('authCodes');
    const authCode = authCodes.find((item) => item.code === code && !item.used && item.expiresAt > nowMs());
    let user;

    if (authCode) {
      await setDocument('authCodes', authCode._id, { ...authCode, used: true });
      user = await upsertUserByTelegram({
        telegramId: authCode.telegramId,
        name: authCode.name,
        username: authCode.username,
      });
    } else {
      return res.status(400).json({ error: "Kod noto'g'ri yoki muddati o'tgan" });
    }

    await createSession(user, req, res);
    res.json({ user: sanitizeUser(user) });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  res.json(sanitizeUser(req.user));
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    await destroySession(req, res);
    res.json({ success: true });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.get('/api/admin/stats', auth, adminAuth, async (req, res) => {
  const [users, authCodes, botSessions, followers, posts, comments] = await Promise.all([
    listCollection('users'),
    listCollection('authCodes'),
    listCollection('botSessions'),
    listCollection('followers'),
    listCollection('posts'),
    listCollection('comments'),
  ]);

  const botUsers = users.filter((user) => user.registered && user.telegramId && !user.isBlocked);
  res.json({
    totalUsers: users.length,
    botUsers: botUsers.length,
    authCodes: authCodes.length,
    botSessions: botSessions.length,
    followers: followers.length,
    posts: posts.filter((item) => !item.isHidden).length,
    comments: comments.filter((item) => !item.isHidden).length,
  });
});

app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || 30)));
  const users = await listCollection('users');
  const items = users
    .filter((user) => user.registered)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .slice(0, limit)
    .map((user) => withAdminFlag(user));
  res.json({ users: items });
});

app.post('/api/admin/broadcast', auth, adminAuth, async (req, res) => {
  const message = String(req.body?.message || '').trim();
  if (!message) return res.status(400).json({ error: 'Xabar matni kerak' });
  if (!BOT_TOKEN) return res.status(400).json({ error: 'BOT_TOKEN topilmadi' });

  const users = await listCollection('users');
  const targets = users.filter((user) => user.registered && user.telegramId && !user.isBlocked);
  let sent = 0;
  let failed = 0;

  for (const user of targets) {
    const result = await sendMsg(user.telegramId, message);
    if (result?.ok) sent++;
    else failed++;
  }

  res.json({ total: targets.length, sent, failed });
});

app.get('/api/posts', async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.max(1, Math.min(20, Number(req.query.limit || 10)));
    const tag = String(req.query.tag || '').trim();
    const sort = String(req.query.sort || 'new');
    const followingOnly = String(req.query.following || '') === '1';
    const currentUser = await getOptionalUser(req);

    const [postsRaw, users, comments, followers] = await Promise.all([
      listCollection('posts'),
      listCollection('users'),
      listCollection('comments'),
      listFollowers(),
    ]);
    let posts = postsRaw.filter((post) => !post.isHidden);
    if (followingOnly) {
      if (!currentUser) return res.json({ posts: [], total: 0, page, pages: 1 });
      const followingIds = new Set(
        followers
          .filter((item) => item.followerId === currentUser._id)
          .map((item) => item.followingId)
      );
      posts = posts.filter((post) => followingIds.has(post.authorId));
    }
    if (tag) posts = posts.filter((post) => post.tag === tag);
    posts = attachCommentCounts(posts, comments);
    posts.sort((a, b) => {
      if (sort === 'top') return (b.likes.length - a.likes.length) || (new Date(b.createdAt) - new Date(a.createdAt));
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    const total = posts.length;
    const sliced = await Promise.all(posts.slice((page - 1) * limit, page * limit).map((post) => hydratePost(post, users)));
    res.json({ posts: sliced, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.get('/api/posts/saved/list', auth, async (req, res) => {
  const [postsRaw, users, comments] = await Promise.all([listCollection('posts'), listCollection('users'), listCollection('comments')]);
  const posts = await Promise.all(
    attachCommentCounts(postsRaw, comments)
      .filter((post) => !post.isHidden && (post.savedBy || []).includes(req.user._id))
      .map((post) => hydratePost(post, users))
  );
  res.json({ posts });
});

app.get('/api/posts/my/list', auth, async (req, res) => {
  const [postsRaw, users, comments] = await Promise.all([listCollection('posts'), listCollection('users'), listCollection('comments')]);
  const posts = await Promise.all(
    attachCommentCounts(postsRaw, comments)
      .filter((post) => post.authorId === req.user._id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map((post) => hydratePost(post, users))
  );
  res.json({ posts });
});

app.get('/api/posts/:id', async (req, res) => {
  const [post, users, commentsRaw, postsRaw] = await Promise.all([
    getDocument('posts', req.params.id),
    listCollection('users'),
    listCollection('comments'),
    listCollection('posts'),
  ]);
  if (!post || post.isHidden) return res.status(404).json({ error: 'Post topilmadi' });

  post.views = (post.views || 0) + 1;
  await setDocument('posts', post._id, post);

  const comments = await Promise.all(
    commentsRaw
      .filter((comment) => comment.postId === post._id && !comment.isHidden)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
      .map((comment) => hydrateComment(comment, users, postsRaw))
  );

  res.json({ post: await hydratePost(post, users), comments });
});

app.post('/api/posts', auth, writeLimiter, async (req, res) => {
  const title = String(req.body?.title || '').trim();
  const content = String(req.body?.content || '').trim();
  const tag = String(req.body?.tag || 'Umumiy').trim() || 'Umumiy';
  if (!title || !content) return res.status(400).json({ error: 'Sarlavha va matn kerak' });
  if (title.length > 160) return res.status(400).json({ error: 'Sarlavha juda uzun' });
  if (content.length > 10000) return res.status(400).json({ error: 'Matn juda uzun' });
  if (content.length < 50) return res.status(400).json({ error: "Matn kamida 50 harf bo'lishi kerak" });

  const post = await createDocument('posts', {
    title,
    content,
    tag,
    authorId: req.user._id,
    likes: [],
    savedBy: [],
    views: 0,
    isHidden: false,
    createdAt: nowIso(),
  }, makeId('pst'));

  await setDocument('users', req.user._id, { ...req.user, postCount: (req.user.postCount || 0) + 1 });
  res.status(201).json({ ...(await hydratePost(post, [req.user])) });
});

app.delete('/api/posts/:id', auth, writeLimiter, async (req, res) => {
  const post = await getDocument('posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Post topilmadi' });
  if (post.authorId !== req.user._id) return res.status(403).json({ error: "Ruxsat yo'q" });

  const comments = await listCollection('comments');
  await deleteDocument('posts', req.params.id);
  await Promise.all(comments.filter((comment) => comment.postId === req.params.id).map((comment) => deleteDocument('comments', comment._id)));
  await setDocument('users', req.user._id, { ...req.user, postCount: Math.max(0, (req.user.postCount || 0) - 1) });
  res.json({ success: true });
});

app.post('/api/posts/:id/like', auth, writeLimiter, async (req, res) => {
  const post = await getDocument('posts', req.params.id);
  if (!post || post.isHidden) return res.status(404).json({ error: 'Post topilmadi' });
  const author = await getDocument('users', post.authorId);
  const likes = [...(post.likes || [])];
  const index = likes.indexOf(req.user._id);
  if (index >= 0) likes.splice(index, 1);
  else likes.push(req.user._id);
  post.likes = likes;
  await setDocument('posts', post._id, post);
  if (index < 0 && author && author._id !== req.user._id) {
    await notifyUser(author, `${req.user.name} postingizni yoqtirdi ❤️`);
  }
  res.json({ liked: index < 0, likeCount: likes.length });
});

app.post('/api/posts/:id/save', auth, writeLimiter, async (req, res) => {
  const post = await getDocument('posts', req.params.id);
  if (!post || post.isHidden) return res.status(404).json({ error: 'Post topilmadi' });
  const savedBy = [...(post.savedBy || [])];
  const index = savedBy.indexOf(req.user._id);
  if (index >= 0) savedBy.splice(index, 1);
  else savedBy.push(req.user._id);
  post.savedBy = savedBy;
  await setDocument('posts', post._id, post);
  res.json({ saved: index < 0 });
});

app.post('/api/posts/:id/comments', auth, writeLimiter, async (req, res) => {
  const text = String(req.body?.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Izoh matni kerak' });
  if (text.length > 2000) return res.status(400).json({ error: 'Izoh juda uzun' });
  const post = await getDocument('posts', req.params.id);
  if (!post || post.isHidden) return res.status(404).json({ error: 'Post topilmadi' });
  const author = await getDocument('users', post.authorId);

  const comment = await createDocument('comments', {
    postId: post._id,
    authorId: req.user._id,
    text,
    isHidden: false,
    createdAt: nowIso(),
  }, makeId('cmt'));

  res.status(201).json({
    ...comment,
    author: sanitizeUser(req.user),
    post: { _id: post._id, title: post.title },
  });
  if (author && author._id !== req.user._id) {
    await notifyUser(author, `${req.user.name} postingizga izoh qoldirdi 💬`);
  }
});

app.get('/api/posts/:id/comments', async (req, res) => {
  const [commentsRaw, users, posts] = await Promise.all([listCollection('comments'), listCollection('users'), listCollection('posts')]);
  const comments = await Promise.all(
    commentsRaw
      .filter((comment) => comment.postId === req.params.id && !comment.isHidden)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
      .map((comment) => hydrateComment(comment, users, posts))
  );
  res.json({ comments });
});

app.get('/api/stats/trending', async (req, res) => {
  const [postsRaw, users] = await Promise.all([listCollection('posts'), listCollection('users')]);
  const posts = await Promise.all(
    postsRaw
      .filter((post) => !post.isHidden)
      .sort((a, b) => (b.likes.length - a.likes.length) || ((b.views || 0) - (a.views || 0)))
      .slice(0, 5)
      .map((post) => hydratePost(post, users))
  );
  res.json({ posts });
});

app.get('/api/stats/top-writers', async (req, res) => {
  const currentUser = await getOptionalUser(req);
  const users = await listCollection('users');
  const followers = await listFollowers();
  const writers = users
    .filter((user) => user.registered && !user.isBlocked)
    .sort((a, b) => (b.postCount || 0) - (a.postCount || 0))
    .slice(0, 5)
    .map((user) => ({
      _id: user._id,
      name: user.name,
      username: user.username,
      postCount: user.postCount || 0,
      followerCount: followers.filter((item) => item.followingId === user._id).length,
      followedByCurrentUser: currentUser
        ? followers.some((item) => item.followingId === user._id && item.followerId === currentUser._id)
        : false,
    }));
  res.json({ writers });
});

app.get('/api/stats/following-posts', async (req, res) => {
  const currentUser = await getOptionalUser(req);
  if (!currentUser) return res.json({ posts: [] });

  const [postsRaw, users, followers] = await Promise.all([
    listCollection('posts'),
    listCollection('users'),
    listFollowers(),
  ]);

  const followingIds = new Set(
    followers
      .filter((item) => item.followerId === currentUser._id)
      .map((item) => item.followingId)
  );

  if (!followingIds.size) return res.json({ posts: [] });

  const posts = await Promise.all(
    postsRaw
      .filter((post) => !post.isHidden && followingIds.has(post.authorId))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 5)
      .map((post) => hydratePost(post, users))
  );

  res.json({ posts });
});

app.post('/api/users/:id/follow', auth, writeLimiter, async (req, res) => {
  const targetUser = await getDocument('users', req.params.id);
  if (!targetUser) return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });
  if (targetUser._id === req.user._id) return res.status(400).json({ error: 'O‘zingizga obuna bo‘la olmaysiz' });

  const existing = await getFollowRecord(req.user._id, targetUser._id);
  if (existing) {
    await deleteDocument('followers', existing._id);
    return res.json({ following: false });
  }

  await createDocument('followers', {
    followerId: req.user._id,
    followingId: targetUser._id,
    createdAt: nowIso(),
  }, makeId('fol'));

  await notifyUser(targetUser, `${req.user.name} sizni kuzatishni boshladi 👀`);
  res.json({ following: true });
});

app.post('/api/ai/write', auth, aiLimiter, async (req, res) => {
  const prompt = String(req.body?.prompt || '').trim();
  if (!prompt) return res.status(400).json({ error: 'Prompt kerak' });
  if (prompt.length > 2000) return res.status(400).json({ error: 'Prompt juda uzun' });

  if (!ANTHROPIC_API_KEY || ANTHROPIC_API_KEY === 'your_anthropic_api_key_here') {
    return res.json({
      text: `Sarlavha: ${prompt.slice(0, 60)}\n\nKirish: Bu mavzu dasturchilar uchun foydali bo‘lib, amaliy tajriba va qisqa tushuntirish bilan yoritiladi.\n\nAsosiy qism: Muammoni aniqlang, yechimni bosqichma-bosqich ko‘rsating va misol keltiring.\n\nXulosa: Qisqa tavsiya va keyingi qadamlarni yozing.`,
    });
  }

  try {
    const response = await httpClient.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 700,
      system: "Siz o'zbek tilida qisqa va foydali blog matn yozadigan yordamchisiz.",
      messages: [{ role: 'user', content: prompt }],
    }, {
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
    });
    res.json({ text: response.data.content?.[0]?.text || '' });
  } catch {
    res.status(500).json({ error: 'AI xatosi' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, async () => {
  try {
    console.log(`MyDevHub server: http://localhost:${PORT}`);
    console.log(`Saqlash turi: Firestore (${FIREBASE.projectId})`);
    if (BOT_TOKEN && WEBHOOK_URL) {
      await ensureTelegramWebhook();
    } else if (BOT_TOKEN && BOT_POLLING) {
      startTelegramPolling();
    } else if (BOT_TOKEN) {
      console.log('Telegram bot uchun WEBHOOK_URL yoki BOT_POLLING=true kerak.');
    }
  } catch (error) {
    console.error('Firestore ulanishida xato:', error.response?.data || error.message);
  }
});

