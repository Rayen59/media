const express = require('express');
const Database = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const dns = require('dns');

// Prioritize IPv4 for instantaneous Google API resolution
dns.setDefaultResultOrder('ipv4first');

// Load environment variables from /app/.dev.env.json if available
try {
  const fs = require('fs');
  const devEnvPath = fs.existsSync('/app/.dev.env.json')
    ? '/app/.dev.env.json'
    : path.join(__dirname, '..', '.dev.env.json');
  if (fs.existsSync(devEnvPath)) {
    const devEnv = JSON.parse(fs.readFileSync(devEnvPath, 'utf8'));
    for (const [k, v] of Object.entries(devEnv)) {
      if (!process.env[k] || process.env[k] === 'MY_GEMINI_API_KEY' || process.env[k] === '') {
        process.env[k] = v;
      }
    }
  }
} catch (e) {}

const E = process.env;
const SECRET = E.JWT_SECRET || 'nova-gemini-secret-2026';
const getGeminiApiKey = () => process.env.GEMINI_API_KEY || E.GEMINI_API_KEY;

const db = new Database(process.env.DB_PATH || 'mediassist.db');
db.pragma('journal_mode = WAL');

// Ensure database schema
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL COLLATE NOCASE,
  name TEXT,
  pass TEXT NOT NULL,
  verified INTEGER DEFAULT 1,
  model TEXT DEFAULT 'gemini-3-flash-preview',
  settings TEXT DEFAULT '{}',
  created INTEGER
);

CREATE TABLE IF NOT EXISTS chats (
  id TEXT PRIMARY KEY,
  uid INTEGER NOT NULL,
  title TEXT NOT NULL,
  created INTEGER,
  updated INTEGER
);
CREATE INDEX IF NOT EXISTS idx_chats_uid ON chats(uid, updated);

CREATE TABLE IF NOT EXISTS chat_msgs (
  id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL,
  uid INTEGER NOT NULL,
  role TEXT NOT NULL,
  text TEXT,
  files TEXT DEFAULT '[]',
  ts INTEGER
);
CREATE INDEX IF NOT EXISTS idx_chat_msgs_chat ON chat_msgs(chat_id, ts);
`);

// Safe migrations
try { db.exec('ALTER TABLE users ADD COLUMN name TEXT'); } catch(e){}
try { db.exec('ALTER TABLE users ADD COLUMN model TEXT DEFAULT "gemini-3-flash-preview"'); } catch(e){}
try { db.exec('ALTER TABLE users ADD COLUMN settings TEXT DEFAULT "{}"'); } catch(e){}

// Rate limiter
const hits = new Map();
const limit = (n, ms) => (q, r, x) => {
  const k = q.ip + q.path;
  const t = Date.now();
  const a = (hits.get(k) || []).filter(v => t - v < ms);
  if (a.length >= n) return r.status(429).json({ error: 'Trop de requêtes, veuillez patienter un instant.' });
  a.push(t);
  hits.set(k, a);
  x();
};

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '35mb' }), cookie(), express.static(path.join(__dirname, 'public')));

// Authentication middleware (supports Bearer header and SameSite None cross-origin cookies)
const auth = (q, r, x) => {
  try {
    const authH = q.headers.authorization;
    const bearer = authH && authH.startsWith('Bearer ') ? authH.slice(7) : null;
    const tok = q.cookies.t || bearer;
    if (!tok) throw 0;
    const p = jwt.verify(tok, SECRET);
    q.u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
    if (!q.u) throw 0;
    x();
  } catch {
    r.status(401).json({ error: 'Session expirée ou non connecté.' });
  }
};

const setTok = (r, id) => {
  const tok = jwt.sign({ id }, SECRET, { expiresIn: '30d' });
  r.cookie('t', tok, { httpOnly: true, sameSite: 'none', secure: true, maxAge: 30 * 864e5 });
  return tok;
};

const okEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length < 255;

// ===== AUTH ROUTES =====

// Register: Strictly enforces single email usage
app.post('/api/register', limit(15, 36e5), async (q, r) => {
  try {
    const email = String(q.body.email || '').trim().toLowerCase();
    const pw = String(q.body.password || '');
    const name = String(q.body.name || '').trim() || email.split('@')[0];

    if (!okEmail(email)) return r.status(400).json({ error: 'Format d’adresse e-mail invalide.' });
    if (pw.length < 6) return r.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères.' });

    // STRICT UNIQUE CHECK: An email cannot be registered more than once!
    const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
    if (existing) {
      return r.status(409).json({ error: 'Cette adresse e-mail est déjà utilisée. Un compte existe déjà avec cette adresse.' });
    }

    const hashed = bcrypt.hashSync(pw, 10);
    const now = Date.now();
    const defaultSettings = {
      theme: 'dark',
      view: 'chat',
      anim: true,
      autoClose: true,
      typing: true,
      btAuto: false,
      speed: 'normal',
      compact: false,
      model: 'gemini-3-flash-preview',
      temp: 0.7,
      tokens: 2048,
      stream: false
    };

    const res = db.prepare('INSERT INTO users(email, name, pass, verified, model, settings, created) VALUES(?,?,?,1,?,?,?)')
      .run(email, name, hashed, 'gemini-3-flash-preview', JSON.stringify(defaultSettings), now);
    const userId = res.lastInsertRowid;

    // Create initial conversation
    const defaultChatId = 'chat_' + now;
    db.prepare('INSERT INTO chats(id, uid, title, created, updated) VALUES(?,?,?,?,?)')
      .run(defaultChatId, userId, 'Bienvenue sur NOVA', now, now);

    const welcomeMsg = 'Bonjour ' + name + ' ! Je suis **NOVA**, votre assistant d’intelligence artificielle d’élite, développé par **Med Rayen Bouazizi, CEO of MK**.\n\nJe suis prêt à vous accompagner dans vos analyses, résolutions de problèmes, synthèses documentaires ou créations de projets. Sur quoi souhaitez-vous travailler ?';
    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)')
      .run('msg_' + now, defaultChatId, userId, 'bot', welcomeMsg, '[]', now);

    const token = setTok(r, userId);
    return r.json({
      ok: true,
      token,
      user: {
        id: userId,
        email,
        name,
        model: 'gemini-3-flash-preview',
        settings: defaultSettings
      }
    });
  } catch (e) {
    console.error('Register error:', e);
    if (e.message && e.message.includes('UNIQUE constraint failed')) {
      return r.status(409).json({ error: 'Cette adresse e-mail est déjà utilisée. Un compte existe déjà avec cette adresse.' });
    }
    return r.status(500).json({ error: 'Erreur lors de la création du compte.' });
  }
});

// Login
app.post('/api/login', limit(25, 9e5), (q, r) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const pw = String(q.body.password || '');
  if (!email || !pw) return r.status(400).json({ error: 'Veuillez saisir votre e-mail et votre mot de passe.' });

  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(pw, u.pass)) {
    return r.status(401).json({ error: 'Adresse e-mail ou mot de passe incorrect.' });
  }

  const token = setTok(r, u.id);
  const userSettings = JSON.parse(u.settings || '{}');
  return r.json({
    ok: true,
    token,
    user: {
      id: u.id,
      email: u.email,
      name: u.name || email.split('@')[0],
      model: u.model || 'gemini-3-flash-preview',
      settings: userSettings
    }
  });
});

app.post('/api/logout', (q, r) => {
  r.clearCookie('t', { sameSite: 'none', secure: true });
  r.json({ ok: true });
});

app.get('/api/me', auth, (q, r) => {
  const u = q.u;
  const userSettings = JSON.parse(u.settings || '{}');
  r.json({
    id: u.id,
    email: u.email,
    name: u.name || u.email.split('@')[0],
    model: u.model || 'gemini-3-flash-preview',
    settings: userSettings
  });
});

app.post('/api/change-password', auth, (q, r) => {
  const oldPw = String(q.body.oldPassword || '');
  const newPw = String(q.body.newPassword || '');
  if (!oldPw || !newPw) return r.status(400).json({ error: 'Veuillez remplir tous les champs.' });
  if (newPw.length < 6) return r.status(400).json({ error: 'Le nouveau mot de passe doit contenir au moins 6 caractères.' });

  if (!bcrypt.compareSync(oldPw, q.u.pass)) {
    return r.status(400).json({ error: 'Mot de passe actuel incorrect.' });
  }

  const hashed = bcrypt.hashSync(newPw, 10);
  db.prepare('UPDATE users SET pass=? WHERE id=?').run(hashed, q.u.id);
  r.json({ ok: true, message: 'Mot de passe modifié avec succès.' });
});

app.put('/api/settings', auth, (q, r) => {
  const { model, settings, name } = q.body;
  if (name && typeof name === 'string' && name.trim()) {
    db.prepare('UPDATE users SET name=? WHERE id=?').run(name.trim().slice(0, 100), q.u.id);
  }
  if (model && typeof model === 'string') {
    db.prepare('UPDATE users SET model=? WHERE id=?').run(model.trim(), q.u.id);
  }
  if (settings && typeof settings === 'object') {
    db.prepare('UPDATE users SET settings=? WHERE id=?').run(JSON.stringify(settings).slice(0, 8000), q.u.id);
  }
  r.json({ ok: true });
});

// ===== CHAT MANAGEMENT ROUTES =====

app.get('/api/chats', auth, (q, r) => {
  const chats = db.prepare('SELECT id, title, created, updated FROM chats WHERE uid=? ORDER BY updated DESC').all(q.u.id);
  r.json(chats);
});

app.post('/api/chats', auth, (q, r) => {
  const id = String(q.body.id || ('chat_' + Date.now())).trim();
  const title = String(q.body.title || 'Nouvelle conversation').trim().slice(0, 80);
  const now = Date.now();
  db.prepare('INSERT OR REPLACE INTO chats(id, uid, title, created, updated) VALUES(?,?,?,?,?)')
    .run(id, q.u.id, title, now, now);
  r.json({ ok: true, id, title });
});

app.delete('/api/chats/:id', auth, (q, r) => {
  db.prepare('DELETE FROM chat_msgs WHERE chat_id=? AND uid=?').run(q.params.id, q.u.id);
  db.prepare('DELETE FROM chats WHERE id=? AND uid=?').run(q.params.id, q.u.id);
  r.json({ ok: true });
});

app.delete('/api/chats', auth, (q, r) => {
  db.prepare('DELETE FROM chat_msgs WHERE uid=?').run(q.u.id);
  db.prepare('DELETE FROM chats WHERE uid=?').run(q.u.id);
  r.json({ ok: true });
});

app.get('/api/chats/:id/messages', auth, (q, r) => {
  const msgs = db.prepare('SELECT id, role, text, files, ts FROM chat_msgs WHERE chat_id=? AND uid=? ORDER BY ts ASC')
    .all(q.params.id, q.u.id);
  const parsed = msgs.map(m => {
    let f = [];
    try { f = JSON.parse(m.files || '[]'); } catch(e){}
    return { id: m.id, role: m.role, text: m.text, files: f, ts: m.ts };
  });
  r.json(parsed);
});

// ===== NOVA AI ENGINE =====

const NOVA_SYSTEM_PROMPT = `Tu es NOVA, un assistant d'intelligence artificielle d'élite hautement qualifié, professionnel, rigoureux et bienveillant, développé par Med Rayen Bouazizi, CEO of MK.
Si l'utilisateur te demande qui t'a créé ou développé, réponds toujours clairement que tu as été développé par Med Rayen Bouazizi, CEO of MK.
Ton champ d'expertise couvre l'analyse stratégique, la rédaction professionnelle, l'ingénierie logicielle, les sciences, la synthèse de documents et la résolution de problèmes complexes.

Principes fondamentaux :
1. Précision et clarté : Structure tes réponses de façon limpide avec du formatage Markdown soigné (titres, listes à puces, mise en valeur en gras, tableaux comparatifs si utile, blocs de code syntaxiques).
2. Ton professionnel : Chaleureux mais sérieux, concis tout en étant exhaustif sur le fond. Évite les fioritures inutiles.
3. Analyse multimodale : Si l'utilisateur joint des images ou documents PDF, analyse-les avec une minutie exemplaire (extraits, graphiques, valeurs, anomalies, synthèses de haut niveau).
4. Multi-langue : Détecte immédiatement la langue de l'utilisateur (français, anglais, arabe, espagnol, etc.) et réponds dans cette même langue avec une maîtrise linguistique irréprochable.
5. Intégrité : Si une question médicale, juridique ou financière sensible est posée, fournis une analyse experte des protocoles établis, tout en rappelant avec tact la nécessité d'une validation par un professionnel assermenté.`;

async function callGeminiGenerate(modelName, systemPrompt, contents, temp, maxTokens) {
  const apiKey = getGeminiApiKey();
  if (!apiKey) throw new Error('GEMINI_API_KEY manquant sur le serveur.');

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;
  const payload = {
    systemInstruction: { parts: [{ text: systemPrompt }] },
    contents,
    generationConfig: {
      temperature: temp !== undefined ? temp : 0.7,
      maxOutputTokens: maxTokens || 2048
    }
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey,
      'User-Agent': 'aistudio-build'
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error?.message || `Erreur IA HTTP ${res.status}`);
  }

  const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) {
    throw new Error('Réponse vide du modèle IA.');
  }
  return text;
}

app.post('/api/chat', auth, limit(60, 6e4), async (q, r) => {
  try {
    const text = String(q.body.text || '').trim();
    const files = Array.isArray(q.body.files) ? q.body.files.slice(0, 6) : [];
    const chatId = String(q.body.chatId || '').trim();
    const requestedModel = q.body.model || q.u.model || 'gemini-3-flash-preview';
    const temp = typeof q.body.temp === 'number' ? q.body.temp : 0.7;
    const tokens = typeof q.body.tokens === 'number' ? Math.min(q.body.tokens, 8192) : 2048;

    if (!text && !files.length) {
      return r.status(400).json({ error: 'Message ou fichier requis.' });
    }

    if (!getGeminiApiKey()) {
      return r.status(500).json({ error: 'Configuration serveur : variable GEMINI_API_KEY manquante.' });
    }

    const now = Date.now();
    let currentChatId = chatId;
    let chat = chatId ? db.prepare('SELECT * FROM chats WHERE id=? AND uid=?').get(chatId, q.u.id) : null;

    if (!chat) {
      currentChatId = 'chat_' + now;
      const initialTitle = text ? (text.slice(0, 32) + (text.length > 32 ? '…' : '')) : 'Nouvelle conversation';
      db.prepare('INSERT INTO chats(id, uid, title, created, updated) VALUES(?,?,?,?,?)')
        .run(currentChatId, q.u.id, initialTitle, now, now);
    }

    // Load recent conversation history
    const historyRows = db.prepare('SELECT role, text FROM chat_msgs WHERE chat_id=? AND uid=? ORDER BY ts ASC LIMIT 20')
      .all(currentChatId, q.u.id);

    const contents = [];
    for (const row of historyRows) {
      if (row.text) {
        contents.push({
          role: row.role === 'user' ? 'user' : 'model',
          parts: [{ text: row.text }]
        });
      }
    }

    // Build current user message parts (multimodal)
    const currentParts = [];
    for (const f of files) {
      if (!f.data) continue;
      const mimeType = f.type === 'application/pdf' ? 'application/pdf' : (/^image\/(png|gif|webp)$/.test(f.type) ? f.type : 'image/jpeg');
      currentParts.push({
        inlineData: {
          mimeType,
          data: f.data
        }
      });
    }
    currentParts.push({ text: text || 'Veuillez analyser les documents joints.' });
    contents.push({ role: 'user', parts: currentParts });

    // Call Gemini with intelligent fallback chain
    const candidateModels = [requestedModel, 'gemini-3-flash-preview', 'gemini-3.5-flash'];
    const uniqueModels = [...new Set(candidateModels)];

    let outputText = null;
    let lastError = null;
    let effectiveModel = requestedModel;

    for (const modelCandidate of uniqueModels) {
      try {
        outputText = await callGeminiGenerate(modelCandidate, NOVA_SYSTEM_PROMPT, contents, temp, tokens);
        effectiveModel = modelCandidate;
        break;
      } catch (err) {
        console.warn(`Model ${modelCandidate} failed:`, err.message);
        lastError = err;
      }
    }

    if (!outputText) {
      return r.status(502).json({ error: lastError?.message || 'Erreur lors de la génération avec le moteur IA.' });
    }

    const userMsgId = 'msg_' + now + '_u';
    const botMsgId = 'msg_' + (now + 1) + '_b';

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)')
      .run(userMsgId, currentChatId, q.u.id, 'user', text, JSON.stringify(files.map(f => ({ name: f.name, type: f.type, url: f.url }))), now);

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)')
      .run(botMsgId, currentChatId, q.u.id, 'bot', outputText, '[]', now + 1);

    db.prepare('UPDATE chats SET updated=? WHERE id=?').run(now + 1, currentChatId);

    // Update title on first message
    let chatTitle = null;
    const msgCount = db.prepare('SELECT COUNT(*) as c FROM chat_msgs WHERE chat_id=?').get(currentChatId).c;
    if (msgCount <= 2 && text) {
      chatTitle = text.slice(0, 32) + (text.length > 32 ? '…' : '');
      db.prepare('UPDATE chats SET title=? WHERE id=?').run(chatTitle, currentChatId);
    }

    return r.json({
      ok: true,
      text: outputText,
      chatId: currentChatId,
      userMsgId,
      botMsgId,
      title: chatTitle,
      modelUsed: effectiveModel
    });
  } catch (e) {
    console.error('Server chat error:', e);
    return r.status(500).json({ error: 'Erreur interne du serveur lors du traitement.' });
  }
});

const PORT = parseInt(E.PORT || '3000', 10);
app.listen(PORT, '0.0.0.0', () => console.log('NOVA Assistant IA (Développé par Med Rayen Bouazizi, CEO of MK) en écoute sur http://0.0.0.0:' + PORT));
