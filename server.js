const express = require('express');
const Database = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie-parser');
const path = require('path');
const dns = require('dns');
const fs = require('fs');
const { GoogleGenAI, ThinkingLevel, Type } = require('@google/genai');

// Prioritize IPv4 for instantaneous Google API resolution
dns.setDefaultResultOrder('ipv4first');

// Load environment variables from /app/.dev.env.json if available
try {
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
const DEFAULT_MODEL = 'gemini-4-hydrogen';

const getGeminiApiKey = () =>
  process.env.GEMINI_API_KEY || process.env.API_KEY || E.GEMINI_API_KEY || E.API_KEY || '';

const getAiClient = () => {
  const apiKey = getGeminiApiKey();
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') return null;
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build'
      }
    }
  });
};

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
  model TEXT DEFAULT 'gemini-4-hydrogen',
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
try { db.exec('ALTER TABLE users ADD COLUMN name TEXT'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN model TEXT DEFAULT "gemini-4-hydrogen"'); } catch (e) {}
try { db.exec('ALTER TABLE users ADD COLUMN settings TEXT DEFAULT "{}"'); } catch (e) {}

// Normalize legacy/unsupported model names to active free-tier Gemini models
function normalizeModelName(modelStr) {
  const m = String(modelStr || '').trim();
  if (m === 'gemini-3.1-flash-lite') return 'gemini-3.1-flash-lite';
  return DEFAULT_MODEL;
}

// Rate limiter
const hits = new Map();
const limit = (n, ms) => (q, r, x) => {
  const k = q.ip + q.path;
  const t = Date.now();
  const a = (hits.get(k) || []).filter(v => t - v < ms);
  if (a.length >= n) {
    return r.status(429).json({ error: 'Trop de requêtes, veuillez patienter un instant.' });
  }
  a.push(t);
  hits.set(k, a);
  x();
};

const app = express();
app.set('trust proxy', 1);
app.use((q, r, x) => {
  r.setHeader('Permissions-Policy', 'bluetooth=(*), microphone=(*), geolocation=(*)');
  x();
});
app.use(express.json({ limit: '40mb' }), cookie());

// Serve client-side PDF libraries cleanly from node_modules
app.get('/vendor/jspdf.umd.min.js', (q, r) => {
  r.sendFile(path.join(__dirname, 'node_modules', 'jspdf', 'dist', 'jspdf.umd.min.js'));
});
app.get('/vendor/html2canvas.min.js', (q, r) => {
  r.sendFile(path.join(__dirname, 'node_modules', 'html2canvas', 'dist', 'html2canvas.min.js'));
});

app.use(express.static(path.join(__dirname, 'public')));

// Authentication middleware
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

app.post('/api/register', limit(15, 36e5), async (q, r) => {
  try {
    const email = String(q.body.email || '').trim().toLowerCase();
    const pw = String(q.body.password || '');
    const name = String(q.body.name || '').trim() || email.split('@')[0];

    if (!okEmail(email)) return r.status(400).json({ error: 'Format d’adresse e-mail invalide.' });
    if (pw.length < 6) return r.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères.' });

    const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
    if (existing) {
      return r.status(409).json({
        error: 'Cette adresse e-mail est déjà utilisée. Un compte existe déjà avec cette adresse.'
      });
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
      model: DEFAULT_MODEL,
      powerMode: 'max',
      webSearch: true,
      voiceLang: 'auto'
    };

    const res = db
      .prepare('INSERT INTO users(email, name, pass, verified, model, settings, created) VALUES(?,?,?,1,?,?,?)')
      .run(email, name, hashed, DEFAULT_MODEL, JSON.stringify(defaultSettings), now);
    const userId = res.lastInsertRowid;

    const defaultChatId = 'chat_' + now;
    db.prepare('INSERT INTO chats(id, uid, title, created, updated) VALUES(?,?,?,?,?)').run(
      defaultChatId,
      userId,
      'Bienvenue sur NOVA',
      now,
      now
    );

    const welcomeMsg =
      'Bonjour ' +
      name +
      ' ! Je suis **NOVA**, votre assistant d’intelligence artificielle d’élite, développé par **Med Rayen Bouazizi, CEO of MK**.\n\n' +
      'Je peux désormais rédiger des textes d’exception, **créer des documents PDF professionnels**, générer des **QCM interactifs avec corrigé**, préparer ou résoudre des **devoirs complets**, créer des **illustrations vectorielles HD/PNG**, analyser vos **photos et PDF**, et effectuer des recherches internet en direct.\n\nSur quoi souhaitez-vous travailler ?';

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      'msg_' + now,
      defaultChatId,
      userId,
      'bot',
      welcomeMsg,
      '[]',
      now
    );

    const token = setTok(r, userId);
    return r.json({
      ok: true,
      token,
      user: {
        id: userId,
        email,
        name,
        model: DEFAULT_MODEL,
        settings: defaultSettings
      }
    });
  } catch (e) {
    console.error('Register error:', e);
    if (e.message && e.message.includes('UNIQUE constraint failed')) {
      return r.status(409).json({
        error: 'Cette adresse e-mail est déjà utilisée. Un compte existe déjà avec cette adresse.'
      });
    }
    return r.status(500).json({ error: 'Erreur lors de la création du compte.' });
  }
});

app.post('/api/login', limit(25, 9e5), (q, r) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const pw = String(q.body.password || '');
  if (!email || !pw) return r.status(400).json({ error: 'Veuillez saisir votre e-mail et votre mot de passe.' });

  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(pw, u.pass)) {
    return r.status(401).json({ error: 'Adresse e-mail ou mot de passe incorrect.' });
  }

  const token = setTok(r, u.id);
  let userSettings = {};
  try {
    userSettings = JSON.parse(u.settings || '{}');
  } catch (e) {}
  userSettings.model = normalizeModelName(userSettings.model || u.model);

  return r.json({
    ok: true,
    token,
    user: {
      id: u.id,
      email: u.email,
      name: u.name || email.split('@')[0],
      model: normalizeModelName(u.model),
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
  let userSettings = {};
  try {
    userSettings = JSON.parse(u.settings || '{}');
  } catch (e) {}
  userSettings.model = normalizeModelName(userSettings.model || u.model);

  r.json({
    id: u.id,
    email: u.email,
    name: u.name || u.email.split('@')[0],
    model: normalizeModelName(u.model),
    settings: userSettings
  });
});

app.post('/api/change-password', auth, (q, r) => {
  const oldPw = String(q.body.oldPassword || '');
  const newPw = String(q.body.newPassword || '');
  if (!oldPw || !newPw) return r.status(400).json({ error: 'Veuillez remplir tous les champs.' });
  if (newPw.length < 6) {
    return r.status(400).json({ error: 'Le nouveau mot de passe doit contenir au moins 6 caractères.' });
  }
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
    db.prepare('UPDATE users SET model=? WHERE id=?').run(normalizeModelName(model), q.u.id);
  }
  if (settings && typeof settings === 'object') {
    const clean = { ...settings, model: normalizeModelName(settings.model) };
    db.prepare('UPDATE users SET settings=? WHERE id=?').run(JSON.stringify(clean).slice(0, 8000), q.u.id);
  }
  r.json({ ok: true });
});

// ===== CHAT MANAGEMENT ROUTES =====

app.get('/api/chats', auth, (q, r) => {
  const chats = db.prepare('SELECT id, title, created, updated FROM chats WHERE uid=? ORDER BY updated DESC').all(q.u.id);
  r.json(chats);
});

app.post('/api/chats', auth, (q, r) => {
  const id = String(q.body.id || 'chat_' + Date.now()).trim();
  const title = String(q.body.title || 'Nouvelle conversation').trim().slice(0, 80);
  const now = Date.now();
  db.prepare('INSERT OR REPLACE INTO chats(id, uid, title, created, updated) VALUES(?,?,?,?,?)').run(
    id,
    q.u.id,
    title,
    now,
    now
  );
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
  const msgs = db
    .prepare('SELECT id, role, text, files, ts FROM chat_msgs WHERE chat_id=? AND uid=? ORDER BY ts ASC')
    .all(q.params.id, q.u.id);
  const parsed = msgs.map(m => {
    let f = [];
    try {
      f = JSON.parse(m.files || '[]');
    } catch (e) {}
    return { id: m.id, role: m.role, text: m.text, files: f, ts: m.ts };
  });
  r.json(parsed);
});

// ===== NOVA ELITE AI SYSTEM PROMPT =====

const NOVA_SYSTEM_PROMPT = `Tu es NOVA, un assistant d'intelligence artificielle d'élite ultra-puissant, rigoureux, créatif et polyvalent, développé par Med Rayen Bouazizi, CEO of MK.
Si l'utilisateur te demande qui t'a créé ou développé, réponds toujours clairement que tu as été développé par Med Rayen Bouazizi, CEO of MK.

TES CAPACITÉS DE POINTE :
1. RÉDACTION & SYNTHÈSE D'EXCELLENCE :
   - Rédige des réponses approfondies, structurées, précises et directement exploitables : dissertations, rapports professionnels, cours complets, fiches de révision, lettres, CV, programmes informatiques complets, analyses scientifiques, médicales et stratégiques.
   - Organise tes réponses avec des titres clairs (#, ##, ###), des listes à puces ou numérotées, des citations (>) pour les définitions ou points clés, et des tableaux comparatifs Markdown (| ... | ... |).

2. EXCELLENCE EN FRANÇAIS, ARABE ET ANGLAIS :
   - FRANÇAIS : Orthographe, grammaire, accords et typographie irréprochables. Style riche, précis et fluide.
   - ARABE (اللغة العربية الفصحى المعاصرة) : Maîtrise parfaite de la grammaire (نحو), de la conjugaison (صرف) et de l'orthographe (إملاء، همزات، تاء مربوطة). Structure cohérente de droite à gauche.
   - ANGLAIS : Anglais académique ou technique naturel et précis.

3. DEVOIRS, EXERCICES, MATHÉMATIQUES & QCM :
   - Quand l'utilisateur soumet un devoir, un exercice ou un examen (en texte, photo ou PDF) :
     1) Reformule brièvement l'énoncé et identifie les notions clés.
     2) Donne la résolution complète étape par étape avec formules claires, calculs détaillés, justification rigoureuse et réponse finale encadrée/mise en gras.
     3) Ajoute des conseils méthodologiques et les pièges classiques à éviter.
   - Quand on te demande de créer un devoir ou une fiche PDF, structure-le proprement avec en-tête (Matière, Niveau, Durée, Barème), exercices progressifs et corrigé complet séparé.

4. ANALYSE VISUELLE & DOCUMENTAIRE (PHOTOS & PDF) :
   - Lis et retranscris avec une précision maximale tout texte manuscrit ou imprimé, formule mathématique, tableau, graphique ou schéma présent dans les images ou PDF joints.
   - Ne devine jamais ce qui n'est pas lisible : signale-le honnêtement si une zone est floue.

5. URGENCES MÉDICALES & RECHERCHE WEB :
   - En cas de question médicale ou d'urgence, donne des informations fiables et prudentes, rappelle les numéros d'urgence (15 / 112 en Europe, 190 en Tunisie, 911 aux USA) et exploite les établissements de santé proches fournis dans le contexte.
   - Lorsque des résultats de recherche Google ou des liens URL sont utilisés, cite les informations vérifiées avec exactitude et sans invention.`;

// ===== LIEUX MÉDICAUX À PROXIMITÉ =====

async function findNearbyPlaces(lat, lon, query = 'hospital clinic pharmacy') {
  try {
    let url;
    if (lat && lon) {
      url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(query)}&format=json&viewbox=${lon - 0.15},${lat + 0.15},${lon + 0.15},${lat - 0.15}&bounded=1&limit=4`;
    } else {
      url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(query)}&format=json&limit=4`;
    }
    const res = await fetch(url, {
      signal: AbortSignal.timeout(2200),
      headers: { 'User-Agent': 'NOVA-MK-Assistant/3.0' }
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (Array.isArray(data) ? data : []).slice(0, 4).map(item => ({
      name: item.display_name.split(',')[0],
      address: item.display_name,
      lat: item.lat,
      lon: item.lon,
      mapUrl: `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(item.display_name)}`
    }));
  } catch (e) {
    return [];
  }
}

// ===== HELPERS ERREURS GEMINI & EXTRACTION SOURCES =====

function formatGeminiError(err) {
  const msg = String(err?.message || err || 'Erreur inconnue');
  if (msg.includes('PERMISSION_DENIED') || msg.includes('API_KEY_INVALID') || msg.includes('403') || msg.includes('400')) {
    return 'Clé API Gemini invalide ou non configurée. Vérifiez la configuration dans Settings > Secrets.';
  }
  if (msg.includes('RESOURCE_EXHAUSTED') || msg.includes('429')) {
    return 'Limite de requêtes atteinte temporairement. Patientez quelques secondes ou passez en mode Rapide.';
  }
  if (msg.includes('NOT_FOUND') || msg.includes('404')) {
    return 'Modèle IA indisponible. Réessayez avec le moteur NOVA Hydrogen.';
  }
  if (msg.includes('timeout') || msg.includes('Délai')) {
    return 'Le traitement a pris plus de temps que prévu. Réessayez ou simplifiez la demande.';
  }
  return msg;
}

function extractGroundingSources(response) {
  const chunks = response?.candidates?.[0]?.groundingMetadata?.groundingChunks;
  if (!Array.isArray(chunks)) return [];
  const seen = new Set();
  const sources = [];
  for (const c of chunks) {
    if (c?.web?.uri && !seen.has(c.web.uri)) {
      seen.add(c.web.uri);
      sources.push({
        title: c.web.title || c.web.uri,
        uri: c.web.uri
      });
    }
  }
  return sources.slice(0, 6);
}

function resolveThinkingLevel(powerMode, modelName) {
  if (modelName === 'gemini-3.1-flash-lite') return ThinkingLevel.MINIMAL;
  switch (powerMode) {
    case 'fast':
      return ThinkingLevel.LOW;
    case 'balanced':
      return ThinkingLevel.MEDIUM;
    case 'max':
      return ThinkingLevel.XHIGH;
    default:
      return ThinkingLevel.HIGH;
  }
}

function buildGeminiConfig(modelName, systemInstruction, { powerMode, useSearch, urlsInPrompt, responseSchema } = {}) {
  const config = {
    systemInstruction
  };

  if (modelName === 'gemini-4-hydrogen') {
    config.thinkingConfig = {
      thinkingLevel: resolveThinkingLevel(powerMode, modelName)
    };
  } else if (modelName === 'gemini-3.1-flash-lite') {
    config.thinkingConfig = {
      thinkingLevel: ThinkingLevel.MINIMAL
    };
  }

  if (responseSchema) {
    config.responseMimeType = 'application/json';
    config.responseSchema = responseSchema;
  } else if (urlsInPrompt && urlsInPrompt.length > 0 && !useSearch) {
    config.tools = [{ urlContext: {} }];
  } else if (useSearch) {
    config.tools = [{ googleSearch: {} }];
  }

  return config;
}

async function generateWithRetry(ai, params, timeoutMs = 85000) {
  let lastErr = null;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Délai dépassé (${Math.round(timeoutMs / 1000)}s)`)), timeoutMs)
      );
      const response = await Promise.race([ai.models.generateContent(params), timeoutPromise]);
      return response;
    } catch (err) {
      lastErr = err;
      const msg = String(err?.message || '');
      const isTransient =
        msg.includes('503') ||
        msg.includes('high demand') ||
        msg.includes('ECONNRESET') ||
        msg.includes('ETIMEDOUT');
      if (attempt < 2 && isTransient) {
        await new Promise(r => setTimeout(r, 800 * attempt));
        continue;
      }
      throw err;
    }
  }
  throw lastErr;
}

// ===== GÉNÉRATEUR D'ILLUSTRATIONS VECTORIELLES HD (FREE TIER + EXPORT PNG 2K) =====

function sanitizeAndValidateSvg(rawText, width, height) {
  let text = String(rawText || '').trim();
  if (!text) return null;

  // Strip markdown fences if present
  text = text.replace(/^```(?:xml|svg|html)?\s*/i, '').replace(/```\s*$/i, '').trim();

  const startIdx = text.search(/<svg[\s>]/i);
  if (startIdx === -1) return null;
  let svg = text.slice(startIdx);

  const endIdx = svg.search(/<\/svg>/i);
  if (endIdx !== -1) {
    svg = svg.slice(0, endIdx);
  }

  // Strip unsafe or external elements that break <img> data URI or canvas export
  svg = svg
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<foreignObject[\s\S]*?<\/foreignObject>/gi, '')
    .replace(/<image\b[^>]*\b(?:href|xlink:href)\s*=\s*["']https?:\/\/[^"']*["'][^>]*\/?>/gi, '')
    .replace(/\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');

  // Recover unclosed <defs> or <g> tags cleanly before closing </svg>
  if (/<defs[\s>]/i.test(svg) && !/<\/defs>/i.test(svg)) svg += '</defs>';
  const openG = (svg.match(/<g[\s>]/gi) || []).length;
  const closeG = (svg.match(/<\/g>/gi) || []).length;
  for (let i = 0; i < Math.max(0, openG - closeG); i++) svg += '</g>';
  svg += '</svg>';

  // Ensure root <svg> attributes are valid for strict XML parsing inside <img>
  svg = svg.replace(/<svg\b([^>]*)>/i, (_, attrs) => {
    let cleanAttrs = attrs;
    if (!/\bxmlns\s*=/i.test(cleanAttrs)) {
      cleanAttrs += ' xmlns="http://www.w3.org/2000/svg"';
    }
    if (!/\bviewBox\s*=/i.test(cleanAttrs)) {
      cleanAttrs += ` viewBox="0 0 ${width} ${height}"`;
    }
    if (!/\bwidth\s*=/i.test(cleanAttrs)) {
      cleanAttrs += ` width="${width}"`;
    }
    if (!/\bheight\s*=/i.test(cleanAttrs)) {
      cleanAttrs += ` height="${height}"`;
    }
    return `<svg${cleanAttrs}>`;
  });

  // Escape unescaped ampersands so strict SVG XML parser never fails
  svg = svg.replace(/&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)/g, '&amp;');

  // Must contain actual vector shapes
  if (!/<(path|circle|rect|polygon|ellipse|line|polyline)\b/i.test(svg)) {
    return null;
  }

  return svg;
}

function sanitizeImageAlt(prompt) {
  return (
    String(prompt || 'Illustration NOVA MK')
      .replace(/[\[\]()\r\n]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 110) || 'Illustration NOVA MK'
  );
}

function extractImagePrompt(text) {
  const cleaned = String(text || '')
    .replace(
      /^(?:s['’]?il te pla[îi]t\s*,?\s*|peux[- ]tu\s+|pourrais[- ]tu\s+|je veux\s+(?:que tu\s+)?|merci de\s+)?(?:g[ée]n[èe]re[rz]?|cr[ée]e[rz]?|construi[st]|construire|fais|faire|dessine[rz]?|illustre[rz]?|peins|produis|imagine[rz]?|montre|donne|make|create|build|draw|generate|render|paint|ارسم|انشئ|اصنع|صمم)(?:[- ]moi|[- ]nous)?\s*(?:une|un|des|l['’]|la|le|a|an|the)?\s*(?:image|photo|illustration|dessin|tableau|affiche|logo|portrait|avatar|picture|artwork|صورة|رسم)?\s*(?:d['’]|de|du|des|avec|sur|pour|of|about|with)?\s*/i,
      ''
    )
    .trim();
  return cleaned || String(text || '').trim();
}

async function generateHighQualityImage(prompt, aspectRatio = '1:1', referenceFiles = []) {
  const ai = getAiClient();
  if (!ai) throw new Error('GEMINI_API_KEY manquant sur le serveur.');

  const cleanPrompt = String(prompt).trim();
  const validRatios = ['1:1', '3:4', '4:3', '9:16', '16:9'];
  const ar = validRatios.includes(aspectRatio) ? aspectRatio : '1:1';

  let width = 1024;
  let height = 1024;
  if (ar === '16:9') { width = 1280; height = 720; }
  else if (ar === '9:16') { width = 720; height = 1280; }
  else if (ar === '4:3') { width = 1024; height = 768; }
  else if (ar === '3:4') { width = 768; height = 1024; }

  const svgPrompt = `Tu es un directeur artistique et illustrateur vectoriel SVG d'élite mondiale.
Crée une illustration SVG autonome époustouflante, riche, très détaillée et esthétique représentant : "${cleanPrompt}".
${referenceFiles.length ? "Inspire-toi fidèlement de l'image ou du document joint pour construire ou transformer cette illustration." : ''}

RÈGLES TECHNIQUES STRICTES :
1. Balise racine exacte : <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}"> ... </svg>
2. Utilise des dégradés riches (<linearGradient>, <radialGradient>), des filtres lumineux ou d'ombre (<filter> avec feGaussianBlur / feDropShadow), de nombreuses formes composées (<path>, <circle>, <ellipse>, <polygon>, <rect>) en couches successives (arrière-plan atmosphérique, plan intermédiaire, sujet principal très détaillé, reflets et particules lumineuses).
3. Sois fidèle au sujet demandé (personnages, animaux, paysages, objets scientifiques, schémas, architecture, scène futuriste, etc.) avec de vraies proportions artistiques, des ombres et lumières cohérentes.
4. XML STRICTEMENT VALIDE : n'utilise JAMAIS le caractère "&" nu (écris "&amp;"), pas de balises <script>, pas de <foreignObject>, pas de lien <image href="http...">.
5. N'ajoute PAS de texte parasite ou de filigrane sauf si la description demande explicitement du texte.
6. Réponds STRICTEMENT et UNIQUEMENT avec le code SVG brut commençant par <svg et finissant par </svg>, sans balises markdown \`\`\` et sans explication.`;

  const parts = [...buildFileParts(referenceFiles), { text: svgPrompt }];
  const imageCandidateModels = [
    { model: DEFAULT_MODEL, config: { thinkingConfig: { thinkingLevel: ThinkingLevel.LOW } } },
    { model: 'gemini-3.1-flash-lite', config: { thinkingConfig: { thinkingLevel: ThinkingLevel.MINIMAL } } }
  ];

  let lastAuthErr = null;
  for (const candidate of imageCandidateModels) {
    try {
      const svgRes = await generateWithRetry(
        ai,
        {
          model: candidate.model,
          contents: [{ role: 'user', parts }],
          config: candidate.config
        },
        75000
      );

      const cleanSvg = sanitizeAndValidateSvg(svgRes.text || '', width, height);
      if (cleanSvg) {
        const b64 = Buffer.from(cleanSvg, 'utf8').toString('base64');
        return {
          imageUrl: `data:image/svg+xml;base64,${b64}`,
          modelUsed: candidate.model,
          isFallback: false
        };
      }
    } catch (err) {
      const msg = String(err?.message || '');
      console.warn(`Image gen attempt (${candidate.model}) failed:`, msg);
      if (msg.includes('PERMISSION_DENIED') || msg.includes('API_KEY_INVALID') || msg.includes('403') || msg.includes('401')) {
        lastAuthErr = err;
      }
    }
  }

  if (lastAuthErr) {
    throw lastAuthErr;
  }

  // Fallback graphique vectoriel stylisé et XML-safe si la réponse n'a pas pu être parsée
  const safeTitle = cleanPrompt.slice(0, 48).replace(/[<>&"']/g, c => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&apos;'
  }[c]));
  const proceduralSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#070b16"/>
        <stop offset="50%" stop-color="#111a2e"/>
        <stop offset="100%" stop-color="#05070c"/>
      </linearGradient>
      <linearGradient id="glow" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#3b82f6"/>
        <stop offset="50%" stop-color="#8b5cf6"/>
        <stop offset="100%" stop-color="#06b6d4"/>
      </linearGradient>
      <radialGradient id="halo" cx="50%" cy="45%" r="50%">
        <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.42"/>
        <stop offset="100%" stop-color="#070b16" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <rect width="${width}" height="${height}" fill="url(#bg)"/>
    <circle cx="${width / 2}" cy="${height * 0.45}" r="${Math.min(width, height) * 0.42}" fill="url(#halo)"/>
    <rect x="${width * 0.08}" y="${height * 0.12}" width="${width * 0.84}" height="${height * 0.76}" rx="28" fill="#0d1424" stroke="url(#glow)" stroke-width="2.5" fill-opacity="0.9"/>
    <circle cx="${width / 2}" cy="${height * 0.4}" r="76" fill="url(#glow)" fill-opacity="0.18" stroke="url(#glow)" stroke-width="2.5"/>
    <path d="M ${width / 2 - 48} ${height * 0.45} L ${width / 2 - 12} ${height * 0.36} L ${width / 2 + 16} ${height * 0.42} L ${width / 2 + 48} ${height * 0.33} L ${width / 2 + 54} ${height * 0.46} Z" fill="url(#glow)" opacity="0.85"/>
    <circle cx="${width / 2 - 22}" cy="${height * 0.35}" r="9" fill="#f8fafc" opacity="0.9"/>
    <text x="${width / 2}" y="${height * 0.64}" font-family="system-ui, sans-serif" font-size="24" font-weight="700" fill="#f8fafc" text-anchor="middle">${safeTitle}</text>
    <text x="${width / 2}" y="${height * 0.71}" font-family="system-ui, sans-serif" font-size="14" font-weight="500" fill="#94a3b8" text-anchor="middle">NOVA MK · Studio Créatif</text>
  </svg>`;
  return {
    imageUrl: `data:image/svg+xml;base64,${Buffer.from(proceduralSvg, 'utf8').toString('base64')}`,
    modelUsed: DEFAULT_MODEL,
    isFallback: true
  };
}

// ===== GÉNÉRATEUR DE QCM STRUCTURÉ (JSON SCHEMA) =====

const QCM_RESPONSE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    title: { type: Type.STRING, description: 'Titre clair du QCM' },
    subject: { type: Type.STRING, description: 'Matière ou domaine' },
    level: { type: Type.STRING, description: 'Niveau scolaire ou expertise' },
    durationMinutes: { type: Type.INTEGER, description: 'Durée conseillée en minutes' },
    questions: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          question: { type: Type.STRING, description: 'Énoncé clair et précis de la question' },
          options: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: 'Exactement 4 propositions de réponse (A, B, C, D sans préfixe lettre)'
          },
          correctIndex: {
            type: Type.INTEGER,
            description: 'Index de la bonne réponse entre 0 et 3'
          },
          explanation: {
            type: Type.STRING,
            description: 'Explication pédagogique détaillée justifiant la bonne réponse'
          }
        },
        required: ['question', 'options', 'correctIndex', 'explanation']
      }
    }
  },
  required: ['title', 'subject', 'level', 'durationMinutes', 'questions']
};

function buildFileParts(files = []) {
  const parts = [];
  for (const f of files.slice(0, 6)) {
    if (!f?.data) continue;
    let rawData = String(f.data);
    if (rawData.includes(';base64,')) {
      rawData = rawData.split(';base64,')[1];
    }
    rawData = rawData.trim();
    if (!rawData) continue;
    if (f.type === 'image/svg+xml') {
      try {
        const svgSource = Buffer.from(rawData, 'base64').toString('utf8').slice(0, 12000);
        parts.push({ text: `[Image vectorielle SVG jointe (${f.name || 'image.svg'})] :\n${svgSource}` });
      } catch (e) {}
      continue;
    }
    const mimeType =
      f.type === 'application/pdf'
        ? 'application/pdf'
        : /^image\/(png|gif|webp)$/.test(f.type)
          ? f.type
          : 'image/jpeg';
    parts.push({ inlineData: { mimeType, data: rawData } });
  }
  return parts;
}

function formatQcmMarkdown(qcm) {
  let md = `## 📝 ${qcm.title}\n\n`;
  md += `**Matière :** ${qcm.subject} · **Niveau :** ${qcm.level} · **Durée estimée :** ${qcm.durationMinutes} min · **Questions :** ${qcm.questions.length}\n\n---\n\n`;
  const letters = ['A', 'B', 'C', 'D'];
  qcm.questions.forEach((item, idx) => {
    md += `### Question ${idx + 1}\n${item.question}\n`;
    (item.options || []).forEach((opt, oi) => {
      md += `- **${letters[oi] || oi + 1}.** ${opt}\n`;
    });
    md += `\n`;
  });
  return md;
}

async function generateStructuredQcm(ai, { topic, subject, level, count = 8, language = 'Français', files = [] }) {
  const numQuestions = Math.max(3, Math.min(25, parseInt(count, 10) || 8));
  const prompt = `Génère un QCM pédagogique complet, rigoureux et stimulant de ${numQuestions} questions en ${language}.
Sujet / Consigne : ${topic || 'Basé sur les documents joints'}
Matière : ${subject || 'Générale'}
Niveau : ${level || 'Lycée / Université'}

Règles strictes :
- Chaque question doit avoir EXACTEMENT 4 options plausibles et distinctes (ne mets pas "A.", "B." dans le texte des options).
- Une seule réponse correcte (correctIndex de 0 à 3).
- Fournis une explication pédagogique claire et complète pour chaque question.
- Si des fichiers (image ou PDF de cours) sont joints, base les questions directement sur leur contenu.`;

  const parts = [...buildFileParts(files), { text: prompt }];

  const resp = await generateWithRetry(
    ai,
    {
      model: DEFAULT_MODEL,
      contents: [{ role: 'user', parts }],
      config: {
        systemInstruction: NOVA_SYSTEM_PROMPT,
        thinkingConfig: { thinkingLevel: ThinkingLevel.HIGH },
        responseMimeType: 'application/json',
        responseSchema: QCM_RESPONSE_SCHEMA
      }
    },
    85000
  );

  const rawJson = (resp.text || '{}').trim();
  const qcm = JSON.parse(rawJson);
  if (!Array.isArray(qcm.questions) || !qcm.questions.length) {
    throw new Error('Le QCM généré ne contient aucune question.');
  }
  qcm.questions = qcm.questions.map(q => ({
    question: String(q.question || ''),
    options: Array.isArray(q.options) ? q.options.slice(0, 4).map(String) : ['Option A', 'Option B', 'Option C', 'Option D'],
    correctIndex: Math.max(0, Math.min(3, parseInt(q.correctIndex, 10) || 0)),
    explanation: String(q.explanation || '')
  }));
  return qcm;
}

// ===== HELPERS LANGUE & RÉSUMÉ VOCAL =====

function detectLanguage(text) {
  const arMatches = (text.match(/[\u0600-\u06FF]/g) || []).length;
  const latMatches = (text.match(/[a-zA-ZÀ-ÿ]/g) || []).length;
  if (arMatches > latMatches * 0.5 && arMatches > 8) return 'ar';
  const isEn =
    /\b(the|is|and|you|this|with|for|that|have)\b/i.test(text) &&
    !/\b(le|la|les|est|vous|pour|avec|dans|une)\b/i.test(text);
  return isEn ? 'en' : 'fr';
}

function buildSpeechSummary(outputText) {
  const cleanOutput = (outputText || '')
    .replace(/```[\s\S]*?```/g, '')
    .replace(/!\[([^\]]*)\]\([^\)]+\)/g, '')
    .replace(/[#*`_>|!\[\]\(\)]/g, '')
    .replace(/https?:\/\/\S+/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const firstSentenceMatch = cleanOutput.match(/^(.*?[.!?](\s|$))/);
  let summary = firstSentenceMatch ? firstSentenceMatch[0].trim() : cleanOutput.slice(0, 160);
  if (summary.length < 25 && cleanOutput.length > 25) {
    summary = cleanOutput.slice(0, 160);
  }
  return summary;
}

function loadChatHistoryContents(chatId, uid) {
  const historyRows = db
    .prepare('SELECT role, text FROM chat_msgs WHERE chat_id=? AND uid=? ORDER BY ts ASC LIMIT 20')
    .all(chatId, uid);

  const contents = [];
  for (const row of historyRows) {
    if (!row.text) continue;
    // Strip inline base64 data URIs from history so context stays light and fast
    const cleanedText = row.text.replace(/!\[([^\]]*)\]\(data:image\/[^)\s]+\)/g, '[Image générée: $1]').trim();
    if (!cleanedText) continue;
    contents.push({
      role: row.role === 'user' ? 'user' : 'model',
      parts: [{ text: cleanedText }]
    });
  }
  return contents;
}

function ensureChatExists(chatId, uid, titleSeed) {
  const now = Date.now();
  let currentChatId = chatId;
  const chat = chatId ? db.prepare('SELECT * FROM chats WHERE id=? AND uid=?').get(chatId, uid) : null;
  if (!chat) {
    currentChatId = 'chat_' + now;
    const initialTitle = titleSeed ? titleSeed.slice(0, 36) + (titleSeed.length > 36 ? '…' : '') : 'Nouvelle conversation';
    db.prepare('INSERT INTO chats(id, uid, title, created, updated) VALUES(?,?,?,?,?)').run(
      currentChatId,
      uid,
      initialTitle,
      now,
      now
    );
  }
  return currentChatId;
}

// ===== TRANSCRIPTION AUDIO =====

app.post('/api/transcribe', auth, limit(60, 6e4), async (q, r) => {
  try {
    const audioData = q.body.audio;
    const mimeType = q.body.mimeType || 'audio/webm';
    if (!audioData) return r.status(400).json({ error: 'Fichier audio manquant.' });

    let rawData = String(audioData);
    if (rawData.includes(';base64,')) rawData = rawData.split(';base64,')[1];
    rawData = rawData.trim();

    const ai = getAiClient();
    if (!ai) return r.status(500).json({ error: 'GEMINI_API_KEY manquant sur le serveur.' });

    let transcript = '';
    const transcribeModels = ['gemini-3.5-transcribe', DEFAULT_MODEL, 'gemini-3.1-flash-lite'];
    for (const m of transcribeModels) {
      try {
        const resp = await ai.models.generateContent({
          model: m,
          contents: [
            {
              parts: [
                { inlineData: { mimeType, data: rawData } },
                {
                  text: 'Tu es un transcripteur vocal expert multilingue (français, arabe, anglais). Retranscris avec une précision irréprochable les propos enregistrés. Ne retourne strictement QUE le texte exact prononcé, sans commentaire.'
                }
              ]
            }
          ]
        });
        transcript = resp.text?.trim() || '';
        if (transcript) break;
      } catch (err) {
        console.warn(`Transcribe model ${m} failed:`, err.message);
      }
    }
    return r.json({ ok: true, transcript });
  } catch (e) {
    console.error('Transcribe error:', e);
    return r.status(500).json({ error: 'Erreur lors de la transcription vocale.' });
  }
});

// ===== ENDPOINT GÉNÉRATION D'IMAGES =====

app.post('/api/generate-image', auth, limit(30, 6e4), async (q, r) => {
  const startTime = Date.now();
  try {
    const prompt = String(q.body.prompt || '').trim();
    const aspectRatio = String(q.body.aspectRatio || '1:1');
    const chatId = String(q.body.chatId || '').trim();
    const files = Array.isArray(q.body.files) ? q.body.files.slice(0, 4) : [];

    if (!prompt) {
      return r.status(400).json({ error: 'Veuillez saisir une description pour votre image.' });
    }

    const gen = await generateHighQualityImage(prompt, aspectRatio, files);
    const imageUrl = gen.imageUrl;
    const safeAlt = sanitizeImageAlt(prompt);
    const now = Date.now();
    const currentChatId = ensureChatExists(chatId, q.u.id, 'Image : ' + prompt.slice(0, 24));

    const botMsgId = 'msg_' + now + '_img';
    const textDesc = `Voici votre création visuelle générée par NOVA :\n\n**« ${safeAlt} »**\n\n![${safeAlt}](${imageUrl})`;
    const extraFiles = [{ type: 'nova/image', url: imageUrl, name: safeAlt, isSvg: imageUrl.startsWith('data:image/svg+xml') }];

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      botMsgId,
      currentChatId,
      q.u.id,
      'bot',
      textDesc,
      JSON.stringify(extraFiles),
      now
    );
    db.prepare('UPDATE chats SET updated=? WHERE id=?').run(now, currentChatId);

    return r.json({
      ok: true,
      imageUrl,
      prompt,
      text: textDesc,
      files: extraFiles,
      speechSummary: `Illustration générée pour : ${safeAlt.slice(0, 60)}`,
      chatId: currentChatId,
      botMsgId,
      modelUsed: gen.modelUsed,
      durationMs: Date.now() - startTime
    });
  } catch (e) {
    console.error('API generate-image error:', e);
    return r.status(500).json({ error: formatGeminiError(e) });
  }
});

// ===== ENDPOINT GÉNÉRATION DE QCM INTERACTIF =====

app.post('/api/generate-qcm', auth, limit(30, 6e4), async (q, r) => {
  const startTime = Date.now();
  try {
    const { topic, subject, level, count, language, files = [], chatId } = q.body;
    if (!topic && !files.length) {
      return r.status(400).json({ error: 'Veuillez préciser un sujet ou joindre un document.' });
    }
    const ai = getAiClient();
    if (!ai) return r.status(500).json({ error: 'GEMINI_API_KEY manquant sur le serveur.' });

    const qcm = await generateStructuredQcm(ai, { topic, subject, level, count, language, files });
    const now = Date.now();
    const currentChatId = ensureChatExists(chatId, q.u.id, 'QCM : ' + (qcm.title || topic || 'Quiz'));

    const userMsgId = 'msg_' + now + '_u';
    const botMsgId = 'msg_' + (now + 1) + '_b';
    const userPromptText = `📝 **Créer un QCM** : ${topic || 'D’après document'} (${subject || 'Général'} · ${level || 'Standard'} · ${qcm.questions.length} questions)`;
    const botMarkdown = formatQcmMarkdown(qcm);
    const metaFiles = [{ type: 'nova/qcm', name: qcm.title, qcm }];

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      userMsgId,
      currentChatId,
      q.u.id,
      'user',
      userPromptText,
      JSON.stringify(files.map(f => ({ name: f.name, type: f.type, url: f.url }))),
      now
    );
    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      botMsgId,
      currentChatId,
      q.u.id,
      'bot',
      botMarkdown,
      JSON.stringify(metaFiles),
      now + 1
    );
    db.prepare('UPDATE chats SET updated=? WHERE id=?').run(now + 1, currentChatId);

    return r.json({
      ok: true,
      qcm,
      text: botMarkdown,
      files: metaFiles,
      chatId: currentChatId,
      userMsgId,
      botMsgId,
      durationMs: Date.now() - startTime,
      modelUsed: DEFAULT_MODEL
    });
  } catch (e) {
    console.error('API generate-qcm error:', e);
    return r.status(500).json({ error: formatGeminiError(e) });
  }
});

// ===== ENDPOINT DEVOIRS & EXERCICES =====

app.post('/api/generate-devoir', auth, limit(30, 6e4), async (q, r) => {
  const startTime = Date.now();
  try {
    const {
      subject = 'Mathématiques',
      level = 'Lycée / Terminale',
      topic = '',
      mode = 'create',
      language = 'Français',
      files = [],
      chatId
    } = q.body;

    if (!topic && !files.length) {
      return r.status(400).json({ error: 'Veuillez décrire le devoir/exercice ou joindre une photo/PDF.' });
    }
    const ai = getAiClient();
    if (!ai) return r.status(500).json({ error: 'GEMINI_API_KEY manquant sur le serveur.' });

    const taskPrompt =
      mode === 'solve'
        ? `MODE RÉSOLUTION EXPERTE DE DEVOIR (${language}) :
Matière : ${subject} | Niveau : ${level}
Consigne / Énoncé : ${topic || 'Analyser et résoudre intégralement le devoir dans les fichiers joints.'}

Fournis une correction magistrale structurée :
### 1. Analyse de l'énoncé & Rappels de cours
### 2. Résolution détaillée étape par étape (avec calculs, formules et justification complète)
### 3. Réponse finale rédigée (prête à recopier)
### 4. Conseils & Pièges à éviter`
        : `MODE CRÉATION DE DEVOIR COMPLET (${language}) :
Matière : ${subject} | Niveau : ${level} | Thème : ${topic || 'Basé sur les documents joints'}

Crée un devoir sur table officiel, complet et rigoureux prêt à imprimer en PDF :
# Devoir de ${subject} — ${topic || 'Évaluation'}
**Niveau :** ${level} · **Durée conseillée :** 1h30 · **Barème total :** 20 points

Organise le devoir en 3 à 4 exercices progressifs (du cours vers l'approfondissement/problème) avec le barème exact de chaque question.
Puis ajoute une grande section séparée à la fin :
---
## ✅ Corrigé Détaillé & Barème de Correction
Avec la solution complète, rigoureuse et pédagogique de chaque question.`;

    const parts = [...buildFileParts(files), { text: taskPrompt }];
    const resp = await generateWithRetry(
      ai,
      {
        model: DEFAULT_MODEL,
        contents: [{ role: 'user', parts }],
        config: buildGeminiConfig(DEFAULT_MODEL, NOVA_SYSTEM_PROMPT, { powerMode: 'max' })
      },
      95000
    );

    const outputText = resp.text;
    if (!outputText) throw new Error('Réponse vide du modèle IA.');

    const now = Date.now();
    const currentChatId = ensureChatExists(chatId, q.u.id, `Devoir : ${subject} - ${(topic || 'Exercice').slice(0, 20)}`);
    const userMsgId = 'msg_' + now + '_u';
    const botMsgId = 'msg_' + (now + 1) + '_b';
    const userLabel =
      mode === 'solve'
        ? `📚 **Résoudre mon devoir** (${subject} · ${level}) : ${topic || 'Fichier joint'}`
        : `📚 **Créer un devoir** (${subject} · ${level}) : ${topic || 'D’après document'}`;
    const metaFiles = [{ type: 'nova/meta', isPdfReady: true }];

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      userMsgId,
      currentChatId,
      q.u.id,
      'user',
      userLabel,
      JSON.stringify(files.map(f => ({ name: f.name, type: f.type, url: f.url }))),
      now
    );
    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      botMsgId,
      currentChatId,
      q.u.id,
      'bot',
      outputText,
      JSON.stringify(metaFiles),
      now + 1
    );
    db.prepare('UPDATE chats SET updated=? WHERE id=?').run(now + 1, currentChatId);

    return r.json({
      ok: true,
      text: outputText,
      files: metaFiles,
      isPdfReady: true,
      detectedLang: detectLanguage(outputText),
      speechSummary: buildSpeechSummary(outputText),
      chatId: currentChatId,
      userMsgId,
      botMsgId,
      durationMs: Date.now() - startTime,
      modelUsed: DEFAULT_MODEL
    });
  } catch (e) {
    console.error('API generate-devoir error:', e);
    return r.status(500).json({ error: formatGeminiError(e) });
  }
});

// ===== ENDPOINT CRÉATION DE DOCUMENTS PDF =====

app.post('/api/generate-document', auth, limit(30, 6e4), async (q, r) => {
  const startTime = Date.now();
  try {
    const {
      docType = 'Cours & Fiche de synthèse',
      title = '',
      instructions = '',
      language = 'Français',
      files = [],
      chatId
    } = q.body;

    if (!title && !instructions && !files.length) {
      return r.status(400).json({ error: 'Veuillez renseigner un titre ou des instructions pour votre document.' });
    }
    const ai = getAiClient();
    if (!ai) return r.status(500).json({ error: 'GEMINI_API_KEY manquant sur le serveur.' });

    const docPrompt = `Génère un document complet de très haute qualité prêt pour exportation en PDF professionnel A4.
Type de document : ${docType}
Titre : ${title || 'Document professionnel'}
Langue de rédaction : ${language}
Instructions & Contenu demandé : ${instructions || 'Synthèse complète et structurée des documents joints.'}

Exigences de mise en page Markdown :
- Commence par un titre principal (# Titre) suivi d'un court chapeau / résumé exécutif en citation (> ...).
- Structure le document en sections claires (##, ###), paragraphes riches, listes à puces et au moins un tableau récapitulatif Markdown si pertinent.
- Sois complet, rigoureux, concret et sans remplissage inutile.`;

    const parts = [...buildFileParts(files), { text: docPrompt }];
    const resp = await generateWithRetry(
      ai,
      {
        model: DEFAULT_MODEL,
        contents: [{ role: 'user', parts }],
        config: buildGeminiConfig(DEFAULT_MODEL, NOVA_SYSTEM_PROMPT, { powerMode: 'high' })
      },
      90000
    );

    const outputText = resp.text;
    if (!outputText) throw new Error('Réponse vide du modèle IA.');

    const now = Date.now();
    const currentChatId = ensureChatExists(chatId, q.u.id, `PDF : ${(title || docType).slice(0, 26)}`);
    const userMsgId = 'msg_' + now + '_u';
    const botMsgId = 'msg_' + (now + 1) + '_b';
    const userLabel = `📄 **Créer un document PDF** (${docType}) : ${title || instructions.slice(0, 60)}`;
    const metaFiles = [{ type: 'nova/meta', isPdfReady: true, docTitle: title || docType }];

    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      userMsgId,
      currentChatId,
      q.u.id,
      'user',
      userLabel,
      JSON.stringify(files.map(f => ({ name: f.name, type: f.type, url: f.url }))),
      now
    );
    db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
      botMsgId,
      currentChatId,
      q.u.id,
      'bot',
      outputText,
      JSON.stringify(metaFiles),
      now + 1
    );
    db.prepare('UPDATE chats SET updated=? WHERE id=?').run(now + 1, currentChatId);

    return r.json({
      ok: true,
      text: outputText,
      files: metaFiles,
      isPdfReady: true,
      docTitle: title || docType,
      detectedLang: detectLanguage(outputText),
      speechSummary: buildSpeechSummary(outputText),
      chatId: currentChatId,
      userMsgId,
      botMsgId,
      durationMs: Date.now() - startTime,
      modelUsed: DEFAULT_MODEL
    });
  } catch (e) {
    console.error('API generate-document error:', e);
    return r.status(500).json({ error: formatGeminiError(e) });
  }
});

// ===== CHAT PRINCIPAL (AVEC STREAMING SSE + FALLBACK CLASSIQUE) =====

async function prepareChatContext(q) {
  const text = String(q.body.text || '').trim();
  const files = Array.isArray(q.body.files) ? q.body.files.slice(0, 6) : [];
  const chatId = String(q.body.chatId || '').trim();
  const requestedModel = normalizeModelName(q.body.model || q.u.model || DEFAULT_MODEL);
  const powerMode = String(q.body.powerMode || 'max');
  const userLoc = q.body.location;
  const isExplicitWebSearch = q.body.webSearch !== false;

  const currentChatId = ensureChatExists(chatId, q.u.id, text || 'Analyse document');

  const lowerText = text.toLowerCase();
  const needsMedical =
    /hopital|hôpital|clinique|cabinet|urgence|médical|médecin|docteur|douleur|blessure|malade|santé|pharmacie|hospital|clinic|doctor|emergency|مستشفى|طبيب|عيادة|طوارئ|صيدلية|ألم|مرض|إسعاف/.test(
      lowerText
    );
  const needsSearch =
    isExplicitWebSearch &&
    /actualit|nouvelle|météo|weather|news|recherche|cherche|internet|web|derni[èe]re|aujourd'hui|2025|2026|prix|cours|résultat|score|أخبار|طقس|بحث|ابحث/.test(
      lowerText
    );
  const urlsInPrompt = text.match(/https?:\/\/[^\s<>"']+/g) || [];

  let nearbyPlaces = [];
  let enrichedContext = '';

  if (needsMedical) {
    nearbyPlaces = await findNearbyPlaces(userLoc?.lat, userLoc?.lng, 'hopital urgence clinique pharmacie');
    if (nearbyPlaces.length) {
      enrichedContext +=
        `\n\n[DONNÉES GPS EN TEMPS RÉEL - ÉTABLISSEMENTS DE SANTÉ À PROXIMITÉ (${userLoc?.lat || ''}, ${userLoc?.lng || ''})] :\n` +
        nearbyPlaces.map((p, i) => `${i + 1}. ${p.name} - ${p.address} (Lien GPS: ${p.mapUrl})`).join('\n') +
        `\nIndique immédiatement ces établissements si l'utilisateur cherche un médecin, une pharmacie ou une urgence, et rappelle le numéro d'urgence adapté.`;
    }
  }

  const contents = loadChatHistoryContents(currentChatId, q.u.id);
  const currentParts = buildFileParts(files);
  let fullUserPrompt =
    text || 'Veuillez analyser avec précision les documents ou photos joints et me fournir une synthèse détaillée.';
  if (enrichedContext) {
    fullUserPrompt += '\n\n' + enrichedContext;
  }
  currentParts.push({ text: fullUserPrompt });
  contents.push({ role: 'user', parts: currentParts });

  const isPdfRequest =
    /\b(en pdf|format pdf|document pdf|cr[ée]e[rz]? un pdf|fais[- ]moi un pdf|g[ée]n[èe]re[rz]? un pdf|exporter en pdf|fiche pdf|ملف pdf)\b/i.test(
      text
    );

  const isTechImageTopic = /\b(docker|iso|disque|container|conteneur|vm|virtualbox|linux)\b/i.test(text);
  const hasImageCreateVerb =
    /\b(g[ée]n[èe]re[rz]?|cr[ée]e[rz]?|construi[st]|construire|fais|faire|dessine[rz]?|illustre[rz]?|peins|peindre|produis|imagine[rz]?|montre[- ]moi|donne[- ]moi|make|create|build|draw|generate|render|paint|ارسم|انشئ|اصنع|صمم)\b/i.test(
      text
    );
  const hasImageNoun =
    /\b(image|images|photo|photos|illustration|illustrations|dessin|dessins|tableau|affiche|logo|portrait|avatar|picture|wallpaper|artwork|صورة|رسم)\b/i.test(
      text
    );
  const hasImageEditVerb =
    files.some(f => f.type && f.type.startsWith('image/')) &&
    /\b(modifie|transforme|[ée]dite|retouche|change|redessine|edit|modify|transform|redraw)\b/i.test(text);

  const isImagePrompt =
    !isPdfRequest &&
    !isTechImageTopic &&
    ((hasImageCreateVerb && hasImageNoun) || hasImageEditVerb);

  const isAutoQcmPrompt =
    !isPdfRequest &&
    /^(gén[èe]re|cr[ée]e|fais|donne|prépare|make|create)\b.*(qcm|quiz|questionnaire à choix|اختبار اختيار)/i.test(
      text
    );

  return {
    text,
    files,
    currentChatId,
    requestedModel,
    powerMode,
    nearbyPlaces,
    needsSearch,
    urlsInPrompt,
    contents,
    isPdfRequest,
    isImagePrompt,
    isAutoQcmPrompt
  };
}

function finalizeChatMessages(currentChatId, uid, text, files, outputText, extraFiles = []) {
  const now = Date.now();
  const userMsgId = 'msg_' + now + '_u';
  const botMsgId = 'msg_' + (now + 1) + '_b';

  db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
    userMsgId,
    currentChatId,
    uid,
    'user',
    text,
    JSON.stringify(files.map(f => ({ name: f.name, type: f.type, url: f.url }))),
    now
  );
  db.prepare('INSERT INTO chat_msgs(id, chat_id, uid, role, text, files, ts) VALUES(?,?,?,?,?,?,?)').run(
    botMsgId,
    currentChatId,
    uid,
    'bot',
    outputText,
    JSON.stringify(extraFiles),
    now + 1
  );
  db.prepare('UPDATE chats SET updated=? WHERE id=?').run(now + 1, currentChatId);

  let chatTitle = null;
  const msgCount = db.prepare('SELECT COUNT(*) as c FROM chat_msgs WHERE chat_id=?').get(currentChatId).c;
  if (msgCount <= 2 && text) {
    chatTitle = text.slice(0, 36) + (text.length > 36 ? '…' : '');
    db.prepare('UPDATE chats SET title=? WHERE id=?').run(chatTitle, currentChatId);
  }

  return { userMsgId, botMsgId, chatTitle };
}

// Endpoint streaming SSE (temps réel mot à mot)
app.post('/api/chat/stream', auth, limit(60, 6e4), async (q, r) => {
  const startTime = Date.now();
  r.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  r.setHeader('Cache-Control', 'no-cache, no-transform');
  r.setHeader('Connection', 'keep-alive');
  r.flushHeaders?.();

  const sendEvent = (event, data) => {
    r.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const ai = getAiClient();
    if (!ai) {
      sendEvent('error', { error: 'Clé API Gemini manquante sur le serveur (GEMINI_API_KEY).' });
      return r.end();
    }

    const ctx = await prepareChatContext(q);
    if (!ctx.text && !ctx.files.length) {
      sendEvent('error', { error: 'Message ou fichier requis.' });
      return r.end();
    }

    // 1. Auto-image generation
    if (ctx.isImagePrompt) {
      const imagePrompt = extractImagePrompt(ctx.text);
      const gen = await generateHighQualityImage(imagePrompt, '1:1', ctx.files);
      const imageUrl = gen.imageUrl;
      const safeAlt = sanitizeImageAlt(imagePrompt);
      const botMsgText = `Voici votre illustration générée par NOVA :\n\n**« ${safeAlt} »**\n\n![${safeAlt}](${imageUrl})`;
      const extraFiles = [{ type: 'nova/image', url: imageUrl, name: safeAlt, isSvg: imageUrl.startsWith('data:image/svg+xml') }];
      const { userMsgId, botMsgId, chatTitle } = finalizeChatMessages(
        ctx.currentChatId,
        q.u.id,
        ctx.text,
        ctx.files,
        botMsgText,
        extraFiles
      );
      sendEvent('chunk', { delta: botMsgText });
      sendEvent('done', {
        ok: true,
        text: botMsgText,
        imageUrl,
        files: extraFiles,
        speechSummary: `Illustration générée pour ${safeAlt.slice(0, 60)}`,
        detectedLang: detectLanguage(ctx.text),
        chatId: ctx.currentChatId,
        userMsgId,
        botMsgId,
        title: chatTitle,
        modelUsed: gen.modelUsed,
        durationMs: Date.now() - startTime
      });
      return r.end();
    }

    // 2. Auto interactive QCM generation
    if (ctx.isAutoQcmPrompt) {
      const qcm = await generateStructuredQcm(ai, {
        topic: ctx.text,
        language: detectLanguage(ctx.text) === 'ar' ? 'Arabe' : 'Français',
        files: ctx.files
      });
      const botMarkdown = formatQcmMarkdown(qcm);
      const metaFiles = [{ type: 'nova/qcm', name: qcm.title, qcm }];
      const { userMsgId, botMsgId, chatTitle } = finalizeChatMessages(
        ctx.currentChatId,
        q.u.id,
        ctx.text,
        ctx.files,
        botMarkdown,
        metaFiles
      );
      sendEvent('chunk', { delta: botMarkdown });
      sendEvent('done', {
        ok: true,
        text: botMarkdown,
        qcm,
        files: metaFiles,
        speechSummary: `QCM interactif généré : ${qcm.title}`,
        detectedLang: detectLanguage(botMarkdown),
        chatId: ctx.currentChatId,
        userMsgId,
        botMsgId,
        title: chatTitle,
        modelUsed: DEFAULT_MODEL,
        durationMs: Date.now() - startTime
      });
      return r.end();
    }

    // 3. Streaming text + grounding
    const primaryModel = ctx.powerMode === 'fast' ? 'gemini-3.1-flash-lite' : ctx.requestedModel;
    const candidateModels = [...new Set([primaryModel, DEFAULT_MODEL, 'gemini-3.1-flash-lite'])];

    let outputText = '';
    let effectiveModel = candidateModels[0];
    let webSources = [];
    let lastError = null;

    for (const modelCandidate of candidateModels) {
      try {
        const config = buildGeminiConfig(modelCandidate, NOVA_SYSTEM_PROMPT, {
          powerMode: ctx.powerMode,
          useSearch: ctx.needsSearch,
          urlsInPrompt: ctx.urlsInPrompt
        });

        const stream = await ai.models.generateContentStream({
          model: modelCandidate,
          contents: ctx.contents,
          config
        });

        let lastChunk = null;
        for await (const chunk of stream) {
          lastChunk = chunk;
          const delta = chunk.text || '';
          if (delta) {
            outputText += delta;
            sendEvent('chunk', { delta });
          }
          const chunkSources = extractGroundingSources(chunk);
          if (chunkSources.length) webSources = chunkSources;
        }
        if (!webSources.length && lastChunk) {
          webSources = extractGroundingSources(lastChunk);
        }
        if (outputText.trim()) {
          effectiveModel = modelCandidate;
          break;
        }
      } catch (err) {
        console.warn(`Stream model ${modelCandidate} failed:`, err.message);
        lastError = err;
        if (outputText.trim()) break; // Partial output already sent
      }
    }

    if (!outputText.trim()) {
      sendEvent('error', { error: formatGeminiError(lastError || new Error('Réponse vide du modèle IA.')) });
      return r.end();
    }

    const extraFiles = [];
    if (webSources.length || ctx.nearbyPlaces.length || ctx.isPdfRequest) {
      extraFiles.push({
        type: 'nova/meta',
        sources: webSources,
        places: ctx.nearbyPlaces,
        isPdfReady: ctx.isPdfRequest
      });
    }

    const { userMsgId, botMsgId, chatTitle } = finalizeChatMessages(
      ctx.currentChatId,
      q.u.id,
      ctx.text,
      ctx.files,
      outputText,
      extraFiles
    );

    sendEvent('done', {
      ok: true,
      text: outputText,
      speechSummary: buildSpeechSummary(outputText),
      detectedLang: detectLanguage(outputText),
      nearbyPlaces: ctx.nearbyPlaces,
      webSources,
      isPdfReady: ctx.isPdfRequest,
      files: extraFiles,
      chatId: ctx.currentChatId,
      userMsgId,
      botMsgId,
      title: chatTitle,
      modelUsed: effectiveModel,
      durationMs: Date.now() - startTime
    });
    return r.end();
  } catch (e) {
    console.error('Stream error:', e);
    sendEvent('error', { error: formatGeminiError(e) });
    return r.end();
  }
});

// Endpoint classique (non-streaming)
app.post('/api/chat', auth, limit(60, 6e4), async (q, r) => {
  const startTime = Date.now();
  try {
    const ai = getAiClient();
    if (!ai) {
      return r.status(500).json({ error: 'Configuration serveur : variable GEMINI_API_KEY manquante.' });
    }

    const ctx = await prepareChatContext(q);
    if (!ctx.text && !ctx.files.length) {
      return r.status(400).json({ error: 'Message ou fichier requis.' });
    }

    if (ctx.isImagePrompt) {
      const imagePrompt = extractImagePrompt(ctx.text);
      const gen = await generateHighQualityImage(imagePrompt, '1:1', ctx.files);
      const imageUrl = gen.imageUrl;
      const safeAlt = sanitizeImageAlt(imagePrompt);
      const botMsgText = `Voici votre illustration générée par NOVA :\n\n**« ${safeAlt} »**\n\n![${safeAlt}](${imageUrl})`;
      const extraFiles = [{ type: 'nova/image', url: imageUrl, name: safeAlt, isSvg: imageUrl.startsWith('data:image/svg+xml') }];
      const { userMsgId, botMsgId, chatTitle } = finalizeChatMessages(
        ctx.currentChatId,
        q.u.id,
        ctx.text,
        ctx.files,
        botMsgText,
        extraFiles
      );
      return r.json({
        ok: true,
        text: botMsgText,
        imageUrl,
        files: extraFiles,
        speechSummary: `Illustration générée pour ${safeAlt.slice(0, 60)}`,
        detectedLang: detectLanguage(ctx.text),
        chatId: ctx.currentChatId,
        userMsgId,
        botMsgId,
        title: chatTitle,
        modelUsed: gen.modelUsed,
        durationMs: Date.now() - startTime
      });
    }

    if (ctx.isAutoQcmPrompt) {
      const qcm = await generateStructuredQcm(ai, {
        topic: ctx.text,
        language: detectLanguage(ctx.text) === 'ar' ? 'Arabe' : 'Français',
        files: ctx.files
      });
      const botMarkdown = formatQcmMarkdown(qcm);
      const metaFiles = [{ type: 'nova/qcm', name: qcm.title, qcm }];
      const { userMsgId, botMsgId, chatTitle } = finalizeChatMessages(
        ctx.currentChatId,
        q.u.id,
        ctx.text,
        ctx.files,
        botMarkdown,
        metaFiles
      );
      return r.json({
        ok: true,
        text: botMarkdown,
        qcm,
        files: metaFiles,
        speechSummary: `QCM interactif généré : ${qcm.title}`,
        detectedLang: detectLanguage(botMarkdown),
        chatId: ctx.currentChatId,
        userMsgId,
        botMsgId,
        title: chatTitle,
        modelUsed: DEFAULT_MODEL,
        durationMs: Date.now() - startTime
      });
    }

    const primaryModel = ctx.powerMode === 'fast' ? 'gemini-3.1-flash-lite' : ctx.requestedModel;
    const candidateModels = [...new Set([primaryModel, DEFAULT_MODEL, 'gemini-3.1-flash-lite'])];

    let outputText = null;
    let webSources = [];
    let effectiveModel = candidateModels[0];
    let lastError = null;

    for (const modelCandidate of candidateModels) {
      try {
        const config = buildGeminiConfig(modelCandidate, NOVA_SYSTEM_PROMPT, {
          powerMode: ctx.powerMode,
          useSearch: ctx.needsSearch,
          urlsInPrompt: ctx.urlsInPrompt
        });
        const response = await generateWithRetry(ai, {
          model: modelCandidate,
          contents: ctx.contents,
          config
        });
        if (response.text) {
          outputText = response.text;
          webSources = extractGroundingSources(response);
          effectiveModel = modelCandidate;
          break;
        }
      } catch (err) {
        console.warn(`Model ${modelCandidate} failed:`, err.message);
        lastError = err;
      }
    }

    if (!outputText) {
      return r.status(502).json({ error: formatGeminiError(lastError || new Error('Réponse vide du modèle IA.')) });
    }

    const extraFiles = [];
    if (webSources.length || ctx.nearbyPlaces.length || ctx.isPdfRequest) {
      extraFiles.push({
        type: 'nova/meta',
        sources: webSources,
        places: ctx.nearbyPlaces,
        isPdfReady: ctx.isPdfRequest
      });
    }

    const { userMsgId, botMsgId, chatTitle } = finalizeChatMessages(
      ctx.currentChatId,
      q.u.id,
      ctx.text,
      ctx.files,
      outputText,
      extraFiles
    );

    return r.json({
      ok: true,
      text: outputText,
      speechSummary: buildSpeechSummary(outputText),
      detectedLang: detectLanguage(outputText),
      nearbyPlaces: ctx.nearbyPlaces,
      webSources,
      isPdfReady: ctx.isPdfRequest,
      files: extraFiles,
      chatId: ctx.currentChatId,
      userMsgId,
      botMsgId,
      title: chatTitle,
      modelUsed: effectiveModel,
      durationMs: Date.now() - startTime
    });
  } catch (e) {
    console.error('Server chat error:', e);
    return r.status(500).json({ error: formatGeminiError(e) });
  }
});

const PORT = parseInt(E.PORT || '3000', 10);
app.listen(PORT, '0.0.0.0', () =>
  console.log('NOVA Assistant IA (Développé par Med Rayen Bouazizi, CEO of MK) en écoute sur http://0.0.0.0:' + PORT)
);
