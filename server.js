const express = require('express');
const Database = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const dns = require('dns');
const { GoogleGenAI } = require('@google/genai');

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
const getAiClient = () => {
  const apiKey = getGeminiApiKey();
  if (!apiKey) return null;
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

RÈGLES STRICTES DE LANGUE ET D'ÉCRITURE :
1. LANGUE FRANÇAISE :
   - Rédige dans un français impeccable, élégant, riche et sans aucune faute de grammaire, d'accord ou d'orthographe.
   - Respecte la typographie française (ponctuation soignée, pas d'anglicismes maladroits).
   - Organise tes réponses de façon limpide : titres clairs (###), listes à puces soignées, paragraphes aérés, mise en valeur des termes clés en gras.

2. LANGUE ARABE (اللغة العربية الفصحى) :
   - Lorsque l'utilisateur s'adresse à toi en arabe ou demande une réponse en arabe, utilise une langue arabe littéraire moderne (الفصحى المعاصرة) d'un niveau d'excellence linguistique irréprochable.
   - Évite formellement toute faute de grammaire (نحو), de conjugaison (صرف) ou d'orthographe (إملاء، همزات، تاء مربوطة ومفتوحة).
   - Structure le texte de droite à gauche avec cohérence, en évitant les mélanges désordonnés de signes de ponctuation ou de parenthèses.

3. LECTURE & ANALYSE DE PHOTOS ET DOCUMENTS :
   - Lorsqu'une photo, image ou document PDF est soumis, analyse-le avec une acuité visuelle maximale.
   - S'il y a du texte dans l'image (manuscrit, imprimé, panneaux, étiquettes, reçus, documents, captures), lis-le attentivement, retranscris-le fidèlement et interprète son contenu.
   - Décris précisément ce que contient l'image (contexte, personnes, objets, couleurs, graphiques, données chiffrées).
   - Réponds de manière complète et personnalisée à la requête de l'utilisateur sur cette photo.

4. STRUCTURE & PRÉSENTATION :
   - Évite les pavés de texte monolithiques. Aère systématiquement avec des sous-titres, des listes et des tableaux comparatifs Markdown si utile.
   - Fournis toujours des explications claires, méthodiques et directement exploitables.`;

// ===== SERVICES WEB SEARCH & LIEUX MÉDICAUX (POUR SMART WATCH & TÉLÉPHONE) =====

async function searchLiveWeb(query) {
  try {
    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    const res = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'fr-FR,fr;q=0.9,ar;q=0.8,en;q=0.7'
      }
    });
    if (!res.ok) return [];
    const html = await res.text();
    const snippets = (html.match(/<a class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g) || [])
      .map(x => x.replace(/<[^>]+>/g, '').trim())
      .filter(Boolean);
    return snippets.slice(0, 4);
  } catch (e) {
    return [];
  }
}

async function findNearbyPlaces(lat, lon, query = 'hospital') {
  try {
    let url;
    if (lat && lon) {
      url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(query)}&format=json&lat=${lat}&lon=${lon}&limit=5`;
    } else {
      url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(query)}&format=json&limit=5`;
    }
    const res = await fetch(url, { headers: { 'User-Agent': 'NOVA-MK-Assistant/2.0' } });
    if (!res.ok) return [];
    const data = await res.json();
    return (Array.isArray(data) ? data : []).slice(0, 5).map(item => ({
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

async function callGeminiGenerate(modelName, systemPrompt, contents, temp, maxTokens) {
  const ai = getAiClient();
  if (!ai) throw new Error('GEMINI_API_KEY manquant sur le serveur.');

  const config = {
    systemInstruction: systemPrompt
  };
  if (temp !== undefined && !modelName.startsWith('gemini-3.8') && !modelName.startsWith('gemini-4')) {
    config.temperature = temp;
  }
  if (maxTokens) {
    config.maxOutputTokens = maxTokens;
  }

  const response = await ai.models.generateContent({
    model: modelName,
    contents,
    config
  });

  const text = response.text;
  if (!text) {
    throw new Error('Réponse vide du modèle IA.');
  }
  return text;
}

// Endpoint de transcription audio (Web Speech fallback pour Smart Watch et Mobile)
app.post('/api/transcribe', auth, limit(60, 6e4), async (q, r) => {
  try {
    const audioData = q.body.audio;
    const mimeType = q.body.mimeType || 'audio/webm';
    if (!audioData) return r.status(400).json({ error: 'Fichier audio manquant.' });

    let rawData = String(audioData);
    if (rawData.includes(';base64,')) {
      rawData = rawData.split(';base64,')[1];
    }
    rawData = rawData.trim();

    const ai = getAiClient();
    if (!ai) return r.status(500).json({ error: 'GEMINI_API_KEY manquant sur le serveur.' });

    let transcript = '';
    const transcribeModels = ['gemini-3.5-transcribe', 'gemini-flash-latest'];
    for (const m of transcribeModels) {
      try {
        const resp = await ai.models.generateContent({
          model: m,
          contents: [{
            parts: [
              { inlineData: { mimeType, data: rawData } },
              { text: "Tu es un transcripteur vocal expert multilingue (français, arabe, anglais). Retranscris avec une précision irréprochable les propos enregistrés. Ne retourne strictement QUE le texte exact prononcé, sans aucune ponctuation inutile, sans guillemets et sans commentaire." }
            ]
          }]
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

app.post('/api/chat', auth, limit(60, 6e4), async (q, r) => {
  try {
    const text = String(q.body.text || '').trim();
    const files = Array.isArray(q.body.files) ? q.body.files.slice(0, 6) : [];
    const chatId = String(q.body.chatId || '').trim();
    const requestedModel = q.body.model || q.u.model || 'gemini-3-flash-preview';
    const temp = typeof q.body.temp === 'number' ? q.body.temp : 0.7;
    const tokens = typeof q.body.tokens === 'number' ? Math.min(q.body.tokens, 8192) : 2048;
    const userLoc = q.body.location; // { lat, lng, city }

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

    // Détection de recherche internet ou de recherche de lieux médicaux (hôpitaux, urgences, cabinets)
    const lowerText = text.toLowerCase();
    const needsMedical = /hopital|hôpital|clinique|cabinet|urgence|médical|médecin|docteur|douleur|blessure|malade|santé|pharmacie|hospital|clinic|doctor|emergency|مستشفى|طبيب|عيادة|طوارئ|صيدلية|ألم|مرض|إسعاف/.test(lowerText);
    const needsSearch = /recherche|cherche|actualit|nouvelle|météo|qui est|qu'est-ce|combien|prix|dernier|aujourd'hui|c'est quoi|news|weather|search|ابحث|أخبار|ما هو|من هو|طقس|كم/.test(lowerText);

    let enrichedContext = '';
    let nearbyPlaces = [];
    let webSources = [];

    // Recherche de lieux de santé géolocalisés
    if (needsMedical) {
      const lat = userLoc?.lat;
      const lon = userLoc?.lng;
      nearbyPlaces = await findNearbyPlaces(lat, lon, 'hopital urgence clinique');
      if (nearbyPlaces.length) {
        enrichedContext += `\n\n[DONNÉES EN TEMPS RÉEL - ÉTABLISSEMENTS DE SANTÉ À PROXIMITÉ (GPS: ${lat || 'Général'}, ${lon || ''})] :\n` +
          nearbyPlaces.map((p, i) => `${i + 1}. ${p.name} - ${p.address} (Lien GPS: ${p.mapUrl})`).join('\n') +
          `\nImportant : Si l'utilisateur exprime une détresse ou cherche un secours, indique-lui immédiatement le nom et l'adresse de ces hôpitaux/cabinets les plus proches, conseille d'appeler les urgences locales (15/112 en Europe, 190 en Tunisie, 911 aux USA, etc.) et formule une consigne vocale rassurante et directe.\n`;
      }
    }

    // Recherche web en temps réel si demandé ou informatif
    if (needsSearch && !needsMedical) {
      const webSnippets = await searchLiveWeb(text);
      if (webSnippets.length) {
        webSources = webSnippets;
        enrichedContext += `\n\n[RÉSULTATS DE RECHERCHE INTERNET EN DIRECT] :\n` +
          webSnippets.map((s, idx) => `Source ${idx + 1}: ${s}`).join('\n') +
          `\nIntègre ces données vérifiées d'actualité pour apporter une réponse pointue et à jour.\n`;
      }
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
      let rawData = String(f.data);
      if (rawData.includes(';base64,')) {
        rawData = rawData.split(';base64,')[1];
      }
      rawData = rawData.trim();
      const mimeType = f.type === 'application/pdf' ? 'application/pdf' : (/^image\/(png|gif|webp|svg\+xml)$/.test(f.type) ? f.type : 'image/jpeg');
      currentParts.push({
        inlineData: {
          mimeType,
          data: rawData
        }
      });
    }
    
    let fullUserPrompt = text || 'Veuillez analyser avec précision les documents ou photos joints et me fournir une synthèse détaillée.';
    if (enrichedContext) {
      fullUserPrompt += '\n\n' + enrichedContext;
    }
    currentParts.push({ text: fullUserPrompt });
    contents.push({ role: 'user', parts: currentParts });

    // Call Gemini with intelligent fallback chain
    const normalizeModel = (m) => {
      if (!m || m.includes('1.5') || m.includes('2.0') || m.includes('2.5') || m.includes('3-flash-preview') || m.includes('3.5-flash')) {
        return 'gemini-flash-latest';
      }
      return m;
    };
    const candidateModels = [normalizeModel(requestedModel), 'gemini-flash-latest', 'gemini-3.8-flash', 'gemini-3.1-flash-lite'];
    const uniqueModels = [...new Set(candidateModels)];

    let outputText = null;
    let lastError = null;
    let effectiveModel = uniqueModels[0];

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

    // Détection de la langue principale (Arabe, Français, Anglais)
    const isAr = /[\u0600-\u06FF]/.test(outputText);
    const isEn = /\b(the|is|and|you|this|hospital|doctor|health)\b/i.test(outputText) && !/\b(le|la|les|est|vous|hôpital)\b/i.test(outputText);
    const detectedLang = isAr ? 'ar' : (isEn ? 'en' : 'fr');

    // Génération d'un résumé vocal court et percutant spécialement conçu pour l'écran et le haut-parleur de la Smart Watch
    let speechSummary = '';
    const cleanOutput = outputText.replace(/```[\s\S]*?```/g, '')
                                  .replace(/[#*`_>|]/g, '')
                                  .replace(/https?:\/\/\S+/g, '')
                                  .trim();
    const firstSentenceMatch = cleanOutput.match(/^(.*?[.!?](\s|$))/);
    speechSummary = firstSentenceMatch ? firstSentenceMatch[0].trim() : cleanOutput.slice(0, 180);
    if (speechSummary.length < 30 && cleanOutput.length > 30) {
      speechSummary = cleanOutput.slice(0, 180);
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
      speechSummary,
      detectedLang,
      nearbyPlaces,
      webSources,
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
