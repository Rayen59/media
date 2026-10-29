const fs = require('fs');
const path = require('path');

class SimpleDB {
  constructor(filePath) {
    let resolved = filePath || process.env.DB_PATH || 'mediassist_data.json';
    if (resolved.endsWith('.db')) {
      resolved = resolved.replace(/\.db$/, '.json');
    }
    this.filePath = resolved;
    this.data = {
      users: [],
      chats: [],
      chat_msgs: [],
      _lastUserId: 0
    };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          this.data = {
            users: Array.isArray(parsed.users) ? parsed.users : [],
            chats: Array.isArray(parsed.chats) ? parsed.chats : [],
            chat_msgs: Array.isArray(parsed.chat_msgs) ? parsed.chat_msgs : [],
            _lastUserId: parsed._lastUserId || (parsed.users?.length ? Math.max(...parsed.users.map(u => u.id || 0)) : 0)
          };
        }
      }
    } catch (e) {
      console.warn('Could not load database file, starting fresh:', e.message);
    }
  }

  save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (e) {
      console.error('Error saving database file:', e.message);
    }
  }

  pragma() {}
  exec() {}

  prepare(sql) {
    const s = sql.trim().replace(/\s+/g, ' ');
    const db = this;

    return {
      get(...params) {
        // Users
        if (s.includes('FROM users WHERE id=?')) {
          const id = Number(params[0]);
          return db.data.users.find(u => u.id === id) || null;
        }
        if (s.includes('FROM users WHERE email=?')) {
          const email = String(params[0] || '').toLowerCase().trim();
          return db.data.users.find(u => u.email.toLowerCase() === email) || null;
        }
        // Chats
        if (s.includes('FROM chats WHERE id=? AND uid=?')) {
          const [id, uid] = params;
          return db.data.chats.find(c => c.id === String(id) && c.uid === Number(uid)) || null;
        }
        // Count msgs
        if (s.includes('COUNT(*) as c FROM chat_msgs WHERE chat_id=?')) {
          const chatId = String(params[0]);
          const count = db.data.chat_msgs.filter(m => m.chat_id === chatId).length;
          return { c: count };
        }
        return null;
      },

      all(...params) {
        // Chats list for user
        if (s.includes('FROM chats WHERE uid=? ORDER BY updated DESC')) {
          const uid = Number(params[0]);
          const list = db.data.chats
            .filter(c => c.uid === uid)
            .sort((a, b) => (b.updated || 0) - (a.updated || 0));
          return list.map(c => ({ id: c.id, title: c.title, created: c.created, updated: c.updated }));
        }
        // All chat messages
        if (s.includes('FROM chat_msgs WHERE chat_id=? AND uid=? ORDER BY ts ASC LIMIT 20')) {
          const [chatId, uid] = params;
          const list = db.data.chat_msgs
            .filter(m => m.chat_id === String(chatId) && m.uid === Number(uid))
            .sort((a, b) => (a.ts || 0) - (b.ts || 0))
            .slice(-20);
          return list.map(m => ({ id: m.id, role: m.role, text: m.text, files: m.files, ts: m.ts }));
        }
        if (s.includes('FROM chat_msgs WHERE chat_id=? AND uid=? ORDER BY ts ASC')) {
          const [chatId, uid] = params;
          const list = db.data.chat_msgs
            .filter(m => m.chat_id === String(chatId) && m.uid === Number(uid))
            .sort((a, b) => (a.ts || 0) - (b.ts || 0));
          return list.map(m => ({ id: m.id, role: m.role, text: m.text, files: m.files, ts: m.ts }));
        }
        return [];
      },

      run(...params) {
        let changes = 0;
        let lastInsertRowid = 0;

        // INSERT INTO users
        if (s.includes('INSERT INTO users')) {
          const [email, name, pass, model, settings, created] = params;
          const cleanEmail = String(email || '').toLowerCase().trim();
          if (db.data.users.some(u => u.email.toLowerCase() === cleanEmail)) {
            throw new Error('UNIQUE constraint failed: users.email');
          }
          db.data._lastUserId = (db.data._lastUserId || 0) + 1;
          const id = db.data._lastUserId;
          db.data.users.push({
            id,
            email: cleanEmail,
            name: String(name || cleanEmail.split('@')[0]),
            pass: String(pass),
            verified: 1,
            model: String(model || 'gemini-3-flash-preview'),
            settings: String(settings || '{}'),
            created: Number(created || Date.now())
          });
          lastInsertRowid = id;
          changes = 1;
          db.save();
          return { changes, lastInsertRowid };
        }

        // INSERT INTO chats or INSERT OR REPLACE INTO chats
        if (s.includes('INTO chats')) {
          const [id, uid, title, created, updated] = params;
          const existingIdx = db.data.chats.findIndex(c => c.id === String(id));
          const chatObj = {
            id: String(id),
            uid: Number(uid),
            title: String(title),
            created: Number(created || Date.now()),
            updated: Number(updated || Date.now())
          };
          if (existingIdx >= 0) {
            db.data.chats[existingIdx] = chatObj;
          } else {
            db.data.chats.push(chatObj);
          }
          changes = 1;
          db.save();
          return { changes, lastInsertRowid: 0 };
        }

        // INSERT INTO chat_msgs
        if (s.includes('INSERT INTO chat_msgs')) {
          const [id, chatId, uid, role, text, files, ts] = params;
          db.data.chat_msgs.push({
            id: String(id),
            chat_id: String(chatId),
            uid: Number(uid),
            role: String(role),
            text: String(text || ''),
            files: typeof files === 'string' ? files : JSON.stringify(files || []),
            ts: Number(ts || Date.now())
          });
          changes = 1;
          db.save();
          return { changes, lastInsertRowid: 0 };
        }

        // UPDATE users pass
        if (s.includes('UPDATE users SET pass=? WHERE id=?')) {
          const [pass, id] = params;
          const u = db.data.users.find(user => user.id === Number(id));
          if (u) {
            u.pass = String(pass);
            changes = 1;
            db.save();
          }
          return { changes, lastInsertRowid: 0 };
        }

        // UPDATE users name
        if (s.includes('UPDATE users SET name=? WHERE id=?')) {
          const [name, id] = params;
          const u = db.data.users.find(user => user.id === Number(id));
          if (u) {
            u.name = String(name);
            changes = 1;
            db.save();
          }
          return { changes, lastInsertRowid: 0 };
        }

        // UPDATE users model
        if (s.includes('UPDATE users SET model=? WHERE id=?')) {
          const [model, id] = params;
          const u = db.data.users.find(user => user.id === Number(id));
          if (u) {
            u.model = String(model);
            changes = 1;
            db.save();
          }
          return { changes, lastInsertRowid: 0 };
        }

        // UPDATE users settings
        if (s.includes('UPDATE users SET settings=? WHERE id=?')) {
          const [settings, id] = params;
          const u = db.data.users.find(user => user.id === Number(id));
          if (u) {
            u.settings = String(settings);
            changes = 1;
            db.save();
          }
          return { changes, lastInsertRowid: 0 };
        }

        // UPDATE chats updated
        if (s.includes('UPDATE chats SET updated=? WHERE id=?')) {
          const [updated, id] = params;
          const c = db.data.chats.find(chat => chat.id === String(id));
          if (c) {
            c.updated = Number(updated);
            changes = 1;
            db.save();
          }
          return { changes, lastInsertRowid: 0 };
        }

        // UPDATE chats title
        if (s.includes('UPDATE chats SET title=? WHERE id=?')) {
          const [title, id] = params;
          const c = db.data.chats.find(chat => chat.id === String(id));
          if (c) {
            c.title = String(title);
            changes = 1;
            db.save();
          }
          return { changes, lastInsertRowid: 0 };
        }

        // DELETE chat msgs single chat
        if (s.includes('DELETE FROM chat_msgs WHERE chat_id=? AND uid=?')) {
          const [chatId, uid] = params;
          const initialLen = db.data.chat_msgs.length;
          db.data.chat_msgs = db.data.chat_msgs.filter(m => !(m.chat_id === String(chatId) && m.uid === Number(uid)));
          changes = initialLen - db.data.chat_msgs.length;
          db.save();
          return { changes, lastInsertRowid: 0 };
        }

        // DELETE single chat
        if (s.includes('DELETE FROM chats WHERE id=? AND uid=?')) {
          const [chatId, uid] = params;
          const initialLen = db.data.chats.length;
          db.data.chats = db.data.chats.filter(c => !(c.id === String(chatId) && c.uid === Number(uid)));
          changes = initialLen - db.data.chats.length;
          db.save();
          return { changes, lastInsertRowid: 0 };
        }

        // DELETE all chat msgs for user
        if (s.includes('DELETE FROM chat_msgs WHERE uid=?')) {
          const uid = Number(params[0]);
          const initialLen = db.data.chat_msgs.length;
          db.data.chat_msgs = db.data.chat_msgs.filter(m => m.uid !== uid);
          changes = initialLen - db.data.chat_msgs.length;
          db.save();
          return { changes, lastInsertRowid: 0 };
        }

        // DELETE all chats for user
        if (s.includes('DELETE FROM chats WHERE uid=?')) {
          const uid = Number(params[0]);
          const initialLen = db.data.chats.length;
          db.data.chats = db.data.chats.filter(c => c.uid !== uid);
          changes = initialLen - db.data.chats.length;
          db.save();
          return { changes, lastInsertRowid: 0 };
        }

        return { changes: 0, lastInsertRowid: 0 };
      }
    };
  }
}

module.exports = SimpleDB;
