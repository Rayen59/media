const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),
cookie=require('cookie-parser'),nodemailer=require('nodemailer'),crypto=require('crypto'),path=require('path');
const E=process.env,SECRET=E.JWT_SECRET||'dev-secret-change-me',KEY=crypto.createHash('sha256').update(SECRET).digest();
const db=new Database(process.env.DB_PATH||'mediassist.db');db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL COLLATE NOCASE,pass TEXT NOT NULL,verified INTEGER DEFAULT 0,apikey TEXT,profile TEXT DEFAULT '{}',created INTEGER);
CREATE TABLE IF NOT EXISTS codes(email TEXT PRIMARY KEY COLLATE NOCASE,code TEXT,exp INTEGER,tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY,uid INTEGER NOT NULL,role TEXT,text TEXT,lang TEXT,ts INTEGER);
CREATE INDEX IF NOT EXISTS i_m ON msgs(uid,id);`);
const mail=E.SMTP_HOST?nodemailer.createTransport({host:E.SMTP_HOST,port:+E.SMTP_PORT||465,secure:(+E.SMTP_PORT||465)==465,auth:{user:E.SMTP_USER,pass:E.SMTP_PASS}}):null;
const enc=t=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',KEY,iv),b=Buffer.concat([c.update(t,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),b]).toString('base64')};
const dec=s=>{const b=Buffer.from(s,'base64'),d=crypto.createDecipheriv('aes-256-gcm',KEY,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8')};
const hits=new Map();const limit=(n,ms)=>(q,r,x)=>{const k=q.ip+q.path,t=Date.now(),a=(hits.get(k)||[]).filter(v=>t-v<ms);if(a.length>=n)return r.status(429).json({error:'Trop de requêtes, patientez.'});a.push(t);hits.set(k,a);x()};
async function sendCode(email){
  const code=String(crypto.randomInt(100000,1000000));
  db.prepare('REPLACE INTO codes(email,code,exp,tries) VALUES(?,?,?,0)').run(email,code,Date.now()+10*60e3);
  if(E.BREVO_KEY){const r=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':E.BREVO_KEY,'content-type':'application/json'},body:JSON.stringify({sender:{email:E.MAIL_FROM},to:[{email}],subject:'Votre code MediAssist',textContent:`Votre code de vérification : ${code}\nValable 10 minutes.`})});if(!r.ok)throw new Error('mail '+r.status)}
  else if(mail)await mail.sendMail({from:E.MAIL_FROM||E.SMTP_USER,to:email,subject:'Votre code MediAssist',text:`Votre code de vérification : ${code}\nValable 10 minutes.`});
  else console.log(`[DEV] Code pour ${email} : ${code}`);
}
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'30mb'}),cookie(),express.static(path.join(__dirname,'public')));
const auth=(q,r,x)=>{try{const p=jwt.verify(q.cookies.t,SECRET);q.u=db.prepare('SELECT * FROM users WHERE id=?').get(p.id);if(!q.u)throw 0;x()}catch{r.status(401).json({error:'Non connecté'})}};
const setTok=(r,id)=>r.cookie('t',jwt.sign({id},SECRET,{expiresIn:'30d'}),{httpOnly:true,sameSite:'lax',secure:!!E.COOKIE_SECURE,maxAge:30*864e5});
const okEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)&&e.length<255;

app.post('/api/register',limit(8,36e5),async(q,r)=>{
  const email=String(q.body.email||'').trim().toLowerCase(),pw=String(q.body.password||'');
  if(!okEmail(email))return r.status(400).json({error:'Email invalide'});
  if(pw.length<8)return r.status(400).json({error:'Mot de passe : 8 caractères minimum'});
  const ex=db.prepare('SELECT verified FROM users WHERE email=?').get(email);
  if(ex&&ex.verified)return r.status(409).json({error:'Cet email est déjà utilisé'});
  const h=bcrypt.hashSync(pw,11);
  if(ex)db.prepare('UPDATE users SET pass=? WHERE email=?').run(h,email);
  else db.prepare('INSERT INTO users(email,pass,created) VALUES(?,?,?)').run(email,h,Date.now());
  try{await sendCode(email)}catch(e){console.error(e);return r.status(500).json({error:'Envoi email impossible'})}
  r.json({ok:true,needVerify:true});
});
app.post('/api/resend',limit(5,36e5),async(q,r)=>{const email=String(q.body.email||'').toLowerCase();
  if(db.prepare('SELECT 1 FROM users WHERE email=? AND verified=0').get(email))try{await sendCode(email)}catch{}r.json({ok:true})});
app.post('/api/verify',limit(20,36e5),(q,r)=>{
  const email=String(q.body.email||'').toLowerCase(),c=db.prepare('SELECT * FROM codes WHERE email=?').get(email);
  if(!c||c.exp<Date.now()||c.tries>=5)return r.status(400).json({error:'Code expiré, demandez-en un nouveau'});
  if(c.code!==String(q.body.code||'').trim()){db.prepare('UPDATE codes SET tries=tries+1 WHERE email=?').run(email);return r.status(400).json({error:'Code incorrect'})}
  db.prepare('UPDATE users SET verified=1 WHERE email=?').run(email);db.prepare('DELETE FROM codes WHERE email=?').run(email);
  setTok(r,db.prepare('SELECT id FROM users WHERE email=?').get(email).id);r.json({ok:true});
});
app.post('/api/login',limit(15,9e5),(q,r)=>{
  const email=String(q.body.email||'').toLowerCase(),u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!u||!bcrypt.compareSync(String(q.body.password||''),u.pass))return r.status(401).json({error:'Email ou mot de passe incorrect'});
  if(!u.verified){sendCode(email).catch(()=>{});return r.status(403).json({needVerify:true,error:'Email non vérifié : un code vient d’être envoyé'})}
  setTok(r,u.id);r.json({ok:true});
});
app.post('/api/logout',(q,r)=>{r.clearCookie('t');r.json({ok:true})});
app.get('/api/me',auth,(q,r)=>r.json({email:q.u.email,hasKey:!!q.u.apikey,profile:JSON.parse(q.u.profile)}));
app.put('/api/settings',auth,(q,r)=>{
  const k=q.body.apikey;if(typeof k==='string'&&k.trim()){if(!/^sk-ant-/.test(k.trim()))return r.status(400).json({error:'Clé invalide (sk-ant-…)'});db.prepare('UPDATE users SET apikey=? WHERE id=?').run(enc(k.trim()),q.u.id)}
  if(q.body.profile)db.prepare('UPDATE users SET profile=? WHERE id=?').run(JSON.stringify(q.body.profile).slice(0,4000),q.u.id);r.json({ok:true})});
app.get('/api/history',auth,(q,r)=>r.json(db.prepare('SELECT id,role,text,lang,ts FROM msgs WHERE uid=? ORDER BY id DESC LIMIT 200').all(q.u.id).reverse()));
app.delete('/api/history',auth,(q,r)=>{db.prepare('DELETE FROM msgs WHERE uid=?').run(q.u.id);r.json({ok:true})});
app.delete('/api/history/:id',auth,(q,r)=>{db.prepare('DELETE FROM msgs WHERE uid=? AND id=?').run(q.u.id,+q.params.id);r.json({ok:true})});

async function nearby(lat,lng,type){
  const f=type==='pharmacy'?'["amenity"="pharmacy"]':'["amenity"~"hospital|clinic"]';
  const ql=`[out:json][timeout:12];nwr${f}(around:5000,${lat},${lng});out center 12;`;
  const j=await(await fetch('https://overpass-api.de/api/interpreter',{method:'POST',body:'data='+encodeURIComponent(ql),headers:{'Content-Type':'application/x-www-form-urlencoded'}})).json();
  const R=6371e3,rad=x=>x*Math.PI/180;
  return j.elements.map(e=>{const a=e.lat??e.center?.lat,b=e.lon??e.center?.lon,dl=rad(a-lat),dn=rad(b-lng);
    const d=2*R*Math.asin(Math.sqrt(Math.sin(dl/2)**2+Math.cos(rad(lat))*Math.cos(rad(a))*Math.sin(dn/2)**2));
    return{name:e.tags.name||(type==='pharmacy'?'Pharmacie':'Établissement de santé'),dist:Math.round(d),lat:a,lng:b,phone:e.tags.phone||e.tags['contact:phone']||'',hours:e.tags.opening_hours||''}}).sort((x,y)=>x.dist-y.dist).slice(0,8);
}
app.get('/api/nearby',auth,limit(30,6e4),async(q,r)=>{try{r.json(await nearby(+q.query.lat,+q.query.lng,q.query.type==='pharmacy'?'pharmacy':'hospital'))}catch{r.status(502).json({error:'Recherche indisponible'})}});

const SYS=(p,pl)=>`Tu es MediAssist, assistant médical IA expert, clair et bienveillant.
RÈGLE 1 : la TOUTE PREMIÈRE ligne de ta réponse est exactement [[lang:XX-YY]] (code BCP-47 de la langue utilisée par l'utilisateur, ex. fr-FR, en-US, ar-SA, es-ES, zh-CN). Réponds ensuite dans cette langue. Réponse courte et parlable (pas de tableaux ni de symboles inutiles), listes courtes si besoin.
Dossier patient : ${JSON.stringify(p)}.
Méthode : questions ciblées si flou (durée, intensité, signes associés) ; causes probables ; conseils pratiques ; médicaments usuels en vente libre avec posologie adulte standard, contre-indications, interactions avec ses traitements/allergies, et rappel de suivre la notice ou de demander au pharmacien ; signaux d'alarme => urgences immédiates (15/112/911). Photos/PDF : décris et lis précisément (valeurs, unités, normes, anomalies), explique simplement, signale l'incertitude. Pas de diagnostic définitif.${pl?`\nÉtablissements proches de l'utilisateur (données réelles, cite-les) : ${JSON.stringify(pl)}`:''}`;

app.post('/api/chat',auth,limit(40,6e4),async(q,r)=>{
  try{
    if(!q.u.apikey)return r.status(400).json({error:'Ajoutez votre clé API Claude dans ⚙ Réglages'});
    const text=String(q.body.text||'').slice(0,8000),files=(q.body.files||[]).slice(0,6);
    let pl=null;const L=q.body.loc;
    if(L&&/pharma|médicament|medicament|medicine|drug|صيدلية|دواء|farmacia|hôpital|hopital|hospital|urgence|emergency|clinic|مستشفى|طوارئ/i.test(text)){
      try{pl=await nearby(+L.lat,+L.lng,/pharma|médic|medic|drug|صيدلية|دواء|farmacia/i.test(text)?'pharmacy':'hospital')}catch{}}
    const hist=db.prepare('SELECT role,text FROM msgs WHERE uid=? ORDER BY id DESC LIMIT 16').all(q.u.id).reverse().map(m=>({role:m.role,content:m.text}));
    const content=[...files.map(f=>f.type==='application/pdf'?{type:'document',source:{type:'base64',media_type:'application/pdf',data:f.data}}:{type:'image',source:{type:'base64',media_type:/^image\/(png|gif|webp)$/.test(f.type)?f.type:'image/jpeg',data:f.data}}),{type:'text',text:text||'Analyse ces documents.'}];
    const a=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'x-api-key':dec(q.u.apikey),'anthropic-version':'2023-06-01','content-type':'application/json'},
      body:JSON.stringify({model:E.CLAUDE_MODEL||'claude-sonnet-5-5',max_tokens:1500,system:SYS(JSON.parse(q.u.profile),pl),messages:[...hist,{role:'user',content}]})});
    const j=await a.json();if(!a.ok)return r.status(502).json({error:j.error?.message||'Erreur API Claude'});
    let out=j.content.filter(b=>b.type==='text').map(b=>b.text).join('\n'),lang='fr-FR';
    const m=out.match(/^\s*\[\[lang:([\w-]+)\]\]\s*/);if(m){lang=m[1];out=out.slice(m[0].length)}
    const ins=db.prepare('INSERT INTO msgs(uid,role,text,lang,ts) VALUES(?,?,?,?,?)');
    const i1=ins.run(q.u.id,'user',text+(files.length?` [📎 ${files.length}]`:''),null,Date.now()).lastInsertRowid;
    const i2=ins.run(q.u.id,'assistant',out,lang,Date.now()).lastInsertRowid;
    r.json({text:out,lang,places:pl,ids:[i1,i2]});
  }catch(e){console.error(e);r.status(500).json({error:'Erreur serveur'})}
});
app.listen(E.PORT||3000,()=>console.log('MediAssist sur http://localhost:'+(E.PORT||3000)));
