const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'db.json');
const load = () => fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : { users: [], docs: [], consents: [], forms: [] };
const save = (d) => fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2));

const MASTER_KEY = process.env.MASTER_KEY || crypto.randomBytes(32).toString('hex');
const encKey = crypto.createHash('sha256').update(MASTER_KEY).digest();
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function decrypt(b64) {
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.slice(0, 12), tag = buf.slice(12, 28), data = buf.slice(28);
  const d = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(data), d.final()]).toString('utf8');
}

function hashPwd(pwd, salt = crypto.randomBytes(16).toString('hex')) {
  const h = crypto.pbkdf2Sync(pwd, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${h}`;
}
function verifyPwd(pwd, stored) {
  const [salt, h] = stored.split(':');
  const check = crypto.pbkdf2Sync(pwd, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(check));
}

const sessions = {};
function auth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
  req.userId = sessions[token];
  next();
}

app.post('/api/register', (req, res) => {
  const { email, password } = req.body;
  const db = load();
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Already exists' });
  const user = { id: crypto.randomUUID(), email, password: hashPwd(password), createdAt: Date.now() };
  db.users.push(user);
  save(db);
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = user.id;
  res.json({ token, userId: user.id });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const db = load();
  const user = db.users.find(u => u.email === email);
  if (!user || !verifyPwd(password, user.password)) return res.status(401).json({ error: 'Invalid' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = user.id;
  res.json({ token, userId: user.id });
});

app.get('/api/docs', auth, (req, res) => {
  const db = load();
  const docs = db.docs.filter(d => d.userId === req.userId)
    .map(({ id, type, label, createdAt, updatedAt }) => ({ id, type, label, createdAt, updatedAt }));
  res.json(docs);
});

app.post('/api/docs', auth, (req, res) => {
  const { type, label, data } = req.body;
  const db = load();
  const doc = {
    id: crypto.randomUUID(), userId: req.userId, type, label,
    data: encrypt(JSON.stringify(data || {})),
    createdAt: Date.now(), updatedAt: Date.now()
  };
  db.docs.push(doc);
  save(db);
  res.json({ id: doc.id });
});

app.put('/api/docs/:id', auth, (req, res) => {
  const db = load();
  const doc = db.docs.find(d => d.id === req.params.id && d.userId === req.userId);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  if (req.body.data) doc.data = encrypt(JSON.stringify(req.body.data));
  if (req.body.label) doc.label = req.body.label;
  doc.updatedAt = Date.now();
  save(db);
  res.json({ ok: true });
});

app.get('/api/docs/:id', auth, (req, res) => {
  const db = load();
  const doc = db.docs.find(d => d.id === req.params.id && d.userId === req.userId);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json({ ...doc, data: JSON.parse(decrypt(doc.data)) });
});

app.delete('/api/docs/:id', auth, (req, res) => {
  const db = load();
  db.docs = db.docs.filter(d => !(d.id === req.params.id && d.userId === req.userId));
  save(db);
  res.json({ ok: true });
});

app.post('/api/ai/fill', auth, (req, res) => {
  const { formType } = req.body;
  const db = load();
  const docs = db.docs.filter(d => d.userId === req.userId).map(d => ({
    type: d.type, data: JSON.parse(decrypt(d.data))
  }));
  const flat = {};
  docs.forEach(d => Object.assign(flat, d.data));
  const templates = {
    'pm-kisan': {
      title: 'PM-KISAN Application',
      fields: {
        name: flat.name || '', aadhaar: flat.aadhaar || '',
        mobile: flat.mobile || '', bank_account: flat.bank_account || '',
        land_area: flat.land_area || '', address: flat.address || ''
      }
    },
    'scholarship': {
      title: 'National Scholarship',
      fields: {
        name: flat.name || '', aadhaar: flat.aadhaar || '',
        income: flat.income || '', category: flat.category || '',
        institution: flat.institution || '', marks: flat.marks || ''
      }
    }
  };
  const template = templates[formType];
  if (!template) return res.status(400).json({ error: 'Unknown form' });
  db.consents.push({
    id: crypto.randomUUID(), userId: req.userId,
    purpose: `AI auto-fill for ${template.title}`,
    dataUsed: docs.map(d => d.type),
    at: Date.now(), status: 'pending-user-approval'
  });
  save(db);
  res.json({ formType, ...template, missingDocs: [] });
});

app.post('/api/forms/submit', auth, (req, res) => {
  const { formType, fields, signature, consentId } = req.body;
  if (!signature) return res.status(400).json({ error: 'e-Sign required' });
  const db = load();
  const consent = db.consents.find(c => c.id === consentId && c.userId === req.userId);
  if (consent) { consent.status = 'approved'; consent.approvedAt = Date.now(); }
  const record = {
    id: crypto.randomUUID(), userId: req.userId, formType, fields,
    signatureHash: crypto.createHash('sha256').update(signature + Date.now()).digest('hex'),
    submittedAt: Date.now()
  };
  db.forms.push(record);
  save(db);
  res.json({ ok: true, referenceId: record.id });
});

app.get('/api/consents', auth, (req, res) => {
  const db = load();
  res.json(db.consents.filter(c => c.userId === req.userId));
});

app.get('/api/forms', auth, (req, res) => {
  const db = load();
  res.json(db.forms.filter(f => f.userId === req.userId));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running: http://localhost:${PORT}`));
