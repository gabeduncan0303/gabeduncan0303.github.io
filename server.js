import express from 'express';
import session from 'express-session';
import { MongoClient } from 'mongodb';
import fs from 'fs';
import path from 'path';
import busboy from 'busboy';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { fileTypeFromFile } from 'file-type';
import mime from 'mime-types';
import crypto from 'crypto';
import archiver from 'archiver';



// natural sort helpers: group by type (image < video), then numeric by name
const naturalCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

function normalizeName(item) {
  const name = (item?.originalName || item?.filename || '').toString().trim().toLowerCase();
  // If filename had a leading timestamp like "1699999999999-...", strip it for comparison only
  return name.replace(/^\d{10,}-/, '');
}

// Returns a sort key: [typeRank, num, fallbackString]
// - typeRank: 0 for image*, 1 for video*, 2 for everything else
// - num: parsed number from imageNNN / videoNNN, otherwise Infinity
function extractKey(item) {
  const core = normalizeName(item);
  const m = core.match(/^(image|video)\s*0*(\d+)/i);
  if (m) {
    const typeRank = m[1].toLowerCase() === 'image' ? 0 : 1;
    const num = parseInt(m[2], 10);
    return [typeRank, isNaN(num) ? Number.POSITIVE_INFINITY : num, core];
  }
  return [2, Number.POSITIVE_INFINITY, core];
}

function sortUploads(uploads) {
  const lastInt = (s) => {
    const m = String(s).match(/(\d+)(?!.*\d)/);
    return m ? parseInt(m[1], 10) : Number.POSITIVE_INFINITY;
  };

  return [...uploads].sort((a, b) => {
    const [tA, nA, nameA] = extractKey(a); // [typeRank, numericKey, displayName]
    const [tB, nB, nameB] = extractKey(b);

    if (tA !== tB) return tA - tB;

    const aNum = Number.isFinite(nA) ? nA : Number.isFinite(+nA) ? +nA : lastInt(nameA);
    const bNum = Number.isFinite(nB) ? nB : Number.isFinite(+nB) ? +nB : lastInt(nameB);
    if (aNum !== bNum) return aNum - bNum;

    return naturalCollator.compare(nameA, nameB); // keep as your final, stable fallback
  });
}



const normalizeForMatch = s => (s || '').toString().toLowerCase().replace(/^\d{10,}-/, '');
const matchesQuery = (item, q) => {
  const n = normalizeForMatch(q);
  if (!n) return true;
  return normalizeForMatch(item.originalName).includes(n) || normalizeForMatch(item.filename).includes(n);
};



const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 8080;
const MONGO_URL = 'mongodb://127.0.0.1:27017';
const DB_NAME = 'uploadApp';

let db;
const client = new MongoClient(MONGO_URL);
await client.connect();
db = client.db(DB_NAME);
console.log("Connected to MongoDB");

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true
}));

function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);
  const existing = await db.collection('users').findOne({ username });
  if (existing) return res.send('Username taken. <a href="/register">Try again</a>');
  await db.collection('users').insertOne({ username, passwordHash, uploads: [] });
  res.redirect('/login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.collection('users').findOne({ username });
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    req.session.user = username;
    res.redirect('/');
  } else {
    res.send('Invalid credentials. <a href="/login">Try again</a>');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});


app.post('/upload', isAuthenticated, (req, res) => {
  const bb = busboy({ headers: req.headers });
  const username = req.session.user;
  const userDir = path.join(__dirname, 'uploads', username);
  fs.mkdirSync(userDir, { recursive: true });

  const uploadedFiles = [];
  const writeJobs = [];

  bb.on('file', (fieldname, file, infoOrFilename) => {
    let originalName, headerMime;
    if (infoOrFilename && typeof infoOrFilename === 'object') {
      originalName = infoOrFilename.filename;
      headerMime = infoOrFilename.mimeType;
    } else {
      originalName = infoOrFilename;
    }
    if (!originalName) {
      file.resume();
      return;
    }

    const safeBase = path.basename(originalName);
    const ext = path.extname(safeBase).toLowerCase();
    const unique = `${Date.now()}-${crypto.randomUUID()}`;
    const finalName = `${unique}${ext || ''}`;
    const saveTo = path.join(userDir, finalName);

    const ws = fs.createWriteStream(saveTo);

    const job = new Promise((resolve, reject) => {
      ws.on('finish', async () => {
        try {
          const stats = fs.statSync(saveTo);
          // if (stats.size < 32) {
          //   return reject(new Error(`File too small (${stats.size} bytes): ${finalName}`));
          // }

          let sniff = await fileTypeFromFile(saveTo);
          const sniffMime = sniff?.mime;
          const fallbackMime = headerMime || mime.lookup(ext) || 'application/octet-stream';
          const mimeType = sniffMime || fallbackMime;

          uploadedFiles.push({
            filename: finalName,
            mimeType,
            ext: sniff?.ext ? `.${sniff.ext}` : ext || null,
            originalName: safeBase,
            size: stats.size
          });

          resolve();
        } catch (e) {
          reject(e);
        }
      });
      ws.on('error', reject);
      file.on('error', reject);
    });

    writeJobs.push(job);
    file.pipe(ws);
  });

  bb.on('finish', async () => {
    try {
      await Promise.all(writeJobs); // ensure disk writes completed

      if (uploadedFiles.length) {
        // push new items first
        await db.collection('users').updateOne(
          { username },
          { $push: { uploads: { $each: uploadedFiles } } }
        );

        // re-fetch, sort (imageN then videoN, numeric within type), and persist
        const user = await db.collection('users').findOne({ username });
        if (user?.uploads?.length) {
          const sorted = sortUploads(user.uploads);
          await db.collection('users').updateOne(
            { username },
            { $set: { uploads: sorted } }
          );
        }
      }
    } catch (err) {
      console.error('Upload error:', err);
      // optional: render an error page here
    }

    res.redirect('/gallery');
  });

  req.pipe(bb);
});





app.post('/delete', isAuthenticated, async (req, res) => {
  const username = req.session.user;
  const { filename } = req.body;
  if (!filename) return res.redirect('/gallery');
  const userDir = path.join(__dirname, 'uploads', username);
  const filePath = path.join(userDir, filename);
  try { fs.unlinkSync(filePath); } catch (e) {}
  await db.collection('users').updateOne(
    { username },
    { $pull: { uploads: { filename } } }
  );
  res.redirect('/gallery');
});

app.post('/delete-all', isAuthenticated, async (req, res) => {
  const username = req.session.user;
  const userDir = path.join(__dirname, 'uploads', username);

  try {
    // Remove all files/folders inside the user's upload dir (but keep the dir)
    if (fs.existsSync(userDir)) {
      for (const entry of fs.readdirSync(userDir)) {
        const entryPath = path.join(userDir, entry);
        try {
          const stat = fs.statSync(entryPath);
          if (stat.isDirectory()) {
            fs.rmSync(entryPath, { recursive: true, force: true });
          } else {
            fs.unlinkSync(entryPath);
          }
        } catch (e) {
          console.error('Failed to remove', entryPath, e);
        }
      }
    }

    // Clear uploads array in MongoDB
    await db.collection('users').updateOne(
      { username },
      { $set: { uploads: [] } }
    );
  } catch (err) {
    console.error('Error during delete-all:', err);
  }

  res.redirect('/gallery');
});

app.get('/gallery', isAuthenticated, async (req, res) => {
  const user = await db.collection('users').findOne({ username: req.session.user });
  if (!user || !user.uploads || user.uploads.length === 0) {
    return res.send('No uploads yet.');
  }

  // Always sort first (imageN then videoN, numeric within type)
  const sortedMedia = sortUploads(user.uploads);

  // Persist sorted order back to DB so it stays consistent thereafter
  // if (JSON.stringify(sortedMedia.map(x => x.filename)) !== JSON.stringify(user.uploads.map(x => x.filename))) {
  //   await db.collection('users').updateOne(
  //     { username: user.username },
  //     { $set: { uploads: sortedMedia } }
  //   );
  // }

  // Optional search filter via ?q=...
  const q = (req.query.q || '').trim();
  const filtered = q ? sortedMedia.filter(item => matchesQuery(item, q)) : sortedMedia;

  res.render('gallery', {
    username: user.username,
    media: filtered,
    q
  });
});


app.get('/search', isAuthenticated, async (req, res) => {
  const q = (req.query.q || '').trim();
  const user = await db.collection('users').findOne({ username: req.session.user });
  if (!user || !user.uploads) return res.send('No uploads yet.');

  const filtered = user.uploads.filter(it => matchesQuery(it, q));
  res.render('gallery', {
    username: user.username,
    media: filtered,
    q
  });
});

app.post('/download-selected', isAuthenticated, async (req, res) => {
  const username = req.session.user;
  let { files } = req.body;

  if (!files) return res.redirect('/gallery');
  if (!Array.isArray(files)) files = [files];

  const userDir = path.join(__dirname, 'uploads', username);
  const user = await db.collection('users').findOne({ username });

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="downloads.zip"');

  const archive = archiver('zip', { zlib: { level: 9 } });

  archive.on('error', err => {
    console.error('Archive error:', err);
    res.status(500).end();
  });

  archive.pipe(res);

  for (const f of files) {
    const filePath = path.join(userDir, f);
    if (!fs.existsSync(filePath)) continue;

    const meta = user?.uploads?.find(u => u.filename === f);
    const nameInZip = meta?.originalName || f;

    archive.file(filePath, { name: nameInZip });
  }

  archive.finalize();
});




app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
