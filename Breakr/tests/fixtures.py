# breakr: ignore-file
# This file is intentionally full of vulnerable code. The marker above keeps
# it out of normal Breakr scans; use --include-ignored to scan it on purpose.

"""
Throwaway projects for the test suite.

They are written to a temp folder at test time, never committed, so
the fake secrets below (built by string concatenation) can't trip
GitHub secret scanning.
"""

import base64
import json
from pathlib import Path


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


FAKE_STRIPE_LIVE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
FAKE_GITHUB = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_SERVICE_ROLE_JWT = ".".join([
    _b64({"alg": "HS256", "typ": "JWT"}),
    _b64({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "service_role"}),
    "c2lnbmF0dXJlX25vdF9yZWFsX2J1dF9sb25nX2Vub3VnaA",
])
FAKE_ANON_JWT = ".".join([
    _b64({"alg": "HS256", "typ": "JWT"}),
    _b64({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "anon"}),
    "c2lnbmF0dXJlX25vdF9yZWFsX2J1dF9sb25nX2Vub3VnaA",
])


VULNERABLE_PROJECT = {

    "package.json": json.dumps({
        "name": "vulnerable-demo",
        "dependencies": {
            "express": "4.17.1",
            "lodash": "4.17.15",
            "next": "14.1.0",
            "jsonwebtoken": "8.5.1",
            "multer": "1.4.5-lts.1",
            "@supabase/supabase-js": "^2.39.0",
            "react": "^18.2.0",
            "left-pad": "*",
        },
    }, indent=2),

    "server.js": """\
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const app = express();
app.use(cors({ origin: '*', credentials: true }));

app.post('/api/users', async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});

app.get('/api/users/:id', async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

app.delete('/admin/users/:id', requireAuth, async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  res.send('deleted');
});

app.post('/login', async (req, res) => {
  const user = await User.findOne(req.body);
  if (user.password === req.body.password) {
    res.json({ token: jwt.sign({ id: user.id }, 'supersecret') });
  }
});

app.get('/download', (req, res) => {
  res.sendFile(path.join(__dirname, 'files', req.query.name));
});

app.post('/tools/traceroute', (req, res) => {
  exec(`traceroute ${req.body.host}`, (err, out) => res.send(out));
});

app.get('/search', (req, res) => {
  res.send(`<h1>Results for ${req.query.q}</h1>`);
});

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const event = JSON.parse(req.body);
  handlePayment(event);
  res.sendStatus(200);
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});

const resetToken = Math.random().toString(36).slice(2);
app.listen(3000);
""",

    "upload.js": """\
const multer = require('multer');
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });
router.post('/upload', upload.single('file'), (req, res) => res.json({ ok: true }));
app.use('/uploads', express.static('uploads'));
""",

    "crypto.js": """\
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
const claims = jwt.decode(token);
const digest = crypto.createHash('md5').update(password).digest('hex');
""",

    "src/lib/supabase.js": f"""\
import {{ createClient }} from '@supabase/supabase-js';
export const supabaseAdmin = createClient(process.env.SUPABASE_URL, "{FAKE_SERVICE_ROLE_JWT}");
""",

    "components/AdminPanel.jsx": """\
import { supabaseAdmin } from '../src/lib/supabase';
export default function AdminPanel({ user, html }) {
  if (user.role === 'admin') {
    localStorage.setItem('token', user.token);
  }
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
""",

    "public/app.js": """\
document.getElementById('out').innerHTML = location.hash.slice(1);
""",

    "app/api/orders/route.ts": """\
export async function GET() {
  return Response.json(await db.order.findMany());
}

export async function POST(request: Request) {
  const body = await request.json();
  return Response.json(await db.order.create({ data: body }));
}
""",

    "app/actions.ts": """\
'use server'

export async function deleteAccount(id: string) {
  await db.user.delete({ where: { id } });
}
""",

    "pages/api/admin/stats.js": """\
export default async function handler(req, res) {
  res.json(await db.stats.findMany());
}
""",

    "app.py": """\
import os, pickle, subprocess, hashlib, random, yaml
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)
SECRET_KEY = "changeme"
DEBUG = True


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    os.system("rm -rf /data/" + request.form["name"])
    return "ok"


@app.route("/users/<int:user_id>")
def get_user(user_id):
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return render_template_string(request.args.get("tpl"))


@app.post("/upload")
def upload():
    f = request.files["file"]
    f.save(os.path.join("uploads", f.filename))
    return "saved"


reset_token = str(random.randint(100000, 999999))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


config = yaml.load(open("config.yml"))
payload = pickle.loads(request.data)
response = requests.get("https://internal.acme.io", verify=False)

if __name__ == "__main__":
    app.run(debug=True)
""",

    "settings.py": f"""\
STRIPE_KEY = "{FAKE_STRIPE_LIVE}"
GITHUB_TOKEN = "{FAKE_GITHUB}"
password = "hunter22"
""",

    ".env": "\n".join([
        "DATABASE_URL=postgres://admin:S3cretPass@db-prod.internal.acme.io:5432/app",
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=placeholder",
        "",
    ]),

    "supabase/migrations/001_init.sql": """\
create table public.profiles (id uuid primary key, email text);
create table public.notes (id uuid primary key, body text, user_id uuid);
alter table public.notes enable row level security;
create policy "anyone can edit notes" on public.notes for update using (true);
create policy "public read" on public.notes for select using (true);
""",

    "firestore.rules": """\
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2030, 1, 1);
    }
    match /public/{doc} {
      allow read;
    }
  }
}
""",

    "requirements.txt": """\
flask==2.2.2
requests
pyyaml==5.3.1
django>=3.2
""",

    "Dockerfile": """\
FROM node:20
COPY . .
CMD ["node", "server.js"]
""",
}


SAFE_PROJECT = {

    "package.json": json.dumps({
        "name": "safe-demo",
        "dependencies": {
            "express": "^4.21.2",
            "lodash": "^4.17.21",
            "helmet": "^7.1.0",
            "express-rate-limit": "^7.1.0",
            "@supabase/supabase-js": "^2.39.0",
            "react": "^18.2.0",
        },
    }, indent=2),

    "package-lock.json": json.dumps({
        "name": "safe-demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "safe-demo"},
            "node_modules/express": {"version": "4.21.2"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/helmet": {"version": "7.1.0"},
        },
    }),

    ".gitignore": "node_modules\n.env\n.env.*\n!.env.example\n",

    ".env": f"SUPABASE_SERVICE_ROLE_KEY={FAKE_SERVICE_ROLE_JWT}\n",

    ".env.example": "SUPABASE_SERVICE_ROLE_KEY=your-service-role-key\n",

    "server.js": """\
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { requireAuth, requireAdmin } = require('./auth');
const adminRouter = require('./routes/admin');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 60000, max: 10 }));
app.use('/admin', requireAuth, requireAdmin, adminRouter);

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  const ok = await bcrypt.compare(req.body.password, user.passwordHash);
  res.json({ ok });
});

app.get('/api/users/:id', requireAuth, async (req, res) => {
  const user = await User.findOne({ _id: req.params.id, ownerId: req.user.id });
  res.json(user);
});

app.post('/api/posts', requireAuth, async (req, res) => {
  const { title, body } = req.body;
  const rows = await db.query('INSERT INTO posts (title, body) VALUES ($1, $2)', [title, body]);
  res.json(rows);
});

const token = require('crypto').randomBytes(32).toString('hex');
app.listen(3000);
""",

    "routes/admin.js": """\
const router = require('express').Router();

router.delete('/users/:id', async (req, res) => {
  await User.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});

module.exports = router;
""",

    "src/lib/supabase.js": f"""\
import {{ createClient }} from '@supabase/supabase-js';
export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, "{FAKE_ANON_JWT}");
""",

    "components/Comment.jsx": """\
export default function Comment({ comment }) {
  return <p className="comment">{comment.body}</p>;
}
""",

    "app.py": """\
import os
import secrets
from flask import Flask, request, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg"}
DEBUG = os.environ.get("DEBUG") == "1"


@app.route("/api/notes", methods=["POST"])
@login_required
def create_note():
    cur.execute("INSERT INTO notes (body, user_id) VALUES (%s, %s)", (request.form["body"], current_user.id))
    return "ok"


@app.post("/upload")
@login_required
def upload():
    f = request.files["file"]
    if not allowed_file(f.filename):
        abort(400)
    f.save(os.path.join("uploads", secure_filename(f.filename)))
    return "saved"


reset_token = secrets.token_urlsafe(32)
""",

    "supabase/migrations/001_init.sql": """\
create table public.todos (id uuid primary key, user_id uuid references auth.users, title text);
alter table public.todos enable row level security;
create policy "owners manage todos" on public.todos
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
""",

    "firestore.rules": """\
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{noteId} {
      allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;
    }
  }
}
""",

    "requirements.txt": """\
flask==3.0.3
requests==2.32.4
""",

    "Dockerfile": """\
FROM node:20
USER node
COPY . .
CMD ["node", "server.js"]
""",
}


def write_project(root: Path, files: dict):
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root
