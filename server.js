/**
 * LUCCA - proxy web estilo Hidester
 * Uso: npm install && npm start  ->  http://localhost:3000
 *
 * Variables de entorno:
 *   PORT              puerto (por defecto 3000)
 *   LUCCA_PASSWORD    contraseña del usuario "admin"; activa el login y el panel /admin
 *                     (si no se define, el acceso es libre y el panel queda desactivado)
 *   LUCCA_SECRET      clave para firmar la sesión de login (recomendado fijarla)
 *   LUCCA_COOKIES     "off" para no guardar cookies de los sitios visitados
 *   TRUST_PROXY       "1" si va detrás de Nginx/Caddy/Cloudflare
 */
const express = require('express');
const cheerio = require('cheerio');
const crypto = require('crypto');
const dns = require('dns').promises;
const fs = require('fs');
const net = require('net');
const path = require('path');
const { Readable } = require('stream');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.LUCCA_PASSWORD || '';
const AUTH_ENABLED = PASSWORD.length > 0;
const SECRET = process.env.LUCCA_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIES_ENABLED = (process.env.LUCCA_COOKIES || 'on').toLowerCase() !== 'off';
const BLOCKLIST_FILE = path.join(__dirname, 'blocklist.txt');

const TIMEOUT_MS = 15000;
const MAX_HTML_BYTES = 8 * 1024 * 1024;
const RATE_LIMIT = { windowMs: 60_000, max: 240 };
const LOGIN_LIMIT = { windowMs: 15 * 60_000, max: 5 };
const AUTH_TTL_MS = 7 * 24 * 3600 * 1000;
const JAR_TTL_MS = 2 * 3600 * 1000;
const MAX_COOKIES_PER_JAR = 150;

const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

/* ====================================================================
 *  Utilidades de cookies del navegador (sin dependencias)
 * ==================================================================== */
function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setCookie(res, req, name, value, maxAgeSec) {
  let c = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax`;
  if (maxAgeSec !== undefined) c += `; Max-Age=${maxAgeSec}`;
  if (req.secure) c += '; Secure';
  const prev = res.getHeader('Set-Cookie');
  res.setHeader('Set-Cookie', prev ? [].concat(prev, c) : c);
}

/* ====================================================================
 *  Límite de peticiones
 * ==================================================================== */
function makeLimiter({ windowMs, max }) {
  const map = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, r] of map) if (now - r.start > windowMs) map.delete(k);
  }, windowMs).unref();
  return {
    hit(key) {
      const now = Date.now();
      let r = map.get(key);
      if (!r || now - r.start > windowMs) r = { count: 0, start: now };
      r.count++;
      map.set(key, r);
      return r.count > max;
    },
    over(key) {
      const r = map.get(key);
      return !!r && Date.now() - r.start <= windowMs && r.count >= max;
    },
    reset(key) { map.delete(key); },
  };
}
const generalLimiter = makeLimiter(RATE_LIMIT);
const loginLimiter = makeLimiter(LOGIN_LIMIT);

app.use((req, res, next) => {
  if (generalLimiter.hit(req.ip)) return res.status(429).send('Demasiadas peticiones. Espera un minuto.');
  next();
});

/* ====================================================================
 *  Sesión anónima (identifica el "cookie jar") y login opcional
 * ==================================================================== */
app.use((req, res, next) => {
  const cookies = parseCookies(req.headers.cookie);
  let sid = cookies.lucca_sid;
  if (!/^[0-9a-f]{48}$/.test(sid || '')) {
    sid = crypto.randomBytes(24).toString('hex');
    setCookie(res, req, 'lucca_sid', sid, 30 * 24 * 3600);
  }
  req.sid = sid;
  req.luccaCookies = cookies;
  next();
});

/* ====================================================================
 *  Usuarios: "admin" (contraseña en LUCCA_PASSWORD) + usuarios en users.json
 * ==================================================================== */
const USERS_FILE = path.join(__dirname, 'users.json');
const USER_RE = /^[a-z0-9_-]{3,32}$/;
const MAX_USERS = 200;

let usersCache = { mtime: -1, users: [] };
function loadUsers() {
  try {
    const st = fs.statSync(USERS_FILE);
    if (st.mtimeMs === usersCache.mtime) return usersCache.users;
    const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    usersCache = { mtime: st.mtimeMs, users: Array.isArray(data.users) ? data.users : [] };
  } catch {
    usersCache = { mtime: -1, users: [] };
  }
  return usersCache.users;
}
function saveUsers(users) {
  const tmp = USERS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ users }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, USERS_FILE);
  usersCache.mtime = -1;
}
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
}
function verifyHash(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const a = Buffer.from(hash, 'hex');
  const b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const DUMMY_HASH = hashPassword(crypto.randomBytes(8).toString('hex')); // iguala tiempos si el usuario no existe

function adminPasswordMatches(input) {
  const a = crypto.createHash('sha256').update(String(input)).digest();
  const b = crypto.createHash('sha256').update(PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}
function checkLogin(username, password) {
  const name = String(username || '').trim().toLowerCase();
  const pw = String(password || '');
  if (name === 'admin') return adminPasswordMatches(pw) ? 'admin' : null;
  const u = loadUsers().find((x) => x.username === name);
  const ok = verifyHash(pw, u ? u.hash : DUMMY_HASH);
  return u && ok ? name : null;
}
function userExists(name) {
  return name === 'admin' || loadUsers().some((u) => u.username === name);
}

/* ====================================================================
 *  Sesión de login (cookie firmada) y páginas de acceso
 * ==================================================================== */
function sign(value) {
  return crypto.createHmac('sha256', SECRET).update(value).digest('hex');
}
function makeAuthToken(username) {
  const payload = `${username}:${Date.now() + AUTH_TTL_MS}`;
  return `${payload}:${sign(payload)}`;
}
function currentUser(req) {
  if (!AUTH_ENABLED) return null;
  const parts = (req.luccaCookies.lucca_auth || '').split(':');
  if (parts.length !== 3) return null;
  const [name, exp, sig] = parts;
  if (!(Number(exp) > Date.now())) return null;
  const a = Buffer.from(sig);
  const b = Buffer.from(sign(`${name}:${exp}`));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return userExists(name) ? name : null; // si borras al usuario, su sesión deja de valer
}
function isAuthed(req) { return !AUTH_ENABLED || !!currentUser(req); }
function safeNext(next) {
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/';
}
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function pageShell(title, body) {
  return `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="color-scheme" content="dark">
<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#0f0f17;color:#e8e8f0;font:16px/1.5 Inter,system-ui,-apple-system,'Segoe UI',sans-serif">
<main style="width:min(100% - 2rem,26rem);padding:2rem 0">${body}</main></body></html>`;
}

function loginPage(next, error) {
  const field = 'border:1px solid #2a2a3c;border-radius:10px;background:#1a1a26;color:#e8e8f0;padding:.85rem 1rem;font:1.05rem Inter,system-ui,sans-serif;width:100%;box-sizing:border-box';
  return pageShell('LUCCA · Acceso', `
<h1 style="font-size:2.5rem;letter-spacing:-.02em;margin:0 0 .5rem;font-weight:800">LUCCA <span style="color:#818cf8">Proxy</span></h1>
<p style="margin:0 0 1.5rem;color:#9a9ab0">Inicia sesión para usar el proxy.</p>
${error ? `<p role="alert" style="margin:0 0 1rem;color:#f87171;font-weight:600">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/login" style="display:grid;gap:.75rem">
<input type="hidden" name="next" value="${escapeHtml(next)}">
<input name="username" required autofocus autocomplete="username" placeholder="Usuario" aria-label="Usuario" style="${field}">
<input type="password" name="password" required autocomplete="current-password" placeholder="Contraseña" aria-label="Contraseña" style="${field}">
<button style="border:0;border-radius:10px;padding:.9rem;background:#6366f1;color:#fff;font:600 1rem Inter,system-ui,sans-serif;cursor:pointer">Entrar</button>
</form>`);
}

app.get('/login', (req, res) => {
  if (!AUTH_ENABLED || isAuthed(req)) return res.redirect(safeNext(req.query.next));
  res.type('html').send(loginPage(safeNext(req.query.next)));
});

app.post('/login', (req, res) => {
  if (!AUTH_ENABLED) return res.redirect('/');
  const next = safeNext(req.body.next);
  if (loginLimiter.over(req.ip)) {
    return res.status(429).type('html').send(loginPage(next, 'Demasiados intentos. Espera unos minutos.'));
  }
  const user = checkLogin(req.body.username, req.body.password);
  if (user) {
    loginLimiter.reset(req.ip);
    setCookie(res, req, 'lucca_auth', makeAuthToken(user), Math.floor(AUTH_TTL_MS / 1000));
    return res.redirect(303, next);
  }
  loginLimiter.hit(req.ip);
  res.status(401).type('html').send(loginPage(next, 'Usuario o contraseña incorrectos.'));
});

app.get('/logout', (req, res) => {
  setCookie(res, req, 'lucca_auth', '', 0);
  res.redirect(AUTH_ENABLED ? '/login' : '/');
});

// Todo lo que sigue requiere haber iniciado sesión (si el login está activo)
app.use((req, res, next) => {
  if (!AUTH_ENABLED) return next();
  const user = currentUser(req);
  if (user) { req.user = user; return next(); }
  res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
});

/* ====================================================================
 *  Panel de administración (/admin): lista de bloqueo y usuarios
 * ==================================================================== */
const FLASH = {
  saved: ['Lista de bloqueo guardada.', false],
  baddomain: ['Hay una línea que no es un dominio válido. No se guardó nada.', true],
  added: ['Usuario creado.', false],
  baduser: ['Usuario no válido: usa de 3 a 32 letras minúsculas, números, guion o guion bajo.', true],
  reserved: ['Ese nombre ya existe o está reservado.', true],
  shortpw: ['La contraseña debe tener entre 8 y 200 caracteres.', true],
  full: ['Se alcanzó el máximo de usuarios.', true],
  deleted: ['Usuario eliminado.', false],
};

function csrfToken(req) { return sign('csrf:' + req.sid); }

function requireAdmin(req, res, next) {
  if (!AUTH_ENABLED) {
    return errorPage(res, 404, 'Panel desactivado', 'Define LUCCA_PASSWORD al arrancar para activar el login y el panel.');
  }
  if (req.user !== 'admin') return errorPage(res, 403, 'Solo para el administrador', 'Entra con el usuario admin.');
  next();
}
function checkCsrf(req, res, next) {
  const given = Buffer.from(String(req.body._csrf || ''));
  const expected = Buffer.from(csrfToken(req));
  if (given.length === expected.length && crypto.timingSafeEqual(given, expected)) return next();
  errorPage(res, 403, 'Petición no válida', 'Vuelve al panel y repite la acción.');
}

function adminPage(req, code) {
  const flash = Object.hasOwn(FLASH, code) ? FLASH[code] : null;
  let list = '';
  try { list = fs.readFileSync(BLOCKLIST_FILE, 'utf8'); } catch { /* aún no existe */ }
  const csrf = csrfToken(req);
  const rows = loadUsers().map((u) => `<li><span>${escapeHtml(u.username)}</span>
<form method="post" action="/admin/users/delete" onsubmit="return confirm('¿Eliminar a este usuario?')">
<input type="hidden" name="_csrf" value="${csrf}"><input type="hidden" name="username" value="${escapeHtml(u.username)}">
<button class="danger">Eliminar</button></form></li>`).join('') || '<li class="muted">Todavía no hay otros usuarios.</li>';

  return `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LUCCA · Panel</title>
<meta name="color-scheme" content="dark">
<style>
:root{--bg:#0f0f17;--bar:#14141f;--panel:#1a1a26;--line:#2a2a3c;--text:#e8e8f0;--muted:#9a9ab0;--accent:#6366f1;--accent-hover:#7477f5;--accent-soft:#818cf8;--bad:#f87171}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:1rem;padding:.9rem 1.25rem;background:var(--bar);border-bottom:1px solid var(--line)}
header strong{margin-right:auto;font-size:1.15rem;font-weight:800}header strong span{color:var(--accent-soft)}
header a{color:var(--muted);text-decoration:none}header a:hover{color:var(--text)}
main{width:min(100% - 2rem,44rem);margin:2rem auto;display:grid;gap:1.5rem}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.25rem}
h2{margin:0 0 .25rem;font-size:1.2rem}p.hint{margin:0 0 1rem;color:var(--muted);font-size:.95rem}
textarea,input{width:100%;border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem;font:inherit;background:var(--bg);color:var(--text)}
textarea:focus,input:focus{border-color:var(--accent)}
textarea{min-height:12rem;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.95rem}
button{border:0;border-radius:8px;padding:.7rem 1.2rem;background:var(--accent);color:#fff;font:600 1rem Inter,system-ui,sans-serif;cursor:pointer}
button:hover{background:var(--accent-hover)}
button.danger{background:transparent;color:var(--bad);border:1px solid var(--bad);padding:.35rem .8rem}
button.danger:hover{background:rgba(248,113,113,.12)}
button:focus-visible,input:focus-visible,textarea:focus-visible,a:focus-visible{outline:2px solid var(--accent-soft);outline-offset:2px}
form.stack{display:grid;gap:.75rem}ul{list-style:none;margin:0 0 1.25rem;padding:0}
li{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.55rem 0;border-bottom:1px solid var(--line)}
li.muted{color:var(--muted)}form{margin:0}
.flash{padding:.7rem 1rem;border-radius:8px;background:#16261d;border:1px solid #2f6b45;color:#bbf7d0}
.flash.err{background:#2b181a;border-color:#7f2d33;color:#fecaca}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}@media(max-width:34rem){.grid2{grid-template-columns:1fr}}
</style>
<header><strong>LUCCA <span>Panel</span></strong><a href="/">Volver al proxy</a><a href="/logout">Salir</a></header>
<main>
${flash ? `<div class="flash${flash[1] ? ' err' : ''}" role="status">${escapeHtml(flash[0])}</div>` : ''}
<section>
<h2>Sitios bloqueados</h2>
<p class="hint">Un dominio por línea. Bloquear un dominio bloquea también sus subdominios. Las líneas con # son comentarios.</p>
<form class="stack" method="post" action="/admin/blocklist">
<input type="hidden" name="_csrf" value="${csrf}">
<textarea name="blocklist" spellcheck="false" aria-label="Dominios bloqueados">${escapeHtml(list)}</textarea>
<div><button>Guardar lista</button></div>
</form>
</section>
<section>
<h2>Usuarios</h2>
<p class="hint">El usuario admin usa la contraseña definida en LUCCA_PASSWORD. Aquí gestionas los demás.</p>
<ul>${rows}</ul>
<form class="stack" method="post" action="/admin/users/add">
<input type="hidden" name="_csrf" value="${csrf}">
<div class="grid2">
<input name="username" required placeholder="Nombre de usuario" autocomplete="off" aria-label="Nombre de usuario">
<input type="password" name="password" required minlength="8" placeholder="Contraseña (mínimo 8)" autocomplete="new-password" aria-label="Contraseña">
</div>
<div><button>Crear usuario</button></div>
</form>
</section>
</main></html>`;
}

app.get('/admin', requireAdmin, (req, res) => res.type('html').send(adminPage(req, req.query.m)));

app.post('/admin/blocklist', requireAdmin, checkCsrf, (req, res) => {
  const clean = [];
  for (const raw of String(req.body.blocklist || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('#')) { clean.push(line); continue; }
    const d = line.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z0-9-]{2,}$/.test(d)) return res.redirect(303, '/admin?m=baddomain');
    clean.push(d);
  }
  fs.writeFileSync(BLOCKLIST_FILE, clean.join('\n') + (clean.length ? '\n' : ''));
  res.redirect(303, '/admin?m=saved');
});

app.post('/admin/users/add', requireAdmin, checkCsrf, (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const users = loadUsers();
  if (!USER_RE.test(username)) return res.redirect(303, '/admin?m=baduser');
  if (username === 'admin' || users.some((u) => u.username === username)) return res.redirect(303, '/admin?m=reserved');
  if (password.length < 8 || password.length > 200) return res.redirect(303, '/admin?m=shortpw');
  if (users.length >= MAX_USERS) return res.redirect(303, '/admin?m=full');
  saveUsers([...users, { username, hash: hashPassword(password) }]);
  res.redirect(303, '/admin?m=added');
});

app.post('/admin/users/delete', requireAdmin, checkCsrf, (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  saveUsers(loadUsers().filter((u) => u.username !== username));
  res.redirect(303, '/admin?m=deleted');
});

app.use(express.static(path.join(__dirname, 'public')));

/* ====================================================================
 *  Lista de dominios bloqueados (blocklist.txt)
 * ==================================================================== */
let blocked = { mtime: 0, entries: [] };
function loadBlocklist() {
  try {
    const st = fs.statSync(BLOCKLIST_FILE);
    if (st.mtimeMs === blocked.mtime) return blocked.entries;
    const entries = fs.readFileSync(BLOCKLIST_FILE, 'utf8')
      .split(/\r?\n/)
      .map((l) => l.replace(/#.*/, '').trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, ''))
      .filter(Boolean);
    blocked = { mtime: st.mtimeMs, entries };
  } catch {
    blocked = { mtime: 0, entries: [] };
  }
  return blocked.entries;
}
function isBlocked(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  return loadBlocklist().some((e) => host === e || host.endsWith('.' + e));
}

/* ====================================================================
 *  Cookies de los sitios visitados (guardadas en el servidor, por sesión)
 * ==================================================================== */
const jars = new Map(); // sid -> { cookies: [], last }
setInterval(() => {
  const now = Date.now();
  for (const [sid, j] of jars) if (now - j.last > JAR_TTL_MS) jars.delete(sid);
}, 10 * 60_000).unref();

function getJar(sid) {
  let jar = jars.get(sid);
  if (!jar) { jar = { cookies: [], last: Date.now() }; jars.set(sid, jar); }
  jar.last = Date.now();
  return jar;
}

function storeCookies(jar, setCookieHeaders, url) {
  const host = url.hostname.toLowerCase();
  const now = Date.now();
  for (const raw of setCookieHeaders) {
    const parts = raw.split(';').map((s) => s.trim());
    const eq = parts[0].indexOf('=');
    if (eq <= 0) continue;
    const name = parts[0].slice(0, eq);
    const value = parts[0].slice(eq + 1);
    const c = { name, value, domain: host, hostOnly: true, path: null, expires: null, secure: false };
    let maxAge = null;
    for (const attr of parts.slice(1)) {
      const i = attr.indexOf('=');
      const k = (i < 0 ? attr : attr.slice(0, i)).toLowerCase();
      const v = i < 0 ? '' : attr.slice(i + 1);
      if (k === 'domain') {
        const d = v.replace(/^\./, '').toLowerCase();
        if (d.includes('.') && (host === d || host.endsWith('.' + d))) { c.domain = d; c.hostOnly = false; }
        else if (d) { c.invalid = true; }
      } else if (k === 'path' && v.startsWith('/')) c.path = v;
      else if (k === 'max-age') maxAge = Number(v);
      else if (k === 'expires') { const t = Date.parse(v); if (!Number.isNaN(t)) c.expires = t; }
      else if (k === 'secure') c.secure = true;
    }
    if (c.invalid) continue;
    if (!c.path) c.path = url.pathname.replace(/\/[^/]*$/, '') || '/';
    if (maxAge !== null && !Number.isNaN(maxAge)) c.expires = now + maxAge * 1000;
    // Reemplazar la cookie existente con el mismo nombre/dominio/ruta
    jar.cookies = jar.cookies.filter((x) => !(x.name === c.name && x.domain === c.domain && x.path === c.path));
    if (c.expires !== null && c.expires <= now) continue; // cookie borrada por el sitio
    jar.cookies.push(c);
  }
  if (jar.cookies.length > MAX_COOKIES_PER_JAR) jar.cookies = jar.cookies.slice(-MAX_COOKIES_PER_JAR);
}

function cookieHeaderFor(jar, url) {
  const host = url.hostname.toLowerCase();
  const now = Date.now();
  jar.cookies = jar.cookies.filter((c) => c.expires === null || c.expires > now);
  return jar.cookies
    .filter((c) => (c.hostOnly ? host === c.domain : host === c.domain || host.endsWith('.' + c.domain)))
    .filter((c) => url.pathname === c.path || url.pathname.startsWith(c.path.endsWith('/') ? c.path : c.path + '/'))
    .filter((c) => !c.secure || url.protocol === 'https:')
    .sort((a, b) => b.path.length - a.path.length)
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');
}

app.get('/clear-cookies', (req, res) => {
  jars.delete(req.sid);
  const back = String(req.query.back || '');
  res.redirect(back.startsWith('/go?url=') ? back : '/');
});

/* ====================================================================
 *  Seguridad: bloquear destinos internos (SSRF)
 * ==================================================================== */
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::1' || l === '::') return true;
    if (l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe8') || l.startsWith('fe9') ||
        l.startsWith('fea') || l.startsWith('feb')) return true;
    const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
  }
  return false;
}

async function assertPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error('Destino no permitido.');
    return;
  }
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Destino no permitido.');
  }
  const addrs = await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('Destino no permitido.');
  }
}

/* ====================================================================
 *  Utilidades de URL
 * ==================================================================== */
const PROXY_PATH = '/go?url=';
const SKIP = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;

function proxify(value, base) {
  if (!value) return value;
  const v = value.trim();
  if (SKIP.test(v) || v.startsWith(PROXY_PATH)) return value;
  try {
    const u = new URL(v, base);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return value;
    const hash = u.hash;
    u.hash = '';
    return PROXY_PATH + encodeURIComponent(u.href) + hash;
  } catch {
    return value;
  }
}

function normalizeInput(raw) {
  const text = String(raw || '').trim();
  if (!text) return null;
  if (/^https?:\/\//i.test(text)) return text;
  if (/^[^\s]+\.[^\s]{2,}$/.test(text)) return 'https://' + text;
  return 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(text);
}

/* ====================================================================
 *  Reescritura de CSS y HTML
 * ==================================================================== */
function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${proxify(u, base)}${q})`)
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => `@import ${q}${proxify(u, base)}${q}`);
}

function shimScript(base) {
  return `(function(){var B=${JSON.stringify(base)};
function P(u){try{if(typeof u!=='string')return u;if(u.indexOf('/go?url=')===0)return u;
var a=new URL(u,B);if(a.protocol!=='http:'&&a.protocol!=='https:')return u;
return '/go?url='+encodeURIComponent(a.href)}catch(e){return u}}
var f=window.fetch;if(f)window.fetch=function(i,o){
if(typeof i==='string')i=P(i);else if(i&&i.url)i=new Request(P(i.url),i);return f.call(this,i,o)};
var x=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){
arguments[1]=P(u);return x.apply(this,arguments)};
var w=window.open;window.open=function(u){arguments[0]=P(u);return w.apply(this,arguments)};
})();`;
}

function barHtml(current, user) {
  const safe = escapeHtml(current);
  const linkStyle = 'color:#9a9ab0;text-decoration:none;font-weight:500;white-space:nowrap';
  const clear = COOKIES_ENABLED
    ? `<a href="/clear-cookies?back=${encodeURIComponent(PROXY_PATH + encodeURIComponent(current))}" style="${linkStyle}">Borrar cookies</a>`
    : '';
  const panel = user === 'admin' ? `<a href="/admin" style="${linkStyle}">Panel</a>` : '';
  const logout = AUTH_ENABLED ? `<a href="/logout" style="${linkStyle}">Salir</a>` : '';
  return `<style>html{padding-top:46px!important}#lucca-bar a:hover{color:#e8e8f0!important}</style>
<div id="lucca-bar" style="position:fixed;top:0;left:0;right:0;height:46px;z-index:2147483647;
background:#14141f;color:#e8e8f0;display:flex;align-items:center;gap:12px;padding:0 12px;
font:600 14px Inter,system-ui,sans-serif;border-bottom:1px solid #2a2a3c;box-shadow:0 2px 10px rgba(0,0,0,.45)">
<a href="/" style="color:#e8e8f0;text-decoration:none;font-weight:800;white-space:nowrap">LUCCA <span style="color:#818cf8">Proxy</span></a>
<form action="/go" method="get" style="flex:1;display:flex;gap:8px;margin:0">
<input name="url" value="${safe}" aria-label="Dirección o búsqueda"
style="flex:1;min-width:0;height:30px;border:1px solid #2a2a3c;border-radius:8px;padding:0 10px;background:#1a1a26;color:#e8e8f0;font:14px Inter,system-ui,sans-serif">
<button style="height:30px;border:0;border-radius:8px;padding:0 14px;background:#6366f1;color:#fff;
font:600 14px Inter,system-ui,sans-serif;cursor:pointer">Ir</button></form>${clear}${panel}${logout}</div>`;
}

function rewriteHtml(html, pageUrl, user) {
  const $ = cheerio.load(html);

  let base = pageUrl;
  const baseTag = $('base[href]').first().attr('href');
  if (baseTag) {
    try { base = new URL(baseTag, pageUrl).href; } catch { /* ignorar */ }
  }
  $('base').remove();

  $('meta[http-equiv]').each((_, el) => {
    const kind = ($(el).attr('http-equiv') || '').toLowerCase();
    if (kind === 'content-security-policy') {
      $(el).remove();
    } else if (kind === 'refresh') {
      const c = $(el).attr('content') || '';
      const m = c.match(/^(\s*\d+\s*;\s*url=)(.+)$/i);
      if (m) $(el).attr('content', m[1] + proxify(m[2].replace(/^['"]|['"]$/g, ''), base));
    }
  });
  $('[integrity]').removeAttr('integrity');
  $('[nonce]').removeAttr('nonce');
  $('[crossorigin]').removeAttr('crossorigin');

  const attrs = ['href', 'src', 'poster', 'data-src', 'data-href'];
  $('*').each((_, el) => {
    const $el = $(el);
    for (const a of attrs) {
      const v = $el.attr(a);
      if (v) $el.attr(a, proxify(v, base));
    }
    const srcset = $el.attr('srcset');
    if (srcset) {
      $el.attr('srcset', srcset.split(',').map((part) => {
        const [u, ...rest] = part.trim().split(/\s+/);
        return [proxify(u, base), ...rest].join(' ');
      }).join(', '));
    }
    const style = $el.attr('style');
    if (style) $el.attr('style', rewriteCss(style, base));
  });

  $('form').each((_, el) => {
    const $f = $(el);
    const action = $f.attr('action') || '';
    let abs;
    try { abs = new URL(action || pageUrl, base).href; } catch { return; }
    const method = ($f.attr('method') || 'get').toLowerCase();
    if (method === 'post') {
      $f.attr('action', proxify(abs, base));
    } else {
      $f.attr('action', '/go');
      $f.prepend(`<input type="hidden" name="__lucca" value="${escapeHtml(abs)}">`);
    }
    $f.removeAttr('target');
  });

  $('a[target]').attr('target', '_self');

  $('style').each((_, el) => {
    const css = $(el).html();
    if (css) $(el).html(rewriteCss(css, base));
  });

  $('head').prepend(`<script>${shimScript(base)}</script>`);
  if ($('head').length === 0) $.root().prepend(`<script>${shimScript(base)}</script>`);
  $('body').prepend(barHtml(pageUrl, user));

  return $.html();
}

/* ====================================================================
 *  Ruta principal del proxy
 * ==================================================================== */
const STRIP_RESPONSE = new Set([
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'set-cookie', 'content-encoding', 'content-length', 'transfer-encoding', 'connection',
  'strict-transport-security', 'report-to', 'nel', 'cross-origin-opener-policy',
  'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'permissions-policy',
]);

function decodeBody(buffer, contentType) {
  const m = /charset=([^;\s]+)/i.exec(contentType || '');
  const charset = (m ? m[1] : 'utf-8').replace(/["']/g, '');
  try { return new TextDecoder(charset).decode(buffer); }
  catch { return new TextDecoder('utf-8').decode(buffer); }
}

async function readLimited(stream, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of Readable.fromWeb(stream)) {
    size += chunk.length;
    if (size > limit) throw new Error('La página es demasiado grande.');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function errorPage(res, status, title, message) {
  res.status(status).type('html').send(pageShell(`LUCCA · ${escapeHtml(title)}`, `
<h1 style="margin:0 0 .5rem">${escapeHtml(title)}</h1>
<p style="line-height:1.5">${escapeHtml(message)}</p>
<p><a href="/" style="color:#818cf8;font-weight:600">Volver a LUCCA</a></p>`));
}

async function handle(req, res) {
  try {
    let target = req.query.__lucca || req.query.url || req.body?.url;
    if (req.query.__lucca) {
      const u = new URL(req.query.__lucca);
      for (const [k, v] of Object.entries(req.query)) {
        if (k !== '__lucca') u.searchParams.set(k, v);
      }
      target = u.href;
    } else {
      target = normalizeInput(target);
    }
    if (!target) return res.redirect('/');

    const url = new URL(target);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return errorPage(res, 400, 'Dirección no válida', 'Solo se permiten direcciones http y https.');
    }
    if (isBlocked(url.hostname)) {
      return errorPage(res, 403, 'Sitio bloqueado', `El administrador de LUCCA bloqueó ${url.hostname}.`);
    }
    await assertPublicHost(url.hostname);

    const headers = {
      'user-agent': req.get('user-agent') || 'Mozilla/5.0',
      accept: req.get('accept') || '*/*',
      'accept-language': req.get('accept-language') || 'es,en;q=0.8',
    };
    if (req.get('range')) headers.range = req.get('range');

    const jar = COOKIES_ENABLED ? getJar(req.sid) : null;
    if (jar) {
      const ch = cookieHeaderFor(jar, url);
      if (ch) headers.cookie = ch;
    }

    const init = {
      method: req.method === 'POST' ? 'POST' : 'GET',
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    };
    if (init.method === 'POST') {
      const body = { ...req.body };
      delete body.url;
      init.body = new URLSearchParams(body).toString();
      headers['content-type'] = 'application/x-www-form-urlencoded';
    }

    const upstream = await fetch(url.href, init);

    if (jar && typeof upstream.headers.getSetCookie === 'function') {
      storeCookies(jar, upstream.headers.getSetCookie(), url);
    }

    if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get('location')) {
      const next = new URL(upstream.headers.get('location'), url.href).href;
      return res.redirect(303, proxify(next, url.href));
    }

    const type = upstream.headers.get('content-type') || 'application/octet-stream';
    for (const [k, v] of upstream.headers) {
      if (!STRIP_RESPONSE.has(k.toLowerCase())) res.setHeader(k, v);
    }
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-content-type-options', 'nosniff');
    res.status(upstream.status);

    if (/text\/html|application\/xhtml/i.test(type)) {
      const buf = await readLimited(upstream.body, MAX_HTML_BYTES);
      res.type('text/html; charset=utf-8').send(rewriteHtml(decodeBody(buf, type), url.href, req.user));
    } else if (/text\/css/i.test(type)) {
      const buf = await readLimited(upstream.body, MAX_HTML_BYTES);
      res.type('text/css; charset=utf-8').send(rewriteCss(decodeBody(buf, type), url.href));
    } else if (upstream.body) {
      Readable.fromWeb(upstream.body).on('error', () => res.destroy()).pipe(res);
    } else {
      res.end();
    }
  } catch (err) {
    const msg = err.name === 'TimeoutError' ? 'El sitio tardó demasiado en responder.' : err.message;
    if (!res.headersSent) errorPage(res, 502, 'No se pudo abrir la página', msg);
    else res.destroy();
  }
}

app.get('/go', handle);
app.post('/go', handle);

app.listen(PORT, () => {
  console.log(`LUCCA escuchando en http://localhost:${PORT}`);
  if (!AUTH_ENABLED) console.warn('Aviso: LUCCA_PASSWORD no está definida: el acceso es libre y el panel /admin está desactivado.');
  if (AUTH_ENABLED && !process.env.LUCCA_SECRET) {
    console.warn('Aviso: define LUCCA_SECRET para que los logins sobrevivan a un reinicio.');
  }
  console.log(`Cookies de sitios: ${COOKIES_ENABLED ? 'activadas' : 'desactivadas'} | Dominios bloqueados: ${loadBlocklist().length}`);
});
