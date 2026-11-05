import 'dotenv/config';
import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import multer from 'multer';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import { resolveClientIpAddress } from './security/client-ip.ts';
import { canDeleteAssignment, canSeeSubmission, canSubmitAssignment } from './security/authorization.ts';
import { validatePassword } from './security/password-policy.ts';
import { validateSubmissionFile } from './security/upload-validation.ts';
import { migrateTenantFoundation } from './db/migrations.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database(process.env.DATABASE_PATH || 'database.sqlite');
db.pragma('foreign_keys = ON');
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction && (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)) {
  throw new Error('Production requires a JWT_SECRET of at least 32 characters.');
}
const JWT_SECRET = process.env.JWT_SECRET || 'local-demo-only-change-this-secret-before-deployment';
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('not-a-real-user-password',10);
const app = express();

// Baseline browser security headers. The CSP starts in report-only mode so the
// current UI can be observed before any browser enforcement is introduced.
const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self'",
  "script-src-attr 'none'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "media-src 'self' blob:",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
].join('; ');

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy-Report-Only', contentSecurityPolicy);
  if (isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  }
  next();
});
// Forwarded IP headers are ignored unless an operator explicitly configures a trusted ingress header.
// Never enable this when untrusted services can reach the application listener directly.
const TRUSTED_CLIENT_IP_HEADER = (process.env.TRUSTED_CLIENT_IP_HEADER || '').trim().toLowerCase();
if (TRUSTED_CLIENT_IP_HEADER && !/^[a-z0-9-]+$/.test(TRUSTED_CLIENT_IP_HEADER)) {
  throw new Error('TRUSTED_CLIENT_IP_HEADER must be a simple HTTP header name.');
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_login TEXT
);
CREATE TABLE IF NOT EXISTS classes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 year_group TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS class_teachers (
 class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
 teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(class_id, teacher_id)
);
CREATE TABLE IF NOT EXISTS class_students (
 class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
 student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(class_id, student_id)
);
CREATE TABLE IF NOT EXISTS assignments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 instructions TEXT DEFAULT '',
 deadline TEXT,
 created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 status TEXT NOT NULL DEFAULT 'published'
);
CREATE TABLE IF NOT EXISTS assignment_classes (
 assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
 class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
 PRIMARY KEY(assignment_id, class_id)
);
CREATE TABLE IF NOT EXISTS submissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
 student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 original_filename TEXT NOT NULL,
 stored_filename TEXT NOT NULL,
 file_size INTEGER NOT NULL DEFAULT 0,
 submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(assignment_id, student_id)
);
CREATE TABLE IF NOT EXISTS feedback (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
 teacher_id INTEGER NOT NULL REFERENCES users(id),
 comments TEXT NOT NULL,
 grade TEXT,
 status TEXT NOT NULL DEFAULT 'reviewed',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor_id INTEGER REFERENCES users(id),
 action TEXT NOT NULL,
 entity_type TEXT NOT NULL,
 entity_id INTEGER,
 details TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 jti TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL,
 revoked_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_rate_limits (
 bucket_key TEXT PRIMARY KEY,
 window_started_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL,
 blocked_until INTEGER
);
CREATE INDEX IF NOT EXISTS idx_login_rate_limits_window ON login_rate_limits(window_started_at);
`);

const count = (sql: string) => (db.prepare(sql).get() as any).n as number;
const insertUser = db.prepare('INSERT OR IGNORE INTO users(email,display_name,password_hash,role) VALUES(?,?,?,?)');
const seedUser = (email: string, name: string, password: string, role: string) =>
  insertUser.run(email, name, bcrypt.hashSync(password, 10), role);
if (!isProduction && count('SELECT count(*) AS n FROM users') === 0) {
  seedUser('admin@demo.local', 'Platformbeheerder', 'Admin123!', 'admin');
  seedUser('docent.jansen@demo.local', 'Sanne Jansen', 'Teacher123!', 'teacher');
  seedUser('docent.visser@demo.local', 'Mark Visser', 'Teacher123!', 'teacher');
  seedUser('student.noor@demo.local', 'Noor de Vries', 'Student123!', 'student');
  seedUser('student.liam@demo.local', 'Liam Bakker', 'Student123!', 'student');
  seedUser('student.sara@demo.local', 'Sara Peters', 'Student123!', 'student');
  const t1 = db.prepare("SELECT id FROM users WHERE email='docent.jansen@demo.local'").get() as any;
  const t2 = db.prepare("SELECT id FROM users WHERE email='docent.visser@demo.local'").get() as any;
  const s1 = db.prepare("SELECT id FROM users WHERE email='student.noor@demo.local'").get() as any;
  const s2 = db.prepare("SELECT id FROM users WHERE email='student.liam@demo.local'").get() as any;
  const s3 = db.prepare("SELECT id FROM users WHERE email='student.sara@demo.local'").get() as any;
  const c1 = db.prepare("INSERT INTO classes(name,year_group) VALUES('ICT 2A','2026–2027')").run().lastInsertRowid as number;
  const c2 = db.prepare("INSERT INTO classes(name,year_group) VALUES('Media 3B','2026–2027')").run().lastInsertRowid as number;
  db.prepare('INSERT INTO class_teachers(class_id,teacher_id) VALUES(?,?)').run(c1,t1.id);
  db.prepare('INSERT INTO class_teachers(class_id,teacher_id) VALUES(?,?)').run(c2,t2.id);
  db.prepare('INSERT INTO class_students(class_id,student_id) VALUES(?,?)').run(c1,s1.id);
  db.prepare('INSERT INTO class_students(class_id,student_id) VALUES(?,?)').run(c1,s2.id);
  db.prepare('INSERT INTO class_students(class_id,student_id) VALUES(?,?)').run(c2,s3.id);
  const a1 = db.prepare("INSERT INTO assignments(title,description,instructions,deadline,created_by) VALUES(?,?,?,?,?)")
    .run('Netwerkontwerp','Ontwerp een klein bedrijfsnetwerk.','Lever je netwerkdiagram en een korte toelichting in.','2026-11-14',t1.id).lastInsertRowid as number;
  const a2 = db.prepare("INSERT INTO assignments(title,description,instructions,deadline,created_by) VALUES(?,?,?,?,?)")
    .run('Reflectieverslag','Reflecteer op je projectwerk.','Beschrijf je aanpak, keuzes en leerpunten.','2026-11-20',t1.id).lastInsertRowid as number;
  const a3 = db.prepare("INSERT INTO assignments(title,description,instructions,deadline,created_by) VALUES(?,?,?,?,?)")
    .run('Portfolio media','Verzamel je beste werk in een portfolio.','Upload een PDF of ZIP-bestand.','2026-11-18',t2.id).lastInsertRowid as number;
  [a1,a2].forEach(a => db.prepare('INSERT INTO assignment_classes(assignment_id,class_id) VALUES(?,?)').run(a,c1));
  db.prepare('INSERT INTO assignment_classes(assignment_id,class_id) VALUES(?,?)').run(a3,c2);
}

migrateTenantFoundation(db,isProduction);

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
// Keep route handlers safe when a request has no JSON body or a non-object body.
app.use((req: any, _res, next) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) req.body = {};
  next();
});

// Signed double-submit CSRF token. The signature prevents sibling subdomains or other
// untrusted origins from planting a valid token cookie for this host.
const createCsrfToken = () => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(nonce).digest('hex');
  return `${nonce}.${signature}`;
};
const isValidCsrfToken = (value: unknown): value is string => {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 2 || !/^[a-f0-9]{64}$/.test(parts[0]) || !/^[a-f0-9]{64}$/.test(parts[1])) return false;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(parts[0]).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(parts[1], 'hex'), Buffer.from(expected, 'hex'));
};

app.get('/api/csrf', (_req, res) => {
  const token = createCsrfToken();
  res.cookie('learnora_csrf', token, {
    httpOnly: false,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  });
  res.setHeader('Cache-Control', 'no-store');
  res.json({ csrfToken: token });
});

// All API requests that can change state require the signed token in both the
// host-only cookie and a custom header. Safe methods remain available without it.
app.use('/api', (req: any, res: any, next: any) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const cookieToken = req.cookies?.learnora_csrf;
  const headerToken = req.get('x-csrf-token');
  if (!isValidCsrfToken(cookieToken) || typeof headerToken !== 'string' ||
      headerToken.length !== cookieToken.length ||
      !crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(cookieToken))) {
    return res.status(403).json({ error: 'CSRF-controle mislukt. Vernieuw de pagina en probeer opnieuw.' });
  }
  next();
});

type SessionUser = { id: number; email: string; displayName: string; role: 'admin'|'teacher'|'student' };
const authenticate = (req: any, res: any, next: any) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Log eerst in.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET) as SessionUser & { jti?: string };
    if (!Number.isSafeInteger(payload.id) || typeof payload.jti !== 'string' || !payload.jti) {
      return res.status(401).json({ error: 'Ongeldige sessie. Log opnieuw in.' });
    }
    const session = db.prepare(`SELECT active_organization_id FROM sessions
      WHERE jti=? AND user_id=? AND revoked_at IS NULL AND expires_at>?`)
      .get(payload.jti, payload.id, Math.floor(Date.now() / 1000)) as {active_organization_id:number|null}|undefined;
    if (!session) return res.status(401).json({ error: 'Sessie is beëindigd. Log opnieuw in.' });
    const user = db.prepare('SELECT id,email,display_name as displayName,role,active FROM users WHERE id=?').get(payload.id) as any;
    if (!user || !user.active) return res.status(401).json({ error: 'Account is niet actief.' });
    let organization: {id:number;role:string;displayName:string}|null = null;
    if (session.active_organization_id !== null) {
      organization = db.prepare(`SELECT o.id,m.role,o.display_name AS displayName
        FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id
        WHERE m.organization_id=? AND m.user_id=? AND m.active=1 AND o.status='active'`)
        .get(session.active_organization_id,user.id) as typeof organization;
      if (!organization) return res.status(401).json({ error: 'Organisatiecontext van de sessie is niet meer geldig.' });
    }
    if (organization) user.role = organization.role === 'org_admin' ? 'admin' : organization.role;
    req.user = user;
    req.organization = organization;
    req.organizationId = organization?.id ?? null;
    next();
  } catch { return res.status(401).json({ error: 'Sessie verlopen. Log opnieuw in.' }); }
};
const requireOrganization = (req: any, res: any, next: any) =>
  Number.isSafeInteger(req.organizationId) && req.organizationId > 0
    ? next()
    : res.status(403).json({ error: 'Er is geen actieve schoolorganisatie aan deze sessie gekoppeld.' });
const requireRole = (...roles: string[]) => (req: any, res: any, next: any) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Je hebt geen toegang tot deze functie.' });
const audit = (actor: number, action: string, type: string, id: number|null, details = '', organizationId: number|null = null) =>
  db.prepare('INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details,organization_id) VALUES(?,?,?,?,?,?)')
    .run(actor,action,type,id,details,organizationId);
const canTeachClass = (teacherId: number, classId: number, organizationId: number) =>
  !!db.prepare('SELECT 1 FROM class_teachers WHERE teacher_id=? AND class_id=? AND organization_id=?')
    .get(teacherId,classId,organizationId);
const isBoundedString = (value: unknown, maxLength: number): value is string =>
  typeof value === 'string' && value.length <= maxLength;
const isValidEmail = (value: unknown): value is string =>
  typeof value === 'string' && value.trim().length <= 254 &&
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
const isValidDateOnly = (value: unknown): value is string => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
};
const parsePositiveId = (value: unknown): number | null => {
  const id = typeof value === 'number' ? value : typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : NaN;
  return Number.isSafeInteger(id) && id > 0 ? id : null;
};

const classExists = (classId: number, organizationId: number) =>
  !!db.prepare('SELECT 1 FROM classes WHERE id=? AND organization_id=?').get(classId,organizationId);
const canSeeAssignment = (user: any, assignmentId: number, organizationId: number) => {
  if (user.role === 'admin') return !!db.prepare('SELECT 1 FROM assignments WHERE id=? AND organization_id=?').get(assignmentId,organizationId);
  if (user.role === 'teacher') return !!db.prepare(`SELECT 1 FROM assignments a JOIN assignment_classes ac ON ac.assignment_id=a.id
    JOIN class_teachers ct ON ct.class_id=ac.class_id AND ct.organization_id=?
    WHERE a.id=? AND a.organization_id=? AND ac.organization_id=? AND ct.teacher_id=?`)
    .get(organizationId,assignmentId,organizationId,organizationId,user.id);
  return !!db.prepare(`SELECT 1 FROM assignments a
    JOIN assignment_classes ac ON ac.assignment_id=a.id AND ac.organization_id=?
    JOIN class_students cs ON cs.class_id=ac.class_id AND cs.organization_id=?
    WHERE a.id=? AND a.organization_id=? AND a.status='published' AND cs.student_id=?`)
    .get(organizationId,organizationId,assignmentId,organizationId,user.id);
};


const LOGIN_RATE_WINDOW_SECONDS = 15 * 60;
const LOGIN_RATE_LIMITS = { identity: 10, ip: 30 } as const;
let loginRequestCount = 0;

const loginBucketKey = (kind: 'identity'|'ip', value: string) =>
  `${kind}:${crypto.createHmac('sha256', JWT_SECRET).update(value).digest('hex')}`;

const getBlockedUntil = (keys: string[], now: number): number | null => {
  const placeholders = keys.map(() => '?').join(',');
  const rows = db.prepare(`SELECT blocked_until FROM login_rate_limits
    WHERE bucket_key IN (${placeholders}) AND blocked_until>?`).all(...keys,now) as Array<{blocked_until:number}>;
  return rows.reduce<number|null>((latest,row) =>
    latest===null || row.blocked_until>latest ? row.blocked_until : latest, null);
};

const recordLoginFailures = (buckets: Array<{key:string;limit:number}>, now: number) => {
  const record = db.prepare('SELECT window_started_at,attempts FROM login_rate_limits WHERE bucket_key=?');
  const upsert = db.prepare(`INSERT INTO login_rate_limits(bucket_key,window_started_at,attempts,blocked_until)
    VALUES(?,?,?,?) ON CONFLICT(bucket_key) DO UPDATE SET
    window_started_at=excluded.window_started_at,attempts=excluded.attempts,blocked_until=excluded.blocked_until`);
  const update = db.transaction(() => {
    for (const bucket of buckets) {
      const previous = record.get(bucket.key) as {window_started_at:number;attempts:number}|undefined;
      const expired = !previous || now-previous.window_started_at>=LOGIN_RATE_WINDOW_SECONDS;
      const windowStartedAt = expired ? now : previous.window_started_at;
      const attempts = expired ? 1 : previous.attempts+1;
      const blockedUntil = attempts>=bucket.limit ? now+LOGIN_RATE_WINDOW_SECONDS : null;
      upsert.run(bucket.key,windowStartedAt,attempts,blockedUntil);
    }
  });
  update();
};

app.post('/api/login',(req:any,res:any) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase().slice(0,254) : '';
  const suppliedPassword = typeof req.body.password === 'string' ? req.body.password : '';
  const passwordTooLong = Buffer.byteLength(suppliedPassword, 'utf8') > 1024;
  const password = passwordTooLong ? '' : suppliedPassword;
  const clientAddress = resolveClientIpAddress(
    TRUSTED_CLIENT_IP_HEADER ? req.get(TRUSTED_CLIENT_IP_HEADER) : undefined,
    req.socket?.remoteAddress,
    Boolean(TRUSTED_CLIENT_IP_HEADER),
  );
  const clientIp = clientAddress.ip;
  const identityKey = loginBucketKey('identity',clientIp + String.fromCharCode(0) + email);
  const ipKey = loginBucketKey('ip',clientIp);
  // A socket peer behind a shared reverse proxy is not a unique client IP.
  // Apply the IP-wide bucket only when a trusted ingress header is explicitly configured.
  const rateLimitKeys = clientAddress.source === 'trusted-header' ? [identityKey,ipKey] : [identityKey];
  const now = Math.floor(Date.now()/1000);
  loginRequestCount += 1;
  if (loginRequestCount%100===0) {
    db.prepare('DELETE FROM login_rate_limits WHERE window_started_at<? AND (blocked_until IS NULL OR blocked_until<=?)')
      .run(now-24*60*60,now);
  }

  const blockedUntil = getBlockedUntil(rateLimitKeys,now);
  if (blockedUntil!==null) {
    res.setHeader('Retry-After',String(Math.max(1,blockedUntil-now)));
    res.setHeader('Cache-Control','no-store');
    return res.status(429).json({error:'Te veel mislukte inlogpogingen. Probeer het later opnieuw.'});
  }

  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email) as any;
  const passwordHash = user && user.active && !passwordTooLong ? user.password_hash : DUMMY_PASSWORD_HASH;
  const passwordMatches = bcrypt.compareSync(password,passwordHash);
  if (!user || !user.active || passwordTooLong || !passwordMatches) {
    recordLoginFailures([
      {key:identityKey,limit:LOGIN_RATE_LIMITS.identity},
      ...(clientAddress.source === 'trusted-header' ? [{key:ipKey,limit:LOGIN_RATE_LIMITS.ip}] : []),
    ],now);
    res.setHeader('Cache-Control','no-store');
    return res.status(401).json({error:'E-mailadres of wachtwoord klopt niet.'});
  }
  const memberships = db.prepare(`SELECT m.organization_id,m.role,o.display_name AS displayName
    FROM organization_memberships m JOIN organizations o ON o.id=m.organization_id
    WHERE m.user_id=? AND m.active=1 AND o.status='active'
    ORDER BY m.organization_id`).all(user.id) as Array<{organization_id:number;role:string;displayName:string}>;
  const requestedOrganizationId = req.body.organizationId === undefined ? null : parsePositiveId(req.body.organizationId);
  if (req.body.organizationId !== undefined && requestedOrganizationId === null) {
    return res.status(400).json({error:'Ongeldige organisatie.'});
  }
  const activeMembership = requestedOrganizationId === null
    ? memberships[0] ?? null
    : memberships.find((membership)=>membership.organization_id===requestedOrganizationId) ?? null;
  if (requestedOrganizationId !== null && !activeMembership) {
    return res.status(403).json({error:'Je hebt geen actief lidmaatschap bij deze organisatie.'});
  }
  db.prepare('DELETE FROM login_rate_limits WHERE bucket_key=?').run(identityKey);
  res.setHeader('Cache-Control','no-store');
  db.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?').run(user.id);
  const jti = crypto.randomUUID();
  const expiresAt = Math.floor(Date.now() / 1000) + 8 * 60 * 60;
  db.prepare('DELETE FROM sessions WHERE expires_at<=? OR revoked_at IS NOT NULL').run(Math.floor(Date.now() / 1000));
  const createSession = db.transaction(() => {
    db.prepare('INSERT INTO sessions(jti,user_id,expires_at,active_organization_id) VALUES(?,?,?,?)').run(jti,user.id,expiresAt,activeMembership?.organization_id ?? null);
    audit(user.id,'auth.login','session',null);
  });
  createSession();
  const token = jwt.sign({id:user.id,jti},JWT_SECRET,{expiresIn:'8h'});
  res.cookie('session',token,{httpOnly:true,secure:isProduction,sameSite:'lax',maxAge:8*60*60*1000,path:'/'});
  res.json({user:{id:user.id,email:user.email,displayName:user.display_name,role:user.role,organizationId:activeMembership?.organization_id ?? null,organizationRole:activeMembership?.role ?? null}});
});
app.post('/api/logout',(req,res)=>{
  const token = req.cookies.session;
  if (token) {
    try {
      const payload = jwt.verify(token,JWT_SECRET,{ignoreExpiration:true}) as SessionUser & {jti?:string};
      if (Number.isSafeInteger(payload.id) && typeof payload.jti === 'string' && payload.jti) {
        const revoked = db.prepare('UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE jti=? AND user_id=? AND revoked_at IS NULL')
          .run(payload.jti,payload.id);
        if (revoked.changes > 0) audit(payload.id,'auth.logout','session',null);
      }
    } catch {
      // Invalid or tampered tokens are simply cleared; they cannot identify a trusted session.
    }
  }
  res.clearCookie('session',{path:'/'});
  res.json({success:true});
});
app.get('/api/me',authenticate,(req:any,res)=>res.json({user:{id:req.user.id,email:req.user.email,displayName:req.user.displayName,role:req.user.role,organizationId:req.organizationId,organizationRole:req.organization?.role ?? null}}));

app.post('/api/account/password',authenticate,(req:any,res)=>{
  const currentPassword=req.body.currentPassword;
  const newPassword=req.body.newPassword;
  if(typeof currentPassword!=='string'||!currentPassword||Buffer.byteLength(currentPassword,'utf8')>1024)
    return res.status(400).json({error:'Vul je huidige wachtwoord in.'});
  const passwordError=validatePassword(newPassword);
  if(passwordError) return res.status(400).json({error:passwordError});

  const account=db.prepare('SELECT password_hash FROM users WHERE id=? AND active=1').get(req.user.id) as {password_hash:string}|undefined;
  if(!account||!bcrypt.compareSync(currentPassword,account.password_hash))
    return res.status(400).json({error:'Het huidige wachtwoord klopt niet.'});
  if(bcrypt.compareSync(newPassword,account.password_hash))
    return res.status(400).json({error:'Kies een nieuw wachtwoord dat verschilt van je huidige wachtwoord.'});

  const updatePassword=db.transaction(()=>{
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(newPassword,10),req.user.id);
    db.prepare('UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL').run(req.user.id);
    audit(req.user.id,'user.password_changed','user',req.user.id,'self-service');
  });
  updatePassword();
  res.clearCookie('session',{path:'/'});
  res.setHeader('Cache-Control','no-store');
  res.json({success:true,sessionsRevoked:true,reauthenticate:true});
});

app.get('/api/dashboard',authenticate,(req:any,res)=>{
  const u=req.user;
  if(u.role==='student'){
    const assignments=db.prepare(`SELECT a.*, c.name AS class_name, s.id AS submission_id,s.submitted_at,
      f.status AS review_status,f.comments,f.grade
      FROM assignments a JOIN assignment_classes ac ON ac.assignment_id=a.id
      JOIN classes c ON c.id=ac.class_id JOIN class_students cs ON cs.class_id=c.id
      LEFT JOIN submissions s ON s.assignment_id=a.id AND s.student_id=?
      LEFT JOIN feedback f ON f.submission_id=s.id
      WHERE cs.student_id=? AND a.status='published' ORDER BY a.deadline IS NULL,a.deadline`).all(u.id,u.id);
    return res.json({assignments,classes:db.prepare('SELECT c.* FROM classes c JOIN class_students cs ON cs.class_id=c.id WHERE cs.student_id=?').all(u.id)});
  }
  const classWhere=u.role==='admin'?'':'WHERE ct.teacher_id=?';
  const classes=db.prepare(`SELECT c.*,COUNT(DISTINCT cs.student_id) AS student_count FROM classes c
    ${u.role==='admin'?'LEFT JOIN class_teachers ct ON ct.class_id=c.id':'JOIN class_teachers ct ON ct.class_id=c.id'}
    LEFT JOIN class_students cs ON cs.class_id=c.id ${classWhere} GROUP BY c.id ORDER BY c.name`).all(...(u.role==='admin'?[]:[u.id]));
  const assignmentSql=u.role==='admin'?`SELECT a.*,COUNT(DISTINCT ac.class_id) AS class_count,COUNT(DISTINCT s.id) AS submission_count
    FROM assignments a
    LEFT JOIN assignment_classes ac ON ac.assignment_id=a.id
    LEFT JOIN submissions s ON s.assignment_id=a.id
      AND EXISTS (SELECT 1 FROM class_students csx WHERE csx.class_id=ac.class_id AND csx.student_id=s.student_id)
    GROUP BY a.id ORDER BY a.created_at DESC`:
    `SELECT a.*,COUNT(DISTINCT ac.class_id) AS class_count,COUNT(DISTINCT s.id) AS submission_count
    FROM assignments a
    JOIN assignment_classes ac ON ac.assignment_id=a.id
    JOIN class_teachers ct ON ct.class_id=ac.class_id
    LEFT JOIN submissions s ON s.assignment_id=a.id
      AND EXISTS (SELECT 1 FROM class_students csx WHERE csx.class_id=ac.class_id AND csx.student_id=s.student_id)
    WHERE ct.teacher_id=? GROUP BY a.id ORDER BY a.created_at DESC`;
  const assignments=db.prepare(assignmentSql).all(...(u.role==='admin'?[]:[u.id]));
  const totals=db.prepare(`SELECT COUNT(DISTINCT a.id) assignments,COUNT(DISTINCT s.id) submissions,
    COUNT(DISTINCT cs.student_id) students FROM assignments a
    LEFT JOIN assignment_classes ac ON ac.assignment_id=a.id
    LEFT JOIN class_students cs ON cs.class_id=ac.class_id
    LEFT JOIN submissions s ON s.assignment_id=a.id AND s.student_id=cs.student_id
    ${u.role==='admin'?'':'JOIN class_teachers ct ON ct.class_id=ac.class_id WHERE ct.teacher_id=?'}`).get(...(u.role==='admin'?[]:[u.id]));
  res.json({classes,assignments,totals});
});

app.get('/api/classes',authenticate,requireOrganization,(req:any,res)=>{
  const sql=req.user.role==='admin'?`SELECT c.*,GROUP_CONCAT(DISTINCT u.display_name) teachers FROM classes c LEFT JOIN class_teachers ct ON ct.class_id=c.id AND ct.organization_id=? LEFT JOIN users u ON u.id=ct.teacher_id WHERE c.organization_id=? GROUP BY c.id ORDER BY c.name`:
    req.user.role==='teacher'?`SELECT c.*,GROUP_CONCAT(DISTINCT u.display_name) teachers FROM classes c JOIN class_teachers mine ON mine.class_id=c.id AND mine.organization_id=? LEFT JOIN class_teachers ct ON ct.class_id=c.id AND ct.organization_id=? LEFT JOIN users u ON u.id=ct.teacher_id WHERE c.organization_id=? AND mine.teacher_id=? GROUP BY c.id ORDER BY c.name`:
    `SELECT c.*,'' teachers FROM classes c JOIN class_students cs ON cs.class_id=c.id AND cs.organization_id=? WHERE c.organization_id=? AND cs.student_id=? ORDER BY c.name`;
  const params=req.user.role==='admin'?[req.organizationId,req.organizationId]:
    req.user.role==='teacher'?[req.organizationId,req.organizationId,req.organizationId,req.user.id]:
    [req.organizationId,req.organizationId,req.user.id];
  res.json(db.prepare(sql).all(...params));
});
app.post('/api/classes',authenticate,requireOrganization,requireRole('teacher','admin'),(req:any,res)=>{
  const name=typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const yearGroup=req.body.yearGroup ?? '';
  if(!name||name.length>120||!isBoundedString(yearGroup,32))
    return res.status(400).json({error:'Vul een klasnaam en een geldig leerjaar in (maximaal 120 en 32 tekens).'});
  let assignedTeacherId: number|undefined;
  if(req.user.role==='admin' && req.body.teacherId !== undefined && req.body.teacherId !== null && req.body.teacherId !== ''){
    assignedTeacherId=Number(req.body.teacherId);
    if(!Number.isSafeInteger(assignedTeacherId)||assignedTeacherId<=0||
      !db.prepare("SELECT 1 FROM organization_memberships WHERE organization_id=? AND user_id=? AND role='teacher' AND active=1").get(req.organizationId,assignedTeacherId)){
      return res.status(400).json({error:'Selecteer een actief docentaccount voor deze klas.'});
    }
  }
  const create=db.transaction(()=>{
    const id=db.prepare('INSERT INTO classes(name,year_group,organization_id) VALUES(?,?,?)').run(name,yearGroup,req.organizationId).lastInsertRowid as number;
    if(req.user.role==='teacher') db.prepare('INSERT INTO class_teachers(class_id,teacher_id,organization_id) VALUES(?,?,?)').run(id,req.user.id,req.organizationId);
    else if(assignedTeacherId) db.prepare('INSERT INTO class_teachers(class_id,teacher_id,organization_id) VALUES(?,?,?)').run(id,assignedTeacherId,req.organizationId);
    audit(req.user.id,'class.created','class',id,name,req.organizationId); return id;
  });
  try { res.json({id:create()}); } catch { res.status(400).json({error:'Aanmaken van de klas is niet gelukt.'}); }
});
app.get('/api/classes/:id/students',authenticate,requireOrganization,requireRole('teacher','admin'),(req:any,res)=>{
  const id=parsePositiveId(req.params.id);
  if(id===null) return res.status(400).json({error:'Ongeldig klasnummer.'});
  if(!classExists(id,req.organizationId)) return res.status(404).json({error:'Klas niet gevonden.'});
  if(req.user.role==='teacher'&&!canTeachClass(req.user.id,id,req.organizationId)) return res.status(403).json({error:'Deze klas hoort niet bij jouw account.'});
  const students=db.prepare(`SELECT u.id,u.email,u.display_name AS displayName FROM users u JOIN class_students cs ON cs.student_id=u.id WHERE cs.class_id=? AND cs.organization_id=? AND u.active=1 ORDER BY u.display_name`).all(id,req.organizationId);
  res.json(students);
});
app.post('/api/classes/:id/students',authenticate,requireOrganization,requireRole('teacher','admin'),(req:any,res)=>{
  const classId=parsePositiveId(req.params.id);
  if(classId===null) return res.status(400).json({error:'Ongeldig klasnummer.'});
  if(!classExists(classId,req.organizationId)) return res.status(404).json({error:'Klas niet gevonden.'});
  if(req.user.role==='teacher'&&!canTeachClass(req.user.id,classId,req.organizationId)) return res.status(403).json({error:'Geen toegang tot deze klas.'});
  const email=typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const name=typeof req.body.displayName === 'string' ? req.body.displayName.trim() : '';
  if(!isValidEmail(email)||!name||name.length>120) return res.status(400).json({error:'Vul een geldige naam (maximaal 120 tekens) en e-mailadres in.'});
  let student=db.prepare("SELECT * FROM users WHERE email=?").get(email) as any;
  if(student&&student.role!=='student') return res.status(400).json({error:'Dit account is geen studentaccount.'});
  if(student&&!student.active) return res.status(400).json({error:'Dit studentaccount is niet actief.'});
  const existingMembership = student ? db.prepare('SELECT role FROM organization_memberships WHERE organization_id=? AND user_id=? AND active=1').get(req.organizationId,student.id) as {role:string}|undefined : undefined;
  if(existingMembership && existingMembership.role!=='student') return res.status(400).json({error:'Dit account heeft in deze organisatie geen leerlingrol.'});
  const passwordError=!student?validatePassword(req.body.password):null;
  if(passwordError) return res.status(400).json({error:passwordError});
  const enrollStudent=db.transaction(()=>{
    if(!student){
      const result=db.prepare("INSERT INTO users(email,display_name,password_hash,role) VALUES(?,?,?,'student')")
        .run(email,name,bcrypt.hashSync(req.body.password,10));
      student={id:result.lastInsertRowid};
    }
    db.prepare("INSERT OR IGNORE INTO organization_memberships(organization_id,user_id,role,active) VALUES(?,?,'student',1)").run(req.organizationId,student.id);
    db.prepare('INSERT OR IGNORE INTO class_students(class_id,student_id,organization_id) VALUES(?,?,?)').run(classId,student.id,req.organizationId);
    audit(req.user.id,'student.enrolled','class',classId,email,req.organizationId);
  });
  enrollStudent();
  res.json({success:true,student:{id:student.id,email,displayName:name}});
});

app.get('/api/assignments',authenticate,requireOrganization,(req:any,res)=>{
  if(req.user.role==='student'){
    return res.json(db.prepare(`SELECT a.*,c.name class_name,s.id submission_id,s.submitted_at,f.status review_status,f.comments,f.grade
      FROM assignments a JOIN assignment_classes ac ON ac.assignment_id=a.id JOIN classes c ON c.id=ac.class_id
      JOIN class_students cs ON cs.class_id=c.id AND cs.organization_id=?
      LEFT JOIN submissions s ON s.assignment_id=a.id AND s.student_id=? AND s.organization_id=?
      LEFT JOIN feedback f ON f.submission_id=s.id AND f.organization_id=?
      WHERE cs.student_id=? AND a.organization_id=? AND ac.organization_id=? AND c.organization_id=?
        AND a.status='published' ORDER BY a.deadline`).all(req.organizationId,req.user.id,req.organizationId,req.organizationId,req.user.id,req.organizationId,req.organizationId,req.organizationId));
  }
  const sql=req.user.role==='admin'
    ? `SELECT a.*,GROUP_CONCAT(DISTINCT c.name) class_names FROM assignments a
       LEFT JOIN assignment_classes ac ON ac.assignment_id=a.id AND ac.organization_id=?
       LEFT JOIN classes c ON c.id=ac.class_id AND c.organization_id=?
       WHERE a.organization_id=? GROUP BY a.id ORDER BY a.created_at DESC`
    : `SELECT DISTINCT a.*,GROUP_CONCAT(DISTINCT c.name) class_names FROM assignments a
       JOIN assignment_classes ac ON ac.assignment_id=a.id AND ac.organization_id=?
       JOIN classes c ON c.id=ac.class_id AND c.organization_id=?
       JOIN class_teachers ct ON ct.class_id=c.id AND ct.organization_id=?
       WHERE a.organization_id=? AND ct.teacher_id=? GROUP BY a.id ORDER BY a.created_at DESC`;
  const params=req.user.role==='admin'
    ? [req.organizationId,req.organizationId,req.organizationId]
    : [req.organizationId,req.organizationId,req.organizationId,req.organizationId,req.user.id];
  res.json(db.prepare(sql).all(...params));
});
app.post('/api/assignments',authenticate,requireOrganization,requireRole('teacher','admin'),(req:any,res)=>{
  const title=typeof req.body.title === 'string' ? req.body.title.trim() : '';
  const description=req.body.description ?? '';
  const instructions=req.body.instructions ?? '';
  const deadline=req.body.deadline ?? '';
  const rawClassIds=Array.isArray(req.body.classIds)?req.body.classIds:[];
  const classIds=rawClassIds.map(parsePositiveId);
  if(!title||title.length>200||!classIds.length) return res.status(400).json({error:'Titel (maximaal 200 tekens) en minimaal één klas zijn verplicht.'});
  if(!isBoundedString(description,4000)||!isBoundedString(instructions,8000)||
    !(deadline===''||deadline===null||isValidDateOnly(deadline)))
    return res.status(400).json({error:'Omschrijving, instructies of deadline zijn ongeldig of te lang.'});
  if(classIds.some((id:number|null)=>id===null)) return res.status(400).json({error:'Een of meer klasnummers zijn ongeldig.'});
  const validClassIds=classIds as number[];
  if(new Set(validClassIds).size!==validClassIds.length) return res.status(400).json({error:'Een klas mag maar één keer worden geselecteerd.'});
  if(validClassIds.some((id:number)=>!classExists(id,req.organizationId))) return res.status(400).json({error:'Een of meer geselecteerde klassen bestaan niet.'});
  if(req.user.role==='teacher'&&validClassIds.some((id:number)=>!canTeachClass(req.user.id,id,req.organizationId))) return res.status(403).json({error:'Je kunt alleen opdrachten koppelen aan je eigen klassen.'});
  const create=db.transaction(()=>{
    const id=db.prepare('INSERT INTO assignments(title,description,instructions,deadline,created_by,organization_id) VALUES(?,?,?,?,?,?)')
      .run(title,description,instructions,deadline||null,req.user.id,req.organizationId).lastInsertRowid as number;
    const add=db.prepare('INSERT INTO assignment_classes(assignment_id,class_id,organization_id) VALUES(?,?,?)');
    validClassIds.forEach((classId:number)=>add.run(id,classId,req.organizationId));
    audit(req.user.id,'assignment.created','assignment',id,title,req.organizationId); return id;
  });
  res.json({id:create()});
});
app.delete('/api/assignments/:id',authenticate,requireOrganization,requireRole('teacher','admin'),(req:any,res)=>{
  const id=parsePositiveId(req.params.id);
  if(id===null) return res.status(400).json({error:'Ongeldig opdrachtnummer.'});
  const assignmentInOrganization = !!db.prepare('SELECT 1 FROM assignments WHERE id=? AND organization_id=?').get(id,req.organizationId);
  if(!assignmentInOrganization || !canDeleteAssignment(db,req.user,id)) return res.status(404).json({error:'Opdracht niet gevonden.'});
  const storedFiles=db.prepare('SELECT stored_filename FROM submissions WHERE assignment_id=? AND organization_id=?').all(id,req.organizationId) as Array<{stored_filename:string}>;
  const deleteAssignment=db.transaction(()=>{
    db.prepare('DELETE FROM assignments WHERE id=? AND organization_id=?').run(id,req.organizationId);
    audit(req.user.id,'assignment.deleted','assignment',id,'',req.organizationId);
  });
  deleteAssignment();
  for(const row of storedFiles){
    if(path.basename(row.stored_filename)!==row.stored_filename) continue;
    try{fs.unlinkSync(path.join(uploadDir,row.stored_filename));}catch{}
  }
  res.json({success:true});
});

app.get('/api/assignments/:id/progress',authenticate,requireOrganization,requireRole('teacher','admin'),(req:any,res)=>{
  const id=parsePositiveId(req.params.id);
  if(id===null) return res.status(400).json({error:'Ongeldig opdrachtnummer.'});
  if(!canSeeAssignment(req.user,id,req.organizationId)) return res.status(404).json({error:'Opdracht niet gevonden.'});
  const rows=db.prepare(`SELECT u.id student_id,u.display_name student_name,u.email student_email,c.name class_name,
    s.id submission_id,s.submitted_at,f.status review_status,f.grade
    FROM assignment_classes ac JOIN classes c ON c.id=ac.class_id AND c.organization_id=?
    JOIN class_students cs ON cs.class_id=c.id AND cs.organization_id=? JOIN users u ON u.id=cs.student_id
    LEFT JOIN submissions s ON s.assignment_id=ac.assignment_id AND s.student_id=u.id AND s.organization_id=?
    LEFT JOIN feedback f ON f.submission_id=s.id AND f.organization_id=?
    WHERE ac.assignment_id=? AND ac.organization_id=? ${req.user.role==='teacher'?'AND EXISTS (SELECT 1 FROM class_teachers ct WHERE ct.class_id=c.id AND ct.organization_id=? AND ct.teacher_id=?)':''}
    ORDER BY c.name,u.display_name`).all(...(req.user.role==='teacher'
      ? [req.organizationId,req.organizationId,req.organizationId,req.organizationId,id,req.organizationId,req.organizationId,req.user.id]
      : [req.organizationId,req.organizationId,req.organizationId,req.organizationId,id,req.organizationId]));
  res.json(rows);
});

const defaultUploadDir=isProduction
  ? path.join(process.cwd(),'uploads','submissions')
  : path.join(path.dirname(path.resolve(process.cwd())),`${path.basename(path.resolve(process.cwd()))}-private-uploads`);
const uploadDir=path.resolve(process.env.UPLOAD_DIR || defaultUploadDir);
const publicRoot=path.resolve(isProduction?path.join(process.cwd(),'dist'):process.cwd());
const uploadRelativePath=path.relative(publicRoot,uploadDir);
if(uploadRelativePath===''||(!uploadRelativePath.startsWith(`..${path.sep}`)&&uploadRelativePath!=='..'&&!path.isAbsolute(uploadRelativePath)))
  throw new Error('UPLOAD_DIR must be outside the publicly served web root.');
fs.mkdirSync(uploadDir,{recursive:true});
// Prevent legacy/default project-root uploads from being served by Vite in development.
app.use('/uploads',(_req,res)=>res.status(404).end());
const upload=multer({storage:multer.diskStorage({
  destination:(_req,_file,cb)=>cb(null,uploadDir),
  filename:(_req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())
}),limits:{fileSize:20*1024*1024},fileFilter:(_req,file,cb)=>{
  const ext=path.extname(file.originalname).toLowerCase();
  cb(null,['.pdf','.doc','.docx','.zip'].includes(ext));
}});
app.post('/api/assignments/:id/submit',authenticate,requireRole('student'),(req:any,res,next:any)=>{
  const assignmentId=parsePositiveId(req.params.id);
  if(assignmentId===null) return res.status(400).json({error:'Ongeldig opdrachtnummer.'});
  if(!canSubmitAssignment(db,req.user,assignmentId))
    return res.status(403).json({error:'Deze opdracht is niet beschikbaar voor jouw klas.'});
  next();
},upload.single('file'),(req:any,res)=>{
  const assignmentId=Number(req.params.id), file=req.file;
  if(!file) return res.status(400).json({error:'Kies een PDF-, Word- of ZIP-bestand (maximaal 20 MB).'});
  if (!validateSubmissionFile(file.path, file.originalname, file.mimetype)) {
    try { fs.unlinkSync(file.path); } catch {}
    return res.status(400).json({error:'Het bestandstype komt niet overeen met de inhoud. Upload een geldig PDF-, Word- of ZIP-bestand.'});
  }
  // Re-check authorization inside the same synchronous transaction as the write.
  // No other request can change class membership or assignment links between this check and INSERT.
  const saveSubmission = db.transaction(() => {
    if (!canSubmitAssignment(db,req.user,assignmentId)) return null;
    const previous=db.prepare('SELECT * FROM submissions WHERE assignment_id=? AND student_id=?').get(assignmentId,req.user.id) as any;
    const result=db.prepare(`INSERT INTO submissions(assignment_id,student_id,original_filename,stored_filename,file_size)
      VALUES(?,?,?,?,?) ON CONFLICT(assignment_id,student_id) DO UPDATE SET original_filename=excluded.original_filename,
      stored_filename=excluded.stored_filename,file_size=excluded.file_size,submitted_at=CURRENT_TIMESTAMP`)
      .run(assignmentId,req.user.id,file.originalname,file.filename,file.size);
    const row=db.prepare('SELECT id FROM submissions WHERE assignment_id=? AND student_id=?').get(assignmentId,req.user.id) as any;
    audit(req.user.id,'submission.uploaded','submission',row.id,file.originalname);
    return { id: row.id, previous };
  });
  let saved: ReturnType<typeof saveSubmission>;
  try {
    saved = saveSubmission();
  } catch (error) {
    // Multer has already written the new file. If the database transaction fails,
    // remove that unreferenced file and leave the previous submission untouched.
    try { fs.unlinkSync(file.path); } catch {}
    throw error;
  }
  if (!saved) {
    try { fs.unlinkSync(file.path); } catch {}
    return res.status(403).json({error:'Deze opdracht is niet aan jouw klas gekoppeld.'});
  }
  if(saved.previous){try{fs.unlinkSync(path.join(uploadDir,saved.previous.stored_filename));}catch{}}
  res.json({success:true,id:saved.id});
});
app.post('/api/submissions/:id/feedback',authenticate,requireRole('teacher','admin'),(req:any,res)=>{
  const id=parsePositiveId(req.params.id);
  if(id===null) return res.status(400).json({error:'Ongeldig inzendingsnummer.'});
  if(!canSeeSubmission(db,req.user,id)) return res.status(404).json({error:'Inzending niet gevonden.'});
  const comments=typeof req.body.comments === 'string' ? req.body.comments.trim() : '';
  const grade=req.body.grade ?? '';
  if(!comments||comments.length>10000||!isBoundedString(grade,50))
    return res.status(400).json({error:'Feedback is verplicht (maximaal 10.000 tekens) en het cijfer mag maximaal 50 tekens zijn.'});
  const saveFeedback=db.transaction(()=>{
    db.prepare(`INSERT INTO feedback(submission_id,teacher_id,comments,grade,status,updated_at) VALUES(?,?,?,?, 'reviewed',CURRENT_TIMESTAMP)
      ON CONFLICT(submission_id) DO UPDATE SET teacher_id=excluded.teacher_id,comments=excluded.comments,grade=excluded.grade,status='reviewed',updated_at=CURRENT_TIMESTAMP`)
      .run(id,req.user.id,comments,grade);
    audit(req.user.id,'feedback.saved','submission',id);
  });
  saveFeedback();
  res.json({success:true});
});
app.get('/api/submissions/:id/download',authenticate,(req:any,res)=>{
  const id=parsePositiveId(req.params.id);
  if(id===null) return res.status(400).json({error:'Ongeldig inzendingsnummer.'});
  const row=db.prepare('SELECT * FROM submissions WHERE id=?').get(id) as any;
  if(!row) return res.status(404).json({error:'Inzending niet gevonden.'});
  if(!canSeeSubmission(db,req.user,id)) return res.status(403).json({error:'Geen toegang tot deze inzending.'});
  const file=path.join(uploadDir,row.stored_filename);
  if(!fs.existsSync(file)) return res.status(404).json({error:'Bestand staat niet meer op de server.'});
  res.download(file,row.original_filename,{
    headers:{
      'X-Content-Type-Options':'nosniff',
      'Content-Security-Policy':"sandbox; default-src 'none'",
      'Cross-Origin-Resource-Policy':'same-origin',
      'Cache-Control':'private, no-store',
    },
  });
});

app.get('/api/admin/overview',authenticate,requireRole('admin'),(_req,res)=>{
  res.json({
    users:db.prepare('SELECT role,COUNT(*) count FROM users GROUP BY role').all(),
    classes:db.prepare('SELECT COUNT(*) count FROM classes').get(),
    assignments:db.prepare('SELECT COUNT(*) count FROM assignments').get(),
    submissions:db.prepare('SELECT COUNT(*) count FROM submissions').get(),
    recent:db.prepare(`SELECT l.*,u.display_name actor_name FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.created_at DESC LIMIT 20`).all()
  });
});
app.get('/api/admin/users',authenticate,requireRole('admin'),(_req,res)=>{
  res.json(db.prepare('SELECT id,email,display_name displayName,role,active,last_login lastLogin,created_at createdAt FROM users ORDER BY role,display_name').all());
});
app.patch('/api/admin/users/:id',authenticate,requireRole('admin'),(req:any,res)=>{
  const id=parsePositiveId(req.params.id);
  if(id===null) return res.status(400).json({error:'Ongeldig gebruikers-ID.'});
  const target=db.prepare('SELECT id,email,display_name,role,active FROM users WHERE id=?').get(id) as any;
  if(!target) return res.status(404).json({error:'Gebruiker niet gevonden.'});

  const updates:{role?:string;active?:number;password_hash?:string}={};
  if(Object.prototype.hasOwnProperty.call(req.body,'role')){
    if(!['admin','teacher','student'].includes(req.body.role)) return res.status(400).json({error:'Ongeldige gebruikersrol.'});
    if(req.body.role!==target.role) updates.role=req.body.role;
  }
  if(Object.prototype.hasOwnProperty.call(req.body,'active')){
    if(typeof req.body.active!=='boolean') return res.status(400).json({error:'De accountstatus moet actief of inactief zijn.'});
    if(Number(req.body.active)!==target.active) updates.active=Number(req.body.active);
  }
  if(Object.prototype.hasOwnProperty.call(req.body,'password') && req.body.password!==''){
    const passwordError=validatePassword(req.body.password);
    if(passwordError) return res.status(400).json({error:passwordError});
    updates.password_hash=bcrypt.hashSync(req.body.password,10);
  }
  const changed=Object.keys(updates);
  if(!changed.length) return res.status(400).json({error:'Er zijn geen geldige accountwijzigingen opgegeven.'});
  if(id===req.user.id && (updates.active===0 || (updates.role!==undefined && updates.role!=='admin')))
    return res.status(400).json({error:'Je kunt je eigen beheerdersaccount niet deactiveren of van beheerdersrol veranderen.'});

  const updateUser=db.transaction(()=>{
    const fields=Object.keys(updates);
    const assignments=fields.map(field=>field+'=?').join(',');
    db.prepare(`UPDATE users SET ${assignments} WHERE id=?`).run(...fields.map(field=>(updates as any)[field]),id);
    db.prepare('UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL').run(id);
    audit(req.user.id,'user.security_updated','user',id,changed.join(','));
  });
  updateUser();
  if(id===req.user.id) res.clearCookie('session',{path:'/'});
  res.json({success:true,sessionsRevoked:true,reauthenticate:id===req.user.id});
});
app.post('/api/admin/users',authenticate,requireRole('admin'),(req:any,res)=>{
  const email=typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const name=typeof req.body.displayName === 'string' ? req.body.displayName.trim() : '';
  const role=typeof req.body.role === 'string' ? req.body.role : '';
  const passwordError=validatePassword(req.body.password);
  if(!isValidEmail(email)||!name||name.length>120||!['teacher','student','admin'].includes(role)||passwordError)
    return res.status(400).json({error:passwordError||'Vul naam, geldig e-mailadres en een geldige rol in.'});
  try{
    const createUser=db.transaction(()=>{
      const id=db.prepare('INSERT INTO users(email,display_name,password_hash,role) VALUES(?,?,?,?)')
        .run(email,name,bcrypt.hashSync(req.body.password,10),role).lastInsertRowid;
      audit(req.user.id,'user.created','user',Number(id),email);
      return id;
    });
    const id=createUser();
    res.json({id});
  }catch(error){
    if(error instanceof Error && error.message.includes('UNIQUE constraint failed: users.email'))
      return res.status(400).json({error:'Dit e-mailadres bestaat al.'});
    throw error;
  }
});
app.get('/api/admin/audit',authenticate,requireRole('admin'),(_req,res)=>{
  res.json(db.prepare('SELECT l.*,u.display_name actor_name FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.created_at DESC LIMIT 100').all());
});

app.use('/api',(req,res)=>res.status(404).json({error:'API-endpoint niet gevonden.'}));

// Keep malformed JSON, upload errors and unexpected API failures in a predictable JSON format.
app.use((err: any, req: any, res: any, next: any) => {
  if (res.headersSent) return next(err);
  if (!req.path.startsWith('/api/')) return next(err);

  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Ongeldige JSON-inhoud.' });
  }
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Het verzoek is te groot.' });
  }
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'Het bestand is groter dan 20 MB.'
      : 'Het uploadverzoek is ongeldig.';
    return res.status(status).json({ error: message });
  }

  console.error('API request failed:', err);
  return res.status(500).json({ error: 'Er is een interne fout opgetreden.' });
});

async function startServer(){
  const port=Number(process.env.PORT||3000);
  if(!isProduction){
    const vite=await createViteServer({server:{middlewareMode:true},appType:'spa'});
    app.use(vite.middlewares);
  }else{
    const dist=path.join(process.cwd(),'dist');
    app.use(express.static(dist));
    app.get('*',(_req,res)=>res.sendFile(path.join(dist,'index.html')));
  }
  app.listen(port,'0.0.0.0',()=>console.log('Learnora draait op http://localhost:'+port));
}
startServer();
