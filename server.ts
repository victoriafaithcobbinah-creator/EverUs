import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import fs from 'fs';
import http from 'http';
import multer from 'multer';
import path from 'path';
import QRCode from 'qrcode';
import { createServer as createViteServer } from 'vite';
import { WebSocket, WebSocketServer } from 'ws';
import Database from 'better-sqlite3';


// --- SQLite Database & Schema ---

const dataDir = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

export const dbPath = path.join(dataDir, 'everus.db');
export const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      nickname TEXT DEFAULT '',
      bio TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      public_key_jwk TEXT DEFAULT '',
      encrypted_key_backup TEXT DEFAULT '',
      recovery_code_hash TEXT NOT NULL,
      dark_mode INTEGER NOT NULL DEFAULT 0,
      email_verified INTEGER NOT NULL DEFAULT 0,
      email_2fa_enabled INTEGER NOT NULL DEFAULT 0,
      last_seen_at TEXT DEFAULT '',
      mood_status TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS email_verifications (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'login_otp', 'reset_password')),
      code_hash TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      consumed_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS couples (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL DEFAULT 'Our Space',
      start_date TEXT NOT NULL,
      pin_hash TEXT NOT NULL DEFAULT '',
      pin_failed_attempts INTEGER NOT NULL DEFAULT 0,
      pin_locked_until TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active')),
      active_wallpaper_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS couple_members (
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('creator', 'partner')),
      joined_at TEXT NOT NULL,
      PRIMARY KEY (couple_id, user_id)
    );

    CREATE TRIGGER IF NOT EXISTS enforce_two_couple_members
    BEFORE INSERT ON couple_members
    BEGIN
      SELECT CASE
        WHEN (SELECT COUNT(*) FROM couple_members WHERE couple_id = NEW.couple_id) >= 2
        THEN RAISE(ABORT, 'Couple space already has two members')
      END;
    END;

    CREATE TABLE IF NOT EXISTS invitations (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      code TEXT UNIQUE NOT NULL,
      created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      used_by TEXT REFERENCES users(id),
      used_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_name TEXT NOT NULL,
      platform TEXT NOT NULL,
      public_key_jwk TEXT DEFAULT '',
      last_active_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      category TEXT NOT NULL CHECK (category IN ('partner_a', 'partner_b', 'shared')),
      assigned_to TEXT REFERENCES users(id),
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      due_at TEXT,
      reminder_at TEXT,
      recurrence TEXT NOT NULL DEFAULT 'none' CHECK (recurrence IN ('none', 'daily', 'weekly', 'monthly')),
      is_completed INTEGER NOT NULL DEFAULT 0,
      completed_by TEXT REFERENCES users(id),
      completed_at TEXT,
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS task_completions (
      id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      completed_by TEXT NOT NULL REFERENCES users(id),
      completed_at TEXT NOT NULL,
      note TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS location_preferences (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      is_sharing INTEGER NOT NULL DEFAULT 0,
      is_paused INTEGER NOT NULL DEFAULT 0,
      arrival_alerts_enabled INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS location_updates (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      latitude REAL NOT NULL,
      longitude REAL NOT NULL,
      accuracy REAL DEFAULT 0,
      label TEXT DEFAULT '',
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS saved_places (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      latitude REAL NOT NULL,
      longitude REAL NOT NULL,
      radius_meters INTEGER NOT NULL DEFAULT 200,
      notify_on_arrival INTEGER NOT NULL DEFAULT 1,
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS message_attachments (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      uploader_id TEXT NOT NULL REFERENCES users(id),
      file_path TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      original_name TEXT NOT NULL,
      encrypted_iv TEXT NOT NULL,
      byte_size INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS encrypted_messages (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      sender_id TEXT NOT NULL REFERENCES users(id),
      recipient_id TEXT NOT NULL REFERENCES users(id),
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      sender_pub_jwk TEXT DEFAULT '',
      message_type TEXT NOT NULL DEFAULT 'text',
      attachment_id TEXT REFERENCES message_attachments(id),
      reply_to_id TEXT,
      reactions_json TEXT NOT NULL DEFAULT '{}',
      is_edited INTEGER NOT NULL DEFAULT 0,
      is_deleted INTEGER NOT NULL DEFAULT 0,
      delivered_at TEXT,
      read_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS love_interactions (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      sender_id TEXT NOT NULL REFERENCES users(id),
      recipient_id TEXT NOT NULL REFERENCES users(id),
      kind TEXT NOT NULL CHECK (kind IN ('heart', 'kiss', 'hug', 'note')),
      message TEXT NOT NULL,
      response_emoji TEXT,
      responded_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS game_sessions (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      game_type TEXT NOT NULL,
      state_json TEXT NOT NULL,
      turn_user_id TEXT REFERENCES users(id),
      status TEXT NOT NULL DEFAULT 'active',
      score_a INTEGER NOT NULL DEFAULT 0,
      score_b INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plans (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_date TEXT DEFAULT '',
      budget REAL DEFAULT 0,
      assigned_to TEXT REFERENCES users(id),
      checklist_json TEXT NOT NULL DEFAULT '[]',
      progress INTEGER NOT NULL DEFAULT 0,
      notes TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'planned',
      created_by TEXT NOT NULL REFERENCES users(id),
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS plan_updates (
      id TEXT PRIMARY KEY,
      plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id),
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memory_albums (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      cover_url TEXT DEFAULT '',
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memories (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      album_id TEXT REFERENCES memory_albums(id) ON DELETE SET NULL,
      uploader_id TEXT NOT NULL REFERENCES users(id),
      media_url TEXT NOT NULL,
      media_type TEXT NOT NULL CHECK (media_type IN ('image', 'video')),
      caption TEXT DEFAULT '',
      memory_date TEXT NOT NULL,
      location_label TEXT DEFAULT '',
      is_favorite INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memory_comments (
      id TEXT PRIMARY KEY,
      memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id),
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS special_dates (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      date_value TEXT NOT NULL,
      category TEXT NOT NULL,
      recurring_yearly INTEGER NOT NULL DEFAULT 1,
      reminder_days_before INTEGER NOT NULL DEFAULT 3,
      notes TEXT DEFAULT '',
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS wallpapers (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      created_by TEXT NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      background_url TEXT NOT NULL,
      template_id TEXT NOT NULL,
      config_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'approved', 'archived')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS wallpaper_approvals (
      wallpaper_id TEXT NOT NULL REFERENCES wallpapers(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      approved INTEGER NOT NULL,
      responded_at TEXT NOT NULL,
      PRIMARY KEY (wallpaper_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS goals (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      owner_id TEXT NOT NULL REFERENCES users(id),
      scope TEXT NOT NULL CHECK (scope IN ('personal', 'shared')),
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      target_date TEXT DEFAULT '',
      progress INTEGER NOT NULL DEFAULT 0,
      is_completed INTEGER NOT NULL DEFAULT 0,
      encouragement_note TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS habits (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      owner_id TEXT NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      frequency TEXT NOT NULL DEFAULT 'daily',
      streak INTEGER NOT NULL DEFAULT 0,
      last_completed_date TEXT DEFAULT '',
      history_json TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      payload_json TEXT NOT NULL DEFAULT '{}',
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notification_preferences (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      messages INTEGER NOT NULL DEFAULT 1,
      love INTEGER NOT NULL DEFAULT 1,
      tasks INTEGER NOT NULL DEFAULT 1,
      memories INTEGER NOT NULL DEFAULT 1,
      dates INTEGER NOT NULL DEFAULT 1,
      plans INTEGER NOT NULL DEFAULT 1,
      games INTEGER NOT NULL DEFAULT 1,
      location INTEGER NOT NULL DEFAULT 1,
      wallpapers INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS saved_verses (
      id TEXT PRIMARY KEY,
      couple_id TEXT NOT NULL REFERENCES couples(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reference TEXT NOT NULL,
      verse_text TEXT NOT NULL,
      note TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_tasks_couple ON tasks(couple_id);
    CREATE INDEX IF NOT EXISTS idx_messages_couple ON encrypted_messages(couple_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_memories_couple ON memories(couple_id, memory_date);
    CREATE INDEX IF NOT EXISTS idx_plans_couple ON plans(couple_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
    CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email, purpose, created_at);
  `);

  // Non-destructive column migrations for existing databases
  const userCols = db.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>;
  const colNames = new Set(userCols.map((c) => c.name));
  if (!colNames.has('email_verified')) {
    db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0');
  }
  if (!colNames.has('email_2fa_enabled')) {
    db.exec('ALTER TABLE users ADD COLUMN email_2fa_enabled INTEGER NOT NULL DEFAULT 0');
  }
  if (!colNames.has('last_seen_at')) {
    db.exec("ALTER TABLE users ADD COLUMN last_seen_at TEXT DEFAULT ''");
  }
  if (!colNames.has('mood_status')) {
    db.exec("ALTER TABLE users ADD COLUMN mood_status TEXT DEFAULT ''");
  }
}

// --- Daily Bible Verses ---
// Public-domain World English Bible (WEB) & King James Version (KJV) daily verses
// Rotates deterministically each day of the year so partners always see a fresh verse.
export interface DailyVerse {
  reference: string;
  text: string;
  translation: string;
}

export const BIBLE_VERSES: DailyVerse[] = [
  {
    reference: '1 Corinthians 13:4–7',
    text: 'Love is patient and is kind. Love doesn’t envy. Love doesn’t brag, is not proud, doesn’t behave itself inappropriately, doesn’t seek its own way, is not provoked, takes no account of evil; bears all things, believes all things, hopes all things, and endures all things.',
    translation: 'WEB',
  },
  {
    reference: 'Song of Solomon 8:7',
    text: 'Many waters can’t quench love, neither can floods drown it. If a man would give all the wealth of his house for love, he would be utterly scorned.',
    translation: 'WEB',
  },
  {
    reference: 'Ecclesiastes 4:9–10',
    text: 'Two are better than one, because they have a good reward for their labor. For if they fall, the one will lift up his fellow.',
    translation: 'WEB',
  },
  {
    reference: 'Colossians 3:14',
    text: 'Above all these things, walk in love, which is the bond of perfection.',
    translation: 'WEB',
  },
  {
    reference: '1 John 4:18',
    text: 'There is no fear in love; but perfect love casts out fear, because fear has punishment. He who fears is not made perfect in love.',
    translation: 'WEB',
  },
  {
    reference: 'Proverbs 3:3–4',
    text: 'Don’t let kindness and truth forsake you. Bind them around your neck. Write them on the tablet of your heart. So you will find favor, and good understanding in the sight of God and man.',
    translation: 'WEB',
  },
  {
    reference: 'Ruth 1:16',
    text: 'Don’t urge me to leave you, and to return from following you, for where you go, I will go; and where you stay, I will stay. Your people will be my people, and your God my God.',
    translation: 'WEB',
  },
  {
    reference: 'Ephesians 4:2',
    text: 'With all lowliness and humility, with patience, bearing with one another in love.',
    translation: 'WEB',
  },
  {
    reference: 'Song of Solomon 3:4',
    text: 'I found him whom my soul loves. I held him, and would not let him go.',
    translation: 'WEB',
  },
  {
    reference: '1 Peter 4:8',
    text: 'And above all things be earnest in your love among yourselves, for love covers a multitude of sins.',
    translation: 'WEB',
  },
  {
    reference: 'Philippians 1:3',
    text: 'I thank my God whenever I remember you.',
    translation: 'WEB',
  },
  {
    reference: 'John 15:12',
    text: 'This is my commandment, that you love one another, even as I have loved you.',
    translation: 'WEB',
  },
  {
    reference: 'Romans 12:10',
    text: 'In love of the brothers be tenderly affectionate to one another; in honor preferring one another.',
    translation: 'WEB',
  },
  {
    reference: 'Proverbs 17:17',
    text: 'A friend loves at all times; and a brother is born for adversity.',
    translation: 'WEB',
  },
  {
    reference: 'Psalm 138:8',
    text: 'Yahweh will fulfill that which concerns me. Your loving kindness, Yahweh, endures forever.',
    translation: 'WEB',
  },
  {
    reference: '1 Corinthians 16:14',
    text: 'Let all that you do be done in love.',
    translation: 'WEB',
  },
  {
    reference: 'Psalm 143:8',
    text: 'Cause me to hear your loving kindness in the morning, for I trust in you. Cause me to know the way in which I should walk, for I lift up my soul to you.',
    translation: 'WEB',
  },
  {
    reference: 'Jeremiah 29:11',
    text: 'For I know the thoughts that I think toward you, says Yahweh, thoughts of peace, and not of evil, to give you hope and a future.',
    translation: 'WEB',
  },
  {
    reference: 'Ephesians 4:32',
    text: 'Be kind to one another, tenderhearted, forgiving each other, just as God also in Christ forgave you.',
    translation: 'WEB',
  },
  {
    reference: 'Song of Solomon 2:16',
    text: 'My beloved is mine, and I am his.',
    translation: 'WEB',
  },
  {
    reference: '1 John 4:19',
    text: 'We love him, because he first loved us.',
    translation: 'WEB',
  },
  {
    reference: 'Lamentations 3:22–23',
    text: 'It is because of Yahweh’s loving kindnesses that we are not consumed, because his compassion doesn’t fail. They are new every morning. Great is your faithfulness.',
    translation: 'WEB',
  },
  {
    reference: 'Proverbs 31:29',
    text: 'Many women do noble things, but you excel them all.',
    translation: 'WEB',
  },
  {
    reference: '1 Thessalonians 3:12',
    text: 'May the Lord make you to increase and abound in love toward one another, and toward all men, even as we also do toward you.',
    translation: 'WEB',
  },
  {
    reference: 'Psalm 37:4',
    text: 'Also delight yourself in Yahweh, and he will give you the desires of your heart.',
    translation: 'WEB',
  },
  {
    reference: 'Proverbs 16:9',
    text: 'A man’s heart plans his course, but Yahweh directs his steps.',
    translation: 'WEB',
  },
  {
    reference: 'Romans 15:5–6',
    text: 'Now the God of patience and of encouragement grant you to be of the same mind with one another according to Christ Jesus, that with one accord you may with one mouth glorify the God and Father of our Lord Jesus Christ.',
    translation: 'WEB',
  },
  {
    reference: 'Matthew 19:6',
    text: 'So that they are no more two, but one flesh. What therefore God has joined together, don’t let man tear apart.',
    translation: 'WEB',
  },
  {
    reference: 'Zephaniah 3:17',
    text: 'Yahweh, your God, is among you, a mighty one who will save. He will rejoice over you with joy. He will calm you in his love. He will rejoice over you with singing.',
    translation: 'WEB',
  },
  {
    reference: 'Psalm 90:14',
    text: 'Satisfy us in the morning with your loving kindness, that we may rejoice and be glad all our days.',
    translation: 'WEB',
  },
  {
    reference: '2 Thessalonians 3:5',
    text: 'May the Lord direct your hearts into God’s love, and into the perseverance of Christ.',
    translation: 'WEB',
  },
];

export function getVerseForDate(date = new Date()): DailyVerse & { dayKey: string } {
  const start = new Date(date.getFullYear(), 0, 0);
  const diff = date.getTime() - start.getTime();
  const oneDay = 1000 * 60 * 60 * 24;
  const dayOfYear = Math.floor(diff / oneDay);
  const index = (dayOfYear + date.getFullYear()) % BIBLE_VERSES.length;
  const dayKey = date.toISOString().slice(0, 10);
  return {
    ...BIBLE_VERSES[index],
    dayKey,
  };
}

initDatabase();

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const UPLOADS_ROOT = path.resolve(process.cwd(), 'uploads');
if (!fs.existsSync(UPLOADS_ROOT)) {
  fs.mkdirSync(UPLOADS_ROOT, { recursive: true });
}

// --- Password, PIN & Token Cryptography ---
function hashSecret(plain: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifySecret(plain: string, stored: string): boolean {
  if (!stored || !stored.includes(':')) return false;
  const [salt, expectedHex] = stored.split(':');
  const derived = crypto.scryptSync(plain, salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function hashToken(rawToken: string): string {
  return crypto.createHmac('sha256', SESSION_SECRET).update(rawToken).digest('hex');
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      const k = part.slice(0, idx).trim();
      const v = decodeURIComponent(part.slice(idx + 1).trim());
      result[k] = v;
    }
  }
  return result;
}

function setSessionCookie(res: Response, rawToken: string, req: Request) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const parts = [
    `everus_sid=${encodeURIComponent(rawToken)}`,
    'Path=/',
    'HttpOnly',
    `Max-Age=${60 * 60 * 24 * 30}`,
  ];
  if (isHttps) {
    parts.push('Secure', 'SameSite=None', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res: Response, req: Request) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const parts = ['everus_sid=', 'Path=/', 'HttpOnly', 'Max-Age=0'];
  if (isHttps) {
    parts.push('Secure', 'SameSite=None', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }
  res.setHeader('Set-Cookie', parts.join('; '));
}

// --- In-Memory Rate Limiter for Auth Endpoints ---
const authAttempts = new Map<string, { count: number; resetAt: number }>();
function checkRateLimit(key: string, maxAttempts = 20, windowMs = 15 * 60 * 1000): boolean {
  const now = Date.now();
  const entry = authAttempts.get(key);
  if (!entry || entry.resetAt < now) {
    authAttempts.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= maxAttempts) return false;
  entry.count += 1;
  return true;
}

// --- WebSocket Room Registry ---
interface ConnectedClient {
  ws: WebSocket;
  userId: string;
  coupleId: string;
}
const wsClients = new Set<ConnectedClient>();

function isUserOnline(userId: string | null | undefined): boolean {
  if (!userId) return false;
  for (const client of wsClients) {
    if (client.userId === userId && client.ws.readyState === WebSocket.OPEN) {
      return true;
    }
  }
  return false;
}

function broadcastToCouple(coupleId: string, event: string, payload: unknown, excludeUserId?: string) {
  const message = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
  for (const client of wsClients) {
    if (client.coupleId === coupleId && client.ws.readyState === WebSocket.OPEN) {
      if (excludeUserId && client.userId === excludeUserId) continue;
      client.ws.send(message);
    }
  }
}

async function deliverEmailOtp(
  toEmail: string,
  displayName: string,
  code: string,
  purpose: 'verify_email' | 'login_otp' | 'reset_password'
): Promise<{ delivered: boolean; provider: 'resend' | 'preview'; previewCode?: string }> {
  const subjectMap = {
    verify_email: 'Verify your EverUs email address',
    login_otp: 'Your EverUs sign-in verification code',
    reset_password: 'Reset your EverUs password',
  };
  const headingMap = {
    verify_email: 'Confirm your EverUs email',
    login_otp: 'Sign in to EverUs',
    reset_password: 'Reset your EverUs password',
  };
  const apiKey = process.env.RESEND_API_KEY?.trim();
  const fromEmail = process.env.EMAIL_FROM?.trim() || 'EverUs <onboarding@resend.dev>';

  if (apiKey) {
    try {
      const resp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [toEmail],
          subject: subjectMap[purpose],
          html: `
            <div style="font-family:sans-serif;max-width:460px;margin:0 auto;padding:24px;background:#fff5f8;border-radius:20px;border:1px solid #fbcfe8;color:#3b1426;">
              <h2 style="margin:0 0 8px;">${headingMap[purpose]}</h2>
              <p style="margin:0 0 18px;">Hi ${displayName || 'there'}, use this single-use 6-digit authentication code within 10 minutes:</p>
              <div style="font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;padding:16px;background:#ffffff;border-radius:14px;border:1px solid #f9a8d4;">${code}</div>
              <p style="margin:18px 0 0;font-size:12px;color:#831843;">EverUs — Two lives. One shared journey.</p>
            </div>
          `,
        }),
      });
      if (resp.ok) {
        return { delivered: true, provider: 'resend' };
      }
      console.warn('Resend API returned non-OK status:', resp.status);
    } catch (err) {
      console.warn('Failed sending email via Resend:', err);
    }
  }

  console.info(`[EverUs Email Auth] ${purpose} code generated for ${toEmail} (configure RESEND_API_KEY for live inbox delivery).`);
  return {
    delivered: false,
    provider: 'preview',
    previewCode: process.env.NODE_ENV !== 'production' ? code : undefined,
  };
}

function issueEmailOtpRecord(userId: string | null, email: string, purpose: 'verify_email' | 'login_otp' | 'reset_password'): string {
  const code = String(crypto.randomInt(100000, 1000000));
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  db.prepare(
    `UPDATE email_verifications SET consumed_at = ? WHERE email = ? AND purpose = ? AND consumed_at IS NULL`
  ).run(now.toISOString(), email, purpose);
  db.prepare(
    `INSERT INTO email_verifications (id, user_id, email, purpose, code_hash, attempts, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, 0, ?, ?)`
  ).run(crypto.randomUUID(), userId, email, purpose, hashSecret(code), expiresAt, now.toISOString());
  return code;
}

function verifyEmailOtpRecord(
  email: string,
  purpose: 'verify_email' | 'login_otp' | 'reset_password',
  code: string
): { ok: true; userId: string | null } | { ok: false; error: string } {
  const record = db
    .prepare(
      `SELECT * FROM email_verifications
       WHERE email = ? AND purpose = ? AND consumed_at IS NULL
       ORDER BY created_at DESC LIMIT 1`
    )
    .get(email, purpose) as Record<string, unknown> | undefined;

  if (!record) {
    return { ok: false, error: 'No active verification code found. Request a new code.' };
  }
  if (new Date(String(record.expires_at)).getTime() < Date.now()) {
    return { ok: false, error: 'Verification code expired. Please request a fresh code.' };
  }
  if (Number(record.attempts) >= 5) {
    return { ok: false, error: 'Too many incorrect code attempts. Request a new code.' };
  }

  const cleanCode = code.replace(/\D/g, '').slice(0, 6);
  if (!verifySecret(cleanCode, String(record.code_hash))) {
    db.prepare('UPDATE email_verifications SET attempts = attempts + 1 WHERE id = ?').run(String(record.id));
    return { ok: false, error: 'Incorrect 6-digit verification code.' };
  }

  db.prepare('UPDATE email_verifications SET consumed_at = ? WHERE id = ?').run(new Date().toISOString(), String(record.id));
  return { ok: true, userId: record.user_id ? String(record.user_id) : null };
}

function createNotification(
  coupleId: string,
  targetUserId: string,
  type: string,
  title: string,
  body: string,
  payload: Record<string, unknown> = {}
) {
  const pref = db.prepare('SELECT * FROM notification_preferences WHERE user_id = ?').get(targetUserId) as
    | Record<string, number>
    | undefined;
  if (pref && type in pref && pref[type] === 0) return;

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO notifications (id, couple_id, user_id, type, title, body, payload_json, is_read, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
  ).run(id, coupleId, targetUserId, type, title, body, JSON.stringify(payload), now);

  broadcastToCouple(coupleId, 'notification:new', {
    id,
    user_id: targetUserId,
    type,
    title,
    body,
    payload,
    is_read: 0,
    created_at: now,
  });
}

// --- Auth Types & Middleware ---
interface AuthedRequest extends Request {
  auth?: {
    userId: string;
    deviceId: string;
    coupleId: string | null;
    tokenHash: string;
  };
}

function resolveSessionToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    return header.slice(7).trim();
  }
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.everus_sid) {
    return cookies.everus_sid;
  }
  return null;
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const rawToken = resolveSessionToken(req);
  if (!rawToken) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  // CSRF check for cookie-only state-changing requests
  const usedBearer = Boolean(req.headers.authorization?.startsWith('Bearer '));
  if (!usedBearer && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const customHeader = req.headers['x-requested-with'];
    const origin = req.headers.origin;
    const host = (req.headers['x-forwarded-host'] as string) || req.headers.host || '';
    const originHost = origin ? new URL(origin).host : '';
    if (customHeader !== 'EverUs' && (!originHost || originHost !== host)) {
      res.status(403).json({ error: 'Invalid request origin' });
      return;
    }
  }

  const tokenHash = hashToken(rawToken);
  const session = db
    .prepare(
      `SELECT s.user_id, s.device_id, s.expires_at, cm.couple_id
       FROM sessions s
       LEFT JOIN couple_members cm ON cm.user_id = s.user_id
       WHERE s.token_hash = ?`
    )
    .get(tokenHash) as
    | { user_id: string; device_id: string; expires_at: string; couple_id: string | null }
    | undefined;

  if (!session || new Date(session.expires_at).getTime() < Date.now()) {
    res.status(401).json({ error: 'Session expired or invalid' });
    return;
  }

  db.prepare('UPDATE devices SET last_active_at = ? WHERE id = ?').run(new Date().toISOString(), session.device_id);
  req.auth = {
    userId: session.user_id,
    deviceId: session.device_id,
    coupleId: session.couple_id || null,
    tokenHash,
  };
  next();
}

function requireCouple(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.auth?.coupleId) {
    res.status(403).json({ error: 'No couple space joined yet' });
    return;
  }
  next();
}

function getPartnerId(coupleId: string, currentUserId: string): string | null {
  const row = db
    .prepare('SELECT user_id FROM couple_members WHERE couple_id = ? AND user_id != ?')
    .get(coupleId, currentUserId) as { user_id: string } | undefined;
  return row?.user_id || null;
}

function sanitizeUser(row: Record<string, unknown> | undefined) {
  if (!row) return null;
  const { password_hash: _p, recovery_code_hash: _r, ...safe } = row;
  return safe;
}

function sanitizeCouple(row: Record<string, unknown> | undefined) {
  if (!row) return null;
  const { pin_hash, ...rest } = row;
  return {
    ...rest,
    has_pin: Boolean(pin_hash),
  };
}

// --- Safe Upload Configuration ---
const upload = multer({
  storage: multer.diskStorage({
    destination: (req: AuthedRequest, _file, cb) => {
      const folder = req.auth?.coupleId || `user_${req.auth?.userId || 'anon'}`;
      const targetDir = path.resolve(UPLOADS_ROOT, folder);
      if (!targetDir.startsWith(UPLOADS_ROOT + path.sep)) {
        cb(new Error('Invalid upload path'), UPLOADS_ROOT);
        return;
      }
      fs.mkdirSync(targetDir, { recursive: true });
      cb(null, targetDir);
    },
    filename: (_req, file, cb) => {
      const safeExt = path.extname(file.originalname).replace(/[^a-zA-Z0-9.]/g, '').slice(0, 10) || '.bin';
      cb(null, `${Date.now()}_${crypto.randomBytes(8).toString('hex')}${safeExt}`);
    },
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = [
      'image/jpeg',
      'image/png',
      'image/webp',
      'image/gif',
      'video/mp4',
      'video/webm',
      'video/quicktime',
      'audio/webm',
      'audio/mp4',
      'audio/mpeg',
      'audio/ogg',
      'application/pdf',
      'application/octet-stream',
    ];
    if (allowed.includes(file.mimetype) || file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/') || file.mimetype.startsWith('audio/')) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'));
    }
  },
});

function haversineMeters(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371e3;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// --- Express App Setup ---
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '6mb' }));

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'EverUs' });
});

// --- 1. Authentication, Accounts & Device Management ---
app.post('/api/auth/register', (req, res) => {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(`reg:${ip}`, 30)) {
    res.status(429).json({ error: 'Too many registration attempts. Please wait a moment.' });
    return;
  }

  const { email, password, displayName, nickname, bio, publicKeyJwk, encryptedKeyBackup, deviceName, platform } = req.body || {};
  if (typeof email !== 'string' || !email.includes('@') || typeof password !== 'string' || password.length < 6) {
    res.status(400).json({ error: 'Valid email and password (min 6 characters) are required.' });
    return;
  }
  const cleanEmail = email.trim().toLowerCase();
  const cleanName = typeof displayName === 'string' && displayName.trim() ? displayName.trim().slice(0, 40) : cleanEmail.split('@')[0];

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
  if (existing) {
    res.status(409).json({ error: 'An account with this email already exists.' });
    return;
  }

  const userId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const recoveryCode = `EV-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO users (id, email, password_hash, display_name, nickname, bio, public_key_jwk, encrypted_key_backup, recovery_code_hash, last_seen_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    userId,
    cleanEmail,
    hashSecret(password),
    cleanName,
    typeof nickname === 'string' ? nickname.trim().slice(0, 40) : '',
    typeof bio === 'string' ? bio.trim().slice(0, 200) : '',
    publicKeyJwk ? JSON.stringify(publicKeyJwk) : '',
    typeof encryptedKeyBackup === 'string' ? encryptedKeyBackup : '',
    hashSecret(recoveryCode),
    now,
    now
  );

  db.prepare('INSERT INTO notification_preferences (user_id) VALUES (?)').run(userId);

  db.prepare(
    `INSERT INTO devices (id, user_id, device_name, platform, public_key_jwk, last_active_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    deviceId,
    userId,
    typeof deviceName === 'string' && deviceName ? deviceName.slice(0, 60) : 'Primary Mobile Device',
    typeof platform === 'string' && platform ? platform.slice(0, 30) : 'Web / PWA',
    publicKeyJwk ? JSON.stringify(publicKeyJwk) : '',
    now,
    now
  );

  const rawToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (id, token_hash, user_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    crypto.randomUUID(),
    hashToken(rawToken),
    userId,
    deviceId,
    expiresAt,
    now
  );

  const otp = issueEmailOtpRecord(userId, cleanEmail, 'verify_email');
  deliverEmailOtp(cleanEmail, cleanName, otp, 'verify_email').then((emailResult) => {
    setSessionCookie(res, rawToken, req);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as Record<string, unknown>;
    res.status(201).json({
      token: rawToken,
      recoveryCode,
      emailVerification: {
        sent: true,
        provider: emailResult.provider,
        previewCode: emailResult.previewCode,
      },
      user: sanitizeUser(user),
      couple: null,
      partner: null,
      partnerOnline: false,
      deviceId,
    });
  });
});

app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(`login:${ip}`, 25)) {
    res.status(429).json({ error: 'Too many login attempts. Please wait a few minutes.' });
    return;
  }

  const { email, password, emailOtp, deviceName, platform, publicKeyJwk } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) as Record<string, unknown> | undefined;
  if (!user || !verifySecret(password, String(user.password_hash))) {
    res.status(401).json({ error: 'Incorrect email or password.' });
    return;
  }

  // Enforce Email 2FA when enabled on this account
  if (Number(user.email_2fa_enabled) === 1) {
    if (typeof emailOtp !== 'string' || !emailOtp.trim()) {
      const code = issueEmailOtpRecord(String(user.id), cleanEmail, 'login_otp');
      const delivery = await deliverEmailOtp(cleanEmail, String(user.display_name || ''), code, 'login_otp');
      res.json({
        requiresEmailOtp: true,
        email: cleanEmail,
        provider: delivery.provider,
        previewCode: delivery.previewCode,
      });
      return;
    }
    const check = verifyEmailOtpRecord(cleanEmail, 'login_otp', emailOtp);
    if (!check.ok) {
      res.status(401).json({ error: check.error });
      return;
    }
  }

  const userId = String(user.id);
  const deviceId = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(now, userId);
  if (publicKeyJwk && !user.public_key_jwk) {
    db.prepare('UPDATE users SET public_key_jwk = ? WHERE id = ?').run(JSON.stringify(publicKeyJwk), userId);
  }

  db.prepare(
    `INSERT INTO devices (id, user_id, device_name, platform, public_key_jwk, last_active_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    deviceId,
    userId,
    typeof deviceName === 'string' && deviceName ? deviceName.slice(0, 60) : 'Mobile Browser',
    typeof platform === 'string' && platform ? platform.slice(0, 30) : 'Web / PWA',
    publicKeyJwk ? JSON.stringify(publicKeyJwk) : String(user.public_key_jwk || ''),
    now,
    now
  );

  const rawToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (id, token_hash, user_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    crypto.randomUUID(),
    hashToken(rawToken),
    userId,
    deviceId,
    expiresAt,
    now
  );

  setSessionCookie(res, rawToken, req);
  const membership = db.prepare('SELECT couple_id FROM couple_members WHERE user_id = ?').get(userId) as { couple_id: string } | undefined;
  const couple = membership
    ? (db.prepare('SELECT * FROM couples WHERE id = ?').get(membership.couple_id) as Record<string, unknown>)
    : null;
  const partnerRow = membership
    ? (db
        .prepare(
          `SELECT u.* FROM couple_members cm JOIN users u ON u.id = cm.user_id
           WHERE cm.couple_id = ? AND cm.user_id != ?`
        )
        .get(membership.couple_id, userId) as Record<string, unknown> | undefined)
    : undefined;

  const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as Record<string, unknown>;
  res.json({
    token: rawToken,
    user: sanitizeUser(updatedUser),
    couple: sanitizeCouple(couple || undefined),
    partner: sanitizeUser(partnerRow),
    partnerOnline: isUserOnline(partnerRow ? String(partnerRow.id) : null),
    deviceId,
  });
});

// Send Email Verification / Sign-In / Reset OTP
app.post('/api/auth/email/send-code', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(`emailotp:${ip}`, 20)) {
    res.status(429).json({ error: 'Too many code requests. Please wait a minute.' });
    return;
  }

  const { email, purpose } = req.body || {};
  const allowedPurpose = purpose === 'verify_email' || purpose === 'login_otp' || purpose === 'reset_password' ? purpose : null;
  if (!allowedPurpose) {
    res.status(400).json({ error: 'Invalid verification purpose.' });
    return;
  }

  // If authenticated & verify_email, prefer session user's email
  const rawToken = resolveSessionToken(req);
  let targetUser: Record<string, unknown> | undefined;
  if (rawToken) {
    const sess = db
      .prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?')
      .get(hashToken(rawToken)) as { user_id: string; expires_at: string } | undefined;
    if (sess && new Date(sess.expires_at).getTime() >= Date.now()) {
      targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(sess.user_id) as Record<string, unknown> | undefined;
    }
  }

  const cleanEmail =
    typeof email === 'string' && email.includes('@')
      ? email.trim().toLowerCase()
      : targetUser
        ? String(targetUser.email)
        : '';

  if (!cleanEmail) {
    res.status(400).json({ error: 'Valid email address is required.' });
    return;
  }

  if (!targetUser) {
    targetUser = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) as Record<string, unknown> | undefined;
  }

  if (!targetUser) {
    // Avoid user enumeration on unauthenticated requests
    res.json({ ok: true, provider: process.env.RESEND_API_KEY ? 'resend' : 'preview' });
    return;
  }

  const code = issueEmailOtpRecord(String(targetUser.id), cleanEmail, allowedPurpose);
  const delivery = await deliverEmailOtp(cleanEmail, String(targetUser.display_name || ''), code, allowedPurpose);
  res.json({
    ok: true,
    provider: delivery.provider,
    previewCode: delivery.previewCode,
  });
});

// Verify Email Address (Post-Signup or Settings)
app.post('/api/auth/email/verify', requireAuth, (req: AuthedRequest, res) => {
  const { code } = req.body || {};
  if (typeof code !== 'string' || code.replace(/\D/g, '').length !== 6) {
    res.status(400).json({ error: 'Enter the 6-digit code sent to your email.' });
    return;
  }
  const current = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown>;
  const check = verifyEmailOtpRecord(String(current.email), 'verify_email', code);
  if (!check.ok) {
    res.status(400).json({ error: check.error });
    return;
  }
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(req.auth!.userId);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown>;
  res.json({ ok: true, user: sanitizeUser(updated) });
});

// Passwordless Sign-In with Email Verification Code
app.post('/api/auth/email/login-otp', (req, res) => {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(`loginotp:${ip}`, 20)) {
    res.status(429).json({ error: 'Too many attempts. Please wait a minute.' });
    return;
  }
  const { email, code, deviceName, platform, publicKeyJwk } = req.body || {};
  if (typeof email !== 'string' || typeof code !== 'string') {
    res.status(400).json({ error: 'Email and 6-digit code are required.' });
    return;
  }
  const cleanEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) as Record<string, unknown> | undefined;
  if (!user) {
    res.status(401).json({ error: 'Invalid email or verification code.' });
    return;
  }
  const check = verifyEmailOtpRecord(cleanEmail, 'login_otp', code);
  if (!check.ok) {
    res.status(401).json({ error: check.error });
    return;
  }

  const userId = String(user.id);
  const deviceId = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET email_verified = 1, last_seen_at = ? WHERE id = ?').run(now, userId);

  db.prepare(
    `INSERT INTO devices (id, user_id, device_name, platform, public_key_jwk, last_active_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    deviceId,
    userId,
    typeof deviceName === 'string' && deviceName ? deviceName.slice(0, 60) : 'Mobile Browser',
    typeof platform === 'string' && platform ? platform.slice(0, 30) : 'Web / PWA',
    publicKeyJwk ? JSON.stringify(publicKeyJwk) : String(user.public_key_jwk || ''),
    now,
    now
  );

  const rawToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (id, token_hash, user_id, device_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    crypto.randomUUID(),
    hashToken(rawToken),
    userId,
    deviceId,
    expiresAt,
    now
  );

  setSessionCookie(res, rawToken, req);
  const membership = db.prepare('SELECT couple_id FROM couple_members WHERE user_id = ?').get(userId) as { couple_id: string } | undefined;
  const couple = membership
    ? (db.prepare('SELECT * FROM couples WHERE id = ?').get(membership.couple_id) as Record<string, unknown>)
    : null;
  const partnerRow = membership
    ? (db
        .prepare(
          `SELECT u.* FROM couple_members cm JOIN users u ON u.id = cm.user_id
           WHERE cm.couple_id = ? AND cm.user_id != ?`
        )
        .get(membership.couple_id, userId) as Record<string, unknown> | undefined)
    : undefined;

  const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as Record<string, unknown>;
  res.json({
    token: rawToken,
    user: sanitizeUser(updatedUser),
    couple: sanitizeCouple(couple || undefined),
    partner: sanitizeUser(partnerRow),
    partnerOnline: isUserOnline(partnerRow ? String(partnerRow.id) : null),
    deviceId,
  });
});

// Toggle Email 2FA on Sign-In
app.post('/api/auth/email/2fa-toggle', requireAuth, (req: AuthedRequest, res) => {
  const { enabled } = req.body || {};
  const current = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown>;
  if (enabled && Number(current.email_verified) !== 1) {
    res.status(400).json({ error: 'Verify your email address first before enabling Email 2FA.' });
    return;
  }
  db.prepare('UPDATE users SET email_2fa_enabled = ? WHERE id = ?').run(enabled ? 1 : 0, req.auth!.userId);
  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown>;
  res.json({ user: sanitizeUser(updated) });
});

// Password Recovery via Email Code
app.post('/api/auth/recover-email', (req, res) => {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(`recemail:${ip}`, 15)) {
    res.status(429).json({ error: 'Too many recovery attempts.' });
    return;
  }
  const { email, code, newPassword } = req.body || {};
  if (typeof email !== 'string' || typeof code !== 'string' || typeof newPassword !== 'string' || newPassword.length < 6) {
    res.status(400).json({ error: 'Email, 6-digit code, and new password (min 6 chars) are required.' });
    return;
  }
  const cleanEmail = email.trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail) as Record<string, unknown> | undefined;
  if (!user) {
    res.status(401).json({ error: 'Invalid email or verification code.' });
    return;
  }
  const check = verifyEmailOtpRecord(cleanEmail, 'reset_password', code);
  if (!check.ok) {
    res.status(401).json({ error: check.error });
    return;
  }
  db.prepare('UPDATE users SET password_hash = ?, email_verified = 1 WHERE id = ?').run(hashSecret(newPassword), String(user.id));
  res.json({ ok: true });
});

app.post('/api/auth/recover', (req, res) => {
  const ip = req.ip || 'unknown';
  if (!checkRateLimit(`rec:${ip}`, 15)) {
    res.status(429).json({ error: 'Too many recovery attempts.' });
    return;
  }
  const { email, recoveryCode, newPassword } = req.body || {};
  if (typeof email !== 'string' || typeof recoveryCode !== 'string' || typeof newPassword !== 'string' || newPassword.length < 6) {
    res.status(400).json({ error: 'Email, recovery code, and new password (min 6 chars) are required.' });
    return;
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase()) as Record<string, unknown> | undefined;
  if (!user || !verifySecret(recoveryCode.trim().toUpperCase(), String(user.recovery_code_hash))) {
    res.status(401).json({ error: 'Invalid email or recovery code.' });
    return;
  }
  const nextRecovery = `EV-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  db.prepare('UPDATE users SET password_hash = ?, recovery_code_hash = ? WHERE id = ?').run(
    hashSecret(newPassword),
    hashSecret(nextRecovery),
    String(user.id)
  );
  res.json({ ok: true, newRecoveryCode: nextRecovery });
});

app.post('/api/auth/logout', requireAuth, (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.auth!.tokenHash);
  clearSessionCookie(res, req);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(now, req.auth!.userId);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown> | undefined;
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  const couple = req.auth!.coupleId
    ? (db.prepare('SELECT * FROM couples WHERE id = ?').get(req.auth!.coupleId) as Record<string, unknown> | undefined)
    : undefined;
  const partner = req.auth!.coupleId
    ? (db
        .prepare(
          `SELECT u.* FROM couple_members cm JOIN users u ON u.id = cm.user_id
           WHERE cm.couple_id = ? AND cm.user_id != ?`
        )
        .get(req.auth!.coupleId, req.auth!.userId) as Record<string, unknown> | undefined)
    : undefined;

  const devices = db.prepare('SELECT id, device_name, platform, last_active_at, created_at FROM devices WHERE user_id = ? ORDER BY last_active_at DESC').all(req.auth!.userId);
  const prefs = db.prepare('SELECT * FROM notification_preferences WHERE user_id = ?').get(req.auth!.userId);

  res.json({
    user: sanitizeUser(user),
    couple: sanitizeCouple(couple),
    partner: sanitizeUser(partner),
    partnerOnline: isUserOnline(partner ? String(partner.id) : null),
    devices,
    notificationPreferences: prefs,
    currentDeviceId: req.auth!.deviceId,
  });
});

app.patch('/api/profile', requireAuth, (req: AuthedRequest, res) => {
  const { display_name, nickname, bio, avatar_url, dark_mode, mood_status, public_key_jwk, encrypted_key_backup } = req.body || {};
  const current = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown>;
  db.prepare(
    `UPDATE users SET
      display_name = ?,
      nickname = ?,
      bio = ?,
      avatar_url = ?,
      dark_mode = ?,
      mood_status = ?,
      public_key_jwk = ?,
      encrypted_key_backup = ?
     WHERE id = ?`
  ).run(
    typeof display_name === 'string' && display_name.trim() ? display_name.trim().slice(0, 40) : current.display_name,
    typeof nickname === 'string' ? nickname.trim().slice(0, 40) : current.nickname,
    typeof bio === 'string' ? bio.trim().slice(0, 200) : current.bio,
    typeof avatar_url === 'string' ? avatar_url : current.avatar_url,
    typeof dark_mode === 'boolean' ? (dark_mode ? 1 : 0) : current.dark_mode,
    typeof mood_status === 'string' ? mood_status.trim().slice(0, 60) : current.mood_status || '',
    public_key_jwk ? JSON.stringify(public_key_jwk) : current.public_key_jwk,
    typeof encrypted_key_backup === 'string' ? encrypted_key_backup : current.encrypted_key_backup,
    req.auth!.userId
  );

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth!.userId) as Record<string, unknown>;
  if (req.auth!.coupleId) {
    broadcastToCouple(req.auth!.coupleId, 'couple:updated', { reason: 'profile' });
  }
  res.json({ user: sanitizeUser(updated) });
});

app.delete('/api/devices/:deviceId', requireAuth, (req: AuthedRequest, res) => {
  const { deviceId } = req.params;
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND device_id = ?').run(req.auth!.userId, deviceId);
  db.prepare('DELETE FROM devices WHERE user_id = ? AND id = ?').run(req.auth!.userId, deviceId);
  res.json({ ok: true });
});

app.patch('/api/notifications/preferences', requireAuth, (req: AuthedRequest, res) => {
  const keys = ['messages', 'love', 'tasks', 'memories', 'dates', 'plans', 'games', 'location', 'wallpapers'];
  const current = db.prepare('SELECT * FROM notification_preferences WHERE user_id = ?').get(req.auth!.userId) as Record<string, number>;
  const nextVals = keys.map((k) => (typeof req.body?.[k] === 'boolean' ? (req.body[k] ? 1 : 0) : current[k]));
  db.prepare(
    `UPDATE notification_preferences
     SET messages=?, love=?, tasks=?, memories=?, dates=?, plans=?, games=?, location=?, wallpapers=?
     WHERE user_id = ?`
  ).run(...nextVals, req.auth!.userId);
  const updated = db.prepare('SELECT * FROM notification_preferences WHERE user_id = ?').get(req.auth!.userId);
  res.json({ notificationPreferences: updated });
});

// --- 2. Couple Space Creation, Single-Use Invites & 2-Member Enforcement ---
app.post('/api/couple/create', requireAuth, async (req: AuthedRequest, res) => {
  if (req.auth!.coupleId) {
    res.status(409).json({ error: 'You already belong to a couple space.' });
    return;
  }

  const { name, startDate, pin } = req.body || {};
  if (typeof startDate !== 'string' || !startDate) {
    res.status(400).json({ error: 'Relationship start date is required.' });
    return;
  }
  if (typeof pin !== 'string' || !/^\d{4,6}$/.test(pin)) {
    res.status(400).json({ error: 'Shared app-lock PIN must be 4 to 6 digits.' });
    return;
  }

  const coupleId = crypto.randomUUID();
  const inviteId = crypto.randomUUID();
  const code = `LOVE-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();

  const createTx = db.transaction(() => {
    db.prepare(
      `INSERT INTO couples (id, name, start_date, pin_hash, status, created_at)
       VALUES (?, ?, ?, ?, 'pending', ?)`
    ).run(coupleId, typeof name === 'string' && name.trim() ? name.trim().slice(0, 50) : 'Our EverUs Space', startDate, hashSecret(pin), now);

    db.prepare('INSERT INTO couple_members (couple_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)').run(
      coupleId,
      req.auth!.userId,
      'creator',
      now
    );

    db.prepare(
      `INSERT INTO invitations (id, couple_id, code, created_by, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(inviteId, coupleId, code, req.auth!.userId, expiresAt, now);

    // Seed anniversary special date automatically from startDate
    db.prepare(
      `INSERT INTO special_dates (id, couple_id, title, date_value, category, recurring_yearly, reminder_days_before, notes, created_by, created_at)
       VALUES (?, ?, ?, ?, 'anniversary', 1, 7, 'Our beginning together', ?, ?)`
    ).run(crypto.randomUUID(), coupleId, 'Our Anniversary', startDate, req.auth!.userId, now);

    // Initialize default location preference
    db.prepare(
      `INSERT INTO location_preferences (user_id, couple_id, is_sharing, is_paused, arrival_alerts_enabled, updated_at)
       VALUES (?, ?, 0, 0, 1, ?)`
    ).run(req.auth!.userId, coupleId, now);
  });

  createTx();
  const qrDataUrl = await QRCode.toDataURL(code, {
    width: 240,
    margin: 2,
    color: { dark: '#be185d', light: '#fff5f8' },
  });
  const couple = db.prepare('SELECT * FROM couples WHERE id = ?').get(coupleId) as Record<string, unknown>;
  res.status(201).json({
    couple: sanitizeCouple(couple),
    invitation: { code, expires_at: expiresAt, qrDataUrl },
  });
});

app.get('/api/couple/invitation', requireAuth, requireCouple, async (req: AuthedRequest, res) => {
  const memberCount = (
    db.prepare('SELECT COUNT(*) as c FROM couple_members WHERE couple_id = ?').get(req.auth!.coupleId) as { c: number }
  ).c;
  if (memberCount >= 2) {
    res.json({ paired: true, invitation: null });
    return;
  }

  let invite = db
    .prepare(
      `SELECT * FROM invitations
       WHERE couple_id = ? AND used_at IS NULL AND expires_at > ?
       ORDER BY created_at DESC LIMIT 1`
    )
    .get(req.auth!.coupleId, new Date().toISOString()) as Record<string, unknown> | undefined;

  if (!invite) {
    const code = `LOVE-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
    db.prepare(
      `INSERT INTO invitations (id, couple_id, code, created_by, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(crypto.randomUUID(), req.auth!.coupleId, code, req.auth!.userId, expiresAt, now);
    invite = { code, expires_at: expiresAt };
  }

  const qrDataUrl = await QRCode.toDataURL(String(invite.code), {
    width: 240,
    margin: 2,
    color: { dark: '#be185d', light: '#fff5f8' },
  });

  res.json({
    paired: false,
    invitation: {
      code: invite.code,
      expires_at: invite.expires_at,
      qrDataUrl,
    },
  });
});

app.post('/api/couple/invitation/regenerate', requireAuth, requireCouple, async (req: AuthedRequest, res) => {
  const memberCount = (
    db.prepare('SELECT COUNT(*) as c FROM couple_members WHERE couple_id = ?').get(req.auth!.coupleId) as { c: number }
  ).c;
  if (memberCount >= 2) {
    res.status(409).json({ error: 'This couple space is already paired with two partners.' });
    return;
  }
  const code = `LOVE-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE invitations SET expires_at = ? WHERE couple_id = ? AND used_at IS NULL').run(now, req.auth!.coupleId);
  db.prepare(
    `INSERT INTO invitations (id, couple_id, code, created_by, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(crypto.randomUUID(), req.auth!.coupleId, code, req.auth!.userId, expiresAt, now);
  const qrDataUrl = await QRCode.toDataURL(code, {
    width: 240,
    margin: 2,
    color: { dark: '#be185d', light: '#fff5f8' },
  });
  res.json({ invitation: { code, expires_at: expiresAt, qrDataUrl } });
});

app.post('/api/couple/join', requireAuth, (req: AuthedRequest, res) => {
  if (req.auth!.coupleId) {
    res.status(409).json({ error: 'Your account is already paired in a couple space.' });
    return;
  }
  const { code } = req.body || {};
  if (typeof code !== 'string' || !code.trim()) {
    res.status(400).json({ error: 'Invitation code is required.' });
    return;
  }

  const cleanCode = code.trim().toUpperCase();
  const now = new Date().toISOString();

  try {
    const joinedCoupleId = db.transaction(() => {
      const invite = db.prepare('SELECT * FROM invitations WHERE code = ?').get(cleanCode) as Record<string, unknown> | undefined;
      if (!invite) {
        throw new Error('INVALID_CODE');
      }
      if (invite.used_at) {
        throw new Error('ALREADY_USED');
      }
      if (new Date(String(invite.expires_at)).getTime() < Date.now()) {
        throw new Error('EXPIRED');
      }
      const coupleId = String(invite.couple_id);
      const count = (db.prepare('SELECT COUNT(*) as c FROM couple_members WHERE couple_id = ?').get(coupleId) as { c: number }).c;
      if (count >= 2) {
        throw new Error('SPACE_FULL');
      }

      db.prepare('INSERT INTO couple_members (couple_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)').run(
        coupleId,
        req.auth!.userId,
        'partner',
        now
      );
      db.prepare('UPDATE invitations SET used_by = ?, used_at = ? WHERE id = ?').run(req.auth!.userId, now, String(invite.id));
      db.prepare("UPDATE couples SET status = 'active' WHERE id = ?").run(coupleId);
      db.prepare(
        `INSERT OR IGNORE INTO location_preferences (user_id, couple_id, is_sharing, is_paused, arrival_alerts_enabled, updated_at)
         VALUES (?, ?, 0, 0, 1, ?)`
      ).run(req.auth!.userId, coupleId, now);

      return coupleId;
    })();

    const couple = db.prepare('SELECT * FROM couples WHERE id = ?').get(joinedCoupleId) as Record<string, unknown>;
    const partner = db
      .prepare(
        `SELECT u.* FROM couple_members cm JOIN users u ON u.id = cm.user_id
         WHERE cm.couple_id = ? AND cm.user_id != ?`
      )
      .get(joinedCoupleId, req.auth!.userId) as Record<string, unknown> | undefined;

    const joiner = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    if (partner) {
      createNotification(
        joinedCoupleId,
        String(partner.id),
        'love',
        'Your partner joined EverUs!',
        `${joiner.display_name} paired with your private couple space.`
      );
    }
    broadcastToCouple(joinedCoupleId, 'couple:updated', { reason: 'paired' });

    res.json({
      couple: sanitizeCouple(couple),
      partner: sanitizeUser(partner),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (msg === 'INVALID_CODE') res.status(404).json({ error: 'Invitation code not found.' });
    else if (msg === 'ALREADY_USED') res.status(410).json({ error: 'This invitation code has already been used.' });
    else if (msg === 'EXPIRED') res.status(410).json({ error: 'This invitation code has expired.' });
    else if (msg === 'SPACE_FULL' || msg.includes('two members')) {
      res.status(403).json({ error: 'This couple space already has two partners.' });
    } else {
      res.status(500).json({ error: 'Could not join couple space.' });
    }
  }
});

app.patch('/api/couple', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { name, start_date } = req.body || {};
  const current = db.prepare('SELECT * FROM couples WHERE id = ?').get(req.auth!.coupleId) as Record<string, unknown>;
  db.prepare('UPDATE couples SET name = ?, start_date = ? WHERE id = ?').run(
    typeof name === 'string' && name.trim() ? name.trim().slice(0, 60) : current.name,
    typeof start_date === 'string' && start_date ? start_date : current.start_date,
    req.auth!.coupleId
  );
  const updated = db.prepare('SELECT * FROM couples WHERE id = ?').get(req.auth!.coupleId) as Record<string, unknown>;
  broadcastToCouple(req.auth!.coupleId!, 'couple:updated', { reason: 'details' });
  res.json({ couple: sanitizeCouple(updated) });
});

// --- 3. Shared App Lock PIN Verification, Rate Limiting & Account Recovery ---
app.post('/api/couple/pin/verify', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { pin } = req.body || {};
  if (typeof pin !== 'string' || !/^\d{4,6}$/.test(pin)) {
    res.status(400).json({ error: 'Enter your 4 to 6 digit EverUs PIN.' });
    return;
  }

  const couple = db.prepare('SELECT * FROM couples WHERE id = ?').get(req.auth!.coupleId) as {
    id: string;
    pin_hash: string;
    pin_failed_attempts: number;
    pin_locked_until: string | null;
  };

  if (couple.pin_locked_until && new Date(couple.pin_locked_until).getTime() > Date.now()) {
    const mins = Math.ceil((new Date(couple.pin_locked_until).getTime() - Date.now()) / 60000);
    res.status(429).json({ error: `PIN temporarily locked after too many attempts. Try again in ${mins} min or recover via account password.` });
    return;
  }

  if (!verifySecret(pin, couple.pin_hash)) {
    const nextAttempts = couple.pin_failed_attempts + 1;
    const lockedUntil = nextAttempts >= 5 ? new Date(Date.now() + 10 * 60 * 1000).toISOString() : null;
    db.prepare('UPDATE couples SET pin_failed_attempts = ?, pin_locked_until = ? WHERE id = ?').run(
      nextAttempts >= 5 ? 0 : nextAttempts,
      lockedUntil,
      couple.id
    );
    res.status(401).json({
      error: lockedUntil
        ? 'Too many incorrect PIN attempts. App lock paused for 10 minutes.'
        : `Incorrect PIN (${5 - nextAttempts} attempts left).`,
    });
    return;
  }

  db.prepare('UPDATE couples SET pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = ?').run(couple.id);
  res.json({ unlocked: true });
});

app.post('/api/couple/pin/update', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { accountPassword, newPin } = req.body || {};
  if (typeof accountPassword !== 'string' || typeof newPin !== 'string' || !/^\d{4,6}$/.test(newPin)) {
    res.status(400).json({ error: 'Account password and a 4–6 digit PIN are required.' });
    return;
  }
  const user = db.prepare('SELECT password_hash, display_name FROM users WHERE id = ?').get(req.auth!.userId) as {
    password_hash: string;
    display_name: string;
  };
  if (!verifySecret(accountPassword, user.password_hash)) {
    res.status(401).json({ error: 'Individual account password verification failed.' });
    return;
  }
  db.prepare('UPDATE couples SET pin_hash = ?, pin_failed_attempts = 0, pin_locked_until = NULL WHERE id = ?').run(
    hashSecret(newPin),
    req.auth!.coupleId
  );
  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (partnerId) {
    createNotification(req.auth!.coupleId!, partnerId, 'love', 'Shared App PIN Updated', `${user.display_name} updated your shared EverUs app-lock PIN.`);
  }
  res.json({ ok: true });
});

// --- 4. Private Media Upload & Serving ---
app.post('/api/uploads', requireAuth, upload.single('file'), (req: AuthedRequest, res) => {
  if (!req.file) {
    res.status(400).json({ error: 'No file uploaded.' });
    return;
  }
  const folder = req.auth!.coupleId || `user_${req.auth!.userId}`;
  const safeUrl = `/api/media/${encodeURIComponent(folder)}/${encodeURIComponent(req.file.filename)}`;

  let attachmentId: string | null = null;
  if (req.body?.encrypted === 'true' && req.auth!.coupleId) {
    attachmentId = crypto.randomUUID();
    db.prepare(
      `INSERT INTO message_attachments (id, couple_id, uploader_id, file_path, mime_type, original_name, encrypted_iv, byte_size, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      attachmentId,
      req.auth!.coupleId,
      req.auth!.userId,
      safeUrl,
      String(req.body.originalMime || req.file.mimetype),
      String(req.body.originalName || req.file.originalname).slice(0, 140),
      String(req.body.encryptedIv || ''),
      req.file.size,
      new Date().toISOString()
    );
  }

  res.status(201).json({
    url: safeUrl,
    attachmentId,
    mimeType: req.file.mimetype,
    size: req.file.size,
  });
});

app.get('/api/media/:folder/:filename', requireAuth, (req: AuthedRequest, res) => {
  const folder = String(req.params.folder || '');
  const filename = path.basename(String(req.params.filename || ''));

  const allowedUserFolder = `user_${req.auth!.userId}`;
  const allowedCoupleFolder = req.auth!.coupleId || '';
  if (folder !== allowedUserFolder && (!allowedCoupleFolder || folder !== allowedCoupleFolder)) {
    res.status(403).json({ error: 'Access denied to private media.' });
    return;
  }

  const baseDir = path.resolve(UPLOADS_ROOT, folder);
  const resolved = path.resolve(baseDir, filename);
  if (!resolved.startsWith(baseDir + path.sep) || !fs.existsSync(resolved)) {
    res.status(404).json({ error: 'Media not found.' });
    return;
  }
  res.sendFile(resolved);
});

// --- 5. Daily Bible Verse ---
app.get('/api/verse/today', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const today = getVerseForDate(new Date());
  const saved = db
    .prepare('SELECT * FROM saved_verses WHERE couple_id = ? ORDER BY created_at DESC')
    .all(req.auth!.coupleId);
  res.json({ today, saved });
});

app.post('/api/verse/save', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { reference, text, note, shareWithPartner } = req.body || {};
  if (typeof reference !== 'string' || typeof text !== 'string') {
    res.status(400).json({ error: 'Verse reference and text are required.' });
    return;
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO saved_verses (id, couple_id, user_id, reference, verse_text, note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, req.auth!.coupleId, req.auth!.userId, reference.slice(0, 80), text.slice(0, 600), String(note || '').slice(0, 240), now);

  if (shareWithPartner) {
    const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    if (partnerId) {
      createNotification(req.auth!.coupleId!, partnerId, 'love', `${me.display_name} shared today’s verse`, `${reference}: “${text.slice(0, 90)}…”`);
    }
  }
  const saved = db.prepare('SELECT * FROM saved_verses WHERE couple_id = ? ORDER BY created_at DESC').all(req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'verse:updated', saved);
  res.status(201).json({ saved });
});

// --- 6. Daily Tasks & Real-Time Sync ---
app.get('/api/tasks', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const tasks = db
    .prepare('SELECT * FROM tasks WHERE couple_id = ? ORDER BY is_completed ASC, created_at DESC')
    .all(req.auth!.coupleId);
  const history = db
    .prepare(
      `SELECT tc.*, t.title as task_title, u.display_name as completer_name, u.avatar_url as completer_avatar
       FROM task_completions tc
       JOIN tasks t ON t.id = tc.task_id
       JOIN users u ON u.id = tc.completed_by
       WHERE tc.couple_id = ?
       ORDER BY tc.completed_at DESC LIMIT 50`
    )
    .all(req.auth!.coupleId);
  res.json({ tasks, history });
});

app.post('/api/tasks', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { category, assigned_to, title, description, notes, due_at, reminder_at, recurrence } = req.body || {};
  if (typeof title !== 'string' || !title.trim()) {
    res.status(400).json({ error: 'Task title is required.' });
    return;
  }
  const validCat = ['partner_a', 'partner_b', 'shared'].includes(category) ? category : 'shared';
  const validRec = ['none', 'daily', 'weekly', 'monthly'].includes(recurrence) ? recurrence : 'none';
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO tasks (id, couple_id, category, assigned_to, title, description, notes, due_at, reminder_at, recurrence, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    validCat,
    assigned_to || null,
    title.trim().slice(0, 120),
    String(description || '').slice(0, 500),
    String(notes || '').slice(0, 500),
    due_at || null,
    reminder_at || null,
    validRec,
    req.auth!.userId,
    now,
    now
  );

  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  broadcastToCouple(req.auth!.coupleId!, 'task:sync', { action: 'create', task });
  res.status(201).json({ task });
});

app.patch('/api/tasks/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const existing = db.prepare('SELECT * FROM tasks WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Task not found.' });
    return;
  }

  const now = new Date().toISOString();
  const nextCompleted = typeof req.body?.is_completed === 'boolean' ? (req.body.is_completed ? 1 : 0) : Number(existing.is_completed);
  const completedChangedToTrue = existing.is_completed === 0 && nextCompleted === 1;

  db.prepare(
    `UPDATE tasks SET
      category = ?,
      title = ?,
      description = ?,
      notes = ?,
      due_at = ?,
      reminder_at = ?,
      recurrence = ?,
      is_completed = ?,
      completed_by = ?,
      completed_at = ?,
      updated_at = ?
     WHERE id = ? AND couple_id = ?`
  ).run(
    ['partner_a', 'partner_b', 'shared'].includes(req.body?.category) ? req.body.category : existing.category,
    typeof req.body?.title === 'string' && req.body.title.trim() ? req.body.title.trim().slice(0, 120) : existing.title,
    typeof req.body?.description === 'string' ? req.body.description.slice(0, 500) : existing.description,
    typeof req.body?.notes === 'string' ? req.body.notes.slice(0, 500) : existing.notes,
    req.body?.due_at !== undefined ? req.body.due_at : existing.due_at,
    req.body?.reminder_at !== undefined ? req.body.reminder_at : existing.reminder_at,
    ['none', 'daily', 'weekly', 'monthly'].includes(req.body?.recurrence) ? req.body.recurrence : existing.recurrence,
    nextCompleted,
    nextCompleted ? req.auth!.userId : null,
    nextCompleted ? now : null,
    now,
    req.params.id,
    req.auth!.coupleId
  );

  if (completedChangedToTrue) {
    db.prepare(
      `INSERT INTO task_completions (id, task_id, couple_id, completed_by, completed_at, note)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(crypto.randomUUID(), req.params.id, req.auth!.coupleId, req.auth!.userId, now, String(req.body?.completionNote || ''));

    // If recurring, automatically spawn next occurrence
    if (existing.recurrence && existing.recurrence !== 'none') {
      const baseDate = existing.due_at ? new Date(String(existing.due_at)) : new Date();
      if (existing.recurrence === 'daily') baseDate.setDate(baseDate.getDate() + 1);
      if (existing.recurrence === 'weekly') baseDate.setDate(baseDate.getDate() + 7);
      if (existing.recurrence === 'monthly') baseDate.setMonth(baseDate.getMonth() + 1);
      const nextId = crypto.randomUUID();
      db.prepare(
        `INSERT INTO tasks (id, couple_id, category, assigned_to, title, description, notes, due_at, reminder_at, recurrence, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        nextId,
        req.auth!.coupleId,
        existing.category,
        existing.assigned_to,
        existing.title,
        existing.description,
        existing.notes,
        baseDate.toISOString().slice(0, 16),
        existing.reminder_at,
        existing.recurrence,
        existing.created_by,
        now,
        now
      );
    }

    const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    if (partnerId && existing.category === 'shared') {
      createNotification(req.auth!.coupleId!, partnerId, 'tasks', 'Shared Task Completed', `${me.display_name} completed “${existing.title}”`);
    }
  }

  const tasks = db.prepare('SELECT * FROM tasks WHERE couple_id = ? ORDER BY is_completed ASC, created_at DESC').all(req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'task:sync', { action: 'refresh', tasks });
  res.json({ tasks });
});

app.delete('/api/tasks/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM tasks WHERE id = ? AND couple_id = ?').run(req.params.id, req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'task:sync', { action: 'delete', id: req.params.id });
  res.json({ ok: true });
});

// --- 7. End-to-End Encrypted Chat & Attachments ---
app.get('/api/chat/messages', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const messages = db
    .prepare(
      `SELECT m.*, a.file_path as attachment_url, a.mime_type as attachment_mime, a.original_name as attachment_name, a.encrypted_iv as attachment_iv
       FROM encrypted_messages m
       LEFT JOIN message_attachments a ON a.id = m.attachment_id
       WHERE m.couple_id = ?
       ORDER BY m.created_at ASC`
    )
    .all(req.auth!.coupleId);
  res.json({ messages });
});

app.post('/api/chat/messages', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { ciphertext, iv, sender_pub_jwk, message_type, attachment_id, reply_to_id } = req.body || {};
  if (typeof ciphertext !== 'string' || typeof iv !== 'string' || !ciphertext || !iv) {
    res.status(400).json({ error: 'Encrypted ciphertext and IV are required.' });
    return;
  }
  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (!partnerId) {
    res.status(400).json({ error: 'Waiting for your partner to join before sending encrypted messages.' });
    return;
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO encrypted_messages (id, couple_id, sender_id, recipient_id, ciphertext, iv, sender_pub_jwk, message_type, attachment_id, reply_to_id, delivered_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    req.auth!.userId,
    partnerId,
    ciphertext,
    iv,
    sender_pub_jwk ? JSON.stringify(sender_pub_jwk) : '',
    typeof message_type === 'string' ? message_type : 'text',
    attachment_id || null,
    reply_to_id || null,
    now,
    now
  );

  const msg = db
    .prepare(
      `SELECT m.*, a.file_path as attachment_url, a.mime_type as attachment_mime, a.original_name as attachment_name, a.encrypted_iv as attachment_iv
       FROM encrypted_messages m
       LEFT JOIN message_attachments a ON a.id = m.attachment_id
       WHERE m.id = ?`
    )
    .get(id);

  const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
  createNotification(req.auth!.coupleId!, partnerId, 'messages', `New message from ${me.display_name}`, 'Encrypted message received in Our Chat.');
  broadcastToCouple(req.auth!.coupleId!, 'chat:message', msg);
  res.status(201).json({ message: msg });
});

app.patch('/api/chat/messages/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const existing = db.prepare('SELECT * FROM encrypted_messages WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Message not found.' });
    return;
  }

  if (req.body?.markRead && existing.recipient_id === req.auth!.userId && !existing.read_at) {
    const readAt = new Date().toISOString();
    db.prepare('UPDATE encrypted_messages SET read_at = ? WHERE id = ?').run(readAt, req.params.id);
    broadcastToCouple(req.auth!.coupleId!, 'chat:read', { id: req.params.id, read_at: readAt });
  }

  if (req.body?.reaction) {
    const reactions = JSON.parse(String(existing.reactions_json || '{}')) as Record<string, string>;
    if (reactions[req.auth!.userId] === req.body.reaction) {
      delete reactions[req.auth!.userId];
    } else {
      reactions[req.auth!.userId] = String(req.body.reaction).slice(0, 8);
    }
    db.prepare('UPDATE encrypted_messages SET reactions_json = ? WHERE id = ?').run(JSON.stringify(reactions), req.params.id);
    broadcastToCouple(req.auth!.coupleId!, 'chat:reaction', { id: req.params.id, reactions_json: JSON.stringify(reactions) });
  }

  if (req.body?.ciphertext && req.body?.iv && existing.sender_id === req.auth!.userId) {
    db.prepare('UPDATE encrypted_messages SET ciphertext = ?, iv = ?, is_edited = 1 WHERE id = ?').run(
      req.body.ciphertext,
      req.body.iv,
      req.params.id
    );
    broadcastToCouple(req.auth!.coupleId!, 'chat:edit', { id: req.params.id, ciphertext: req.body.ciphertext, iv: req.body.iv });
  }

  if (req.body?.delete && existing.sender_id === req.auth!.userId) {
    db.prepare('UPDATE encrypted_messages SET is_deleted = 1 WHERE id = ?').run(req.params.id);
    broadcastToCouple(req.auth!.coupleId!, 'chat:delete', { id: req.params.id });
  }

  const updated = db.prepare('SELECT * FROM encrypted_messages WHERE id = ?').get(req.params.id);
  res.json({ message: updated });
});

// --- 8. Send Love Interactions ---
app.get('/api/love', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const items = db
    .prepare('SELECT * FROM love_interactions WHERE couple_id = ? ORDER BY created_at DESC LIMIT 40')
    .all(req.auth!.coupleId);
  res.json({ items });
});

app.post('/api/love', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { kind, message } = req.body || {};
  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (!partnerId) {
    res.status(400).json({ error: 'Invite your partner first to send love.' });
    return;
  }
  const validKind = ['heart', 'kiss', 'hug', 'note'].includes(kind) ? kind : 'heart';
  const cleanMsg = typeof message === 'string' && message.trim() ? message.trim().slice(0, 200) : 'Thinking of you!';
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO love_interactions (id, couple_id, sender_id, recipient_id, kind, message, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, req.auth!.coupleId, req.auth!.userId, partnerId, validKind, cleanMsg, now);

  const item = db.prepare('SELECT * FROM love_interactions WHERE id = ?').get(id);
  const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
  createNotification(req.auth!.coupleId!, partnerId, 'love', `${me.display_name} sent you love`, cleanMsg, { loveId: id, kind: validKind });
  broadcastToCouple(req.auth!.coupleId!, 'love:received', item);
  res.status(201).json({ item });
});

app.post('/api/love/:id/respond', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { emoji } = req.body || {};
  const now = new Date().toISOString();
  db.prepare('UPDATE love_interactions SET response_emoji = ?, responded_at = ? WHERE id = ? AND couple_id = ?').run(
    String(emoji || '❤️').slice(0, 8),
    now,
    req.params.id,
    req.auth!.coupleId
  );
  const item = db.prepare('SELECT * FROM love_interactions WHERE id = ?').get(req.params.id);
  broadcastToCouple(req.auth!.coupleId!, 'love:responded', item);
  res.json({ item });
});

// --- 9. Location Sharing ---
app.get('/api/location', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const prefs = db.prepare('SELECT * FROM location_preferences WHERE couple_id = ?').all(req.auth!.coupleId);
  const updates = db.prepare('SELECT * FROM location_updates WHERE couple_id = ?').all(req.auth!.coupleId);
  const places = db.prepare('SELECT * FROM saved_places WHERE couple_id = ? ORDER BY created_at DESC').all(req.auth!.coupleId);

  // Only reveal partner location if partner has consented (is_sharing = 1 and is_paused = 0)
  const visibleUpdates = (updates as Record<string, unknown>[]).filter((u) => {
    if (u.user_id === req.auth!.userId) return true;
    const p = (prefs as Record<string, unknown>[]).find((x) => x.user_id === u.user_id);
    return Boolean(p && p.is_sharing === 1 && p.is_paused === 0);
  });

  res.json({ preferences: prefs, locations: visibleUpdates, savedPlaces: places });
});

app.patch('/api/location/preferences', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const now = new Date().toISOString();
  const current = db.prepare('SELECT * FROM location_preferences WHERE user_id = ?').get(req.auth!.userId) as
    | Record<string, unknown>
    | undefined;
  const isSharing = typeof req.body?.is_sharing === 'boolean' ? (req.body.is_sharing ? 1 : 0) : Number(current?.is_sharing || 0);
  const isPaused = typeof req.body?.is_paused === 'boolean' ? (req.body.is_paused ? 1 : 0) : Number(current?.is_paused || 0);
  const alerts =
    typeof req.body?.arrival_alerts_enabled === 'boolean'
      ? req.body.arrival_alerts_enabled
        ? 1
        : 0
      : Number(current?.arrival_alerts_enabled ?? 1);

  db.prepare(
    `INSERT INTO location_preferences (user_id, couple_id, is_sharing, is_paused, arrival_alerts_enabled, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET is_sharing=excluded.is_sharing, is_paused=excluded.is_paused, arrival_alerts_enabled=excluded.arrival_alerts_enabled, updated_at=excluded.updated_at`
  ).run(req.auth!.userId, req.auth!.coupleId, isSharing, isPaused, alerts, now);

  broadcastToCouple(req.auth!.coupleId!, 'location:updated', { userId: req.auth!.userId });
  res.json({ ok: true });
});

app.post('/api/location/update', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { latitude, longitude, accuracy, label } = req.body || {};
  if (typeof latitude !== 'number' || typeof longitude !== 'number') {
    res.status(400).json({ error: 'Valid coordinates required.' });
    return;
  }
  const pref = db.prepare('SELECT * FROM location_preferences WHERE user_id = ?').get(req.auth!.userId) as
    | { is_sharing: number; is_paused: number }
    | undefined;
  if (!pref || pref.is_sharing !== 1 || pref.is_paused === 1) {
    res.status(403).json({ error: 'Location sharing is currently disabled or paused for your account.' });
    return;
  }
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO location_updates (user_id, couple_id, latitude, longitude, accuracy, label, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET latitude=excluded.latitude, longitude=excluded.longitude, accuracy=excluded.accuracy, label=excluded.label, updated_at=excluded.updated_at`
  ).run(req.auth!.userId, req.auth!.coupleId, latitude, longitude, Number(accuracy || 0), String(label || '').slice(0, 80), now);

  // Check saved places for arrival alerts
  const places = db.prepare('SELECT * FROM saved_places WHERE couple_id = ? AND notify_on_arrival = 1').all(req.auth!.coupleId) as Array<{
    name: string;
    latitude: number;
    longitude: number;
    radius_meters: number;
  }>;
  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (partnerId) {
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    for (const place of places) {
      const dist = haversineMeters(latitude, longitude, place.latitude, place.longitude);
      if (dist <= place.radius_meters) {
        createNotification(req.auth!.coupleId!, partnerId, 'location', `Arrival at ${place.name}`, `${me.display_name} arrived near ${place.name}.`);
      }
    }
  }

  broadcastToCouple(req.auth!.coupleId!, 'location:updated', { userId: req.auth!.userId });
  res.json({ ok: true, updated_at: now });
});

app.post('/api/location/places', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { name, latitude, longitude, radius_meters, notify_on_arrival } = req.body || {};
  if (typeof name !== 'string' || !name.trim() || typeof latitude !== 'number' || typeof longitude !== 'number') {
    res.status(400).json({ error: 'Place name and coordinates are required.' });
    return;
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO saved_places (id, couple_id, name, latitude, longitude, radius_meters, notify_on_arrival, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    name.trim().slice(0, 60),
    latitude,
    longitude,
    Number(radius_meters || 200),
    notify_on_arrival === false ? 0 : 1,
    req.auth!.userId,
    new Date().toISOString()
  );
  broadcastToCouple(req.auth!.coupleId!, 'location:updated', { placeAdded: id });
  res.status(201).json({ ok: true });
});

app.delete('/api/location/places/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM saved_places WHERE id = ? AND couple_id = ?').run(req.params.id, req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'location:updated', { placeRemoved: req.params.id });
  res.json({ ok: true });
});

// --- 10. Games ---
app.get('/api/games', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const sessions = db.prepare('SELECT * FROM game_sessions WHERE couple_id = ? ORDER BY updated_at DESC').all(req.auth!.coupleId);
  res.json({ sessions });
});

app.post('/api/games', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { game_type, state } = req.body || {};
  if (typeof game_type !== 'string') {
    res.status(400).json({ error: 'Game type is required.' });
    return;
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);

  db.prepare(
    `INSERT INTO game_sessions (id, couple_id, game_type, state_json, turn_user_id, status, score_a, score_b, updated_at, created_at)
     VALUES (?, ?, ?, ?, ?, 'active', 0, 0, ?, ?)`
  ).run(id, req.auth!.coupleId, game_type, JSON.stringify(state || {}), req.auth!.userId, now, now);

  const session = db.prepare('SELECT * FROM game_sessions WHERE id = ?').get(id);
  if (partnerId) {
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    createNotification(req.auth!.coupleId!, partnerId, 'games', 'Game Invitation!', `${me.display_name} started a ${game_type.replace('_', ' ')} game with you.`);
  }
  broadcastToCouple(req.auth!.coupleId!, 'game:updated', session);
  res.status(201).json({ session });
});

app.patch('/api/games/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const existing = db.prepare('SELECT * FROM game_sessions WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Game session not found.' });
    return;
  }
  const now = new Date().toISOString();
  db.prepare(
    `UPDATE game_sessions SET state_json = ?, turn_user_id = ?, status = ?, score_a = ?, score_b = ?, updated_at = ?
     WHERE id = ? AND couple_id = ?`
  ).run(
    req.body?.state !== undefined ? JSON.stringify(req.body.state) : existing.state_json,
    req.body?.turn_user_id !== undefined ? req.body.turn_user_id : existing.turn_user_id,
    req.body?.status || existing.status,
    typeof req.body?.score_a === 'number' ? req.body.score_a : existing.score_a,
    typeof req.body?.score_b === 'number' ? req.body.score_b : existing.score_b,
    now,
    req.params.id,
    req.auth!.coupleId
  );
  const session = db.prepare('SELECT * FROM game_sessions WHERE id = ?').get(req.params.id);
  broadcastToCouple(req.auth!.coupleId!, 'game:updated', session);
  res.json({ session });
});

// --- 11. Our Plans ---
app.get('/api/plans', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const plans = db.prepare('SELECT * FROM plans WHERE couple_id = ? ORDER BY updated_at DESC').all(req.auth!.coupleId);
  const updates = db.prepare('SELECT * FROM plan_updates WHERE couple_id = ? ORDER BY created_at DESC').all(req.auth!.coupleId);
  res.json({ plans, updates });
});

app.post('/api/plans', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { category, title, description, target_date, budget, assigned_to, checklist, notes } = req.body || {};
  if (typeof title !== 'string' || !title.trim()) {
    res.status(400).json({ error: 'Plan title is required.' });
    return;
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const items = Array.isArray(checklist) ? checklist : [];
  const doneCount = items.filter((i: { done?: boolean }) => i.done).length;
  const progress = items.length ? Math.round((doneCount / items.length) * 100) : 0;

  db.prepare(
    `INSERT INTO plans (id, couple_id, category, title, description, target_date, budget, assigned_to, checklist_json, progress, notes, status, created_by, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    String(category || 'Relationship goals'),
    title.trim().slice(0, 120),
    String(description || '').slice(0, 800),
    String(target_date || ''),
    Number(budget || 0),
    assigned_to || null,
    JSON.stringify(items),
    progress,
    String(notes || '').slice(0, 600),
    req.auth!.userId,
    now
  );

  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (partnerId) {
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    createNotification(req.auth!.coupleId!, partnerId, 'plans', 'New Shared Plan', `${me.display_name} added “${title.trim()}”.`);
  }
  broadcastToCouple(req.auth!.coupleId!, 'plan:updated', { id });
  res.status(201).json({ plan: db.prepare('SELECT * FROM plans WHERE id = ?').get(id) });
});

app.patch('/api/plans/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const existing = db.prepare('SELECT * FROM plans WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Plan not found.' });
    return;
  }
  const checklist = Array.isArray(req.body?.checklist) ? req.body.checklist : JSON.parse(String(existing.checklist_json || '[]'));
  const doneCount = checklist.filter((i: { done?: boolean }) => i.done).length;
  const computedProgress = checklist.length
    ? Math.round((doneCount / checklist.length) * 100)
    : typeof req.body?.progress === 'number'
      ? req.body.progress
      : Number(existing.progress);

  const nextStatus = req.body?.status || (computedProgress === 100 ? 'completed' : existing.status);
  const now = new Date().toISOString();

  db.prepare(
    `UPDATE plans SET category=?, title=?, description=?, target_date=?, budget=?, assigned_to=?, checklist_json=?, progress=?, notes=?, status=?, updated_at=?
     WHERE id = ? AND couple_id = ?`
  ).run(
    req.body?.category || existing.category,
    typeof req.body?.title === 'string' && req.body.title.trim() ? req.body.title.trim() : existing.title,
    typeof req.body?.description === 'string' ? req.body.description : existing.description,
    req.body?.target_date !== undefined ? req.body.target_date : existing.target_date,
    typeof req.body?.budget === 'number' ? req.body.budget : existing.budget,
    req.body?.assigned_to !== undefined ? req.body.assigned_to : existing.assigned_to,
    JSON.stringify(checklist),
    computedProgress,
    typeof req.body?.notes === 'string' ? req.body.notes : existing.notes,
    nextStatus,
    now,
    req.params.id,
    req.auth!.coupleId
  );

  if (typeof req.body?.updateNote === 'string' && req.body.updateNote.trim()) {
    db.prepare('INSERT INTO plan_updates (id, plan_id, couple_id, user_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
      crypto.randomUUID(),
      req.params.id,
      req.auth!.coupleId,
      req.auth!.userId,
      req.body.updateNote.trim().slice(0, 400),
      now
    );
  }

  broadcastToCouple(req.auth!.coupleId!, 'plan:updated', { id: req.params.id });
  res.json({ plan: db.prepare('SELECT * FROM plans WHERE id = ?').get(req.params.id) });
});

app.delete('/api/plans/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM plans WHERE id = ? AND couple_id = ?').run(req.params.id, req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'plan:updated', { deleted: req.params.id });
  res.json({ ok: true });
});

// --- 12. Our Memories ---
app.get('/api/memories', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const albums = db.prepare('SELECT * FROM memory_albums WHERE couple_id = ? ORDER BY created_at DESC').all(req.auth!.coupleId);
  const memories = db.prepare('SELECT * FROM memories WHERE couple_id = ? ORDER BY memory_date DESC, created_at DESC').all(req.auth!.coupleId);
  const comments = db.prepare('SELECT * FROM memory_comments WHERE couple_id = ? ORDER BY created_at ASC').all(req.auth!.coupleId);
  res.json({ albums, memories, comments });
});

app.post('/api/memories/albums', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { title } = req.body || {};
  if (typeof title !== 'string' || !title.trim()) {
    res.status(400).json({ error: 'Album title required.' });
    return;
  }
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO memory_albums (id, couple_id, title, created_by, created_at) VALUES (?, ?, ?, ?, ?)').run(
    id,
    req.auth!.coupleId,
    title.trim().slice(0, 80),
    req.auth!.userId,
    new Date().toISOString()
  );
  broadcastToCouple(req.auth!.coupleId!, 'memory:updated', { albumId: id });
  res.status(201).json({ album: db.prepare('SELECT * FROM memory_albums WHERE id = ?').get(id) });
});

app.post('/api/memories', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { album_id, media_url, media_type, caption, memory_date, location_label } = req.body || {};
  if (typeof media_url !== 'string' || !media_url) {
    res.status(400).json({ error: 'Uploaded media URL is required.' });
    return;
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO memories (id, couple_id, album_id, uploader_id, media_url, media_type, caption, memory_date, location_label, is_favorite, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    album_id || null,
    req.auth!.userId,
    media_url,
    media_type === 'video' ? 'video' : 'image',
    String(caption || '').slice(0, 400),
    String(memory_date || now.slice(0, 10)),
    String(location_label || '').slice(0, 100),
    now
  );

  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (partnerId) {
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    createNotification(req.auth!.coupleId!, partnerId, 'memories', 'New Memory Added', `${me.display_name} added a new moment to Our Memories.`);
  }
  broadcastToCouple(req.auth!.coupleId!, 'memory:updated', { id });
  res.status(201).json({ memory: db.prepare('SELECT * FROM memories WHERE id = ?').get(id) });
});

app.patch('/api/memories/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const existing = db.prepare('SELECT * FROM memories WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Memory not found.' });
    return;
  }
  const nextFav = typeof req.body?.is_favorite === 'boolean' ? (req.body.is_favorite ? 1 : 0) : existing.is_favorite;
  db.prepare('UPDATE memories SET is_favorite = ?, caption = ? WHERE id = ? AND couple_id = ?').run(
    nextFav,
    typeof req.body?.caption === 'string' ? req.body.caption.slice(0, 400) : existing.caption,
    req.params.id,
    req.auth!.coupleId
  );
  broadcastToCouple(req.auth!.coupleId!, 'memory:updated', { id: req.params.id });
  res.json({ memory: db.prepare('SELECT * FROM memories WHERE id = ?').get(req.params.id) });
});

app.post('/api/memories/:id/comments', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { content } = req.body || {};
  if (typeof content !== 'string' || !content.trim()) {
    res.status(400).json({ error: 'Comment text required.' });
    return;
  }
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO memory_comments (id, memory_id, couple_id, user_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    id,
    req.params.id,
    req.auth!.coupleId,
    req.auth!.userId,
    content.trim().slice(0, 300),
    new Date().toISOString()
  );
  broadcastToCouple(req.auth!.coupleId!, 'memory:updated', { memoryId: req.params.id });
  res.status(201).json({ ok: true });
});

app.delete('/api/memories/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM memories WHERE id = ? AND couple_id = ?').run(req.params.id, req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'memory:updated', { deleted: req.params.id });
  res.json({ ok: true });
});

// --- 13. Special Dates ---
app.get('/api/special-dates', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const dates = db.prepare('SELECT * FROM special_dates WHERE couple_id = ? ORDER BY date_value ASC').all(req.auth!.coupleId);
  res.json({ dates });
});

app.post('/api/special-dates', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { title, date_value, category, recurring_yearly, reminder_days_before, notes } = req.body || {};
  if (typeof title !== 'string' || !title.trim() || typeof date_value !== 'string' || !date_value) {
    res.status(400).json({ error: 'Title and date are required.' });
    return;
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO special_dates (id, couple_id, title, date_value, category, recurring_yearly, reminder_days_before, notes, created_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    title.trim().slice(0, 100),
    date_value,
    String(category || 'milestone'),
    recurring_yearly === false ? 0 : 1,
    Number(reminder_days_before ?? 3),
    String(notes || '').slice(0, 300),
    req.auth!.userId,
    new Date().toISOString()
  );

  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  if (partnerId) {
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    createNotification(req.auth!.coupleId!, partnerId, 'dates', 'New Special Date Added', `${me.display_name} added “${title.trim()}” (${date_value}).`);
  }
  broadcastToCouple(req.auth!.coupleId!, 'date:updated', { id });
  res.status(201).json({ date: db.prepare('SELECT * FROM special_dates WHERE id = ?').get(id) });
});

app.delete('/api/special-dates/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  db.prepare('DELETE FROM special_dates WHERE id = ? AND couple_id = ?').run(req.params.id, req.auth!.coupleId);
  broadcastToCouple(req.auth!.coupleId!, 'date:updated', { deleted: req.params.id });
  res.json({ ok: true });
});

// --- 14. Our Screen — Wallpaper Studio & Mutual Approval ---
app.get('/api/wallpapers', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const wallpapers = db.prepare('SELECT * FROM wallpapers WHERE couple_id = ? ORDER BY created_at DESC').all(req.auth!.coupleId);
  const approvals = db
    .prepare(
      `SELECT wa.* FROM wallpaper_approvals wa
       JOIN wallpapers w ON w.id = wa.wallpaper_id
       WHERE w.couple_id = ?`
    )
    .all(req.auth!.coupleId);
  res.json({ wallpapers, approvals });
});

app.post('/api/wallpapers', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { title, background_url, template_id, config } = req.body || {};
  if (typeof background_url !== 'string' || !background_url) {
    res.status(400).json({ error: 'Wallpaper background is required.' });
    return;
  }
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const partnerId = getPartnerId(req.auth!.coupleId!, req.auth!.userId);
  // If second partner hasn't joined yet, creator can preview/activate; once both are paired, mutual approval is required!
  const initialStatus = partnerId ? 'proposed' : 'approved';

  db.transaction(() => {
    db.prepare(
      `INSERT INTO wallpapers (id, couple_id, created_by, title, background_url, template_id, config_json, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      id,
      req.auth!.coupleId,
      req.auth!.userId,
      String(title || 'Our Custom Screen').slice(0, 80),
      background_url,
      String(template_id || 'romantic-clock'),
      JSON.stringify(config || {}),
      initialStatus,
      now
    );

    db.prepare('INSERT INTO wallpaper_approvals (wallpaper_id, user_id, approved, responded_at) VALUES (?, ?, 1, ?)').run(
      id,
      req.auth!.userId,
      now
    );

    if (!partnerId) {
      db.prepare('UPDATE couples SET active_wallpaper_id = ? WHERE id = ?').run(id, req.auth!.coupleId);
    }
  })();

  if (partnerId) {
    const me = db.prepare('SELECT display_name FROM users WHERE id = ?').get(req.auth!.userId) as { display_name: string };
    createNotification(
      req.auth!.coupleId!,
      partnerId,
      'wallpapers',
      'New Wallpaper Approval Request',
      `${me.display_name} designed a new shared lock screen “${String(title || 'Our Screen')}” for your approval.`
    );
  }
  broadcastToCouple(req.auth!.coupleId!, 'wallpaper:updated', { id });
  res.status(201).json({ wallpaper: db.prepare('SELECT * FROM wallpapers WHERE id = ?').get(id) });
});

app.post('/api/wallpapers/:id/respond', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { approved } = req.body || {};
  const wp = db.prepare('SELECT * FROM wallpapers WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!wp) {
    res.status(404).json({ error: 'Wallpaper not found.' });
    return;
  }

  const now = new Date().toISOString();
  db.transaction(() => {
    db.prepare(
      `INSERT INTO wallpaper_approvals (wallpaper_id, user_id, approved, responded_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(wallpaper_id, user_id) DO UPDATE SET approved=excluded.approved, responded_at=excluded.responded_at`
    ).run(req.params.id, req.auth!.userId, approved ? 1 : 0, now);

    const approvals = db
      .prepare('SELECT * FROM wallpaper_approvals WHERE wallpaper_id = ? AND approved = 1')
      .all(req.params.id) as Array<{ user_id: string }>;
    const members = db.prepare('SELECT user_id FROM couple_members WHERE couple_id = ?').all(req.auth!.coupleId) as Array<{ user_id: string }>;

    if (!approved) {
      db.prepare("UPDATE wallpapers SET status = 'archived' WHERE id = ?").run(req.params.id);
    } else if (approvals.length >= members.length) {
      db.prepare("UPDATE wallpapers SET status = 'archived' WHERE couple_id = ? AND status = 'approved'").run(req.auth!.coupleId);
      db.prepare("UPDATE wallpapers SET status = 'approved' WHERE id = ?").run(req.params.id);
      db.prepare('UPDATE couples SET active_wallpaper_id = ? WHERE id = ?').run(req.params.id, req.auth!.coupleId);
    }
  })();

  broadcastToCouple(req.auth!.coupleId!, 'wallpaper:updated', { id: req.params.id });
  broadcastToCouple(req.auth!.coupleId!, 'couple:updated', { reason: 'wallpaper' });
  res.json({ ok: true });
});

// --- 15. Our Growth (Goals & Habits) ---
app.get('/api/growth', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const goals = db.prepare('SELECT * FROM goals WHERE couple_id = ? ORDER BY is_completed ASC, created_at DESC').all(req.auth!.coupleId);
  const habits = db.prepare('SELECT * FROM habits WHERE couple_id = ? ORDER BY created_at DESC').all(req.auth!.coupleId);
  res.json({ goals, habits });
});

app.post('/api/growth/goals', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { scope, title, description, target_date } = req.body || {};
  if (typeof title !== 'string' || !title.trim()) {
    res.status(400).json({ error: 'Goal title required.' });
    return;
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO goals (id, couple_id, owner_id, scope, title, description, target_date, progress, is_completed, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)`
  ).run(
    id,
    req.auth!.coupleId,
    req.auth!.userId,
    scope === 'shared' ? 'shared' : 'personal',
    title.trim().slice(0, 120),
    String(description || '').slice(0, 400),
    String(target_date || ''),
    new Date().toISOString()
  );
  broadcastToCouple(req.auth!.coupleId!, 'growth:updated', { goalId: id });
  res.status(201).json({ goal: db.prepare('SELECT * FROM goals WHERE id = ?').get(id) });
});

app.patch('/api/growth/goals/:id', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const existing = db.prepare('SELECT * FROM goals WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | Record<string, unknown>
    | undefined;
  if (!existing) {
    res.status(404).json({ error: 'Goal not found.' });
    return;
  }
  const nextProgress = typeof req.body?.progress === 'number' ? Math.min(100, Math.max(0, req.body.progress)) : Number(existing.progress);
  const nextDone = typeof req.body?.is_completed === 'boolean' ? (req.body.is_completed ? 1 : 0) : nextProgress === 100 ? 1 : Number(existing.is_completed);
  db.prepare('UPDATE goals SET progress = ?, is_completed = ?, encouragement_note = ? WHERE id = ? AND couple_id = ?').run(
    nextProgress,
    nextDone,
    typeof req.body?.encouragement_note === 'string' ? req.body.encouragement_note.slice(0, 240) : existing.encouragement_note,
    req.params.id,
    req.auth!.coupleId
  );
  broadcastToCouple(req.auth!.coupleId!, 'growth:updated', { goalId: req.params.id });
  res.json({ goal: db.prepare('SELECT * FROM goals WHERE id = ?').get(req.params.id) });
});

app.post('/api/growth/habits', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const { title, frequency } = req.body || {};
  if (typeof title !== 'string' || !title.trim()) {
    res.status(400).json({ error: 'Habit title required.' });
    return;
  }
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO habits (id, couple_id, owner_id, title, frequency, streak, history_json, created_at)
     VALUES (?, ?, ?, ?, ?, 0, '[]', ?)`
  ).run(
    id,
    req.auth!.coupleId,
    req.auth!.userId,
    title.trim().slice(0, 100),
    ['daily', 'weekly'].includes(frequency) ? frequency : 'daily',
    new Date().toISOString()
  );
  broadcastToCouple(req.auth!.coupleId!, 'growth:updated', { habitId: id });
  res.status(201).json({ habit: db.prepare('SELECT * FROM habits WHERE id = ?').get(id) });
});

app.post('/api/growth/habits/:id/check', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const habit = db.prepare('SELECT * FROM habits WHERE id = ? AND couple_id = ?').get(req.params.id, req.auth!.coupleId) as
    | { id: string; streak: number; last_completed_date: string; history_json: string }
    | undefined;
  if (!habit) {
    res.status(404).json({ error: 'Habit not found.' });
    return;
  }
  const today = new Date().toISOString().slice(0, 10);
  const history = JSON.parse(habit.history_json || '[]') as string[];
  if (!history.includes(today)) {
    history.push(today);
    db.prepare('UPDATE habits SET streak = ?, last_completed_date = ?, history_json = ? WHERE id = ?').run(
      habit.streak + 1,
      today,
      JSON.stringify(history.slice(-60)),
      habit.id
    );
  }
  broadcastToCouple(req.auth!.coupleId!, 'growth:updated', { habitId: habit.id });
  res.json({ habit: db.prepare('SELECT * FROM habits WHERE id = ?').get(habit.id) });
});

// --- 16. Notifications Feed ---
app.get('/api/notifications', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  const notifications = db
    .prepare('SELECT * FROM notifications WHERE user_id = ? AND couple_id = ? ORDER BY created_at DESC LIMIT 40')
    .all(req.auth!.userId, req.auth!.coupleId);
  res.json({ notifications });
});

app.post('/api/notifications/read-all', requireAuth, requireCouple, (req: AuthedRequest, res) => {
  db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND couple_id = ?').run(req.auth!.userId, req.auth!.coupleId);
  res.json({ ok: true });
});

// --- HTTP + WebSocket + Vite Setup ---
async function startServer() {
  const httpServer = http.createServer(app);
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws, req) => {
    const url = new URL(req.url || '/ws', `http://${req.headers.host || 'localhost'}`);
    const queryToken = url.searchParams.get('token');
    const cookies = parseCookies(req.headers.cookie);
    const rawToken = queryToken || cookies.everus_sid;

    if (!rawToken) {
      ws.close(1008, 'Authentication required');
      return;
    }

    const session = db
      .prepare(
        `SELECT s.user_id, s.expires_at, cm.couple_id
         FROM sessions s
         LEFT JOIN couple_members cm ON cm.user_id = s.user_id
         WHERE s.token_hash = ?`
      )
      .get(hashToken(rawToken)) as { user_id: string; expires_at: string; couple_id: string | null } | undefined;

    if (!session || new Date(session.expires_at).getTime() < Date.now() || !session.couple_id) {
      ws.close(1008, 'Invalid session or unpaired couple');
      return;
    }

    const client: ConnectedClient = {
      ws,
      userId: session.user_id,
      coupleId: session.couple_id,
    };
    wsClients.add(client);
    const connectedAt = new Date().toISOString();
    db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(connectedAt, client.userId);

    const partnerId = getPartnerId(client.coupleId, client.userId);
    const partnerRow = partnerId
      ? (db.prepare('SELECT last_seen_at FROM users WHERE id = ?').get(partnerId) as { last_seen_at?: string } | undefined)
      : undefined;

    if (ws.readyState === WebSocket.OPEN) {
      ws.send(
        JSON.stringify({
          event: 'presence:state',
          payload: {
            partnerOnline: isUserOnline(partnerId),
            partnerLastSeen: partnerRow?.last_seen_at || null,
          },
          timestamp: connectedAt,
        })
      );
    }

    broadcastToCouple(
      client.coupleId,
      'presence:online',
      { userId: client.userId, online: true, lastSeen: connectedAt },
      client.userId
    );

    ws.on('message', (raw) => {
      try {
        const data = JSON.parse(String(raw));
        if (data?.event === 'chat:typing') {
          broadcastToCouple(client.coupleId, 'chat:typing', { userId: client.userId, typing: Boolean(data.typing) }, client.userId);
        } else if (data?.event === 'presence:ping') {
          const pingAt = new Date().toISOString();
          db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(pingAt, client.userId);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(
              JSON.stringify({
                event: 'presence:state',
                payload: {
                  partnerOnline: isUserOnline(partnerId),
                  partnerLastSeen: partnerId
                    ? ((db.prepare('SELECT last_seen_at FROM users WHERE id = ?').get(partnerId) as { last_seen_at?: string } | undefined)
                        ?.last_seen_at || null)
                    : null,
                },
                timestamp: pingAt,
              })
            );
          }
        } else if (data?.event === 'couple:nudge') {
          broadcastToCouple(
            client.coupleId,
            'couple:nudge',
            { userId: client.userId, emoji: typeof data.emoji === 'string' ? data.emoji.slice(0, 8) : '👋' },
            client.userId
          );
        }
      } catch {
        // Ignore malformed WS payloads
      }
    });

    ws.on('close', () => {
      wsClients.delete(client);
      const offlineAt = new Date().toISOString();
      db.prepare('UPDATE users SET last_seen_at = ? WHERE id = ?').run(offlineAt, client.userId);
      if (!isUserOnline(client.userId)) {
        broadcastToCouple(
          client.coupleId,
          'presence:online',
          { userId: client.userId, online: false, lastSeen: offlineAt },
          client.userId
        );
      }
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, allowedHosts: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('/{*splat}', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`EverUs server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start EverUs server:', err);
  process.exit(1);
});
