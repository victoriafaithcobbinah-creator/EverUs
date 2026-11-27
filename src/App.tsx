import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  Bell,
  BookOpen,
  CalendarHeart,
  Camera,
  Check,
  CheckCheck,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Circle,
  Compass,
  Copy,
  Download,
  Edit3,
  Eraser,
  FileUp,
  Gamepad2,
  Heart,
  Home,
  Image as ImageIcon,
  KeyRound,
  Lock,
  LogOut,
  Mail,
  MapPin,
  MessageCircleHeart,
  Mic,
  Moon,
  Paperclip,
  Pause,
  Pencil,
  Play,
  Plus,
  QrCode,
  RefreshCw,
  Reply,
  Search,
  Send,
  Settings,
  Share2,
  ShieldCheck,
  Smartphone,
  Smile,
  Sparkles,
  Square,
  Star,
  Sun,
  SwitchCamera,
  Target,
  Trash2,
  Unlock,
  Upload,
  UserPlus,
  Users,
  Video,
  Wallpaper as WallpaperIcon,
  WifiOff,
  X,
} from 'lucide-react';

// ============================================================================
// 1. END-TO-END ENCRYPTION (Web Crypto ECDH P-256 + HKDF + AES-256-GCM)
// ============================================================================
// Genuine End-to-End Encryption using Web Crypto API (ECDH P-256 + HKDF + AES-256-GCM)
// Private keys remain strictly on-device in IndexedDB; the server only ever sees public JWKs and ciphertext.

const DB_NAME = 'everus-e2ee-keystore';
const STORE_NAME = 'keys';

function openKeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE_NAME)) {
        req.result.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet<T>(key: string): Promise<T | null> {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve((req.result as T) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key: string, value: unknown): Promise<void> {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export interface StoredIdentityKeys {
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
}

export async function generateIdentityKeyPair(): Promise<StoredIdentityKeys> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  // Re-import private key as non-extractable for normal in-browser storage
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );
  return { publicKeyJwk, privateKey };
}

export async function ensureDeviceIdentityKeys(userId: string): Promise<StoredIdentityKeys> {
  const existing = await idbGet<{ publicKeyJwk: JsonWebKey; privateKey: CryptoKey }>(`identity:${userId}`);
  if (existing?.publicKeyJwk && existing?.privateKey) {
    return existing;
  }
  const fresh = await generateIdentityKeyPair();
  await idbSet(`identity:${userId}`, fresh);
  return fresh;
}

export async function generateBackupEnvelope(passphrase: string, pair?: StoredIdentityKeys): Promise<{
  publicKeyJwk: JsonWebKey;
  encryptedKeyBackup: string;
}> {
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicKeyJwk = pair?.publicKeyJwk || (await crypto.subtle.exportKey('jwk', keyPair.publicKey));
  const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(JSON.stringify({ publicKeyJwk, privJwk }))
  );
  const envelope = JSON.stringify({
    salt: toBase64(salt),
    iv: toBase64(iv),
    cipher: toBase64(new Uint8Array(cipher)),
  });
  return { publicKeyJwk, encryptedKeyBackup: envelope };
}

export async function restoreIdentityFromBackup(
  userId: string,
  passphrase: string,
  encryptedBackup: string
): Promise<StoredIdentityKeys> {
  const parsed = JSON.parse(encryptedBackup) as { salt: string; iv: string; cipher: string };
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: fromBase64(parsed.salt) as BufferSource, iterations: 120000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(parsed.iv) as BufferSource },
    aesKey,
    fromBase64(parsed.cipher) as BufferSource
  );
  const { publicKeyJwk, privJwk } = JSON.parse(new TextDecoder().decode(plainBuf)) as {
    publicKeyJwk: JsonWebKey;
    privJwk: JsonWebKey;
  };
  const privateKey = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const record = { publicKeyJwk, privateKey };
  await idbSet(`identity:${userId}`, record);
  return record;
}

export async function deriveSharedAesKey(myPrivateKey: CryptoKey, partnerPublicKeyJwk: JsonWebKey): Promise<CryptoKey> {
  const partnerPub = await crypto.subtle.importKey(
    'jwk',
    partnerPublicKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: partnerPub }, myPrivateKey, 256);
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('EverUs-E2EE-Salt-v1'),
      info: new TextEncoder().encode('EverUs-Couple-AES-256-GCM'),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptText(
  sharedKey: CryptoKey,
  plaintextObj: Record<string, unknown>
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(plaintextObj));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, encoded);
  return {
    ciphertext: toBase64(new Uint8Array(encrypted)),
    iv: toBase64(iv),
  };
}

export async function decryptText<T = Record<string, unknown>>(
  sharedKey: CryptoKey,
  ciphertextB64: string,
  ivB64: string
): Promise<T | null> {
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(ivB64) as BufferSource },
      sharedKey,
      fromBase64(ciphertextB64) as BufferSource
    );
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  } catch {
    return null;
  }
}

export async function encryptBinaryFile(
  sharedKey: CryptoKey,
  buffer: ArrayBuffer
): Promise<{ encryptedBlob: Blob; ivB64: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, buffer);
  return {
    encryptedBlob: new Blob([encrypted], { type: 'application/octet-stream' }),
    ivB64: toBase64(iv),
  };
}

export async function decryptBinaryFile(
  sharedKey: CryptoKey,
  encryptedBuffer: ArrayBuffer,
  ivB64: string,
  mimeType: string
): Promise<string | null> {
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(ivB64) as BufferSource },
      sharedKey,
      encryptedBuffer
    );
    const blob = new Blob([decrypted], { type: mimeType });
    return URL.createObjectURL(blob);
  } catch {
    return null;
  }
}

export async function computeSafetyFingerprint(pubA?: JsonWebKey | null, pubB?: JsonWebKey | null): Promise<string> {
  if (!pubA?.x || !pubB?.x) return 'Pending partner key';
  const sorted = [`${pubA.x}.${pubA.y}`, `${pubB.x}.${pubB.y}`].sort().join('|');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sorted));
  const bytes = new Uint8Array(digest).slice(0, 6);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('-');
}


// ============================================================================
// 2. AUTHENTICATED API & PRIVATE MEDIA CLIENT
// ============================================================================
// In-memory Bearer token store (never stored in localStorage/sessionStorage)
let memoryToken: string | null = null;
const privateMediaCache = new Map<string, string>();

export function setAuthToken(token: string | null) {
  memoryToken = token;
}

export function getAuthToken(): string | null {
  return memoryToken;
}

export async function apiRequest<T = unknown>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (memoryToken) {
    headers.set('Authorization', `Bearer ${memoryToken}`);
  }
  headers.set('X-Requested-With', 'EverUs');
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data as T;
}

export async function uploadPrivateFile(
  file: File | Blob,
  filename: string,
  extra?: { encrypted?: boolean; encryptedIv?: string; originalMime?: string; originalName?: string }
): Promise<{ url: string; attachmentId: string | null; mimeType: string; size: number }> {
  const form = new FormData();
  form.append('file', file, filename);
  if (extra?.encrypted) {
    form.append('encrypted', 'true');
    form.append('encryptedIv', extra.encryptedIv || '');
    form.append('originalMime', extra.originalMime || 'application/octet-stream');
    form.append('originalName', extra.originalName || filename);
  }
  return apiRequest('/api/uploads', {
    method: 'POST',
    body: form,
  });
}

export async function fetchAuthenticatedBlobUrl(mediaUrl: string): Promise<string> {
  if (!mediaUrl) return '';
  if (!mediaUrl.startsWith('/api/media/')) return mediaUrl;
  const cached = privateMediaCache.get(mediaUrl);
  if (cached) return cached;

  const headers = new Headers({ 'X-Requested-With': 'EverUs' });
  if (memoryToken) {
    headers.set('Authorization', `Bearer ${memoryToken}`);
  }
  const res = await fetch(mediaUrl, { headers, credentials: 'include' });
  if (!res.ok) throw new Error('Could not load private media');
  const blob = await res.blob();
  const objUrl = URL.createObjectURL(blob);
  privateMediaCache.set(mediaUrl, objUrl);
  return objUrl;
}

export async function fetchAuthenticatedArrayBuffer(mediaUrl: string): Promise<ArrayBuffer> {
  const headers = new Headers({ 'X-Requested-With': 'EverUs' });
  if (memoryToken) {
    headers.set('Authorization', `Bearer ${memoryToken}`);
  }
  const res = await fetch(mediaUrl, { headers, credentials: 'include' });
  if (!res.ok) throw new Error('Could not load encrypted attachment');
  return res.arrayBuffer();
}


// ============================================================================
// 3. CROSS-PLATFORM PWA INSTALL & OFFLINE SUPPORT
// ============================================================================

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
}

export function usePWAInstall() {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstalled, setIsInstalled] = useState(false);
  const [isIOS, setIsIOS] = useState(false);

  useEffect(() => {
    const isStandalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as unknown as { standalone?: boolean }).standalone === true;
    setIsInstalled(isStandalone);

    const ua = window.navigator.userAgent.toLowerCase();
    setIsIOS(/iphone|ipad|ipod/.test(ua));

    const onPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    };
    const onInstalled = () => {
      setIsInstalled(true);
      setDeferredPrompt(null);
    };

    window.addEventListener('beforeinstallprompt', onPrompt);
    window.addEventListener('appinstalled', onInstalled);
    return () => {
      window.removeEventListener('beforeinstallprompt', onPrompt);
      window.removeEventListener('appinstalled', onInstalled);
    };
  }, []);

  const install = async () => {
    if (!deferredPrompt) return false;
    await deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    if (outcome === 'accepted') {
      setIsInstalled(true);
      setDeferredPrompt(null);
      return true;
    }
    return false;
  };

  return { isInstallable: Boolean(deferredPrompt), isInstalled, isIOS, install };
}

export function useOnlineStatus() {
  const [isOnline, setIsOnline] = useState(typeof navigator !== 'undefined' ? navigator.onLine : true);
  useEffect(() => {
    const up = () => setIsOnline(true);
    const down = () => setIsOnline(false);
    window.addEventListener('online', up);
    window.addEventListener('offline', down);
    return () => {
      window.removeEventListener('online', up);
      window.removeEventListener('offline', down);
    };
  }, []);
  return isOnline;
}

export const PWAInstallButton: React.FC<{ compact?: boolean }> = ({ compact = false }) => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showGuide, setShowGuide] = useState(false);

  if (isInstalled) return null;

  if (isInstallable) {
    return (
      <button
        type="button"
        onClick={install}
        className="inline-flex min-h-[40px] items-center gap-2 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-4 py-2 text-xs font-semibold text-white shadow-sm transition-transform active:scale-[0.98] whitespace-nowrap shrink-0"
      >
        <Download className="h-4 w-4" />
        {compact ? 'Install' : 'Install EverUs App'}
      </button>
    );
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setShowGuide(true)}
        className="inline-flex min-h-[40px] items-center gap-2 rounded-2xl border border-pink-200 dark:border-pink-800/60 bg-white/80 dark:bg-rose-950/60 px-3.5 py-2 text-xs font-semibold text-rose-700 dark:text-pink-200 transition hover:bg-pink-50 dark:hover:bg-rose-900/40 whitespace-nowrap shrink-0"
      >
        <Smartphone className="h-4 w-4 text-pink-500" />
        {isIOS ? 'Add to iPhone' : 'Install App'}
      </button>

      {showGuide && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-3xl bg-white dark:bg-[#281526] p-6 shadow-xl border border-pink-100 dark:border-pink-900/50">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-display text-lg font-semibold text-rose-950 dark:text-pink-50">
                Install EverUs on {isIOS ? 'iPhone / iPad' : 'Android & Desktop'}
              </h3>
              <button
                type="button"
                onClick={() => setShowGuide(false)}
                className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-full hover:bg-pink-50 dark:hover:bg-pink-950/40"
                aria-label="Close install guide"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="space-y-2.5 text-sm text-rose-900/80 dark:text-pink-100/80">
              {isIOS ? (
                <>
                  <p>1. Open EverUs in Safari on your iPhone or iPad.</p>
                  <p>2. Tap the Share button at the bottom toolbar.</p>
                  <p>3. Scroll down and tap Add to Home Screen for a full-screen app experience.</p>
                </>
              ) : (
                <>
                  <p>1. On Android Chrome, open the browser menu (three dots).</p>
                  <p>2. Tap Add to Home Screen or Install App.</p>
                  <p>3. For App Store / Google Play builds, run Capacitor sync from the included setup guide.</p>
                </>
              )}
            </div>
            <button
              type="button"
              onClick={() => setShowGuide(false)}
              className="mt-5 w-full min-h-[44px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 py-2.5 text-sm font-semibold text-white"
            >
              Got it
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export const OfflineIndicator: React.FC = () => {
  const isOnline = useOnlineStatus();
  if (isOnline) return null;
  return (
    <div className="fixed bottom-20 left-4 z-50 flex items-center gap-2 rounded-2xl bg-amber-600 px-3.5 py-2 text-xs font-semibold text-white shadow-lg">
      <WifiOff className="h-3.5 w-3.5" />
      <span>Offline — Cached data active; changes will sync when reconnected</span>
    </div>
  );
};


// ============================================================================
// 4. PRIVATE MEDIA, INTERACTIVE MAP, DRAWING CANVAS & WALLPAPER STUDIO WIDGETS
// ============================================================================

export const GRADIENT_WALLPAPERS: Record<string, { label: string; css: string; stops: [string, string, string] }> = {
  'gradient:rose-quartz': {
    label: 'Rose Quartz Silk',
    css: 'linear-gradient(155deg, #ffd6e8 0%, #f9a8d4 48%, #e9d5ff 100%)',
    stops: ['#ffd6e8', '#f9a8d4', '#e9d5ff'],
  },
  'gradient:lavender-dream': {
    label: 'Lavender Dream',
    css: 'linear-gradient(155deg, #f5d0fe 0%, #ddd6fe 50%, #fbcfe8 100%)',
    stops: ['#f5d0fe', '#ddd6fe', '#fbcfe8'],
  },
  'gradient:peach-blush': {
    label: 'Peach Blush',
    css: 'linear-gradient(155deg, #fed7aa 0%, #fecdd3 52%, #f5d0fe 100%)',
    stops: ['#fed7aa', '#fecdd3', '#f5d0fe'],
  },
};

// --- Authenticated Private Media Viewer ---
export const PrivateImage: React.FC<{
  src?: string;
  alt: string;
  className?: string;
  fallbackLabel?: string;
}> = ({ src, alt, className = '', fallbackLabel }) => {
  const [resolved, setResolved] = useState<string>('');
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    setFailed(false);
    if (!src || src.startsWith('gradient:')) {
      setResolved('');
      return;
    }
    if (!src.startsWith('/api/media/')) {
      setResolved(src);
      return;
    }
    fetchAuthenticatedBlobUrl(src)
      .then((url) => {
        if (active) setResolved(url);
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
    };
  }, [src]);

  if (src && src.startsWith('gradient:')) {
    const grad = GRADIENT_WALLPAPERS[src] || GRADIENT_WALLPAPERS['gradient:rose-quartz'];
    return <div className={className} style={{ background: grad.css }} aria-label={alt} />;
  }

  if (!src || failed || !resolved) {
    return (
      <div
        className={`flex flex-col items-center justify-center bg-gradient-to-br from-pink-100 via-rose-50 to-purple-100 dark:from-rose-950/60 dark:to-purple-950/60 text-rose-400 dark:text-pink-300 ${className}`}
      >
        {fallbackLabel ? (
          <span className="font-display text-lg font-semibold">{fallbackLabel.slice(0, 2).toUpperCase()}</span>
        ) : (
          <ImageIcon className="h-6 w-6 opacity-60" />
        )}
      </div>
    );
  }

  return (
    <img
      src={resolved}
      alt={alt}
      referrerPolicy="no-referrer"
      onError={() => setFailed(true)}
      className={className}
    />
  );
};

export const PrivateVideo: React.FC<{ src: string; className?: string }> = ({ src, className = '' }) => {
  const [resolved, setResolved] = useState('');
  useEffect(() => {
    let active = true;
    if (!src.startsWith('/api/media/')) {
      setResolved(src);
      return;
    }
    fetchAuthenticatedBlobUrl(src)
      .then((u) => {
        if (active) setResolved(u);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [src]);

  if (!resolved) {
    return (
      <div className={`flex items-center justify-center bg-pink-100/60 dark:bg-rose-950/50 ${className}`}>
        <Play className="h-6 w-6 text-pink-500" />
      </div>
    );
  }
  return <video src={resolved} controls playsInline className={className} />;
};

// --- E2EE Encrypted Attachment Viewer ---
export const EncryptedAttachmentView: React.FC<{
  url: string;
  iv: string;
  mimeType: string;
  fileName: string;
  sharedKey: CryptoKey | null;
}> = ({ url, iv, mimeType, fileName, sharedKey }) => {
  const [objectUrl, setObjectUrl] = useState<string>('');
  const [error, setError] = useState(false);

  useEffect(() => {
    let active = true;
    let created = '';
    if (!sharedKey || !url || !iv) return;
    fetchAuthenticatedArrayBuffer(url)
      .then((buf) => decryptBinaryFile(sharedKey, buf, iv, mimeType))
      .then((decryptedUrl) => {
        if (!active) return;
        if (decryptedUrl) {
          created = decryptedUrl;
          setObjectUrl(decryptedUrl);
        } else {
          setError(true);
        }
      })
      .catch(() => {
        if (active) setError(true);
      });
    return () => {
      active = false;
      if (created) URL.revokeObjectURL(created);
    };
  }, [url, iv, mimeType, sharedKey]);

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl bg-rose-100/80 dark:bg-rose-900/40 px-3 py-2 text-xs text-rose-700 dark:text-pink-200">
        <Lock className="h-3.5 w-3.5" />
        <span>Unable to decrypt attachment on this device</span>
      </div>
    );
  }
  if (!objectUrl) {
    return <div className="text-xs opacity-70 py-1">Decrypting attachment…</div>;
  }

  if (mimeType.startsWith('image/')) {
    return (
      <img
        src={objectUrl}
        alt={fileName}
        referrerPolicy="no-referrer"
        className="mt-1.5 max-h-64 w-auto rounded-2xl object-cover shadow-sm"
      />
    );
  }
  if (mimeType.startsWith('video/')) {
    return <video src={objectUrl} controls playsInline className="mt-1.5 max-h-64 w-full rounded-2xl" />;
  }
  if (mimeType.startsWith('audio/')) {
    return <audio src={objectUrl} controls className="mt-1.5 w-full max-w-[240px]" />;
  }
  return (
    <a
      href={objectUrl}
      download={fileName}
      className="mt-1.5 inline-flex items-center gap-2 rounded-xl bg-white/70 dark:bg-black/25 px-3 py-2 text-xs font-medium underline"
    >
      <Download className="h-3.5 w-3.5" />
      <span>{fileName}</span>
    </a>
  );
};

// --- Interactive Couple Map (Leaflet + Safe DOM Markers) ---
export interface MapPersonMarker {
  id: string;
  name: string;
  avatarUrl?: string;
  lat: number;
  lng: number;
  updatedAt: string;
  isSelf: boolean;
}

export interface MapSavedPlace {
  id: string;
  name: string;
  latitude: number;
  longitude: number;
  radius_meters: number;
}

export const PartnerLeafletMap: React.FC<{
  markers: MapPersonMarker[];
  savedPlaces: MapSavedPlace[];
  onPickCoordinate?: (lat: number, lng: number) => void;
}> = ({ markers, savedPlaces, onPickCoordinate }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const layerGroupRef = useRef<L.LayerGroup | null>(null);

  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;
    const defaultCenter: [number, number] = markers[0]
      ? [markers[0].lat, markers[0].lng]
      : [51.5074, -0.1278];
    const map = L.map(containerRef.current, {
      center: defaultCenter,
      zoom: 13,
      zoomControl: true,
    });

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap',
      maxZoom: 19,
    }).addTo(map);

    const group = L.layerGroup().addTo(map);
    mapRef.current = map;
    layerGroupRef.current = group;

    map.on('click', (e: L.LeafletMouseEvent) => {
      onPickCoordinate?.(e.latlng.lat, e.latlng.lng);
    });

    return () => {
      map.remove();
      mapRef.current = null;
      layerGroupRef.current = null;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const group = layerGroupRef.current;
    if (!map || !group) return;
    group.clearLayers();

    const bounds: [number, number][] = [];

    for (const place of savedPlaces) {
      bounds.push([place.latitude, place.longitude]);
      L.circle([place.latitude, place.longitude], {
        radius: place.radius_meters,
        color: '#ec4899',
        fillColor: '#f9a8d4',
        fillOpacity: 0.2,
        weight: 1.5,
      }).addTo(group);

      const placeEl = document.createElement('div');
      placeEl.className =
        'px-2 py-0.5 rounded-full bg-white/95 text-rose-700 text-[11px] font-semibold shadow border border-pink-200 whitespace-nowrap';
      placeEl.textContent = place.name;
      L.marker([place.latitude, place.longitude], {
        icon: L.divIcon({ html: placeEl, className: 'everus-place-marker', iconSize: [90, 24], iconAnchor: [45, 12] }),
      }).addTo(group);
    }

    for (const m of markers) {
      bounds.push([m.lat, m.lng]);
      const wrapper = document.createElement('div');
      wrapper.className = 'flex flex-col items-center';
      const badge = document.createElement('div');
      badge.className = `w-11 h-11 rounded-full border-2 ${
        m.isSelf ? 'border-pink-500 bg-pink-100' : 'border-purple-500 bg-purple-100'
      } shadow-lg flex items-center justify-center overflow-hidden text-xs font-bold text-rose-900`;
      badge.textContent = m.name.slice(0, 2).toUpperCase();
      const caption = document.createElement('span');
      caption.className =
        'mt-1 px-2 py-0.5 rounded-full bg-white/95 text-[10px] font-semibold text-rose-950 shadow whitespace-nowrap';
      caption.textContent = m.name;
      wrapper.appendChild(badge);
      wrapper.appendChild(caption);

      if (m.avatarUrl) {
        fetchAuthenticatedBlobUrl(m.avatarUrl)
          .then((blobUrl) => {
            if (!blobUrl) return;
            badge.textContent = '';
            const img = document.createElement('img');
            img.src = blobUrl;
            img.className = 'w-full h-full object-cover';
            badge.appendChild(img);
          })
          .catch(() => {});
      }

      L.marker([m.lat, m.lng], {
        icon: L.divIcon({ html: wrapper, className: 'everus-partner-marker', iconSize: [64, 68], iconAnchor: [32, 34] }),
      }).addTo(group);
    }

    if (bounds.length === 1) {
      map.setView(bounds[0], 14);
    } else if (bounds.length > 1) {
      map.fitBounds(bounds, { padding: [48, 48], maxZoom: 15 });
    }
  }, [markers, savedPlaces]);

  return (
    <div className="relative h-72 sm:h-80 w-full overflow-hidden rounded-3xl border border-pink-200/70 dark:border-pink-900/40 bg-gradient-to-br from-pink-50 via-rose-50 to-purple-50 dark:from-rose-950/30 dark:to-purple-950/30">
      <div ref={containerRef} className="h-full w-full z-10" />
    </div>
  );
};

// --- Two-Player Drawing & Guessing Canvas ---
export const CoupleDrawingCanvas: React.FC<{
  strokes: Array<{ color: string; points: Array<{ x: number; y: number }> }>;
  canDraw: boolean;
  onAddStroke: (stroke: { color: string; points: Array<{ x: number; y: number }> }) => void;
  onClear: () => void;
}> = ({ strokes, canDraw, onAddStroke, onClear }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [color, setColor] = useState('#ec4899');
  const drawingRef = useRef<Array<{ x: number; y: number }> | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.lineWidth = 4;

    for (const s of strokes) {
      if (s.points.length < 2) continue;
      ctx.strokeStyle = s.color;
      ctx.beginPath();
      ctx.moveTo(s.points[0].x, s.points[0].y);
      for (let i = 1; i < s.points.length; i += 1) {
        ctx.lineTo(s.points[i].x, s.points[i].y);
      }
      ctx.stroke();
    }
  }, [strokes]);

  const getPos = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    return {
      x: ((e.clientX - rect.left) / rect.width) * 400,
      y: ((e.clientY - rect.top) / rect.height) * 260,
    };
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {['#ec4899', '#8b5cf6', '#f97316', '#10b981', '#1e293b'].map((c) => (
            <button
              key={c}
              type="button"
              disabled={!canDraw}
              onClick={() => setColor(c)}
              className={`h-8 w-8 rounded-full border-2 transition ${color === c ? 'scale-110 border-rose-950 dark:border-white' : 'border-white'}`}
              style={{ backgroundColor: c }}
              aria-label={`Select color ${c}`}
            />
          ))}
        </div>
        {canDraw && (
          <button
            type="button"
            onClick={onClear}
            className="inline-flex min-h-[38px] items-center gap-1.5 rounded-xl bg-pink-100 dark:bg-rose-900/50 px-3 py-1.5 text-xs font-semibold text-rose-800 dark:text-pink-100"
          >
            <Eraser className="h-3.5 w-3.5" />
            Clear Canvas
          </button>
        )}
      </div>

      <canvas
        ref={canvasRef}
        width={400}
        height={260}
        onPointerDown={(e) => {
          if (!canDraw) return;
          e.currentTarget.setPointerCapture(e.pointerId);
          drawingRef.current = [getPos(e)];
        }}
        onPointerMove={(e) => {
          if (!canDraw || !drawingRef.current) return;
          drawingRef.current.push(getPos(e));
          const ctx = canvasRef.current?.getContext('2d');
          if (ctx && drawingRef.current.length > 1) {
            const pts = drawingRef.current;
            ctx.strokeStyle = color;
            ctx.lineWidth = 4;
            ctx.lineCap = 'round';
            ctx.beginPath();
            ctx.moveTo(pts[pts.length - 2].x, pts[pts.length - 2].y);
            ctx.lineTo(pts[pts.length - 1].x, pts[pts.length - 1].y);
            ctx.stroke();
          }
        }}
        onPointerUp={() => {
          if (!canDraw || !drawingRef.current) return;
          if (drawingRef.current.length > 1) {
            onAddStroke({ color, points: drawingRef.current });
          }
          drawingRef.current = null;
        }}
        className="w-full touch-none rounded-2xl border border-pink-200 dark:border-pink-800/50 bg-white shadow-inner cursor-crosshair"
      />
    </div>
  );
};

// --- Wallpaper Studio Lock-Screen Renderer & PNG Exporter ---
export interface WallpaperConfig {
  customText: string;
  showClock: boolean;
  showDuration: boolean;
  showSpecialCountdown: boolean;
  showHearts: boolean;
  fontFamily: 'Fraunces' | 'Plus Jakarta Sans' | 'JetBrains Mono';
  textColor: string;
  widgetPosition: 'top' | 'center' | 'bottom';
  overlayTint: number;
}

export const WallpaperLockPreview: React.FC<{
  backgroundUrl: string;
  templateId: string;
  config: WallpaperConfig;
  coupleNames: string;
  daysTogether: number;
  nextSpecialLabel: string;
  avatarA?: string;
  avatarB?: string;
  nameA: string;
  nameB: string;
  compact?: boolean;
}> = ({
  backgroundUrl,
  templateId,
  config,
  coupleNames,
  daysTogether,
  nextSpecialLabel,
  avatarA,
  avatarB,
  nameA,
  nameB,
  compact = false,
}) => {
  const [now, setNow] = useState(new Date());
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 10000);
    return () => clearInterval(id);
  }, []);

  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const dateStr = now.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });

  const fontClass =
    config.fontFamily === 'Fraunces'
      ? 'font-display'
      : config.fontFamily === 'JetBrains Mono'
        ? 'font-mono-nums'
        : 'font-sans';

  const alignClass =
    config.widgetPosition === 'top'
      ? 'justify-start pt-8'
      : config.widgetPosition === 'bottom'
        ? 'justify-end pb-8'
        : 'justify-center';

  const exportLockScreenPng = async () => {
    setExporting(true);
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 1080;
      canvas.height = 1920;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      if (backgroundUrl.startsWith('gradient:')) {
        const gDef = GRADIENT_WALLPAPERS[backgroundUrl] || GRADIENT_WALLPAPERS['gradient:rose-quartz'];
        const grad = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
        grad.addColorStop(0, gDef.stops[0]);
        grad.addColorStop(0.5, gDef.stops[1]);
        grad.addColorStop(1, gDef.stops[2]);
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
      } else {
        const resolvedBg = await fetchAuthenticatedBlobUrl(backgroundUrl);
        await new Promise<void>((resolve, reject) => {
          const img = new Image();
          img.crossOrigin = 'anonymous';
          img.onload = () => {
            const ratio = Math.max(canvas.width / img.width, canvas.height / img.height);
            const w = img.width * ratio;
            const h = img.height * ratio;
            ctx.drawImage(img, (canvas.width - w) / 2, (canvas.height - h) / 2, w, h);
            resolve();
          };
          img.onerror = () => reject(new Error('bg load failed'));
          img.src = resolvedBg;
        });
      }

      ctx.fillStyle = `rgba(36, 12, 24, ${config.overlayTint / 100})`;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = config.textColor || '#ffffff';
      ctx.textAlign = 'center';
      const yBase = config.widgetPosition === 'top' ? 320 : config.widgetPosition === 'bottom' ? 1240 : 760;

      if (config.showClock) {
        ctx.font = `600 44px "${config.fontFamily}", sans-serif`;
        ctx.fillText(dateStr, canvas.width / 2, yBase);
        ctx.font = `700 176px "${config.fontFamily}", sans-serif`;
        ctx.fillText(timeStr, canvas.width / 2, yBase + 175);
      }

      ctx.font = `600 54px "${config.fontFamily}", serif`;
      ctx.fillText(coupleNames, canvas.width / 2, yBase + 275);

      if (config.customText) {
        ctx.font = `500 38px "${config.fontFamily}", sans-serif`;
        ctx.fillText(config.customText, canvas.width / 2, yBase + 340);
      }

      if (config.showDuration) {
        ctx.font = `600 40px "JetBrains Mono", monospace`;
        ctx.fillText(`${daysTogether.toLocaleString()} Days Together`, canvas.width / 2, yBase + 415);
      }

      if (config.showSpecialCountdown && nextSpecialLabel) {
        ctx.font = `500 32px "${config.fontFamily}", sans-serif`;
        ctx.fillText(nextSpecialLabel, canvas.width / 2, yBase + 475);
      }

      const dataUrl = canvas.toDataURL('image/png');
      const link = document.createElement('a');
      link.download = `EverUs-LockScreen-${Date.now()}.png`;
      link.href = dataUrl;
      link.click();
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div
        className={`relative mx-auto overflow-hidden rounded-[2.2rem] border-4 border-rose-200/80 dark:border-pink-900/60 shadow-xl ${
          compact ? 'aspect-[9/16] max-w-[200px]' : 'aspect-[9/16] max-w-[290px]'
        }`}
      >
        <PrivateImage src={backgroundUrl} alt="EverUs Lock Screen" className="absolute inset-0 h-full w-full object-cover" />
        <div
          className="absolute inset-0"
          style={{ backgroundColor: `rgba(32, 10, 22, ${config.overlayTint / 100})` }}
        />

        {templateId === 'polaroid-keepsake' && (
          <div className="absolute inset-x-5 top-1/2 -translate-y-1/2 rounded-3xl border border-white/40 bg-white/15 p-4 backdrop-blur-md" />
        )}

        <div
          className={`relative z-10 flex h-full flex-col items-center px-4 text-center ${alignClass} ${fontClass}`}
          style={{ color: config.textColor || '#ffffff' }}
        >
          {config.showClock && (
            <div className="mb-3">
              <p className={`${compact ? 'text-[10px]' : 'text-xs'} opacity-90`}>{dateStr}</p>
              <p className={`${compact ? 'text-3xl' : 'text-5xl'} font-bold tracking-tight leading-none mt-1 tabular-nums`}>
                {timeStr}
              </p>
            </div>
          )}

          <div className="flex items-center -space-x-2 my-2">
            <div className={`${compact ? 'h-7 w-7' : 'h-10 w-10'} overflow-hidden rounded-full border-2 border-white shadow`}>
              <PrivateImage src={avatarA} alt={nameA} fallbackLabel={nameA} className="h-full w-full object-cover" />
            </div>
            <div className="z-10 flex h-5 w-5 items-center justify-center rounded-full bg-pink-500 text-white shadow">
              <Heart className="h-2.5 w-2.5 fill-current" />
            </div>
            <div className={`${compact ? 'h-7 w-7' : 'h-10 w-10'} overflow-hidden rounded-full border-2 border-white shadow`}>
              <PrivateImage src={avatarB} alt={nameB} fallbackLabel={nameB} className="h-full w-full object-cover" />
            </div>
          </div>

          <p className={`${compact ? 'text-sm' : 'text-lg'} font-semibold mt-1`}>{coupleNames}</p>

          {config.customText && (
            <p className={`${compact ? 'text-[11px]' : 'text-xs'} opacity-90 mt-1 max-w-[90%]`}>{config.customText}</p>
          )}

          {config.showDuration && (
            <div className="mt-2 rounded-2xl bg-white/20 backdrop-blur-md px-3 py-1.5">
              <p className={`${compact ? 'text-[10px]' : 'text-xs'} font-semibold tabular-nums`}>
                {daysTogether.toLocaleString()} Days Together
              </p>
            </div>
          )}

          {config.showSpecialCountdown && nextSpecialLabel && (
            <p className={`${compact ? 'text-[10px]' : 'text-[11px]'} opacity-90 mt-2`}>{nextSpecialLabel}</p>
          )}

          {config.showHearts && (
            <div className="mt-3 flex items-center gap-2 opacity-80">
              <Heart className="h-3.5 w-3.5 fill-current" />
              <Heart className="h-4 w-4 fill-current" />
              <Heart className="h-3.5 w-3.5 fill-current" />
            </div>
          )}
        </div>
      </div>

      {!compact && (
        <button
          type="button"
          onClick={exportLockScreenPng}
          disabled={exporting}
          className="mx-auto flex min-h-[42px] items-center justify-center gap-2 rounded-2xl bg-white/90 dark:bg-rose-950/70 border border-pink-200 dark:border-pink-800 px-4 py-2 text-xs font-semibold text-rose-800 dark:text-pink-100 shadow-sm hover:bg-pink-50"
        >
          {exporting ? <Check className="h-4 w-4" /> : <Download className="h-4 w-4 text-pink-500" />}
          <span>{exporting ? 'Exporting PNG…' : 'Save High-Res Lock Screen (iOS & Android)'}</span>
        </button>
      )}
    </div>
  );
};

// --- Live Interactive Camera & Video Capture Modal ---
export const CameraCaptureModal: React.FC<{
  title?: string;
  allowVideo?: boolean;
  defaultFacingMode?: 'user' | 'environment';
  onCapture: (file: File) => void | Promise<void>;
  onClose: () => void;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ title = 'EverUs Camera', allowVideo = true, defaultFacingMode = 'user', onCapture, onClose, showToast }) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<BlobPart[]>([]);
  const [facingMode, setFacingMode] = useState<'user' | 'environment'>(defaultFacingMode);
  const [cameraError, setCameraError] = useState<string>('');
  const [recordingVideo, setRecordingVideo] = useState(false);
  const [recordSeconds, setRecordSeconds] = useState(0);
  const [capturedFile, setCapturedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string>('');
  const [submitting, setSubmitting] = useState(false);

  const stopStream = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (capturedFile) return;
    let cancelled = false;
    setCameraError('');
    if (!navigator.mediaDevices?.getUserMedia) {
      setCameraError('Live camera preview is not supported in this browser. Use device capture below.');
      return;
    }

    navigator.mediaDevices
      .getUserMedia({
        video: { facingMode },
        audio: allowVideo,
      })
      .catch(() =>
        navigator.mediaDevices.getUserMedia({
          video: { facingMode },
          audio: false,
        })
      )
      .then((stream) => {
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
        }
      })
      .catch(() => {
        if (!cancelled) {
          setCameraError('Camera permission denied or unavailable. You can still take/select a photo below.');
        }
      });

    return () => {
      cancelled = true;
      stopStream();
    };
  }, [facingMode, allowVideo, capturedFile, stopStream]);

  useEffect(() => {
    if (!recordingVideo) {
      setRecordSeconds(0);
      return;
    }
    const id = setInterval(() => setRecordSeconds((s) => s + 1), 1000);
    return () => clearInterval(id);
  }, [recordingVideo]);

  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const snapPhoto = () => {
    const video = videoRef.current;
    if (!video || !video.videoWidth) {
      showToast('Camera is still warming up…', 'error');
      return;
    }
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    if (facingMode === 'user') {
      ctx.translate(canvas.width, 0);
      ctx.scale(-1, 1);
    }
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    canvas.toBlob(
      (blob) => {
        if (!blob) return;
        const file = new File([blob], `EverUs-Moment-${Date.now()}.jpg`, { type: 'image/jpeg' });
        stopStream();
        setCapturedFile(file);
        setPreviewUrl(URL.createObjectURL(blob));
      },
      'image/jpeg',
      0.92
    );
  };

  const toggleVideoRecord = () => {
    if (recordingVideo && recorderRef.current) {
      recorderRef.current.stop();
      setRecordingVideo(false);
      return;
    }
    const stream = streamRef.current;
    if (!stream) return;
    try {
      const recorder = new MediaRecorder(stream);
      chunksRef.current = [];
      recorder.ondataavailable = (ev) => {
        if (ev.data.size > 0) chunksRef.current.push(ev.data);
      };
      recorder.onstop = () => {
        const mime = recorder.mimeType || 'video/webm';
        const blob = new Blob(chunksRef.current, { type: mime });
        const ext = mime.includes('mp4') ? 'mp4' : 'webm';
        const file = new File([blob], `EverUs-Clip-${Date.now()}.${ext}`, { type: mime });
        stopStream();
        setCapturedFile(file);
        setPreviewUrl(URL.createObjectURL(blob));
      };
      recorder.start();
      recorderRef.current = recorder;
      setRecordingVideo(true);
    } catch {
      showToast('Video recording is not supported on this device.', 'error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4">
      <div className="w-full max-w-md overflow-hidden rounded-[2.25rem] bg-[#1f101d] text-pink-50 shadow-2xl border border-pink-400/30">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/10">
          <div className="flex items-center gap-2">
            <Camera className="h-4 w-4 text-pink-400" />
            <span className="font-display text-base font-semibold">{title}</span>
          </div>
          <button
            type="button"
            onClick={() => {
              stopStream();
              onClose();
            }}
            className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded-full hover:bg-white/10"
            aria-label="Close camera"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="relative aspect-[3/4] w-full bg-black flex items-center justify-center overflow-hidden">
          {capturedFile && previewUrl ? (
            capturedFile.type.startsWith('video/') ? (
              <video src={previewUrl} controls autoPlay playsInline className="h-full w-full object-cover" />
            ) : (
              <img src={previewUrl} alt="Captured preview" className="h-full w-full object-cover" />
            )
          ) : cameraError ? (
            <div className="p-6 text-center space-y-4">
              <Camera className="h-10 w-10 text-pink-400 mx-auto opacity-80" />
              <p className="text-xs text-pink-100/80 leading-relaxed">{cameraError}</p>
              <label className="inline-flex min-h-[44px] items-center gap-2 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-5 text-xs font-semibold text-white cursor-pointer">
                <Camera className="h-4 w-4" />
                <span>Open Device Camera / Photo</span>
                <input
                  type="file"
                  accept={allowVideo ? 'image/*,video/*' : 'image/*'}
                  capture={facingMode}
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    setCapturedFile(f);
                    setPreviewUrl(URL.createObjectURL(f));
                  }}
                />
              </label>
            </div>
          ) : (
            <>
              <video
                ref={videoRef}
                autoPlay
                playsInline
                muted
                className={`h-full w-full object-cover ${facingMode === 'user' ? '-scale-x-100' : ''}`}
              />
              {recordingVideo && (
                <div className="absolute top-3 left-1/2 -translate-x-1/2 flex items-center gap-1.5 rounded-full bg-rose-600/90 px-3 py-1 text-xs font-semibold text-white">
                  <span className="h-2 w-2 rounded-full bg-white animate-pulse" />
                  <span className="font-mono-nums">REC {recordSeconds}s</span>
                </div>
              )}
              <button
                type="button"
                onClick={() => setFacingMode((m) => (m === 'user' ? 'environment' : 'user'))}
                className="absolute top-3 right-3 flex h-10 w-10 items-center justify-center rounded-full bg-black/45 text-white backdrop-blur-md hover:bg-black/65"
                title="Switch camera"
              >
                <SwitchCamera className="h-4 w-4" />
              </button>
            </>
          )}
        </div>

        <div className="p-4 flex items-center justify-center gap-3 bg-[#281526]">
          {capturedFile ? (
            <>
              <button
                type="button"
                onClick={() => {
                  if (previewUrl) URL.revokeObjectURL(previewUrl);
                  setCapturedFile(null);
                  setPreviewUrl('');
                }}
                className="flex-1 min-h-[44px] rounded-2xl border border-pink-300/30 text-xs font-semibold text-pink-100"
              >
                Retake
              </button>
              <button
                type="button"
                disabled={submitting}
                onClick={async () => {
                  setSubmitting(true);
                  try {
                    await onCapture(capturedFile);
                    onClose();
                  } finally {
                    setSubmitting(false);
                  }
                }}
                className="flex-1 min-h-[44px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-xs font-semibold text-white shadow-md"
              >
                {submitting ? 'Saving…' : 'Use Photo / Video'}
              </button>
            </>
          ) : (
            !cameraError && (
              <>
                {allowVideo && (
                  <button
                    type="button"
                    onClick={toggleVideoRecord}
                    className={`min-h-[46px] rounded-2xl px-4 text-xs font-semibold flex items-center gap-1.5 ${
                      recordingVideo ? 'bg-rose-600 text-white' : 'bg-white/10 text-pink-100 hover:bg-white/20'
                    }`}
                  >
                    {recordingVideo ? <Square className="h-3.5 w-3.5 fill-current" /> : <Video className="h-4 w-4" />}
                    <span>{recordingVideo ? 'Stop Clip' : 'Video'}</span>
                  </button>
                )}
                <button
                  type="button"
                  disabled={recordingVideo}
                  onClick={snapPhoto}
                  className="h-14 w-14 rounded-full border-4 border-pink-300 bg-white flex items-center justify-center shadow-lg active:scale-95 transition disabled:opacity-40"
                  aria-label="Take photo"
                >
                  <span className="h-10 w-10 rounded-full bg-gradient-to-br from-pink-500 to-rose-500" />
                </button>
                <label className="min-h-[46px] rounded-2xl bg-white/10 hover:bg-white/20 px-4 text-xs font-semibold text-pink-100 flex items-center gap-1.5 cursor-pointer">
                  <Upload className="h-4 w-4" />
                  <span>Gallery</span>
                  <input
                    type="file"
                    accept={allowVideo ? 'image/*,video/*' : 'image/*'}
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (!f) return;
                      stopStream();
                      setCapturedFile(f);
                      setPreviewUrl(URL.createObjectURL(f));
                    }}
                  />
                </label>
              </>
            )
          )}
        </div>
      </div>
    </div>
  );
};


// ============================================================================
// 5. MAIN EVERUS APPLICATION
// ============================================================================

// --- Curated Non-People Pastel Wallpaper Templates ---
const WALLPAPER_TEMPLATES = [
  {
    id: 'rose-quartz',
    name: 'Rose Quartz Silk',
    url: 'gradient:rose-quartz',
  },
  {
    id: 'blush-clouds',
    name: 'Blush Watercolor Sky',
    url: '/src/assets/images/everus_wallpaper_blush_1795795822044.jpg',
  },
  {
    id: 'floral-meadow',
    name: 'Peony Sunset Meadow',
    url: '/src/assets/images/everus_wallpaper_floral_1795795823063.jpg',
  },
  {
    id: 'lavender-dream',
    name: 'Lavender Dream',
    url: 'gradient:lavender-dream',
  },
  {
    id: 'peach-blush',
    name: 'Peach Blush',
    url: 'gradient:peach-blush',
  },
];

const CHOSEN_WALLPAPER_KEY = 'everus_chosen_wallpaper';

function getSavedStarterWallpaper(): string {
  try {
    return localStorage.getItem(CHOSEN_WALLPAPER_KEY) || WALLPAPER_TEMPLATES[0].url;
  } catch {
    return WALLPAPER_TEMPLATES[0].url;
  }
}

function saveStarterWallpaper(url: string) {
  try {
    localStorage.setItem(CHOSEN_WALLPAPER_KEY, url);
  } catch {
    // ignore storage quota errors
  }
}

type SectionKey =
  | 'home'
  | 'tasks'
  | 'location'
  | 'chat'
  | 'games'
  | 'plans'
  | 'memories'
  | 'dates'
  | 'screen'
  | 'growth'
  | 'settings';

interface UserProfile {
  id: string;
  email: string;
  display_name: string;
  nickname: string;
  bio: string;
  avatar_url: string;
  public_key_jwk: string;
  encrypted_key_backup: string;
  dark_mode: number;
  email_verified?: number;
  email_2fa_enabled?: number;
  last_seen_at?: string;
  mood_status?: string;
}

const COUPLE_MOOD_CHIPS = [
  'Missing you 💕',
  'Ready to chat 💬',
  'Cozy & relaxed 🧸',
  'Busy / Working 💻',
  'On my way 🚗',
  'Praying for us 🙏',
];

interface CoupleInfo {
  id: string;
  name: string;
  start_date: string;
  status: 'pending' | 'active';
  active_wallpaper_id: string | null;
  has_pin: boolean;
}

interface NotificationItem {
  id: string;
  type: string;
  title: string;
  body: string;
  is_read: number;
  created_at: string;
}

interface LoveBurst {
  id: string;
  kind: 'heart' | 'kiss' | 'hug' | 'note';
  message: string;
  senderName: string;
}

interface DecryptedChatMessage {
  id: string;
  sender_id: string;
  recipient_id: string;
  ciphertext: string;
  iv: string;
  message_type: string;
  attachment_id: string | null;
  attachment_url?: string;
  attachment_mime?: string;
  attachment_name?: string;
  attachment_iv?: string;
  reply_to_id: string | null;
  reactions_json: string;
  is_edited: number;
  is_deleted: number;
  delivered_at: string | null;
  read_at: string | null;
  created_at: string;
  decryptedText?: string;
  decryptedSticker?: string;
}

const LOVE_PRESETS = [
  { kind: 'kiss' as const, label: 'Million Kisses', message: 'Sending you a million kisses.' },
  { kind: 'heart' as const, label: 'Miss You', message: 'I miss you so much.' },
  { kind: 'heart' as const, label: 'Thinking of You', message: 'Thinking of you right now.' },
  { kind: 'note' as const, label: 'Favourite Person', message: 'You are my favourite person.' },
  { kind: 'hug' as const, label: 'Virtual Hug', message: 'Sending a warm virtual hug.' },
];

const COUPLE_STICKERS = ['😘', '🥰', '💐', '🍓', '💌', '🌙', '🧸', '💍'];

const WOULD_YOU_RATHER_PROMPTS = [
  ['Sunrise picnic on the beach', 'Candlelit rooftop dinner under the stars'],
  ['Spontaneous weekend road trip', 'Cozy cabin stay with hot cocoa & movies'],
  ['Cook a gourmet meal together', 'Order takeout and dance in the kitchen'],
  ['Handwritten love letters every month', 'Surprise mini-dates every Sunday'],
  ['Travel to Paris in spring', 'Explore Kyoto during cherry blossom season'],
];

const COUPLE_QUESTIONS = [
  'What small everyday moment with me makes you feel most loved?',
  'What is one dream trip or adventure you want us to take next year?',
  'When did you first realize our connection was truly special?',
  'What song instantly reminds you of us?',
  'What habit or goal would you love for us to build together this month?',
  'If we had a completely free Sunday with zero responsibilities, what would we do?',
];

const ROMANTIC_CHALLENGES = [
  'Write a 3-sentence appreciation note and send it via Send Love.',
  'Cook or make your partner’s favorite warm drink today.',
  'Take a cozy selfie together and save it to Our Memories.',
  'Plan a 30-minute phone-free walk or evening chat tonight.',
  'Design a brand new lock screen together in Our Screen.',
];

const QUIZ_QUESTIONS = [
  { q: 'What is my ideal Saturday morning?', options: ['Slow coffee in bed', 'Early brunch adventure', 'Farmers market walk', 'Sleeping in late'] },
  { q: 'Which love language speaks loudest to me?', options: ['Words of affirmation', 'Quality time', 'Physical touch', 'Acts of service'] },
  { q: 'What treat always brightens my day?', options: ['Fresh flowers', 'Iced latte or tea', 'Warm pastry or chocolate', 'A surprise voice note'] },
];

const DRAWING_WORDS = ['Heart', 'Sunset', 'Coffee Cup', 'Rose', 'Moon & Stars', 'Picnic', 'Ring', 'House'];

const PLAN_CATEGORIES = [
  'Business plans',
  'Financial goals',
  'Relationship goals',
  'Travel plans',
  'Future dreams',
  'Shared projects',
  'Personal development goals',
];

function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const diffSec = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diffSec < 45) return 'Just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function daysUntilDate(dateStr: string, recurringYearly: boolean): number {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const parts = dateStr.split('-').map(Number);
  if (parts.length !== 3) return 0;
  let target = new Date(parts[0], parts[1] - 1, parts[2]);
  if (recurringYearly) {
    target = new Date(today.getFullYear(), parts[1] - 1, parts[2]);
    if (target < today) {
      target = new Date(today.getFullYear() + 1, parts[1] - 1, parts[2]);
    }
  }
  return Math.ceil((target.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));
}

export default function EverUsApp() {
  // --- Core Auth & Session State ---
  const [bootLoading, setBootLoading] = useState(true);
  const [splashReady, setSplashReady] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [partner, setPartner] = useState<UserProfile | null>(null);
  const [couple, setCouple] = useState<CoupleInfo | null>(null);
  const [devices, setDevices] = useState<Array<{ id: string; device_name: string; platform: string; last_active_at: string }>>([]);
  const [currentDeviceId, setCurrentDeviceId] = useState<string>('');
  const [notifPrefs, setNotifPrefs] = useState<Record<string, number>>({});
  const [isPinUnlocked, setIsPinUnlocked] = useState(false);
  const [pinRequireAfterBoot, setPinRequireAfterBoot] = useState(false);

  // --- UI Navigation & Global Overlays ---
  const [section, setSection] = useState<SectionKey>('home');
  const [darkMode, setDarkMode] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [loveBurst, setLoveBurst] = useState<LoveBurst | null>(null);
  const [showLoveModal, setShowLoveModal] = useState(false);
  const [showNotifDrawer, setShowNotifDrawer] = useState(false);
  const [partnerOnline, setPartnerOnline] = useState(false);
  const [partnerLastSeen, setPartnerLastSeen] = useState<string | null>(null);
  const [homeCameraTarget, setHomeCameraTarget] = useState<'chat' | 'memories' | null>(null);
  const [verseAmen, setVerseAmen] = useState(false);

  // --- E2EE State ---
  const [identityKeys, setIdentityKeys] = useState<StoredIdentityKeys | null>(null);
  const [sharedAesKey, setSharedAesKey] = useState<CryptoKey | null>(null);
  const [safetyFingerprint, setSafetyFingerprint] = useState<string>('Pending partner key');
  const [needsKeyRestore, setNeedsKeyRestore] = useState(false);
  const [restorePassphrase, setRestorePassphrase] = useState('');

  // --- Domain Data States ---
  const [verseToday, setVerseToday] = useState<{ reference: string; text: string; translation: string; dayKey: string } | null>(null);
  const [savedVerses, setSavedVerses] = useState<Array<{ id: string; reference: string; verse_text: string; note: string; created_at: string }>>([]);
  const [tasks, setTasks] = useState<Array<Record<string, any>>>([]);
  const [taskHistory, setTaskHistory] = useState<Array<Record<string, any>>>([]);
  const [messages, setMessages] = useState<DecryptedChatMessage[]>([]);
  const [partnerTyping, setPartnerTyping] = useState(false);
  const [loveItems, setLoveItems] = useState<Array<Record<string, any>>>([]);
  const [locationData, setLocationData] = useState<{
    preferences: Array<Record<string, any>>;
    locations: Array<Record<string, any>>;
    savedPlaces: Array<Record<string, any>>;
  }>({ preferences: [], locations: [], savedPlaces: [] });
  const [games, setGames] = useState<Array<Record<string, any>>>([]);
  const [plansData, setPlansData] = useState<{ plans: Array<Record<string, any>>; updates: Array<Record<string, any>> }>({
    plans: [],
    updates: [],
  });
  const [memoriesData, setMemoriesData] = useState<{
    albums: Array<Record<string, any>>;
    memories: Array<Record<string, any>>;
    comments: Array<Record<string, any>>;
  }>({ albums: [], memories: [], comments: [] });
  const [specialDates, setSpecialDates] = useState<Array<Record<string, any>>>([]);
  const [wallpapersData, setWallpapersData] = useState<{
    wallpapers: Array<Record<string, any>>;
    approvals: Array<Record<string, any>>;
  }>({ wallpapers: [], approvals: [] });
  const [growthData, setGrowthData] = useState<{ goals: Array<Record<string, any>>; habits: Array<Record<string, any>> }>({
    goals: [],
    habits: [],
  });
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [invitationInfo, setInvitationInfo] = useState<{ code: string; expires_at: string; qrDataUrl: string } | null>(null);

  const showToast = useCallback((text: string, type: 'success' | 'error' = 'success') => {
    setToast({ text, type });
    setTimeout(() => setToast(null), 3500);
  }, []);

  // --- Dark Mode Sync ---
  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
  }, [darkMode]);

  // --- Load User Session on Boot ---
  const loadAuthState = useCallback(async () => {
    try {
      const me = await apiRequest<{
        user: UserProfile;
        couple: CoupleInfo | null;
        partner: UserProfile | null;
        partnerOnline?: boolean;
        devices: Array<{ id: string; device_name: string; platform: string; last_active_at: string }>;
        notificationPreferences: Record<string, number>;
        currentDeviceId: string;
      }>('/api/auth/me');
      setUser(me.user);
      setCouple(me.couple);
      setPartner(me.partner);
      setPartnerOnline(Boolean(me.partnerOnline));
      setPartnerLastSeen(me.partner?.last_seen_at || null);
      setDevices(me.devices || []);
      setNotifPrefs(me.notificationPreferences || {});
      setCurrentDeviceId(me.currentDeviceId || '');
      setDarkMode(Boolean(me.user.dark_mode));
      if (me.couple?.has_pin) {
        setPinRequireAfterBoot(true);
      } else {
        setIsPinUnlocked(true);
      }
    } catch {
      setUser(null);
      setCouple(null);
      setPartner(null);
      setPartnerOnline(false);
    } finally {
      setBootLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAuthState();
    const timer = setTimeout(() => setSplashReady(true), 4000);
    return () => clearTimeout(timer);
  }, [loadAuthState]);

  // --- Initialize E2EE Keys when User & Partner are available ---
  useEffect(() => {
    if (!user) {
      setIdentityKeys(null);
      setSharedAesKey(null);
      return;
    }
    let active = true;
    ensureDeviceIdentityKeys(user.id)
      .then(async (keys) => {
        if (!active) return;
        setIdentityKeys(keys);
        // Check if server has a different public key (meaning another browser/device registered originally)
        if (user.public_key_jwk) {
          try {
            const serverPub = JSON.parse(user.public_key_jwk) as JsonWebKey;
            if (serverPub.x && serverPub.x !== keys.publicKeyJwk.x && user.encrypted_key_backup) {
              setNeedsKeyRestore(true);
            }
          } catch {
            // ignore
          }
        } else {
          await apiRequest('/api/profile', {
            method: 'PATCH',
            body: JSON.stringify({ public_key_jwk: keys.publicKeyJwk }),
          }).catch(() => {});
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [user?.id, user?.public_key_jwk, user?.encrypted_key_backup]);

  useEffect(() => {
    if (!identityKeys || !partner?.public_key_jwk) {
      setSharedAesKey(null);
      setSafetyFingerprint('Waiting for partner device key');
      return;
    }
    let active = true;
    try {
      const partnerPub = JSON.parse(partner.public_key_jwk) as JsonWebKey;
      deriveSharedAesKey(identityKeys.privateKey, partnerPub).then((aes) => {
        if (active) setSharedAesKey(aes);
      });
      computeSafetyFingerprint(identityKeys.publicKeyJwk, partnerPub).then((fp) => {
        if (active) setSafetyFingerprint(fp);
      });
    } catch {
      setSharedAesKey(null);
    }
    return () => {
      active = false;
    };
  }, [identityKeys, partner?.public_key_jwk]);

  // --- Domain Data Loaders ---
  const refreshAllCoupleData = useCallback(async () => {
    if (!couple) return;
    try {
      const [
        verseRes,
        tasksRes,
        loveRes,
        locRes,
        gamesRes,
        plansRes,
        memRes,
        datesRes,
        wpRes,
        growthRes,
        notifRes,
        inviteRes,
      ] = await Promise.all([
        apiRequest<{ today: any; saved: any[] }>('/api/verse/today'),
        apiRequest<{ tasks: any[]; history: any[] }>('/api/tasks'),
        apiRequest<{ items: any[] }>('/api/love'),
        apiRequest<{ preferences: any[]; locations: any[]; savedPlaces: any[] }>('/api/location'),
        apiRequest<{ sessions: any[] }>('/api/games'),
        apiRequest<{ plans: any[]; updates: any[] }>('/api/plans'),
        apiRequest<{ albums: any[]; memories: any[]; comments: any[] }>('/api/memories'),
        apiRequest<{ dates: any[] }>('/api/special-dates'),
        apiRequest<{ wallpapers: any[]; approvals: any[] }>('/api/wallpapers'),
        apiRequest<{ goals: any[]; habits: any[] }>('/api/growth'),
        apiRequest<{ notifications: NotificationItem[] }>('/api/notifications'),
        apiRequest<{ paired: boolean; invitation: any }>('/api/couple/invitation'),
      ]);

      setVerseToday(verseRes.today);
      setSavedVerses(verseRes.saved);
      setTasks(tasksRes.tasks);
      setTaskHistory(tasksRes.history);
      setLoveItems(loveRes.items);
      setLocationData(locRes);
      setGames(gamesRes.sessions);
      setPlansData(plansRes);
      setMemoriesData(memRes);
      setSpecialDates(datesRes.dates);
      setWallpapersData(wpRes);
      setGrowthData(growthRes);
      setNotifications(notifRes.notifications);
      setInvitationInfo(inviteRes.invitation);
    } catch {
      // ignore transient boot error
    }
  }, [couple?.id]);

  const loadAndDecryptMessages = useCallback(async () => {
    if (!couple) return;
    try {
      const res = await apiRequest<{ messages: DecryptedChatMessage[] }>('/api/chat/messages');
      if (!sharedAesKey) {
        setMessages(res.messages);
        return;
      }
      const decrypted = await Promise.all(
        res.messages.map(async (m) => {
          if (m.is_deleted) return { ...m, decryptedText: 'This message was deleted' };
          const plain = await decryptText<{ text?: string; sticker?: string }>(sharedAesKey, m.ciphertext, m.iv);
          return {
            ...m,
            decryptedText: plain?.text ?? '[Encrypted with a previous device key]',
            decryptedSticker: plain?.sticker,
          };
        })
      );
      setMessages(decrypted);
    } catch {
      // ignore
    }
  }, [couple?.id, sharedAesKey]);

  useEffect(() => {
    if (couple && (isPinUnlocked || !pinRequireAfterBoot)) {
      refreshAllCoupleData();
    }
  }, [couple?.id, isPinUnlocked, pinRequireAfterBoot, refreshAllCoupleData]);

  useEffect(() => {
    if (couple && (isPinUnlocked || !pinRequireAfterBoot)) {
      loadAndDecryptMessages();
    }
  }, [couple?.id, sharedAesKey, isPinUnlocked, pinRequireAfterBoot, loadAndDecryptMessages]);

  // --- Real-Time WebSocket Client ---
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    if (!user || !couple) return;
    let closedByEffect = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let pingTimer: ReturnType<typeof setInterval> | null = null;

    const connect = () => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const token = getAuthToken();
      const wsUrl = `${proto}//${window.location.host}/ws${token ? `?token=${encodeURIComponent(token)}` : ''}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (pingTimer) clearInterval(pingTimer);
        pingTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ event: 'presence:ping' }));
          }
        }, 20000);
      };

      ws.onmessage = async (ev) => {
        try {
          const { event, payload } = JSON.parse(ev.data);
          if (event === 'presence:state') {
            setPartnerOnline(Boolean(payload.partnerOnline));
            if (payload.partnerLastSeen) setPartnerLastSeen(payload.partnerLastSeen);
          } else if (event === 'presence:online') {
            if (payload.userId !== user.id) {
              setPartnerOnline(Boolean(payload.online));
              if (payload.lastSeen) setPartnerLastSeen(payload.lastSeen);
            }
          } else if (event === 'couple:nudge') {
            if (payload.userId !== user.id) {
              setLoveBurst({
                id: String(Date.now()),
                kind: 'heart',
                message: `${partner?.display_name || 'Your partner'} waved at you ${payload.emoji || '👋'}`,
                senderName: partner?.display_name || 'Your Partner',
              });
              setTimeout(() => setLoveBurst(null), 3200);
            }
          } else if (event === 'couple:updated') {
            await loadAuthState();
            await refreshAllCoupleData();
          } else if (event === 'task:sync') {
            const res = await apiRequest<{ tasks: any[]; history: any[] }>('/api/tasks');
            setTasks(res.tasks);
            setTaskHistory(res.history);
          } else if (event === 'chat:typing') {
            if (payload.userId !== user.id) setPartnerTyping(Boolean(payload.typing));
          } else if (
            event === 'chat:message' ||
            event === 'chat:read' ||
            event === 'chat:reaction' ||
            event === 'chat:edit' ||
            event === 'chat:delete'
          ) {
            await loadAndDecryptMessages();
          } else if (event === 'love:received') {
            const res = await apiRequest<{ items: any[] }>('/api/love');
            setLoveItems(res.items);
            if (payload.sender_id !== user.id) {
              setLoveBurst({
                id: payload.id,
                kind: payload.kind,
                message: payload.message,
                senderName: partner?.display_name || 'Your Partner',
              });
              setTimeout(() => setLoveBurst(null), 4200);
            }
          } else if (event === 'love:responded') {
            const res = await apiRequest<{ items: any[] }>('/api/love');
            setLoveItems(res.items);
          } else if (event === 'location:updated') {
            const res = await apiRequest<any>('/api/location');
            setLocationData(res);
          } else if (event === 'game:updated') {
            const res = await apiRequest<{ sessions: any[] }>('/api/games');
            setGames(res.sessions);
          } else if (event === 'plan:updated') {
            const res = await apiRequest<any>('/api/plans');
            setPlansData(res);
          } else if (event === 'memory:updated') {
            const res = await apiRequest<any>('/api/memories');
            setMemoriesData(res);
          } else if (event === 'date:updated') {
            const res = await apiRequest<{ dates: any[] }>('/api/special-dates');
            setSpecialDates(res.dates);
          } else if (event === 'wallpaper:updated') {
            const res = await apiRequest<any>('/api/wallpapers');
            setWallpapersData(res);
          } else if (event === 'growth:updated') {
            const res = await apiRequest<any>('/api/growth');
            setGrowthData(res);
          } else if (event === 'verse:updated') {
            setSavedVerses(payload);
          } else if (event === 'notification:new') {
            if (payload.user_id === user.id) {
              setNotifications((prev) => (prev.some((n) => n.id === payload.id) ? prev : [payload, ...prev]));
            }
          }
        } catch {
          // ignore
        }
      };

      ws.onclose = () => {
        if (pingTimer) clearInterval(pingTimer);
        if (!closedByEffect) {
          reconnectTimer = setTimeout(connect, 2500);
        }
      };
    };

    connect();
    return () => {
      closedByEffect = true;
      if (pingTimer) clearInterval(pingTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, [user?.id, couple?.id, partner?.display_name, loadAuthState, refreshAllCoupleData, loadAndDecryptMessages]);

  // --- Computed Relationship Duration & Active Wallpaper ---
  const [tickNow, setTickNow] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setTickNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const togetherStats = useMemo(() => {
    if (!couple?.start_date) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0, nextMilestone: 100, milestoneProgress: 0 };
    }
    const start = new Date(`${couple.start_date}T00:00:00`);
    const diffMs = Math.max(0, tickNow.getTime() - start.getTime());
    const totalSec = Math.floor(diffMs / 1000);
    const days = Math.floor(totalSec / 86400);
    const hours = Math.floor((totalSec % 86400) / 3600);
    const minutes = Math.floor((totalSec % 3600) / 60);
    const seconds = totalSec % 60;
    const milestones = [30, 100, 180, 365, 500, 730, 1000, 1460, 1825, 2500, 3650];
    const nextMilestone = milestones.find((m) => m > days) || days + 365;
    const prevMilestone = [...milestones].reverse().find((m) => m <= days) || 0;
    const milestoneProgress = Math.min(100, Math.round(((days - prevMilestone) / Math.max(1, nextMilestone - prevMilestone)) * 100));
    return { days, hours, minutes, seconds, nextMilestone, milestoneProgress };
  }, [couple?.start_date, tickNow]);

  const activeWallpaper = useMemo(() => {
    if (!couple?.active_wallpaper_id) return null;
    return wallpapersData.wallpapers.find((w) => w.id === couple.active_wallpaper_id) || null;
  }, [couple?.active_wallpaper_id, wallpapersData.wallpapers]);

  const unreadNotifsCount = useMemo(() => notifications.filter((n) => n.is_read === 0).length, [notifications]);

  // --- Send Love Action ---
  const triggerSendLove = async (kind: 'heart' | 'kiss' | 'hug' | 'note', message: string) => {
    try {
      await apiRequest('/api/love', {
        method: 'POST',
        body: JSON.stringify({ kind, message }),
      });
      setLoveBurst({
        id: String(Date.now()),
        kind,
        message,
        senderName: user?.display_name || 'You',
      });
      setTimeout(() => setLoveBurst(null), 3500);
      setShowLoveModal(false);
      showToast(`Sent love to ${partner?.display_name || 'your partner'}!`);
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Could not send love', 'error');
    }
  };

  if (bootLoading || !splashReady) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-[#fff5f8] via-[#ffdce9] to-[#efe3ff] dark:from-[#170d16] dark:via-[#231021] dark:to-[#1e122c] p-6 text-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.88 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6 }}
          className="flex flex-col items-center max-w-xs w-full"
        >
          <motion.div
            animate={{ scale: [1, 1.1, 1] }}
            transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
            className="flex h-20 w-20 items-center justify-center rounded-[2rem] bg-gradient-to-br from-pink-500 to-rose-500 text-white shadow-xl"
          >
            <Heart className="h-10 w-10 fill-current" />
          </motion.div>
          <h1 className="mt-6 font-display text-4xl font-bold tracking-tight text-rose-950 dark:text-pink-50">EverUs</h1>
          <p className="mt-1.5 text-sm font-medium text-rose-800/80 dark:text-pink-200/80">
            Two lives. One shared journey.
          </p>

          <div className="mt-7 h-1.5 w-48 overflow-hidden rounded-full bg-white/80 dark:bg-white/15 shadow-inner">
            <motion.div
              initial={{ scaleX: 0 }}
              animate={{ scaleX: 1 }}
              transition={{ duration: 4, ease: 'linear' }}
              style={{ transformOrigin: 'left center' }}
              className="h-full w-full rounded-full bg-gradient-to-r from-pink-500 via-rose-500 to-purple-500"
            />
          </div>
          <p className="mt-3 text-xs text-rose-700/75 dark:text-pink-200/70">Opening your private space…</p>
        </motion.div>
      </div>
    );
  }

  // --- Unauthenticated Welcome / Auth Flow ---
  if (!user) {
    return (
      <>
        <AuthAndWelcomeScreen
          onAuthenticated={(data) => {
            setAuthToken(data.token);
            setUser(data.user);
            setCouple(data.couple);
            setPartner(data.partner);
            setPartnerOnline(Boolean(data.partnerOnline));
            setPartnerLastSeen(data.partner?.last_seen_at || null);
            setDarkMode(Boolean(data.user.dark_mode));
            setIsPinUnlocked(true);
            setPinRequireAfterBoot(false);
          }}
          showToast={showToast}
        />
        <ToastOverlay toast={toast} />
        <OfflineIndicator />
      </>
    );
  }

  // --- Onboarding Couple Space Pairing (Create or Join) ---
  if (!couple) {
    return (
      <>
        <CouplePairingScreen
          user={user}
          onSpaceReady={async () => {
            await loadAuthState();
            setIsPinUnlocked(true);
            setPinRequireAfterBoot(false);
          }}
          onLogout={async () => {
            await apiRequest('/api/auth/logout', { method: 'POST' });
            setAuthToken(null);
            setUser(null);
          }}
          showToast={showToast}
        />
        <ToastOverlay toast={toast} />
        <OfflineIndicator />
      </>
    );
  }

  // --- Shared App-Lock PIN Gate ---
  if (pinRequireAfterBoot && !isPinUnlocked) {
    return (
      <>
        <SharedPinLockScreen
          coupleName={couple.name}
          userEmail={user.email}
          onUnlocked={() => {
            setIsPinUnlocked(true);
            setPinRequireAfterBoot(false);
          }}
          onLogout={async () => {
            await apiRequest('/api/auth/logout', { method: 'POST' });
            setAuthToken(null);
            setUser(null);
          }}
          showToast={showToast}
        />
        <ToastOverlay toast={toast} />
        <OfflineIndicator />
      </>
    );
  }

  const coupleTitle = partner ? `${user.display_name} & ${partner.display_name}` : `${user.display_name}’s Space`;

  const navItems: Array<{ key: SectionKey; label: string; icon: React.FC<{ className?: string }> }> = [
    { key: 'home', label: 'Home', icon: Home },
    { key: 'chat', label: 'Chat', icon: MessageCircleHeart },
    { key: 'tasks', label: 'Tasks', icon: CheckCircle2 },
    { key: 'memories', label: 'Memories', icon: Camera },
    { key: 'settings', label: 'Settings', icon: Settings },
  ];

  const allFeatureShortcuts: Array<{
    key: SectionKey;
    title: string;
    subtitle: string;
    icon: React.FC<{ className?: string }>;
    gradient: string;
  }> = [
    {
      key: 'tasks',
      title: 'Daily Tasks',
      subtitle: `${tasks.filter((t) => !t.is_completed).length} pending`,
      icon: CheckCircle2,
      gradient: 'from-pink-100 to-rose-200/80 dark:from-pink-950/70 dark:to-rose-900/50',
    },
    {
      key: 'location',
      title: 'Location',
      subtitle: 'Consensual live map',
      icon: MapPin,
      gradient: 'from-purple-100 to-pink-100 dark:from-purple-950/70 dark:to-pink-900/50',
    },
    {
      key: 'chat',
      title: 'Our Chat',
      subtitle: 'End-to-end encrypted',
      icon: MessageCircleHeart,
      gradient: 'from-rose-100 to-orange-100 dark:from-rose-950/70 dark:to-amber-950/40',
    },
    {
      key: 'games',
      title: 'Games',
      subtitle: 'Play together live',
      icon: Gamepad2,
      gradient: 'from-fuchsia-100 to-purple-200/80 dark:from-fuchsia-950/70 dark:to-purple-900/50',
    },
    {
      key: 'plans',
      title: 'Our Plans',
      subtitle: `${plansData.plans.length} shared goals`,
      icon: Compass,
      gradient: 'from-orange-100 to-pink-100 dark:from-amber-950/60 dark:to-rose-950/50',
    },
    {
      key: 'memories',
      title: 'Our Memories',
      subtitle: `${memoriesData.memories.length} moments`,
      icon: Camera,
      gradient: 'from-pink-100 to-fuchsia-100 dark:from-pink-950/70 dark:to-fuchsia-900/50',
    },
    {
      key: 'dates',
      title: 'Special Dates',
      subtitle: `${specialDates.length} occasions`,
      icon: CalendarHeart,
      gradient: 'from-rose-100 to-pink-200/80 dark:from-rose-950/70 dark:to-pink-900/50',
    },
    {
      key: 'screen',
      title: 'Our Screen',
      subtitle: 'Wallpaper studio',
      icon: WallpaperIcon,
      gradient: 'from-violet-100 to-rose-100 dark:from-violet-950/70 dark:to-rose-950/50',
    },
    {
      key: 'growth',
      title: 'Our Growth',
      subtitle: `${growthData.habits.length} habits tracked`,
      icon: Target,
      gradient: 'from-pink-50 to-purple-100 dark:from-rose-950/60 dark:to-purple-950/60',
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#fff5f8] via-[#fff0f6] to-[#f8f0ff] dark:from-[#170d16] dark:via-[#1e101c] dark:to-[#1a1124] text-[#2a1420] dark:text-pink-50 transition-colors">
      {/* Subtle Active Wallpaper Atmosphere on Home */}
      {section === 'home' && (
        <div className="pointer-events-none fixed inset-0 z-0 opacity-[0.14] dark:opacity-[0.14]">
          <PrivateImage
            src={activeWallpaper ? activeWallpaper.background_url : getSavedStarterWallpaper()}
            alt=""
            className="h-full w-full object-cover blur-sm"
          />
        </div>
      )}

      {/* Top Sticky App Bar (54px, under 15% cap with bottom bar) */}
      <header className="sticky top-0 z-30 h-[54px] border-b border-pink-200/60 dark:border-pink-900/40 bg-white/80 dark:bg-[#221220]/85 backdrop-blur-md px-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5 min-w-0">
          {section !== 'home' && (
            <button
              type="button"
              onClick={() => setSection('home')}
              className="min-h-[40px] min-w-[40px] -ml-2 flex items-center justify-center rounded-full hover:bg-pink-100/70 dark:hover:bg-pink-950/50 md:hidden"
              aria-label="Back to Home"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>
          )}
          <button
            type="button"
            onClick={() => setSection('home')}
            className="flex items-center gap-2 text-left whitespace-nowrap shrink-0"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-pink-500 to-rose-500 text-white shadow-sm">
              <Heart className="h-4 w-4 fill-current" />
            </span>
            <span className="font-display text-lg font-bold tracking-tight">EverUs</span>
          </button>

          {partner && (
            <button
              type="button"
              onClick={() => setSection('chat')}
              className={`hidden sm:inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold transition ${
                partnerOnline
                  ? 'bg-emerald-100/90 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border border-emerald-300/60'
                  : 'bg-pink-100/70 dark:bg-rose-950/50 text-rose-800/80 dark:text-pink-200/80 border border-pink-200/60'
              }`}
              title={partnerOnline ? `${partner.display_name} is online now` : `Last seen ${formatRelativeTime(partnerLastSeen)}`}
            >
              <span className={`h-2 w-2 rounded-full ${partnerOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-400/70'}`} />
              <span className="truncate max-w-[140px]">
                {partnerOnline ? `${partner.display_name} online` : `Seen ${formatRelativeTime(partnerLastSeen)}`}
              </span>
            </button>
          )}
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          <div className="hidden lg:block">
            <PWAInstallButton compact />
          </div>
          <button
            type="button"
            onClick={() => setHomeCameraTarget('memories')}
            className="inline-flex min-h-[40px] items-center gap-1.5 rounded-2xl border border-pink-200 dark:border-pink-800 bg-white/85 dark:bg-rose-950/60 px-3 py-1.5 text-xs font-semibold text-rose-800 dark:text-pink-100 shadow-xs transition active:scale-[0.97] whitespace-nowrap shrink-0"
            title="Open Camera"
          >
            <Camera className="h-3.5 w-3.5 text-pink-500" />
            <span className="hidden sm:inline">Camera</span>
          </button>
          <button
            type="button"
            onClick={() => setShowLoveModal(true)}
            className="inline-flex min-h-[40px] items-center gap-1.5 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm transition-transform active:scale-[0.97] whitespace-nowrap shrink-0"
          >
            <Heart className="h-3.5 w-3.5 fill-current" />
            <span>Send Love</span>
          </button>
          <button
            type="button"
            onClick={() => setShowNotifDrawer(true)}
            className="relative min-h-[40px] min-w-[40px] flex items-center justify-center rounded-full hover:bg-pink-100/70 dark:hover:bg-pink-950/50"
            aria-label="Notifications"
          >
            <Bell className="h-5 w-5" />
            {unreadNotifsCount > 0 && (
              <span className="absolute top-1.5 right-1.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-bold text-white">
                {unreadNotifsCount}
              </span>
            )}
          </button>
        </div>
      </header>

      {/* Main Responsive Layout: Desktop Sidebar + Content Canvas */}
      <div className="relative z-10 mx-auto flex max-w-7xl">
        {/* Desktop Navigation Rail */}
        <aside className="hidden md:flex md:w-64 md:flex-col md:gap-1.5 md:p-4 md:sticky md:top-[54px] md:h-[calc(100vh-54px)] md:overflow-y-auto border-r border-pink-200/50 dark:border-pink-900/30">
          <div className="mb-3 rounded-3xl bg-white/80 dark:bg-[#281526]/90 p-3.5 border border-pink-100 dark:border-pink-900/40">
            <div className="flex items-center -space-x-2 mb-2">
              <div className="h-10 w-10 overflow-hidden rounded-full border-2 border-white dark:border-[#281526] shadow-sm">
                <PrivateImage src={user.avatar_url} alt={user.display_name} fallbackLabel={user.display_name} className="h-full w-full object-cover" />
              </div>
              {partner ? (
                <div className="relative">
                  <div className={`h-10 w-10 overflow-hidden rounded-full border-2 shadow-sm ${partnerOnline ? 'border-emerald-400' : 'border-white dark:border-[#281526]'}`}>
                    <PrivateImage src={partner.avatar_url} alt={partner.display_name} fallbackLabel={partner.display_name} className="h-full w-full object-cover" />
                  </div>
                  <span
                    className={`absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-white dark:border-[#281526] ${
                      partnerOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-300'
                    }`}
                  />
                </div>
              ) : (
                <div className="h-10 w-10 rounded-full border-2 border-dashed border-pink-300 flex items-center justify-center text-pink-400 bg-pink-50 dark:bg-rose-950/40">
                  <UserPlus className="h-4 w-4" />
                </div>
              )}
            </div>
            <p className="font-display text-sm font-semibold truncate">{coupleTitle}</p>
            <p className="text-xs flex items-center gap-1.5 text-rose-700/80 dark:text-pink-200/80 truncate mt-0.5">
              <span className={`h-2 w-2 rounded-full shrink-0 ${partner ? (partnerOnline ? 'bg-emerald-500' : 'bg-rose-400/70') : 'bg-amber-400'}`} />
              <span className="truncate">
                {partner
                  ? partnerOnline
                    ? `${partner.display_name} is online now`
                    : `Last seen ${formatRelativeTime(partnerLastSeen)}`
                  : 'Waiting for partner invite'}
              </span>
            </p>
            {partner?.mood_status && (
              <p className="mt-1.5 rounded-xl bg-pink-50 dark:bg-black/25 px-2.5 py-1 text-[11px] font-medium truncate">
                {partner.display_name}: {partner.mood_status}
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={() => setSection('home')}
            className={`flex min-h-[42px] items-center gap-3 rounded-2xl px-3.5 py-2 text-sm font-medium transition ${
              section === 'home'
                ? 'bg-gradient-to-r from-pink-500 to-rose-500 text-white shadow-sm'
                : 'hover:bg-pink-100/60 dark:hover:bg-rose-950/40'
            }`}
          >
            <Home className="h-4 w-4" />
            <span>Home</span>
          </button>

          {allFeatureShortcuts.map((item) => {
            const Icon = item.icon;
            const active = section === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setSection(item.key)}
                className={`flex min-h-[42px] items-center gap-3 rounded-2xl px-3.5 py-2 text-sm font-medium transition ${
                  active
                    ? 'bg-gradient-to-r from-pink-500 to-rose-500 text-white shadow-sm'
                    : 'hover:bg-pink-100/60 dark:hover:bg-rose-950/40'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span className="truncate">{item.title}</span>
              </button>
            );
          })}

          <div className="mt-auto pt-3 space-y-1.5 border-t border-pink-100 dark:border-pink-900/40">
            <button
              type="button"
              onClick={() => setSection('settings')}
              className={`flex w-full min-h-[42px] items-center gap-3 rounded-2xl px-3.5 py-2 text-sm font-medium transition ${
                section === 'settings'
                  ? 'bg-gradient-to-r from-pink-500 to-rose-500 text-white shadow-sm'
                  : 'hover:bg-pink-100/60 dark:hover:bg-rose-950/40'
              }`}
            >
              <Settings className="h-4 w-4" />
              <span>Settings</span>
            </button>
            {couple.has_pin && (
              <button
                type="button"
                onClick={() => {
                  setIsPinUnlocked(false);
                  setPinRequireAfterBoot(true);
                }}
                className="flex w-full min-h-[42px] items-center gap-3 rounded-2xl px-3.5 py-2 text-sm font-medium text-rose-700 dark:text-pink-200 hover:bg-pink-100/60 dark:hover:bg-rose-950/40"
              >
                <Lock className="h-4 w-4" />
                <span>Lock App</span>
              </button>
            )}
          </div>
        </aside>

        {/* Scrollable Content Workspace */}
        <main className="flex-1 min-w-0 px-4 py-5 pb-24 md:px-8 md:py-7 md:pb-10">
          {/* Pending Partner Invitation Banner (only shown until Partner 2 joins) */}
          {!partner && invitationInfo && (
            <div className="mb-6 rounded-3xl bg-gradient-to-r from-pink-100 via-rose-50 to-purple-100 dark:from-rose-950/70 dark:to-purple-950/70 p-5 border border-pink-200/80 dark:border-pink-800/50">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="space-y-1.5">
                  <h2 className="font-display text-lg font-semibold">Invite Your Partner to Join EverUs</h2>
                  <p className="text-sm text-rose-800/80 dark:text-pink-100/80">
                    Share this single-use code or QR code. Only two partners can ever belong to this space.
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <span className="font-mono-nums text-base font-bold tracking-wider bg-white/90 dark:bg-black/30 px-3.5 py-1.5 rounded-xl border border-pink-200 dark:border-pink-800">
                      {invitationInfo.code}
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard?.writeText(invitationInfo.code);
                        showToast('Invitation code copied!');
                      }}
                      className="inline-flex min-h-[38px] items-center gap-1.5 rounded-xl bg-white dark:bg-rose-900/50 px-3 py-1.5 text-xs font-semibold shadow-sm"
                    >
                      <Copy className="h-3.5 w-3.5 text-pink-500" />
                      Copy Code
                    </button>
                    <button
                      type="button"
                      onClick={async () => {
                        const res = await apiRequest<{ invitation: any }>('/api/couple/invitation/regenerate', { method: 'POST' });
                        setInvitationInfo(res.invitation);
                        showToast('Generated a fresh single-use invitation code.');
                      }}
                      className="inline-flex min-h-[38px] items-center gap-1.5 rounded-xl bg-white/80 dark:bg-rose-900/40 px-3 py-1.5 text-xs font-semibold"
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                      Regenerate
                    </button>
                  </div>
                </div>
                {invitationInfo.qrDataUrl && (
                  <img
                    src={invitationInfo.qrDataUrl}
                    alt="Partner pairing QR code"
                    className="h-28 w-28 rounded-2xl border-2 border-white shadow-md shrink-0"
                  />
                )}
              </div>
            </div>
          )}

          {/* Key Backup Restore Banner when logging in on a new device */}
          {needsKeyRestore && user.encrypted_key_backup && (
            <div className="mb-6 rounded-3xl bg-purple-100/90 dark:bg-purple-950/60 p-4 border border-purple-200 dark:border-purple-800/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <p className="font-semibold text-sm">Restore End-to-End Chat Keys on This Device</p>
                <p className="text-xs opacity-80">Enter your account password used during sign-up to decrypt your previous messages.</p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="password"
                  value={restorePassphrase}
                  onChange={(e) => setRestorePassphrase(e.target.value)}
                  placeholder="Original password"
                  className="rounded-xl border border-purple-300 dark:border-purple-700 bg-white dark:bg-black/30 px-3 py-2 text-xs"
                />
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      const restored = await restoreIdentityFromBackup(user.id, restorePassphrase, user.encrypted_key_backup);
                      setIdentityKeys(restored);
                      setNeedsKeyRestore(false);
                      showToast('Encryption keys restored securely on this device.');
                    } catch {
                      showToast('Passphrase did not match key backup.', 'error');
                    }
                  }}
                  className="min-h-[38px] rounded-xl bg-purple-600 px-3.5 py-1.5 text-xs font-semibold text-white whitespace-nowrap"
                >
                  Restore Keys
                </button>
              </div>
            </div>
          )}

          {/* Unverified Email Reminder Banner */}
          {user.email_verified === 0 && (
            <div className="mb-5 rounded-3xl bg-pink-100/85 dark:bg-rose-950/60 p-4 border border-pink-300/80 dark:border-pink-800/50 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <Mail className="h-5 w-5 text-pink-600 dark:text-pink-300 shrink-0" />
                <div>
                  <p className="text-sm font-semibold">Verify Your Email for Extra Security</p>
                  <p className="text-xs opacity-80">Confirm {user.email} to enable Email 2FA and email password recovery.</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSection('settings')}
                className="min-h-[38px] rounded-2xl bg-pink-500 px-4 text-xs font-semibold text-white shadow-xs"
              >
                Verify Email
              </button>
            </div>
          )}

          {/* === HOME SCREEN (Strictly Daily Bible Verse, Together Counter, and Feature Shortcuts) === */}
          {section === 'home' && (
            <div className="space-y-7">
              {/* A. Daily Bible Verse */}
              <section className="relative overflow-hidden rounded-[2rem] bg-gradient-to-br from-[#ffe4f0] via-[#fff5f8] to-[#efe3ff] dark:from-[#36162b] dark:via-[#281526] dark:to-[#241738] p-6 sm:p-8 shadow-sm border border-pink-200/60 dark:border-pink-800/40">
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-3 max-w-3xl">
                    <div className="flex items-center gap-2 text-xs font-medium text-rose-700 dark:text-pink-300">
                      <BookOpen className="h-4 w-4" />
                      <span>Daily Bible Verse</span>
                      <span aria-hidden="true">·</span>
                      <span>{verseToday?.reference || 'Loading…'}</span>
                      <span aria-hidden="true">·</span>
                      <span>{verseToday?.translation || 'WEB'}</span>
                    </div>
                    <blockquote className="font-display text-xl sm:text-2xl leading-relaxed text-rose-950 dark:text-pink-50 text-balance">
                      “{verseToday?.text || 'Love is patient and is kind…'}”
                    </blockquote>
                  </div>
                </div>

                <div className="mt-5 flex flex-wrap items-center gap-2.5">
                  <button
                    type="button"
                    onClick={() => {
                      setVerseAmen((v) => !v);
                      showToast(verseAmen ? 'Removed reaction' : 'Amen! Shared your gratitude ❤️');
                    }}
                    className={`inline-flex min-h-[40px] items-center gap-1.5 rounded-2xl px-4 py-2 text-xs font-semibold shadow-sm transition active:scale-95 ${
                      verseAmen
                        ? 'bg-rose-500 text-white'
                        : 'bg-white/90 dark:bg-black/25 text-rose-900 dark:text-pink-100 hover:bg-white'
                    }`}
                  >
                    <Heart className={`h-4 w-4 ${verseAmen ? 'fill-current' : 'text-pink-500'}`} />
                    <span>Amen</span>
                  </button>

                  <button
                    type="button"
                    onClick={async () => {
                      if (!verseToday) return;
                      const res = await apiRequest<{ saved: any[] }>('/api/verse/save', {
                        method: 'POST',
                        body: JSON.stringify({
                          reference: verseToday.reference,
                          text: verseToday.text,
                          shareWithPartner: false,
                        }),
                      });
                      setSavedVerses(res.saved);
                      showToast('Saved to your favourite verses.');
                    }}
                    className="inline-flex min-h-[40px] items-center gap-2 rounded-2xl bg-white/90 dark:bg-black/25 px-4 py-2 text-xs font-semibold text-rose-900 dark:text-pink-100 shadow-sm hover:bg-white transition"
                  >
                    <Star className="h-4 w-4 text-pink-500" />
                    <span>Save Favourite ({savedVerses.length})</span>
                  </button>

                  <button
                    type="button"
                    onClick={async () => {
                      if (!verseToday) return;
                      const res = await apiRequest<{ saved: any[] }>('/api/verse/save', {
                        method: 'POST',
                        body: JSON.stringify({
                          reference: verseToday.reference,
                          text: verseToday.text,
                          shareWithPartner: true,
                        }),
                      });
                      setSavedVerses(res.saved);
                      showToast(`Shared today’s verse with ${partner?.display_name || 'your partner'}!`);
                    }}
                    className="inline-flex min-h-[40px] items-center gap-2 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-4 py-2 text-xs font-semibold text-white shadow-sm hover:opacity-95 transition"
                  >
                    <Share2 className="h-4 w-4" />
                    <span>Share With Partner</span>
                  </button>
                </div>

                {savedVerses.length > 0 && (
                  <details className="mt-4 pt-3 border-t border-pink-200/60 dark:border-pink-800/40">
                    <summary className="cursor-pointer text-xs font-semibold text-rose-700 dark:text-pink-300">
                      View Saved Favourite Verses ({savedVerses.length})
                    </summary>
                    <div className="mt-3 grid gap-2.5 sm:grid-cols-2">
                      {savedVerses.slice(0, 6).map((sv) => (
                        <div key={sv.id} className="rounded-2xl bg-white/75 dark:bg-black/20 p-3 text-xs">
                          <p className="font-semibold text-rose-900 dark:text-pink-200">{sv.reference}</p>
                          <p className="mt-1 opacity-85 line-clamp-2">“{sv.verse_text}”</p>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
              </section>

              {/* B. Our Together Counter & Live Interactive Partner Presence */}
              <section className="rounded-[2rem] bg-white/85 dark:bg-[#281526]/90 p-6 sm:p-8 shadow-sm border border-pink-200/60 dark:border-pink-900/40 space-y-5">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <div className="flex items-center -space-x-2">
                        <div className="h-12 w-12 overflow-hidden rounded-full border-2 border-white dark:border-[#281526] shadow">
                          <PrivateImage src={user.avatar_url} alt={user.display_name} fallbackLabel={user.display_name} className="h-full w-full object-cover" />
                        </div>
                        <div className="relative">
                          <div className={`h-12 w-12 overflow-hidden rounded-full border-2 shadow ${partnerOnline ? 'border-emerald-400' : 'border-white dark:border-[#281526]'}`}>
                            <PrivateImage
                              src={partner?.avatar_url}
                              alt={partner?.display_name || 'Partner'}
                              fallbackLabel={partner?.display_name || 'P2'}
                              className="h-full w-full object-cover"
                            />
                          </div>
                          {partner && (
                            <span
                              className={`absolute bottom-0 right-0 h-3.5 w-3.5 rounded-full border-2 border-white dark:border-[#281526] ${
                                partnerOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-300'
                              }`}
                            />
                          )}
                        </div>
                      </div>
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-xs font-medium text-rose-700 dark:text-pink-300">
                            Our Together Counter · Since {couple.start_date}
                          </p>
                          {partner && (
                            <span
                              className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                                partnerOnline
                                  ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300'
                                  : 'bg-pink-100/80 dark:bg-rose-950/50 text-rose-700 dark:text-pink-200'
                              }`}
                            >
                              <span className={`h-1.5 w-1.5 rounded-full ${partnerOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-400'}`} />
                              {partnerOnline ? `${partner.display_name} is online now` : `Last seen ${formatRelativeTime(partnerLastSeen)}`}
                            </span>
                          )}
                        </div>
                        <h1 className="font-display text-2xl sm:text-3xl font-bold text-balance">{coupleTitle}</h1>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-baseline gap-4 pt-1">
                      <div>
                        <span className="font-mono-nums text-4xl sm:text-5xl font-bold text-pink-600 dark:text-pink-400">
                          {togetherStats.days.toLocaleString()}
                        </span>
                        <span className="ml-2 text-sm font-semibold text-rose-800/80 dark:text-pink-200/80">Days Together</span>
                      </div>
                      <div className="flex items-center gap-2 font-mono-nums text-sm text-rose-700/80 dark:text-pink-200/80">
                        <span>{String(togetherStats.hours).padStart(2, '0')}h</span>
                        <span>·</span>
                        <span>{String(togetherStats.minutes).padStart(2, '0')}m</span>
                        <span>·</span>
                        <span>{String(togetherStats.seconds).padStart(2, '0')}s</span>
                      </div>
                    </div>
                  </div>

                  <div className="w-full lg:w-80 rounded-3xl bg-gradient-to-br from-pink-50 to-purple-50 dark:from-rose-950/60 dark:to-purple-950/50 p-4 border border-pink-100 dark:border-pink-800/40">
                    <div className="flex items-center justify-between text-xs font-semibold">
                      <span>Next Milestone: {togetherStats.nextMilestone.toLocaleString()} Days</span>
                      <span className="font-mono-nums text-pink-600 dark:text-pink-300">{togetherStats.milestoneProgress}%</span>
                    </div>
                    <div className="mt-2.5 h-2.5 w-full overflow-hidden rounded-full bg-white dark:bg-black/30">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-pink-500 to-purple-500 transition-all"
                        style={{ width: `${togetherStats.milestoneProgress}%` }}
                      />
                    </div>
                    <p className="mt-2.5 text-xs text-rose-700/80 dark:text-pink-200/75">
                      Next Anniversary in {daysUntilDate(couple.start_date, true)} days
                    </p>
                  </div>
                </div>

                {/* Interactive Quick Actions & Live Mood Check-In */}
                <div className="pt-4 border-t border-pink-100 dark:border-pink-900/40 flex flex-col gap-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          if (wsRef.current?.readyState === WebSocket.OPEN) {
                            wsRef.current.send(JSON.stringify({ event: 'couple:nudge', emoji: '👋💕' }));
                            showToast(`Waved at ${partner?.display_name || 'your partner'}!`);
                          } else {
                            triggerSendLove('heart', 'Thinking of you right now!');
                          }
                        }}
                        className="min-h-[38px] inline-flex items-center gap-1.5 rounded-2xl bg-pink-100/90 dark:bg-rose-950/70 hover:bg-pink-200/80 px-3.5 py-1.5 text-xs font-semibold text-rose-900 dark:text-pink-100 transition active:scale-95"
                      >
                        <span>👋</span>
                        <span>Wave to {partner?.display_name || 'Partner'}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setHomeCameraTarget('chat')}
                        className="min-h-[38px] inline-flex items-center gap-1.5 rounded-2xl bg-purple-100/90 dark:bg-purple-950/60 hover:bg-purple-200/80 px-3.5 py-1.5 text-xs font-semibold text-purple-900 dark:text-purple-100 transition active:scale-95"
                      >
                        <Camera className="h-3.5 w-3.5" />
                        <span>Snap Encrypted Photo</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setHomeCameraTarget('memories')}
                        className="min-h-[38px] inline-flex items-center gap-1.5 rounded-2xl bg-rose-100/90 dark:bg-rose-950/60 hover:bg-rose-200/80 px-3.5 py-1.5 text-xs font-semibold text-rose-900 dark:text-rose-100 transition active:scale-95"
                      >
                        <Camera className="h-3.5 w-3.5" />
                        <span>Snap Memory</span>
                      </button>
                    </div>
                    {partner?.mood_status && (
                      <span className="text-xs font-medium text-rose-800/85 dark:text-pink-200/85">
                        {partner.display_name}’s vibe: <strong>{partner.mood_status}</strong>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 overflow-x-auto pb-1">
                    <span className="text-[11px] font-semibold opacity-70 shrink-0">Your vibe:</span>
                    {COUPLE_MOOD_CHIPS.map((mood) => {
                      const active = user.mood_status === mood;
                      return (
                        <button
                          key={mood}
                          type="button"
                          onClick={async () => {
                            const nextMood = active ? '' : mood;
                            await apiRequest('/api/profile', {
                              method: 'PATCH',
                              body: JSON.stringify({ mood_status: nextMood }),
                            });
                            await loadAuthState();
                            showToast(nextMood ? `Updated your vibe: ${nextMood}` : 'Cleared your vibe');
                          }}
                          className={`shrink-0 rounded-xl px-2.5 py-1 text-[11px] font-semibold transition ${
                            active
                              ? 'bg-pink-500 text-white shadow-xs'
                              : 'bg-pink-50 dark:bg-black/25 hover:bg-pink-100 dark:hover:bg-rose-950/50'
                          }`}
                        >
                          {mood}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </section>

              {/* C. Feature Shortcuts */}
              <section className="space-y-4">
                <h2 className="font-display text-xl font-semibold">Our Shared World</h2>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3.5 sm:gap-4">
                  {allFeatureShortcuts.map((item) => {
                    const Icon = item.icon;
                    return (
                      <button
                        key={item.key}
                        type="button"
                        onClick={() => setSection(item.key)}
                        className={`group text-left rounded-[1.75rem] bg-gradient-to-br ${item.gradient} p-5 border border-pink-200/50 dark:border-pink-800/40 shadow-sm transition-transform duration-150 hover:-translate-y-0.5 active:scale-[0.98] flex flex-col justify-between min-h-[126px]`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/85 dark:bg-black/25 text-pink-600 dark:text-pink-300 shadow-sm">
                            <Icon className="h-5 w-5" />
                          </span>
                          <ChevronRight className="h-4 w-4 opacity-40 group-hover:opacity-90 transition-opacity" />
                        </div>
                        <div className="mt-4">
                          <p className="font-display text-base font-semibold">{item.title}</p>
                          <p className="text-xs text-rose-800/75 dark:text-pink-200/75 mt-0.5">{item.subtitle}</p>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </section>
            </div>
          )}

          {section === 'tasks' && (
            <DailyTasksSection
              user={user}
              partner={partner}
              tasks={tasks}
              history={taskHistory}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'location' && (
            <LocationSection
              user={user}
              partner={partner}
              data={locationData}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'chat' && (
            <EncryptedChatSection
              user={user}
              partner={partner}
              partnerOnline={partnerOnline}
              partnerLastSeen={partnerLastSeen}
              messages={messages}
              sharedAesKey={sharedAesKey}
              safetyFingerprint={safetyFingerprint}
              partnerTyping={partnerTyping}
              onEmitTyping={(typing) => {
                if (wsRef.current?.readyState === WebSocket.OPEN) {
                  wsRef.current.send(JSON.stringify({ event: 'chat:typing', typing }));
                }
              }}
              onRefreshMessages={loadAndDecryptMessages}
              onSendQuickLove={() => triggerSendLove('heart', 'Sending you a quick heart from Our Chat!')}
              showToast={showToast}
            />
          )}

          {section === 'games' && (
            <GamesSection
              user={user}
              partner={partner}
              sessions={games}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'plans' && (
            <OurPlansSection
              user={user}
              partner={partner}
              plans={plansData.plans}
              updates={plansData.updates}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'memories' && (
            <OurMemoriesSection
              user={user}
              partner={partner}
              albums={memoriesData.albums}
              memories={memoriesData.memories}
              comments={memoriesData.comments}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'dates' && (
            <SpecialDatesSection
              dates={specialDates}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'screen' && (
            <WallpaperStudioSection
              user={user}
              partner={partner}
              couple={couple}
              daysTogether={togetherStats.days}
              specialDates={specialDates}
              wallpapers={wallpapersData.wallpapers}
              approvals={wallpapersData.approvals}
              onRefresh={refreshAllCoupleData}
              onReloadAuth={loadAuthState}
              showToast={showToast}
            />
          )}

          {section === 'growth' && (
            <OurGrowthSection
              user={user}
              partner={partner}
              goals={growthData.goals}
              habits={growthData.habits}
              onRefresh={refreshAllCoupleData}
              showToast={showToast}
            />
          )}

          {section === 'settings' && (
            <SettingsSection
              user={user}
              partner={partner}
              couple={couple}
              devices={devices}
              currentDeviceId={currentDeviceId}
              notifPrefs={notifPrefs}
              darkMode={darkMode}
              safetyFingerprint={safetyFingerprint}
              onToggleDarkMode={async (next) => {
                setDarkMode(next);
                await apiRequest('/api/profile', { method: 'PATCH', body: JSON.stringify({ dark_mode: next }) });
              }}
              onLockNow={() => {
                setIsPinUnlocked(false);
                setPinRequireAfterBoot(true);
              }}
              onReload={loadAuthState}
              onLogout={async () => {
                await apiRequest('/api/auth/logout', { method: 'POST' });
                setAuthToken(null);
                setUser(null);
              }}
              showToast={showToast}
            />
          )}
        </main>
      </div>

      {/* Mobile Bottom Tab Bar (64px height, total sticky height well below 15%) */}
      <nav className="fixed bottom-0 left-0 right-0 z-40 md:hidden bg-white/90 dark:bg-[#221220]/90 backdrop-blur-md border-t border-pink-200/60 dark:border-pink-900/40 pb-safe">
        <div className="grid grid-cols-5 h-16 items-center">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = section === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setSection(item.key)}
                className={`min-h-[44px] flex flex-col items-center justify-center gap-0.5 transition ${
                  active ? 'text-pink-600 dark:text-pink-400' : 'text-rose-900/60 dark:text-pink-100/60'
                }`}
              >
                <Icon className={`h-5 w-5 ${active ? 'scale-110' : ''}`} />
                <span className="text-[10px] font-semibold tracking-tight">{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* Send Love Modal */}
      <AnimatePresence>
        {showLoveModal && (
          <LoveModal
            partnerName={partner?.display_name || 'Your Partner'}
            loveItems={loveItems}
            currentUserId={user.id}
            onClose={() => setShowLoveModal(false)}
            onSend={triggerSendLove}
            onRespond={async (id, emoji) => {
              await apiRequest(`/api/love/${id}/respond`, { method: 'POST', body: JSON.stringify({ emoji }) });
              refreshAllCoupleData();
              showToast('Sent reaction!');
            }}
          />
        )}
      </AnimatePresence>

      {/* Notifications Drawer */}
      <AnimatePresence>
        {showNotifDrawer && (
          <div className="fixed inset-0 z-50 flex justify-end bg-black/40 backdrop-blur-xs">
            <motion.div
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 40 }}
              className="h-full w-full max-w-md bg-white dark:bg-[#241322] p-5 overflow-y-auto shadow-2xl border-l border-pink-200 dark:border-pink-900/40"
            >
              <div className="flex items-center justify-between pb-4 border-b border-pink-100 dark:border-pink-900/40">
                <h3 className="font-display text-lg font-semibold">Notifications</h3>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      await apiRequest('/api/notifications/read-all', { method: 'POST' });
                      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: 1 })));
                    }}
                    className="text-xs font-semibold text-pink-600 dark:text-pink-300"
                  >
                    Mark all read
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowNotifDrawer(false)}
                    className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-full hover:bg-pink-50 dark:hover:bg-rose-950/40"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              </div>
              <div className="mt-4 space-y-2.5">
                {notifications.length === 0 ? (
                  <p className="text-sm text-center py-12 opacity-60">All quiet in your private space.</p>
                ) : (
                  notifications.map((n) => (
                    <div
                      key={n.id}
                      className={`rounded-2xl p-3.5 border ${
                        n.is_read
                          ? 'bg-pink-50/40 dark:bg-black/15 border-pink-100 dark:border-pink-900/30'
                          : 'bg-pink-100/70 dark:bg-rose-950/50 border-pink-300 dark:border-pink-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-semibold">{n.title}</p>
                        <span className="text-[11px] opacity-65">{formatRelativeTime(n.created_at)}</span>
                      </div>
                      <p className="mt-1 text-xs opacity-85">{n.body}</p>
                    </div>
                  ))
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Animated Floating Hearts Burst when Love is Sent or Received */}
      <AnimatePresence>
        {loveBurst && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: -20 }}
            className="pointer-events-none fixed inset-0 z-50 flex flex-col items-center justify-center p-4"
          >
            {Array.from({ length: 12 }).map((_, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0.9, y: 40, x: (idx - 6) * 28, scale: 0.6 }}
                animate={{ opacity: 0, y: -220 - (idx % 3) * 40, x: (idx - 6) * 42, scale: 1.3 }}
                transition={{ duration: 2.2, delay: idx * 0.08 }}
                className="absolute text-pink-500"
              >
                <Heart className="h-7 w-7 fill-current" />
              </motion.div>
            ))}
            <div className="rounded-3xl bg-white/95 dark:bg-[#2b1528]/95 px-6 py-4 shadow-2xl border border-pink-300 dark:border-pink-700 text-center max-w-xs">
              <p className="text-xs font-semibold text-pink-600 dark:text-pink-300">{loveBurst.senderName}</p>
              <p className="font-display text-lg font-semibold mt-1">{loveBurst.message}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Quick Home Camera Capture (Save directly to Memories or Encrypted Chat) */}
      {homeCameraTarget && (
        <CameraCaptureModal
          title={homeCameraTarget === 'chat' ? 'Snap Encrypted Chat Photo' : 'Snap Memory with Camera'}
          allowVideo={true}
          defaultFacingMode="user"
          onClose={() => setHomeCameraTarget(null)}
          showToast={showToast}
          onCapture={async (file) => {
            if (homeCameraTarget === 'chat') {
              if (!sharedAesKey) {
                showToast('Waiting for partner to join so we can encrypt this photo.', 'error');
                return;
              }
              const buf = await file.arrayBuffer();
              const { encryptedBlob, ivB64 } = await encryptBinaryFile(sharedAesKey, buf);
              const uploaded = await uploadPrivateFile(encryptedBlob, `${file.name}.enc`, {
                encrypted: true,
                encryptedIv: ivB64,
                originalMime: file.type || 'image/jpeg',
                originalName: file.name,
              });
              const { ciphertext, iv } = await encryptText(sharedAesKey, { text: file.name });
              await apiRequest('/api/chat/messages', {
                method: 'POST',
                body: JSON.stringify({
                  ciphertext,
                  iv,
                  message_type: file.type.startsWith('video/') ? 'video' : 'image',
                  attachment_id: uploaded.attachmentId,
                }),
              });
              await loadAndDecryptMessages();
              setSection('chat');
              showToast('Encrypted camera moment sent to Our Chat!');
            } else {
              const up = await uploadPrivateFile(file, file.name);
              await apiRequest('/api/memories', {
                method: 'POST',
                body: JSON.stringify({
                  media_url: up.url,
                  media_type: file.type.startsWith('video/') ? 'video' : 'image',
                  caption: 'Captured live in EverUs',
                  memory_date: new Date().toISOString().slice(0, 10),
                  location_label: '',
                }),
              });
              await refreshAllCoupleData();
              setSection('memories');
              showToast('Saved camera moment to Our Memories!');
            }
          }}
        />
      )}

      <ToastOverlay toast={toast} />
      <OfflineIndicator />
    </div>
  );
}

// ============================================================================
// SUB-SECTIONS (Kept unified in EverUsApp.tsx for seamless VS Code delivery)
// ============================================================================

const ToastOverlay: React.FC<{ toast: { type: 'success' | 'error'; text: string } | null }> = ({ toast }) => {
  if (!toast) return null;
  return (
    <div
      className={`fixed top-16 right-4 z-50 max-w-sm rounded-2xl px-4 py-3 text-xs font-semibold shadow-lg ${
        toast.type === 'error' ? 'bg-rose-600 text-white' : 'bg-pink-600 text-white'
      }`}
    >
      {toast.text}
    </div>
  );
};

// --- 1. Welcome & Authentication ---
const AuthAndWelcomeScreen: React.FC<{
  onAuthenticated: (data: { token: string; user: UserProfile; couple: CoupleInfo | null; partner: UserProfile | null; partnerOnline?: boolean }) => void;
  showToast: (text: string, type?: 'success' | 'error') => void;
}> = ({ onAuthenticated, showToast }) => {
  const [mode, setMode] = useState<'welcome' | 'register' | 'login' | 'login-otp' | 'recover'>('welcome');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [nickname, setNickname] = useState('');
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [issuedRecovery, setIssuedRecovery] = useState<{
    code: string;
    authPayload: any;
    emailCodeInput: string;
    emailVerified: boolean;
    previewCode?: string;
    provider?: string;
  } | null>(null);
  const [login2faStep, setLogin2faStep] = useState<{ email: string; otp: string; previewCode?: string; provider?: string } | null>(null);
  const [otpRequested, setOtpRequested] = useState<{ sent: boolean; previewCode?: string; provider?: string } | null>(null);
  const [emailOtpCode, setEmailOtpCode] = useState('');
  const [recoverMode, setRecoverMode] = useState<'email' | 'code'>('email');
  const [selectedWallpaper, setSelectedWallpaper] = useState<string>(() => getSavedStarterWallpaper());
  const [previewNote, setPreviewNote] = useState('Two lives. One shared journey.');
  const [previewHearts, setPreviewHearts] = useState<Array<{ id: number; x: number }>>([]);
  const [clockTick, setClockTick] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setClockTick(new Date()), 10000);
    return () => clearInterval(id);
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const backup = await generateBackupEnvelope(password);
      const res = await apiRequest<any>('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          email,
          password,
          displayName,
          nickname,
          publicKeyJwk: backup.publicKeyJwk,
          encryptedKeyBackup: backup.encryptedKeyBackup,
          platform: /iphone|ipad|ipod/i.test(navigator.userAgent)
            ? 'iOS Safari'
            : /android/i.test(navigator.userAgent)
              ? 'Android'
              : 'Web / Desktop',
        }),
      });
      setIssuedRecovery({
        code: res.recoveryCode,
        authPayload: res,
        emailCodeInput: '',
        emailVerified: false,
        previewCode: res.emailVerification?.previewCode,
        provider: res.emailVerification?.provider,
      });
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Registration failed', 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await apiRequest<any>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email,
          password,
          emailOtp: login2faStep?.otp || undefined,
          platform: /iphone|ipad|ipod/i.test(navigator.userAgent) ? 'iOS' : /android/i.test(navigator.userAgent) ? 'Android' : 'Web',
        }),
      });
      if (res.requiresEmailOtp) {
        setLogin2faStep({
          email: res.email,
          otp: '',
          previewCode: res.previewCode,
          provider: res.provider,
        });
        showToast('Enter the 6-digit authentication code sent to your email.');
      } else {
        onAuthenticated(res);
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Sign in failed', 'error');
    } finally {
      setBusy(false);
    }
  };

  const handleRecover = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (recoverMode === 'email') {
        await apiRequest('/api/auth/recover-email', {
          method: 'POST',
          body: JSON.stringify({ email, code: emailOtpCode, newPassword }),
        });
        showToast('Password updated via email authentication!');
        setOtpRequested(null);
        setEmailOtpCode('');
        setMode('login');
      } else {
        const res = await apiRequest<{ newRecoveryCode: string }>('/api/auth/recover', {
          method: 'POST',
          body: JSON.stringify({ email, recoveryCode: recoveryCodeInput, newPassword }),
        });
        showToast(`Password reset! Save your new recovery code: ${res.newRecoveryCode}`);
        setMode('login');
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Recovery failed', 'error');
    } finally {
      setBusy(false);
    }
  };

  if (issuedRecovery) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-[#fff5f8] via-[#ffe4ef] to-[#efe3ff] p-4">
        <div className="w-full max-w-md rounded-[2rem] bg-white p-7 shadow-xl border border-pink-200 space-y-5">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-pink-100 text-pink-600">
              <Mail className="h-6 w-6" />
            </div>
            <div>
              <h2 className="font-display text-xl font-bold text-rose-950">Email & Recovery Verification</h2>
              <p className="text-xs text-rose-800/75">Verify {issuedRecovery.authPayload.user.email} & save your recovery code</p>
            </div>
          </div>

          {/* Step 1: Post-Signup Email Authentication */}
          <div className="rounded-2xl bg-pink-50/90 border border-pink-200 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-rose-950">1. Email Authentication Code</span>
              {issuedRecovery.emailVerified ? (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Verified
                </span>
              ) : (
                <button
                  type="button"
                  onClick={async () => {
                    const res = await apiRequest<{ provider: string; previewCode?: string }>('/api/auth/email/send-code', {
                      method: 'POST',
                      body: JSON.stringify({ email: issuedRecovery.authPayload.user.email, purpose: 'verify_email' }),
                    });
                    setIssuedRecovery((prev) =>
                      prev ? { ...prev, previewCode: res.previewCode, provider: res.provider } : prev
                    );
                    showToast('Sent a fresh 6-digit email verification code!');
                  }}
                  className="text-xs font-semibold text-pink-600"
                >
                  Resend Code
                </button>
              )}
            </div>

            {!issuedRecovery.emailVerified && (
              <>
                <p className="text-xs text-rose-900/75">
                  {issuedRecovery.provider === 'resend'
                    ? `We emailed a 6-digit code to ${issuedRecovery.authPayload.user.email}.`
                    : `Preview mode (add RESEND_API_KEY in .env for real inbox delivery). Use code:`}
                  {issuedRecovery.previewCode && (
                    <span className="ml-1.5 font-mono-nums font-bold text-pink-600">{issuedRecovery.previewCode}</span>
                  )}
                </p>
                <div className="flex gap-2">
                  <input
                    inputMode="numeric"
                    maxLength={6}
                    value={issuedRecovery.emailCodeInput}
                    onChange={(e) =>
                      setIssuedRecovery((prev) =>
                        prev ? { ...prev, emailCodeInput: e.target.value.replace(/\D/g, '').slice(0, 6) } : prev
                      )
                    }
                    placeholder="6-digit code"
                    className="flex-1 rounded-xl border border-pink-200 bg-white px-3 py-2 text-sm font-mono-nums tracking-widest"
                  />
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        setAuthToken(issuedRecovery.authPayload.token);
                        const res = await apiRequest<{ user: UserProfile }>('/api/auth/email/verify', {
                          method: 'POST',
                          body: JSON.stringify({ code: issuedRecovery.emailCodeInput }),
                        });
                        setIssuedRecovery((prev) =>
                          prev
                            ? {
                                ...prev,
                                emailVerified: true,
                                authPayload: { ...prev.authPayload, user: res.user },
                              }
                            : prev
                        );
                        showToast('Email authenticated!');
                      } catch (err) {
                        showToast(err instanceof Error ? err.message : 'Invalid code', 'error');
                      }
                    }}
                    className="rounded-xl bg-pink-500 px-4 text-xs font-semibold text-white"
                  >
                    Verify
                  </button>
                </div>
              </>
            )}
          </div>

          {/* Step 2: Personal Recovery Code */}
          <div className="space-y-2">
            <p className="text-xs font-semibold text-rose-950">2. Personal Account Recovery Code</p>
            <div className="rounded-2xl bg-pink-50 border border-pink-200 p-3.5 flex items-center justify-between">
              <span className="font-mono-nums text-base font-bold tracking-wider text-rose-950">{issuedRecovery.code}</span>
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard?.writeText(issuedRecovery.code);
                  showToast('Recovery code copied!');
                }}
                className="rounded-xl bg-white px-3 py-1.5 text-xs font-semibold text-pink-600 shadow-sm"
              >
                Copy
              </button>
            </div>
          </div>

          <button
            type="button"
            onClick={() => onAuthenticated(issuedRecovery.authPayload)}
            className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md"
          >
            {issuedRecovery.emailVerified ? 'Continue to EverUs Setup' : 'Verify Later & Continue'}
          </button>
        </div>
      </div>
    );
  }

  const chooseWallpaper = (url: string) => {
    setSelectedWallpaper(url);
    saveStarterWallpaper(url);
  };

  const handlePickOwnPhoto = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        chooseWallpaper(reader.result);
        showToast('Your chosen wallpaper is now active!');
      }
    };
    reader.readAsDataURL(file);
  };

  const triggerPreviewHeart = () => {
    const batch = Array.from({ length: 5 }, (_, i) => ({
      id: Date.now() + i,
      x: (i - 2) * 34 + (Math.random() * 16 - 8),
    }));
    setPreviewHearts((prev) => [...prev.slice(-10), ...batch]);
    setTimeout(() => {
      setPreviewHearts((prev) => prev.filter((h) => !batch.some((b) => b.id === h.id)));
    }, 1800);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#fff5f8] via-[#ffe8f1] to-[#f3e8ff] flex items-center justify-center p-4 lg:p-10">
      <div className="w-full max-w-5xl grid lg:grid-cols-2 gap-8 items-stretch">
        {/* Interactive Wallpaper Picker & Live Lock-Screen Card */}
        <div className="relative overflow-hidden rounded-[2.25rem] shadow-lg min-h-[380px] lg:min-h-[560px] flex flex-col justify-between p-6 sm:p-7 border border-pink-200/70">
          <PrivateImage
            src={selectedWallpaper}
            alt="Your chosen EverUs wallpaper"
            className="absolute inset-0 h-full w-full object-cover transition-all duration-300"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-rose-950/70 via-rose-950/20 to-rose-950/30" />

          {/* Animated Preview Hearts */}
          <div className="pointer-events-none absolute inset-0 overflow-hidden flex items-center justify-center z-20">
            <AnimatePresence>
              {previewHearts.map((h) => (
                <motion.div
                  key={h.id}
                  initial={{ opacity: 0.95, y: 40, x: h.x, scale: 0.7 }}
                  animate={{ opacity: 0, y: -180, x: h.x * 1.4, scale: 1.35 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 1.6 }}
                  className="absolute text-pink-200"
                >
                  <Heart className="h-7 w-7 fill-current drop-shadow" />
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          {/* Top Live Clock & Interactive Heart Button */}
          <div className="relative z-10 flex items-start justify-between gap-3 text-white">
            <div>
              <p className="text-xs font-medium text-pink-100/90">
                {clockTick.toLocaleDateString([], { weekday: 'long', month: 'short', day: 'numeric' })}
              </p>
              <p className="font-mono-nums text-4xl sm:text-5xl font-bold tracking-tight mt-0.5">
                {clockTick.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
            </div>
            <button
              type="button"
              onClick={triggerPreviewHeart}
              className="min-h-[42px] inline-flex items-center gap-1.5 rounded-2xl bg-white/20 hover:bg-white/30 backdrop-blur-md px-3.5 py-2 text-xs font-semibold text-white transition active:scale-95"
            >
              <Heart className="h-4 w-4 fill-pink-300 text-pink-200" />
              <span>Tap Heart</span>
            </button>
          </div>

          {/* Middle Editable Couple Tagline */}
          <div className="relative z-10 my-auto py-6 text-white">
            <h1 className="font-display text-3xl sm:text-4xl font-bold leading-tight text-balance">EverUs</h1>
            <input
              value={previewNote}
              onChange={(e) => setPreviewNote(e.target.value)}
              aria-label="Preview couple tagline"
              className="mt-2 w-full max-w-xs rounded-xl bg-white/15 hover:bg-white/20 focus:bg-white/25 backdrop-blur-md px-3 py-1.5 text-sm text-white placeholder-pink-100 outline-none border border-white/25"
            />
          </div>

          {/* Bottom Interactive Wallpaper Picker */}
          <div className="relative z-10 space-y-2 rounded-3xl bg-white/20 backdrop-blur-md p-3.5 border border-white/30">
            <div className="flex items-center justify-between text-xs font-semibold text-white">
              <span>Pick Your Wallpaper</span>
              <span className="opacity-85">Syncs into Our Screen</span>
            </div>
            <div className="flex items-center gap-2 overflow-x-auto pb-0.5">
              {WALLPAPER_TEMPLATES.map((tpl) => (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => chooseWallpaper(tpl.url)}
                  title={tpl.name}
                  className={`relative h-14 w-11 shrink-0 overflow-hidden rounded-xl border-2 transition ${
                    selectedWallpaper === tpl.url ? 'border-white scale-105 shadow-md' : 'border-white/40 opacity-80 hover:opacity-100'
                  }`}
                >
                  <PrivateImage src={tpl.url} alt={tpl.name} className="h-full w-full object-cover" />
                </button>
              ))}
              <label className="h-14 px-3 shrink-0 rounded-xl border-2 border-dashed border-white/70 bg-white/15 hover:bg-white/25 flex flex-col items-center justify-center text-white cursor-pointer transition">
                <Upload className="h-4 w-4" />
                <span className="text-[10px] font-semibold mt-0.5 whitespace-nowrap">Your Photo</span>
                <input
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handlePickOwnPhoto(f);
                  }}
                />
              </label>
            </div>
          </div>
        </div>

        <div className="rounded-[2.25rem] bg-white/90 backdrop-blur-md p-6 sm:p-9 shadow-lg border border-pink-200/70 flex flex-col justify-center">
          <div className="flex items-center justify-between mb-6">
            <span className="font-display text-xl font-bold text-rose-950">
              {mode === 'welcome' && 'Welcome Home'}
              {mode === 'register' && 'Create Your Account'}
              {mode === 'login' && 'Sign In to EverUs'}
              {mode === 'login-otp' && 'Sign In via Email Code'}
              {mode === 'recover' && 'Recover Account'}
            </span>
            <PWAInstallButton compact />
          </div>

          {mode === 'welcome' && (
            <div className="space-y-4">
              <p className="text-sm leading-relaxed text-rose-900/80">
                A romantic, colourful private space designed exclusively for two partners — featuring end-to-end encrypted chat,
                shared memories, daily tasks, special dates, collaborative plans, games, and lock-screen wallpapers.
              </p>
              <div className="pt-2 space-y-3">
                <button
                  type="button"
                  onClick={() => setMode('register')}
                  className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md hover:opacity-95 transition"
                >
                  Create Individual Account
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setLogin2faStep(null);
                    setMode('login');
                  }}
                  className="w-full min-h-[48px] rounded-2xl border border-pink-200 bg-pink-50/70 text-sm font-semibold text-rose-900 hover:bg-pink-100/70 transition"
                >
                  I Already Have an Account
                </button>
              </div>
            </div>
          )}

          {mode === 'register' && (
            <form onSubmit={handleRegister} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Display Name (e.g. Vivi or Jojo)</label>
                <input
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Vivi"
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm outline-none focus:border-pink-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Nickname (Optional)</label>
                <input
                  value={nickname}
                  onChange={(e) => setNickname(e.target.value)}
                  placeholder="My Sunshine"
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm outline-none focus:border-pink-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="vivi@example.com"
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm outline-none focus:border-pink-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Password (min 6 characters)</label>
                <input
                  type="password"
                  required
                  minLength={6}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm outline-none focus:border-pink-500"
                />
              </div>
              <button
                type="submit"
                disabled={busy}
                className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md"
              >
                {busy ? 'Creating Account & Keys…' : 'Create Account'}
              </button>
              <button type="button" onClick={() => setMode('login')} className="w-full text-xs font-semibold text-pink-600 pt-1">
                Already have an account? Sign in
              </button>
            </form>
          )}

          {mode === 'login' && (
            <form onSubmit={handleLogin} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    setLogin2faStep(null);
                  }}
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm outline-none focus:border-pink-500"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm outline-none focus:border-pink-500"
                />
              </div>
              {login2faStep && (
                <div className="rounded-2xl bg-pink-50 border border-pink-200 p-3.5 space-y-2">
                  <p className="text-xs font-semibold text-rose-950">
                    Email 2FA Code Required
                    {login2faStep.previewCode && (
                      <span className="ml-2 font-mono-nums text-pink-600">(Preview: {login2faStep.previewCode})</span>
                    )}
                  </p>
                  <input
                    required
                    inputMode="numeric"
                    maxLength={6}
                    value={login2faStep.otp}
                    onChange={(e) =>
                      setLogin2faStep((prev) => (prev ? { ...prev, otp: e.target.value.replace(/\D/g, '').slice(0, 6) } : prev))
                    }
                    placeholder="Enter 6-digit email code"
                    className="w-full rounded-xl border border-pink-200 bg-white px-3 py-2 text-sm font-mono-nums tracking-widest"
                  />
                </div>
              )}
              <button
                type="submit"
                disabled={busy}
                className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md"
              >
                {busy ? 'Signing In…' : login2faStep ? 'Verify Email Code & Sign In' : 'Sign In'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setOtpRequested(null);
                  setEmailOtpCode('');
                  setMode('login-otp');
                }}
                className="w-full min-h-[42px] rounded-2xl border border-pink-200 bg-pink-50/60 text-xs font-semibold text-rose-900 hover:bg-pink-100/60"
              >
                Sign In with Email Verification Code Instead
              </button>
              <div className="flex items-center justify-between pt-1 text-xs font-semibold text-pink-600">
                <button type="button" onClick={() => setMode('register')}>
                  Create account
                </button>
                <button type="button" onClick={() => setMode('recover')}>
                  Forgot password?
                </button>
              </div>
            </form>
          )}

          {mode === 'login-otp' && (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                try {
                  if (!otpRequested?.sent) {
                    const res = await apiRequest<{ provider: string; previewCode?: string }>('/api/auth/email/send-code', {
                      method: 'POST',
                      body: JSON.stringify({ email, purpose: 'login_otp' }),
                    });
                    setOtpRequested({ sent: true, provider: res.provider, previewCode: res.previewCode });
                    showToast('Verification code sent to your email!');
                  } else {
                    const res = await apiRequest<any>('/api/auth/email/login-otp', {
                      method: 'POST',
                      body: JSON.stringify({
                        email,
                        code: emailOtpCode,
                        platform: /iphone|ipad|ipod/i.test(navigator.userAgent) ? 'iOS' : /android/i.test(navigator.userAgent) ? 'Android' : 'Web',
                      }),
                    });
                    onAuthenticated(res);
                  }
                } catch (err) {
                  showToast(err instanceof Error ? err.message : 'Email login failed', 'error');
                } finally {
                  setBusy(false);
                }
              }}
              className="space-y-3.5"
            >
              <div>
                <label className="block text-xs font-semibold text-rose-900 mb-1">Account Email</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm"
                />
              </div>
              {otpRequested?.sent && (
                <div className="space-y-2">
                  <p className="text-xs text-rose-900/75">
                    {otpRequested.provider === 'resend' ? 'Enter the 6-digit code sent to your inbox.' : 'Preview code:'}
                    {otpRequested.previewCode && (
                      <span className="ml-1.5 font-mono-nums font-bold text-pink-600">{otpRequested.previewCode}</span>
                    )}
                  </p>
                  <input
                    required
                    inputMode="numeric"
                    maxLength={6}
                    value={emailOtpCode}
                    onChange={(e) => setEmailOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="6-digit email code"
                    className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm font-mono-nums tracking-widest"
                  />
                </div>
              )}
              <button
                type="submit"
                disabled={busy}
                className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md"
              >
                {busy ? 'Working…' : otpRequested?.sent ? 'Verify Code & Sign In' : 'Send 6-Digit Email Code'}
              </button>
              <button type="button" onClick={() => setMode('login')} className="w-full text-xs font-semibold text-pink-600">
                Back to Password Sign In
              </button>
            </form>
          )}

          {mode === 'recover' && (
            <form onSubmit={handleRecover} className="space-y-3.5">
              <div className="grid grid-cols-2 gap-1.5 rounded-xl bg-pink-100/70 p-1">
                <button
                  type="button"
                  onClick={() => setRecoverMode('email')}
                  className={`py-1.5 rounded-lg text-xs font-semibold ${recoverMode === 'email' ? 'bg-white text-rose-950 shadow-xs' : 'text-rose-800/70'}`}
                >
                  Via Email Code
                </button>
                <button
                  type="button"
                  onClick={() => setRecoverMode('code')}
                  className={`py-1.5 rounded-lg text-xs font-semibold ${recoverMode === 'code' ? 'bg-white text-rose-950 shadow-xs' : 'text-rose-800/70'}`}
                >
                  Via Recovery Code
                </button>
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Your email"
                className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm"
              />
              {recoverMode === 'email' ? (
                <>
                  <div className="flex gap-2">
                    <input
                      required
                      inputMode="numeric"
                      maxLength={6}
                      value={emailOtpCode}
                      onChange={(e) => setEmailOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="6-digit email code"
                      className="flex-1 rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm font-mono-nums"
                    />
                    <button
                      type="button"
                      onClick={async () => {
                        if (!email.includes('@')) {
                          showToast('Enter your email first.', 'error');
                          return;
                        }
                        const res = await apiRequest<{ provider: string; previewCode?: string }>('/api/auth/email/send-code', {
                          method: 'POST',
                          body: JSON.stringify({ email, purpose: 'reset_password' }),
                        });
                        setOtpRequested({ sent: true, provider: res.provider, previewCode: res.previewCode });
                        showToast(res.previewCode ? `Preview code: ${res.previewCode}` : 'Reset code emailed!');
                      }}
                      className="rounded-2xl bg-pink-100 px-3.5 text-xs font-semibold text-rose-900 whitespace-nowrap"
                    >
                      Send Code
                    </button>
                  </div>
                  {otpRequested?.previewCode && (
                    <p className="text-xs text-pink-600 font-mono-nums">Preview Reset Code: {otpRequested.previewCode}</p>
                  )}
                </>
              ) : (
                <input
                  required
                  value={recoveryCodeInput}
                  onChange={(e) => setRecoveryCodeInput(e.target.value)}
                  placeholder="Recovery code (e.g. EV-XXXXXX-XXXXXX)"
                  className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm font-mono-nums"
                />
              )}
              <input
                type="password"
                required
                minLength={6}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New password"
                className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm"
              />
              <button
                type="submit"
                disabled={busy}
                className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white"
              >
                {busy ? 'Resetting…' : 'Reset Account Password'}
              </button>
              <button type="button" onClick={() => setMode('login')} className="w-full text-xs font-semibold text-pink-600">
                Back to Sign In
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

// --- 2. Couple Space Setup (Create or Join) ---
const CouplePairingScreen: React.FC<{
  user: UserProfile;
  onSpaceReady: () => Promise<void>;
  onLogout: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, onSpaceReady, onLogout, showToast }) => {
  const [tab, setTab] = useState<'create' | 'join'>('create');
  const [spaceName, setSpaceName] = useState(`${user.display_name} & Partner`);
  const [startDate, setStartDate] = useState(new Date().toISOString().slice(0, 10));
  const [pin, setPin] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [avatarUrl, setAvatarUrl] = useState(user.avatar_url || '');
  const [busy, setBusy] = useState(false);
  const [showSelfieCam, setShowSelfieCam] = useState(false);

  const handleAvatarUpload = async (file: File) => {
    try {
      const uploaded = await uploadPrivateFile(file, file.name);
      await apiRequest('/api/profile', { method: 'PATCH', body: JSON.stringify({ avatar_url: uploaded.url }) });
      setAvatarUrl(uploaded.url);
      showToast('Profile photograph uploaded!');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Upload failed', 'error');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#fff5f8] via-[#ffe4ef] to-[#efe3ff] flex items-center justify-center p-4">
      <div className="w-full max-w-lg rounded-[2.25rem] bg-white/95 p-7 shadow-xl border border-pink-200 space-y-5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <label className="relative cursor-pointer group">
              <div className="h-14 w-14 overflow-hidden rounded-full border-2 border-pink-300 shadow-sm">
                <PrivateImage src={avatarUrl} alt={user.display_name} fallbackLabel={user.display_name} className="h-full w-full object-cover" />
              </div>
              <span className="absolute -bottom-1 -right-1 flex h-6 w-6 items-center justify-center rounded-full bg-pink-500 text-white shadow">
                <Upload className="h-3 w-3" />
              </span>
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleAvatarUpload(f);
                }}
              />
            </label>
            <div>
              <h2 className="font-display text-xl font-bold text-rose-950">Welcome, {user.display_name}</h2>
              <div className="flex items-center gap-2 mt-0.5">
                <button
                  type="button"
                  onClick={() => setShowSelfieCam(true)}
                  className="inline-flex items-center gap-1 rounded-full bg-pink-100 px-2.5 py-0.5 text-[11px] font-semibold text-pink-700 hover:bg-pink-200"
                >
                  <Camera className="h-3 w-3" />
                  Take Selfie
                </button>
                <span className="text-[11px] text-rose-700/75">or tap photo to upload</span>
              </div>
            </div>
          </div>
          <button type="button" onClick={onLogout} className="text-xs font-semibold text-rose-600 shrink-0">
            Sign out
          </button>
        </div>
        {showSelfieCam && (
          <CameraCaptureModal
            title="Take Profile Selfie"
            allowVideo={false}
            defaultFacingMode="user"
            onCapture={handleAvatarUpload}
            onClose={() => setShowSelfieCam(false)}
            showToast={showToast}
          />
        )}

        <div className="grid grid-cols-2 gap-1.5 rounded-2xl bg-pink-100/70 p-1">
          <button
            type="button"
            onClick={() => setTab('create')}
            className={`min-h-[42px] rounded-xl text-xs font-semibold transition ${
              tab === 'create' ? 'bg-white text-rose-950 shadow-sm' : 'text-rose-800/70'
            }`}
          >
            Create a Couple Space
          </button>
          <button
            type="button"
            onClick={() => setTab('join')}
            className={`min-h-[42px] rounded-xl text-xs font-semibold transition ${
              tab === 'join' ? 'bg-white text-rose-950 shadow-sm' : 'text-rose-800/70'
            }`}
          >
            Join with Invite Code
          </button>
        </div>

        {tab === 'create' ? (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                await apiRequest('/api/couple/create', {
                  method: 'POST',
                  body: JSON.stringify({ name: spaceName, startDate, pin }),
                });
                await onSpaceReady();
              } catch (err) {
                showToast(err instanceof Error ? err.message : 'Could not create space', 'error');
              } finally {
                setBusy(false);
              }
            }}
            className="space-y-3.5"
          >
            <div>
              <label className="block text-xs font-semibold text-rose-900 mb-1">Couple Space Name</label>
              <input
                required
                value={spaceName}
                onChange={(e) => setSpaceName(e.target.value)}
                className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-rose-900 mb-1">Relationship Start Date</label>
              <input
                type="date"
                required
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-rose-900 mb-1">Shared App-Lock PIN (4–6 digits, e.g. 5124)</label>
              <input
                type="password"
                inputMode="numeric"
                pattern="\d{4,6}"
                required
                value={pin}
                onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="5124"
                className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm font-mono-nums tracking-widest"
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md"
            >
              {busy ? 'Creating Private Space…' : 'Create Couple Space & Generate Invite'}
            </button>
          </form>
        ) : (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                await apiRequest('/api/couple/join', {
                  method: 'POST',
                  body: JSON.stringify({ code: inviteCode }),
                });
                await onSpaceReady();
                showToast('Paired with your partner!');
              } catch (err) {
                showToast(err instanceof Error ? err.message : 'Invalid invite code', 'error');
              } finally {
                setBusy(false);
              }
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-xs font-semibold text-rose-900 mb-1">Single-Use Invitation Code</label>
              <input
                required
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value.toUpperCase())}
                placeholder="LOVE-XXXXXX"
                className="w-full rounded-2xl border border-pink-200 bg-pink-50/40 px-4 py-3 text-sm font-mono-nums tracking-wider uppercase"
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="w-full min-h-[48px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-sm font-semibold text-white shadow-md"
            >
              {busy ? 'Pairing…' : 'Join Partner Space'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

// --- 3. Shared App Lock PIN Screen ---
const SharedPinLockScreen: React.FC<{
  coupleName: string;
  userEmail: string;
  onUnlocked: () => void;
  onLogout: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ coupleName, userEmail, onUnlocked, onLogout, showToast }) => {
  const [pin, setPin] = useState('');
  const [resetMode, setResetMode] = useState(false);
  const [accountPassword, setAccountPassword] = useState('');
  const [newPin, setNewPin] = useState('');

  const submitPin = async (code: string) => {
    try {
      await apiRequest('/api/couple/pin/verify', { method: 'POST', body: JSON.stringify({ pin: code }) });
      onUnlocked();
    } catch (err) {
      setPin('');
      showToast(err instanceof Error ? err.message : 'Incorrect PIN', 'error');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#ffe4ef] via-[#fff5f8] to-[#efe3ff] dark:from-[#170d16] dark:to-[#281526] flex items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-[2.25rem] bg-white/95 dark:bg-[#281526] p-7 shadow-xl border border-pink-200 dark:border-pink-800/40 text-center space-y-5">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-pink-100 dark:bg-rose-950/60 text-pink-600">
          <Lock className="h-7 w-7" />
        </div>
        <div>
          <h2 className="font-display text-2xl font-bold">{coupleName}</h2>
          <p className="text-xs opacity-75 mt-1">Enter your shared EverUs App PIN</p>
        </div>

        {!resetMode ? (
          <>
            <div className="flex justify-center gap-3 py-2">
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <div
                  key={i}
                  className={`h-3.5 w-3.5 rounded-full border-2 transition ${
                    i < pin.length ? 'bg-pink-500 border-pink-500 scale-110' : 'border-pink-300 dark:border-pink-700'
                  }`}
                />
              ))}
            </div>

            <div className="grid grid-cols-3 gap-2.5 max-w-[240px] mx-auto">
              {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => {
                    if (pin.length < 6) setPin((p) => p + d);
                  }}
                  className="h-14 rounded-2xl bg-pink-50 dark:bg-rose-950/50 text-lg font-semibold hover:bg-pink-100 active:scale-95 transition"
                >
                  {d}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setPin((p) => p.slice(0, -1))}
                className="h-14 rounded-2xl bg-pink-50/60 dark:bg-rose-950/30 text-xs font-semibold"
              >
                Del
              </button>
              <button
                type="button"
                onClick={() => {
                  if (pin.length < 6) setPin((p) => p + '0');
                }}
                className="h-14 rounded-2xl bg-pink-50 dark:bg-rose-950/50 text-lg font-semibold"
              >
                0
              </button>
              <button
                type="button"
                disabled={pin.length < 4}
                onClick={() => submitPin(pin)}
                className="h-14 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-xs font-semibold text-white disabled:opacity-40"
              >
                Unlock
              </button>
            </div>

            <div className="flex items-center justify-between pt-2 text-xs">
              <button type="button" onClick={() => setResetMode(true)} className="font-semibold text-pink-600 dark:text-pink-300">
                Recover via Account
              </button>
              <button type="button" onClick={onLogout} className="opacity-70 hover:opacity-100">
                Switch Account
              </button>
            </div>
          </>
        ) : (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                await apiRequest('/api/couple/pin/update', {
                  method: 'POST',
                  body: JSON.stringify({ accountPassword, newPin }),
                });
                showToast('Shared PIN updated & unlocked!');
                onUnlocked();
              } catch (err) {
                showToast(err instanceof Error ? err.message : 'Verification failed', 'error');
              }
            }}
            className="space-y-3 text-left"
          >
            <p className="text-xs opacity-75">Verify individual account password for {userEmail} to set a new shared PIN.</p>
            <input
              type="password"
              required
              value={accountPassword}
              onChange={(e) => setAccountPassword(e.target.value)}
              placeholder="Your account password"
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
            />
            <input
              type="password"
              inputMode="numeric"
              pattern="\d{4,6}"
              required
              value={newPin}
              onChange={(e) => setNewPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="New 4–6 digit PIN"
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm font-mono-nums"
            />
            <button type="submit" className="w-full min-h-[44px] rounded-2xl bg-pink-500 text-xs font-semibold text-white">
              Verify & Reset PIN
            </button>
            <button type="button" onClick={() => setResetMode(false)} className="w-full text-xs font-semibold opacity-70">
              Back to keypad
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

// --- 4. Daily Tasks ---
const DailyTasksSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  tasks: Array<Record<string, any>>;
  history: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, tasks, history, onRefresh, showToast }) => {
  const [cat, setCat] = useState<'partner_a' | 'partner_b' | 'shared'>('shared');
  const [statusFilter, setStatusFilter] = useState<'pending' | 'completed' | 'history'>('pending');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [dueAt, setDueAt] = useState('');
  const [reminderAt, setReminderAt] = useState('');
  const [recurrence, setRecurrence] = useState<'none' | 'daily' | 'weekly' | 'monthly'>('none');
  const [editingId, setEditingId] = useState<string | null>(null);

  const visibleTasks = tasks.filter(
    (t) => t.category === cat && (statusFilter === 'pending' ? t.is_completed === 0 : t.is_completed === 1)
  );

  const getPerson = (uid: string) => (uid === user.id ? user : partner?.id === uid ? partner : null);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Daily Tasks</h2>
        <p className="text-sm opacity-75">Synchronized personal & shared tasks for both partners.</p>
      </div>

      {/* Category Switcher */}
      <div className="grid grid-cols-3 gap-2 rounded-2xl bg-pink-100/70 dark:bg-rose-950/50 p-1.5">
        <button
          type="button"
          onClick={() => setCat('partner_a')}
          className={`min-h-[42px] rounded-xl px-2 text-xs font-semibold truncate transition ${
            cat === 'partner_a' ? 'bg-white dark:bg-[#281526] shadow-sm' : 'opacity-75'
          }`}
        >
          {user.display_name}’s Tasks
        </button>
        <button
          type="button"
          onClick={() => setCat('partner_b')}
          className={`min-h-[42px] rounded-xl px-2 text-xs font-semibold truncate transition ${
            cat === 'partner_b' ? 'bg-white dark:bg-[#281526] shadow-sm' : 'opacity-75'
          }`}
        >
          {partner?.display_name || 'Partner'}’s Tasks
        </button>
        <button
          type="button"
          onClick={() => setCat('shared')}
          className={`min-h-[42px] rounded-xl px-2 text-xs font-semibold truncate transition ${
            cat === 'shared' ? 'bg-white dark:bg-[#281526] shadow-sm' : 'opacity-75'
          }`}
        >
          Our Shared Tasks
        </button>
      </div>

      {/* Add / Edit Task Form */}
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          try {
            if (editingId) {
              await apiRequest(`/api/tasks/${editingId}`, {
                method: 'PATCH',
                body: JSON.stringify({ title, description, due_at: dueAt || null, reminder_at: reminderAt || null, recurrence, category: cat }),
              });
              setEditingId(null);
              showToast('Task updated!');
            } else {
              await apiRequest('/api/tasks', {
                method: 'POST',
                body: JSON.stringify({
                  category: cat,
                  assigned_to: cat === 'partner_a' ? user.id : cat === 'partner_b' ? partner?.id : null,
                  title,
                  description,
                  due_at: dueAt || null,
                  reminder_at: reminderAt || null,
                  recurrence,
                }),
              });
              showToast('Task added!');
            }
            setTitle('');
            setDescription('');
            setDueAt('');
            setReminderAt('');
            setRecurrence('none');
            await onRefresh();
          } catch (err) {
            showToast(err instanceof Error ? err.message : 'Failed to save task', 'error');
          }
        }}
        className="rounded-3xl bg-white/85 dark:bg-[#281526]/90 p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3"
      >
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Add a task (e.g. Pick up fresh roses or Book dinner)…"
            className="flex-1 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
          />
          <select
            value={recurrence}
            onChange={(e) => setRecurrence(e.target.value as any)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2.5 text-xs font-semibold"
          >
            <option value="none">One-time</option>
            <option value="daily">Recurring Daily</option>
            <option value="weekly">Recurring Weekly</option>
            <option value="monthly">Recurring Monthly</option>
          </select>
        </div>
        <div className="grid sm:grid-cols-3 gap-3">
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Notes or details"
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2 text-xs"
          />
          <label className="flex items-center gap-2 text-xs">
            <span className="opacity-70 shrink-0">Due:</span>
            <input
              type="datetime-local"
              value={dueAt}
              onChange={(e) => setDueAt(e.target.value)}
              className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-2.5 py-1.5 text-xs"
            />
          </label>
          <label className="flex items-center gap-2 text-xs">
            <span className="opacity-70 shrink-0">Remind:</span>
            <input
              type="datetime-local"
              value={reminderAt}
              onChange={(e) => setReminderAt(e.target.value)}
              className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-2.5 py-1.5 text-xs"
            />
          </label>
        </div>
        <div className="flex items-center justify-end gap-2">
          {editingId && (
            <button
              type="button"
              onClick={() => {
                setEditingId(null);
                setTitle('');
                setDescription('');
              }}
              className="rounded-xl px-3 py-2 text-xs font-semibold"
            >
              Cancel Edit
            </button>
          )}
          <button
            type="submit"
            className="inline-flex min-h-[42px] items-center gap-2 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-5 py-2 text-xs font-semibold text-white shadow-sm"
          >
            <Plus className="h-4 w-4" />
            <span>{editingId ? 'Save Changes' : 'Add Task'}</span>
          </button>
        </div>
      </form>

      {/* Filter Bar */}
      <div className="flex items-center gap-2">
        {(['pending', 'completed', 'history'] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setStatusFilter(tab)}
            className={`min-h-[38px] rounded-xl px-4 text-xs font-semibold capitalize transition ${
              statusFilter === tab
                ? 'bg-pink-500 text-white'
                : 'bg-white/75 dark:bg-[#281526] border border-pink-200/60 dark:border-pink-900/40'
            }`}
          >
            {tab === 'history' ? 'Completion History' : tab}
          </button>
        ))}
      </div>

      {/* Task List or Completion History */}
      {statusFilter === 'history' ? (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526]/90 divide-y divide-pink-100 dark:divide-pink-900/40 border border-pink-200/60 dark:border-pink-900/40">
          {history.length === 0 ? (
            <p className="p-8 text-center text-sm opacity-65">No completed tasks recorded yet.</p>
          ) : (
            history.map((h) => (
              <div key={h.id} className="p-4 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="h-9 w-9 overflow-hidden rounded-full border border-pink-200">
                    <PrivateImage src={h.completer_avatar} alt={h.completer_name} fallbackLabel={h.completer_name} className="h-full w-full object-cover" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold">{h.task_title}</p>
                    <p className="text-xs opacity-70">
                      Completed by {h.completer_name} · {formatRelativeTime(h.completed_at)}
                    </p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="space-y-2.5">
          {visibleTasks.length === 0 ? (
            <div className="rounded-3xl bg-white/70 dark:bg-[#281526]/60 p-8 text-center text-sm opacity-70">
              No {statusFilter} tasks in this category yet.
            </div>
          ) : (
            visibleTasks.map((task) => {
              const completer = task.completed_by ? getPerson(task.completed_by) : null;
              return (
                <div
                  key={task.id}
                  className="rounded-2xl bg-white/85 dark:bg-[#281526]/90 p-4 border border-pink-200/50 dark:border-pink-900/40 flex items-start justify-between gap-3"
                >
                  <button
                    type="button"
                    onClick={async () => {
                      await apiRequest(`/api/tasks/${task.id}`, {
                        method: 'PATCH',
                        body: JSON.stringify({ is_completed: !task.is_completed }),
                      });
                      await onRefresh();
                    }}
                    className="min-h-[40px] min-w-[40px] flex items-center justify-center text-pink-500 shrink-0"
                    aria-label="Toggle task completion"
                  >
                    {task.is_completed ? <CheckCircle2 className="h-6 w-6 fill-pink-100" /> : <Circle className="h-6 w-6" />}
                  </button>

                  <div className="flex-1 min-w-0">
                    <p className={`text-sm font-semibold ${task.is_completed ? 'line-through opacity-60' : ''}`}>{task.title}</p>
                    {task.description && <p className="text-xs opacity-75 mt-0.5">{task.description}</p>}
                    <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] opacity-70">
                      {task.recurrence !== 'none' && <span className="capitalize">{task.recurrence}</span>}
                      {task.due_at && (
                        <>
                          <span>·</span>
                          <span>Due {task.due_at.replace('T', ' ')}</span>
                        </>
                      )}
                      {completer && (
                        <>
                          <span>·</span>
                          <span>Completed by {completer.display_name}</span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => {
                        setEditingId(task.id);
                        setTitle(task.title);
                        setDescription(task.description || '');
                        setDueAt(task.due_at || '');
                        setReminderAt(task.reminder_at || '');
                        setRecurrence(task.recurrence || 'none');
                      }}
                      className="min-h-[38px] min-w-[38px] flex items-center justify-center rounded-xl hover:bg-pink-50 dark:hover:bg-rose-950/50"
                      aria-label="Edit task"
                    >
                      <Edit3 className="h-4 w-4" />
                    </button>
                    <button
                      type="button"
                      onClick={async () => {
                        await apiRequest(`/api/tasks/${task.id}`, { method: 'DELETE' });
                        await onRefresh();
                      }}
                      className="min-h-[38px] min-w-[38px] flex items-center justify-center rounded-xl text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/50"
                      aria-label="Delete task"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
};

// --- 5. Consensual Location Sharing ---
const LocationSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  data: { preferences: Array<Record<string, any>>; locations: Array<Record<string, any>>; savedPlaces: Array<Record<string, any>> };
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, data, onRefresh, showToast }) => {
  const myPref = data.preferences.find((p) => p.user_id === user.id);
  const partnerPref = partner ? data.preferences.find((p) => p.user_id === partner.id) : null;
  const myLoc = data.locations.find((l) => l.user_id === user.id);
  const partnerLoc = partner ? data.locations.find((l) => l.user_id === partner.id) : null;

  const [placeName, setPlaceName] = useState('');
  const [pickedCoords, setPickedCoords] = useState<{ lat: number; lng: number } | null>(null);
  const [busyGps, setBusyGps] = useState(false);

  const markers = useMemo(() => {
    const out = [];
    if (myLoc && myPref?.is_sharing === 1 && myPref?.is_paused === 0) {
      out.push({
        id: user.id,
        name: user.display_name,
        avatarUrl: user.avatar_url,
        lat: myLoc.latitude,
        lng: myLoc.longitude,
        updatedAt: myLoc.updated_at,
        isSelf: true,
      });
    }
    if (partner && partnerLoc && partnerPref?.is_sharing === 1 && partnerPref?.is_paused === 0) {
      out.push({
        id: partner.id,
        name: partner.display_name,
        avatarUrl: partner.avatar_url,
        lat: partnerLoc.latitude,
        lng: partnerLoc.longitude,
        updatedAt: partnerLoc.updated_at,
        isSelf: false,
      });
    }
    return out;
  }, [myLoc, partnerLoc, myPref, partnerPref, user, partner]);

  const distanceKm =
    myLoc && partnerLoc ? haversineKm(myLoc.latitude, myLoc.longitude, partnerLoc.latitude, partnerLoc.longitude) : null;

  const shareCurrentGps = () => {
    if (!navigator.geolocation) {
      showToast('Device geolocation is unavailable in this browser.', 'error');
      return;
    }
    setBusyGps(true);
    navigator.geolocation.getCurrentPosition(
      async (pos) => {
        try {
          await apiRequest('/api/location/update', {
            method: 'POST',
            body: JSON.stringify({
              latitude: pos.coords.latitude,
              longitude: pos.coords.longitude,
              accuracy: pos.coords.accuracy,
              label: 'Device GPS',
            }),
          });
          await onRefresh();
          showToast('Your location was updated!');
        } catch (err) {
          showToast(err instanceof Error ? err.message : 'Enable sharing consent first.', 'error');
        } finally {
          setBusyGps(false);
        }
      },
      (err) => {
        setBusyGps(false);
        showToast(err.message || 'Location permission denied by device.', 'error');
      },
      { enableHighAccuracy: true, timeout: 10000 }
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Private Location Sharing</h2>
        <p className="text-sm opacity-75">
          Transparent, consent-based sharing. Each partner controls their own sharing & pause switch independently.
        </p>
      </div>

      {/* Consent Controls */}
      <div className="grid sm:grid-cols-3 gap-3">
        <button
          type="button"
          onClick={async () => {
            await apiRequest('/api/location/preferences', {
              method: 'PATCH',
              body: JSON.stringify({ is_sharing: !(myPref?.is_sharing === 1) }),
            });
            await onRefresh();
          }}
          className={`min-h-[52px] rounded-2xl p-4 text-left border transition ${
            myPref?.is_sharing === 1
              ? 'bg-pink-500 text-white border-pink-500'
              : 'bg-white/85 dark:bg-[#281526] border-pink-200 dark:border-pink-900/40'
          }`}
        >
          <p className="text-xs font-semibold">{myPref?.is_sharing === 1 ? 'Sharing Enabled' : 'Enable Location Sharing'}</p>
          <p className="text-[11px] opacity-85 mt-0.5">Tap to toggle your consent</p>
        </button>

        <button
          type="button"
          onClick={async () => {
            await apiRequest('/api/location/preferences', {
              method: 'PATCH',
              body: JSON.stringify({ is_paused: !(myPref?.is_paused === 1) }),
            });
            await onRefresh();
          }}
          className={`min-h-[52px] rounded-2xl p-4 text-left border transition ${
            myPref?.is_paused === 1
              ? 'bg-amber-500 text-white border-amber-500'
              : 'bg-white/85 dark:bg-[#281526] border-pink-200 dark:border-pink-900/40'
          }`}
        >
          <p className="text-xs font-semibold flex items-center gap-1.5">
            <Pause className="h-3.5 w-3.5" />
            {myPref?.is_paused === 1 ? 'Sharing Paused' : 'Pause Sharing'}
          </p>
          <p className="text-[11px] opacity-85 mt-0.5">Hide location temporarily</p>
        </button>

        <button
          type="button"
          disabled={myPref?.is_sharing !== 1 || myPref?.is_paused === 1 || busyGps}
          onClick={shareCurrentGps}
          className="min-h-[52px] rounded-2xl bg-gradient-to-r from-purple-500 to-pink-500 p-4 text-left text-white shadow-sm disabled:opacity-40"
        >
          <p className="text-xs font-semibold">{busyGps ? 'Reading GPS…' : 'Update My Location Now'}</p>
          <p className="text-[11px] opacity-90 mt-0.5">Uses device GPS with consent</p>
        </button>
      </div>

      {/* Interactive Map */}
      <PartnerLeafletMap
        markers={markers}
        savedPlaces={data.savedPlaces as any}
        onPickCoordinate={(lat, lng) => setPickedCoords({ lat, lng })}
      />

      {/* Distance & Freshness Status (never pretends stale data is live) */}
      <div className="grid sm:grid-cols-3 gap-3">
        <div className="rounded-2xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-100 dark:border-pink-900/40">
          <p className="text-xs opacity-70">{user.display_name}</p>
          <p className="text-sm font-semibold mt-1">
            {myPref?.is_sharing !== 1
              ? 'Not sharing'
              : myPref?.is_paused === 1
                ? 'Paused'
                : myLoc
                  ? `Updated ${formatRelativeTime(myLoc.updated_at)}`
                  : 'No location sent yet'}
          </p>
        </div>

        <div className="rounded-2xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-100 dark:border-pink-900/40">
          <p className="text-xs opacity-70">{partner?.display_name || 'Partner'}</p>
          <p className="text-sm font-semibold mt-1">
            {!partner
              ? 'Not paired yet'
              : partnerPref?.is_sharing !== 1
                ? 'Sharing off'
                : partnerPref?.is_paused === 1
                  ? 'Paused'
                  : partnerLoc
                    ? `Updated ${formatRelativeTime(partnerLoc.updated_at)}`
                    : 'No update yet'}
          </p>
        </div>

        <div className="rounded-2xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-100 dark:border-pink-900/40">
          <p className="text-xs opacity-70">Distance Between Partners</p>
          <p className="font-mono-nums text-sm font-semibold mt-1">
            {distanceKm !== null ? (distanceKm < 1 ? `${Math.round(distanceKm * 1000)} m apart` : `${distanceKm.toFixed(1)} km apart`) : 'Awaiting both locations'}
          </p>
        </div>
      </div>

      {/* Saved Places & Arrival Alerts */}
      <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-display text-base font-semibold">Saved Places & Arrival Alerts</h3>
            <p className="text-xs opacity-70">Tap anywhere on the map above to pick coordinates for a saved place.</p>
          </div>
        </div>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const coords = pickedCoords || (myLoc ? { lat: myLoc.latitude, lng: myLoc.longitude } : null);
            if (!coords) {
              showToast('Tap on the map first or update your GPS location.', 'error');
              return;
            }
            await apiRequest('/api/location/places', {
              method: 'POST',
              body: JSON.stringify({ name: placeName, latitude: coords.lat, longitude: coords.lng, radius_meters: 200 }),
            });
            setPlaceName('');
            setPickedCoords(null);
            await onRefresh();
            showToast('Saved place added with arrival notifications!');
          }}
          className="flex flex-col sm:flex-row gap-2.5"
        >
          <input
            required
            value={placeName}
            onChange={(e) => setPlaceName(e.target.value)}
            placeholder="Place name (e.g. Home, Favorite Cafe)"
            className="flex-1 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-xs"
          />
          <button type="submit" className="min-h-[42px] rounded-2xl bg-pink-500 px-4 py-2 text-xs font-semibold text-white">
            Save Place {pickedCoords ? `(${pickedCoords.lat.toFixed(3)}, ${pickedCoords.lng.toFixed(3)})` : '(Use Map Tap / Current)'}
          </button>
        </form>

        <div className="flex flex-wrap gap-2 pt-1">
          {data.savedPlaces.map((pl) => (
            <div
              key={pl.id}
              className="flex items-center gap-2 rounded-2xl bg-pink-50 dark:bg-rose-950/50 px-3.5 py-2 text-xs font-medium"
            >
              <MapPin className="h-3.5 w-3.5 text-pink-500" />
              <span>{pl.name}</span>
              <button
                type="button"
                onClick={async () => {
                  await apiRequest(`/api/location/places/${pl.id}`, { method: 'DELETE' });
                  await onRefresh();
                }}
                className="text-rose-500 ml-1"
                aria-label="Delete saved place"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// --- 6. Our Chat — End-to-End Encrypted Messaging ---
const EncryptedChatSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  partnerOnline: boolean;
  partnerLastSeen: string | null;
  messages: DecryptedChatMessage[];
  sharedAesKey: CryptoKey | null;
  safetyFingerprint: string;
  partnerTyping: boolean;
  onEmitTyping: (typing: boolean) => void;
  onRefreshMessages: () => Promise<void>;
  onSendQuickLove: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({
  user,
  partner,
  partnerOnline,
  partnerLastSeen,
  messages,
  sharedAesKey,
  safetyFingerprint,
  partnerTyping,
  onEmitTyping,
  onRefreshMessages,
  onSendQuickLove,
  showToast,
}) => {
  const [text, setText] = useState('');
  const [replyTo, setReplyTo] = useState<DecryptedChatMessage | null>(null);
  const [editingMsg, setEditingMsg] = useState<DecryptedChatMessage | null>(null);
  const [showStickers, setShowStickers] = useState(false);
  const [showCamera, setShowCamera] = useState(false);
  const [recording, setRecording] = useState(false);
  const mediaRecRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<BlobPart[]>([]);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  // Mark partner's unread messages as read when viewing chat
  useEffect(() => {
    for (const m of messages) {
      if (m.recipient_id === user.id && !m.read_at) {
        apiRequest(`/api/chat/messages/${m.id}`, {
          method: 'PATCH',
          body: JSON.stringify({ markRead: true }),
        }).catch(() => {});
      }
    }
  }, [messages, user.id]);

  const sendEncryptedMessage = async (
    payload: { text?: string; sticker?: string },
    messageType = 'text',
    attachmentId: string | null = null
  ) => {
    if (!sharedAesKey) {
      showToast('End-to-end key exchange completes once both partners have joined.', 'error');
      return;
    }
    const { ciphertext, iv } = await encryptText(sharedAesKey, payload);
    if (editingMsg) {
      await apiRequest(`/api/chat/messages/${editingMsg.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ ciphertext, iv }),
      });
      setEditingMsg(null);
    } else {
      await apiRequest('/api/chat/messages', {
        method: 'POST',
        body: JSON.stringify({
          ciphertext,
          iv,
          message_type: messageType,
          attachment_id: attachmentId,
          reply_to_id: replyTo?.id || null,
        }),
      });
      setReplyTo(null);
    }
    setText('');
    onEmitTyping(false);
    await onRefreshMessages();
  };

  const handleEncryptedAttachment = async (file: File | Blob, filename: string, mimeType: string, msgType: string) => {
    if (!sharedAesKey) {
      showToast('Waiting for partner E2EE key.', 'error');
      return;
    }
    try {
      const buf = await file.arrayBuffer();
      const { encryptedBlob, ivB64 } = await encryptBinaryFile(sharedAesKey, buf);
      const uploaded = await uploadPrivateFile(encryptedBlob, `${filename}.enc`, {
        encrypted: true,
        encryptedIv: ivB64,
        originalMime: mimeType,
        originalName: filename,
      });
      await sendEncryptedMessage({ text: filename }, msgType, uploaded.attachmentId);
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Encrypted upload failed', 'error');
    }
  };

  const toggleVoiceNote = async () => {
    if (recording && mediaRecRef.current) {
      mediaRecRef.current.stop();
      setRecording(false);
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream);
      chunksRef.current = [];
      recorder.ondataavailable = (ev) => chunksRef.current.push(ev.data);
      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(chunksRef.current, { type: 'audio/webm' });
        await handleEncryptedAttachment(blob, `Voice-Note-${Date.now()}.webm`, 'audio/webm', 'voice');
      };
      recorder.start();
      mediaRecRef.current = recorder;
      setRecording(true);
    } catch {
      showToast('Microphone permission is needed to record voice notes.', 'error');
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-148px)] md:h-[calc(100vh-110px)] rounded-[2rem] bg-white/85 dark:bg-[#281526]/90 border border-pink-200/70 dark:border-pink-900/40 overflow-hidden shadow-sm">
      {/* Chat Header with Live Partner Status & Verified E2EE Fingerprint */}
      <div className="px-5 py-3.5 border-b border-pink-100 dark:border-pink-900/40 flex flex-wrap items-center justify-between gap-3 bg-gradient-to-r from-pink-50/90 to-purple-50/80 dark:from-rose-950/60 dark:to-purple-950/60">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className={`h-10 w-10 overflow-hidden rounded-full border-2 shadow-sm ${partnerOnline ? 'border-emerald-400' : 'border-white dark:border-[#281526]'}`}>
              <PrivateImage
                src={partner?.avatar_url}
                alt={partner?.display_name || 'Partner'}
                fallbackLabel={partner?.display_name || 'P2'}
                className="h-full w-full object-cover"
              />
            </div>
            {partner && (
              <span
                className={`absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-white dark:border-[#281526] ${
                  partnerOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-300'
                }`}
              />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <p className="font-display text-base font-semibold">{partner?.display_name || 'Waiting for Partner'}</p>
              {partner && (
                <span className={`text-[11px] font-semibold ${partnerOnline ? 'text-emerald-600 dark:text-emerald-400' : 'opacity-65'}`}>
                  {partnerTyping ? 'Typing…' : partnerOnline ? '· Online now' : `· Last seen ${formatRelativeTime(partnerLastSeen)}`}
                </span>
              )}
            </div>
            <p className="text-[11px] flex items-center gap-1.5 text-rose-700/80 dark:text-pink-200/80">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>End-to-End Encrypted (ECDH + AES-GCM)</span>
              <span>·</span>
              <span className="font-mono-nums">{safetyFingerprint}</span>
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onSendQuickLove}
          className="inline-flex min-h-[38px] items-center gap-1.5 rounded-2xl bg-pink-500 px-3.5 py-1.5 text-xs font-semibold text-white shadow-sm"
        >
          <Heart className="h-3.5 w-3.5 fill-current" />
          <span>Send Heart</span>
        </button>
      </div>

      {/* Messages Feed */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-3">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center p-6 opacity-75">
            <Lock className="h-8 w-8 text-pink-500 mb-2" />
            <p className="font-display text-base font-semibold">Private End-to-End Encrypted Chat</p>
            <p className="text-xs max-w-sm mt-1">
              Messages, photos, videos, voice notes, and files are encrypted on your device before ever reaching the server.
            </p>
          </div>
        ) : (
          messages.map((m) => {
            const isMine = m.sender_id === user.id;
            const reactions = JSON.parse(m.reactions_json || '{}') as Record<string, string>;
            const reactionList = Object.values(reactions);
            const parentMsg = m.reply_to_id ? messages.find((x) => x.id === m.reply_to_id) : null;

            return (
              <div key={m.id} className={`flex flex-col ${isMine ? 'items-end' : 'items-start'}`}>
                <div
                  className={`group relative max-w-[82%] sm:max-w-[70%] rounded-3xl px-4 py-2.5 shadow-xs ${
                    isMine
                      ? 'bg-gradient-to-br from-pink-500 to-rose-500 text-white rounded-br-md'
                      : 'bg-pink-100/80 dark:bg-rose-950/70 text-rose-950 dark:text-pink-50 rounded-bl-md'
                  }`}
                >
                  {parentMsg && (
                    <div className="mb-1.5 rounded-xl bg-black/10 px-2.5 py-1 text-[11px] opacity-85 truncate">
                      Replying to: {parentMsg.decryptedText || 'Attachment'}
                    </div>
                  )}

                  {m.message_type === 'sticker' && m.decryptedSticker ? (
                    <p className="text-4xl py-1">{m.decryptedSticker}</p>
                  ) : (
                    <>
                      {m.attachment_url && m.attachment_iv && !m.is_deleted && (
                        <EncryptedAttachmentView
                          url={m.attachment_url}
                          iv={m.attachment_iv}
                          mimeType={m.attachment_mime || 'application/octet-stream'}
                          fileName={m.attachment_name || 'attachment'}
                          sharedKey={sharedAesKey}
                        />
                      )}
                      {(!m.attachment_url || m.is_deleted) && (
                        <p className={`text-sm leading-relaxed ${m.is_deleted ? 'italic opacity-70' : ''}`}>
                          {m.decryptedText || 'Encrypted message'}
                        </p>
                      )}
                    </>
                  )}

                  <div className="mt-1 flex items-center justify-end gap-1.5 text-[10px] opacity-80">
                    {m.is_edited === 1 && <span>Edited</span>}
                    <span>{new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    {isMine && (
                      <span>{m.read_at ? <CheckCheck className="inline h-3 w-3" /> : <Check className="inline h-3 w-3" />}</span>
                    )}
                  </div>
                </div>

                {/* Quick Reactions & Actions */}
                {!m.is_deleted && (
                  <div className="mt-1 flex items-center gap-1 text-xs">
                    {reactionList.length > 0 && (
                      <span className="rounded-full bg-white dark:bg-[#241322] border border-pink-200 dark:border-pink-800 px-2 py-0.5 text-xs shadow-xs">
                        {reactionList.join(' ')}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => apiRequest(`/api/chat/messages/${m.id}`, { method: 'PATCH', body: JSON.stringify({ reaction: '❤️' }) }).then(onRefreshMessages)}
                      className="px-1.5 py-0.5 opacity-60 hover:opacity-100"
                      title="React with heart"
                    >
                      ❤️
                    </button>
                    <button
                      type="button"
                      onClick={() => setReplyTo(m)}
                      className="p-1 opacity-60 hover:opacity-100"
                      title="Reply"
                    >
                      <Reply className="h-3 w-3" />
                    </button>
                    {isMine && m.message_type === 'text' && (
                      <button
                        type="button"
                        onClick={() => {
                          setEditingMsg(m);
                          setText(m.decryptedText || '');
                        }}
                        className="p-1 opacity-60 hover:opacity-100"
                        title="Edit"
                      >
                        <Pencil className="h-3 w-3" />
                      </button>
                    )}
                    {isMine && (
                      <button
                        type="button"
                        onClick={() => apiRequest(`/api/chat/messages/${m.id}`, { method: 'PATCH', body: JSON.stringify({ delete: true }) }).then(onRefreshMessages)}
                        className="p-1 opacity-60 hover:opacity-100 text-rose-500"
                        title="Delete"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
        {partnerTyping && (
          <p className="text-xs italic text-pink-600 dark:text-pink-300">{partner?.display_name || 'Partner'} is typing…</p>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Stickers Drawer */}
      {showStickers && (
        <div className="px-4 py-2 border-t border-pink-100 dark:border-pink-900/40 flex items-center gap-3 overflow-x-auto bg-pink-50/70 dark:bg-black/20">
          {COUPLE_STICKERS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => {
                setShowStickers(false);
                sendEncryptedMessage({ sticker: s }, 'sticker');
              }}
              className="text-2xl hover:scale-125 transition-transform p-1"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Reply / Edit Context Bar */}
      {(replyTo || editingMsg) && (
        <div className="px-4 py-2 bg-pink-100/70 dark:bg-rose-950/60 flex items-center justify-between text-xs">
          <span className="truncate">
            {editingMsg ? `Editing: ${editingMsg.decryptedText}` : `Replying to: ${replyTo?.decryptedText}`}
          </span>
          <button
            type="button"
            onClick={() => {
              setReplyTo(null);
              setEditingMsg(null);
              setText('');
            }}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Composer */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!text.trim()) return;
          sendEncryptedMessage({ text: text.trim() }, 'text');
        }}
        className="p-3 border-t border-pink-100 dark:border-pink-900/40 flex items-center gap-2 bg-white/95 dark:bg-[#221220]"
      >
        <button
          type="button"
          onClick={() => setShowStickers((v) => !v)}
          className="min-h-[42px] min-w-[42px] flex items-center justify-center rounded-2xl hover:bg-pink-50 dark:hover:bg-rose-950/40 text-pink-500"
          aria-label="Stickers"
        >
          <Smile className="h-5 w-5" />
        </button>

        <button
          type="button"
          onClick={() => setShowCamera(true)}
          className="min-h-[42px] min-w-[42px] flex items-center justify-center rounded-2xl hover:bg-pink-50 dark:hover:bg-rose-950/40 text-pink-500"
          aria-label="Open camera to send encrypted photo or video"
          title="Camera"
        >
          <Camera className="h-5 w-5" />
        </button>

        <label
          className="min-h-[42px] min-w-[42px] flex items-center justify-center rounded-2xl hover:bg-pink-50 dark:hover:bg-rose-950/40 text-pink-500 cursor-pointer"
          aria-label="Send encrypted file, photo or video"
        >
          <Paperclip className="h-5 w-5" />
          <input
            type="file"
            accept="image/*,video/*,application/pdf"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (!f) return;
              const type = f.type.startsWith('image/') ? 'image' : f.type.startsWith('video/') ? 'video' : 'file';
              handleEncryptedAttachment(f, f.name, f.type || 'application/octet-stream', type);
            }}
          />
        </label>

        <button
          type="button"
          onClick={toggleVoiceNote}
          className={`min-h-[42px] min-w-[42px] flex items-center justify-center rounded-2xl transition ${
            recording ? 'bg-rose-500 text-white' : 'hover:bg-pink-50 dark:hover:bg-rose-950/40 text-pink-500'
          }`}
          aria-label="Record voice note"
        >
          {recording ? <Square className="h-4 w-4 fill-current" /> : <Mic className="h-5 w-5" />}
        </button>

        <input
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            onEmitTyping(Boolean(e.target.value));
          }}
          placeholder={sharedAesKey ? 'Write an encrypted message…' : 'Waiting for partner to join…'}
          className="flex-1 min-h-[42px] rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 text-sm outline-none focus:border-pink-500"
        />

        <button
          type="submit"
          disabled={!text.trim() || !sharedAesKey}
          className="min-h-[42px] min-w-[42px] flex items-center justify-center rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-white shadow-sm disabled:opacity-40"
          aria-label="Send message"
        >
          <Send className="h-4 w-4" />
        </button>
      </form>

      {showCamera && (
        <CameraCaptureModal
          title="Encrypted Chat Camera"
          allowVideo={true}
          defaultFacingMode="user"
          onClose={() => setShowCamera(false)}
          showToast={showToast}
          onCapture={async (file) => {
            const msgType = file.type.startsWith('video/') ? 'video' : 'image';
            await handleEncryptedAttachment(file, file.name, file.type || 'image/jpeg', msgType);
          }}
        />
      )}
    </div>
  );
};

// --- 7. Send Love Modal ---
const LoveModal: React.FC<{
  partnerName: string;
  loveItems: Array<Record<string, any>>;
  currentUserId: string;
  onClose: () => void;
  onSend: (kind: 'heart' | 'kiss' | 'hug' | 'note', message: string) => Promise<void>;
  onRespond: (id: string, emoji: string) => Promise<void>;
}> = ({ partnerName, loveItems, currentUserId, onClose, onSend, onRespond }) => {
  const [customMsg, setCustomMsg] = useState('');
  const [kind, setKind] = useState<'heart' | 'kiss' | 'hug' | 'note'>('heart');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-[2rem] bg-white dark:bg-[#281526] p-6 shadow-2xl border border-pink-200 dark:border-pink-800/40 space-y-5"
      >
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-display text-xl font-bold">Send Love to {partnerName}</h3>
            <p className="text-xs opacity-75">Trigger an animated heart celebration on their screen.</p>
          </div>
          <button type="button" onClick={onClose} className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-full hover:bg-pink-50 dark:hover:bg-rose-950/40">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="grid grid-cols-2 gap-2.5">
          {LOVE_PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              onClick={() => onSend(p.kind, p.message)}
              className="rounded-2xl bg-gradient-to-br from-pink-100 to-rose-100 dark:from-rose-950/70 dark:to-pink-900/50 p-3.5 text-left hover:scale-[1.01] transition"
            >
              <p className="text-xs font-bold text-pink-700 dark:text-pink-300">{p.label}</p>
              <p className="text-xs opacity-85 mt-0.5">{p.message}</p>
            </button>
          ))}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!customMsg.trim()) return;
            onSend(kind, customMsg.trim());
            setCustomMsg('');
          }}
          className="space-y-2.5 pt-1"
        >
          <div className="flex items-center gap-2">
            {(['heart', 'kiss', 'hug', 'note'] as const).map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setKind(k)}
                className={`rounded-xl px-3 py-1.5 text-xs font-semibold capitalize ${
                  kind === k ? 'bg-pink-500 text-white' : 'bg-pink-50 dark:bg-rose-950/40'
                }`}
              >
                {k}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              value={customMsg}
              onChange={(e) => setCustomMsg(e.target.value)}
              placeholder="Write a personal love note…"
              className="flex-1 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
            />
            <button type="submit" className="min-h-[44px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-5 text-xs font-semibold text-white">
              Send
            </button>
          </div>
        </form>

        {loveItems.length > 0 && (
          <div className="space-y-2 pt-2 border-t border-pink-100 dark:border-pink-900/40">
            <p className="text-xs font-semibold opacity-75">Recent Love Notes</p>
            {loveItems.slice(0, 5).map((item) => (
              <div key={item.id} className="rounded-2xl bg-pink-50/70 dark:bg-black/20 p-3 flex items-center justify-between gap-2 text-xs">
                <div>
                  <p className="font-medium">{item.message}</p>
                  <p className="opacity-65 mt-0.5">
                    {formatRelativeTime(item.created_at)}
                    {item.response_emoji ? ` · Response: ${item.response_emoji}` : ''}
                  </p>
                </div>
                {item.recipient_id === currentUserId && !item.response_emoji && (
                  <div className="flex items-center gap-1">
                    {['❤️', '😘', '🤗'].map((em) => (
                      <button key={em} type="button" onClick={() => onRespond(item.id, em)} className="text-base hover:scale-125 transition">
                        {em}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  );
};

// --- 8. Two-Player Couples Games ---
const GamesSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  sessions: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, sessions, onRefresh, showToast }) => {
  const [activeGameType, setActiveGameType] = useState<
    'tictactoe' | 'would_you_rather' | 'couple_questions' | 'quiz' | 'drawing_guess' | 'challenges'
  >('tictactoe');

  const currentSession = useMemo(
    () => sessions.find((s) => s.game_type === activeGameType) || null,
    [sessions, activeGameType]
  );

  const startNewGame = async (type: string, initialState: Record<string, unknown>) => {
    await apiRequest('/api/games', {
      method: 'POST',
      body: JSON.stringify({ game_type: type, state: initialState }),
    });
    await onRefresh();
  };

  const updateGame = async (id: string, patch: Record<string, unknown>) => {
    await apiRequest(`/api/games/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    });
    await onRefresh();
  };

  const gameState = currentSession ? JSON.parse(currentSession.state_json || '{}') : {};
  const [guessText, setGuessText] = useState('');
  const [questionAnswer, setQuestionAnswer] = useState('');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Couples Games</h2>
        <p className="text-sm opacity-75">Interactive two-player games synchronized in real time.</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {[
          { id: 'tictactoe', label: 'Tic-Tac-Toe' },
          { id: 'would_you_rather', label: 'Would You Rather' },
          { id: 'couple_questions', label: 'Couple Questions' },
          { id: 'quiz', label: 'Relationship Quiz' },
          { id: 'drawing_guess', label: 'Draw & Guess' },
          { id: 'challenges', label: 'Romantic Challenges' },
        ].map((g) => (
          <button
            key={g.id}
            type="button"
            onClick={() => setActiveGameType(g.id as any)}
            className={`min-h-[40px] rounded-2xl px-4 text-xs font-semibold transition ${
              activeGameType === g.id
                ? 'bg-gradient-to-r from-pink-500 to-rose-500 text-white shadow-sm'
                : 'bg-white/80 dark:bg-[#281526] border border-pink-200/60 dark:border-pink-900/40'
            }`}
          >
            {g.label}
          </button>
        ))}
      </div>

      {/* Tic-Tac-Toe */}
      {activeGameType === 'tictactoe' && (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-4 max-w-md">
          <div className="flex items-center justify-between">
            <h3 className="font-display text-lg font-semibold">Hearts & Kisses Tic-Tac-Toe</h3>
            <button
              type="button"
              onClick={() => startNewGame('tictactoe', { board: Array(9).fill(null), xUserId: user.id })}
              className="rounded-xl bg-pink-100 dark:bg-rose-950/60 px-3 py-1.5 text-xs font-semibold text-pink-700 dark:text-pink-200"
            >
              New Board
            </button>
          </div>
          {!currentSession ? (
            <button
              type="button"
              onClick={() => startNewGame('tictactoe', { board: Array(9).fill(null), xUserId: user.id })}
              className="w-full min-h-[46px] rounded-2xl bg-pink-500 text-sm font-semibold text-white"
            >
              Start Tic-Tac-Toe Match
            </button>
          ) : (
            <>
              <div className="grid grid-cols-3 gap-2.5">
                {(gameState.board || Array(9).fill(null)).map((cell: string | null, idx: number) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => {
                      if (cell || currentSession.status === 'finished') return;
                      const board = [...(gameState.board || Array(9).fill(null))];
                      const symbol = gameState.xUserId === user.id ? '💖' : '💋';
                      board[idx] = symbol;
                      const wins = [
                        [0, 1, 2],
                        [3, 4, 5],
                        [6, 7, 8],
                        [0, 3, 6],
                        [1, 4, 7],
                        [2, 5, 8],
                        [0, 4, 8],
                        [2, 4, 6],
                      ];
                      const winner = wins.some(([a, b, c]) => board[a] && board[a] === board[b] && board[a] === board[c]);
                      const draw = !winner && board.every(Boolean);
                      updateGame(currentSession.id, {
                        state: { ...gameState, board, winner: winner ? user.display_name : draw ? 'Draw' : null },
                        turn_user_id: partner?.id || user.id,
                        status: winner || draw ? 'finished' : 'active',
                      });
                    }}
                    className="h-24 rounded-2xl bg-pink-50 dark:bg-rose-950/40 text-3xl font-bold flex items-center justify-center border border-pink-200 dark:border-pink-800/50 hover:bg-pink-100 transition"
                  >
                    {cell}
                  </button>
                ))}
              </div>
              {gameState.winner && (
                <p className="text-center font-display text-base font-semibold text-pink-600">
                  {gameState.winner === 'Draw' ? 'A sweet tie!' : `${gameState.winner} wins this round!`}
                </p>
              )}
            </>
          )}
        </div>
      )}

      {/* Would You Rather */}
      {activeGameType === 'would_you_rather' && (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-display text-lg font-semibold">Would You Rather</h3>
            <button
              type="button"
              onClick={() =>
                startNewGame('would_you_rather', {
                  index: Math.floor(Math.random() * WOULD_YOU_RATHER_PROMPTS.length),
                  picks: {},
                })
              }
              className="rounded-xl bg-pink-500 px-3.5 py-2 text-xs font-semibold text-white"
            >
              Next Prompt
            </button>
          </div>
          {(() => {
            const idx = gameState.index ?? 0;
            const pair = WOULD_YOU_RATHER_PROMPTS[idx % WOULD_YOU_RATHER_PROMPTS.length];
            const picks = gameState.picks || {};
            return (
              <div className="grid sm:grid-cols-2 gap-3">
                {pair.map((opt, optIdx) => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => {
                      if (!currentSession) {
                        startNewGame('would_you_rather', { index: idx, picks: { [user.id]: optIdx } });
                      } else {
                        updateGame(currentSession.id, { state: { ...gameState, picks: { ...picks, [user.id]: optIdx } } });
                      }
                    }}
                    className={`rounded-2xl p-5 text-left border transition ${
                      picks[user.id] === optIdx
                        ? 'bg-gradient-to-br from-pink-500 to-rose-500 text-white border-pink-500'
                        : 'bg-pink-50/70 dark:bg-rose-950/40 border-pink-200 dark:border-pink-800/50'
                    }`}
                  >
                    <p className="text-sm font-semibold">{opt}</p>
                    {partner && picks[partner.id] === optIdx && (
                      <p className="text-xs mt-2 opacity-90">{partner.display_name} chose this!</p>
                    )}
                  </button>
                ))}
              </div>
            );
          })()}
        </div>
      )}

      {/* Couple Questions & Random Question Generator */}
      {activeGameType === 'couple_questions' && (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-display text-lg font-semibold">Deep & Playful Couple Questions</h3>
            <button
              type="button"
              onClick={() =>
                startNewGame('couple_questions', {
                  question: COUPLE_QUESTIONS[Math.floor(Math.random() * COUPLE_QUESTIONS.length)],
                  answers: {},
                })
              }
              className="rounded-xl bg-pink-500 px-3.5 py-2 text-xs font-semibold text-white"
            >
              Random Question
            </button>
          </div>
          <p className="font-display text-xl font-medium">
            {gameState.question || COUPLE_QUESTIONS[0]}
          </p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              if (!questionAnswer.trim()) return;
              const answers = { ...(gameState.answers || {}), [user.id]: questionAnswer.trim() };
              if (!currentSession) {
                await startNewGame('couple_questions', { question: COUPLE_QUESTIONS[0], answers });
              } else {
                await updateGame(currentSession.id, { state: { ...gameState, answers } });
              }
              setQuestionAnswer('');
              showToast('Your answer is saved & synced!');
            }}
            className="flex gap-2"
          >
            <input
              value={questionAnswer}
              onChange={(e) => setQuestionAnswer(e.target.value)}
              placeholder="Write your answer…"
              className="flex-1 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
            />
            <button type="submit" className="min-h-[42px] rounded-2xl bg-pink-500 px-5 text-xs font-semibold text-white">
              Save
            </button>
          </form>
          <div className="grid sm:grid-cols-2 gap-3 pt-2">
            <div className="rounded-2xl bg-pink-50 dark:bg-rose-950/40 p-3.5 text-xs">
              <p className="font-semibold">{user.display_name}</p>
              <p className="mt-1 opacity-85">{gameState.answers?.[user.id] || 'No answer yet'}</p>
            </div>
            <div className="rounded-2xl bg-purple-50 dark:bg-purple-950/40 p-3.5 text-xs">
              <p className="font-semibold">{partner?.display_name || 'Partner'}</p>
              <p className="mt-1 opacity-85">{partner ? gameState.answers?.[partner.id] || 'Waiting for partner…' : 'Not paired yet'}</p>
            </div>
          </div>
        </div>
      )}

      {/* Relationship Quiz */}
      {activeGameType === 'quiz' && (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-display text-lg font-semibold">Relationship Quiz</h3>
            <button
              type="button"
              onClick={() => startNewGame('quiz', { qIndex: ((gameState.qIndex ?? 0) + 1) % QUIZ_QUESTIONS.length, answers: {} })}
              className="rounded-xl bg-pink-500 px-3.5 py-2 text-xs font-semibold text-white"
            >
              Next Question
            </button>
          </div>
          {(() => {
            const q = QUIZ_QUESTIONS[(gameState.qIndex ?? 0) % QUIZ_QUESTIONS.length];
            const answers = gameState.answers || {};
            return (
              <div className="space-y-3">
                <p className="font-display text-lg font-semibold">{q.q}</p>
                <div className="grid sm:grid-cols-2 gap-2.5">
                  {q.options.map((opt) => (
                    <button
                      key={opt}
                      type="button"
                      onClick={() => {
                        const nextAns = { ...answers, [user.id]: opt };
                        if (!currentSession) startNewGame('quiz', { qIndex: 0, answers: nextAns });
                        else updateGame(currentSession.id, { state: { ...gameState, answers: nextAns } });
                      }}
                      className={`min-h-[44px] rounded-2xl p-3.5 text-left text-xs font-semibold border ${
                        answers[user.id] === opt
                          ? 'bg-pink-500 text-white border-pink-500'
                          : 'bg-pink-50/60 dark:bg-rose-950/40 border-pink-200 dark:border-pink-800/40'
                      }`}
                    >
                      <span>{opt}</span>
                      {partner && answers[partner.id] === opt && <span className="ml-2 opacity-85">({partner.display_name})</span>}
                    </button>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Drawing & Guessing */}
      {activeGameType === 'drawing_guess' && (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="font-display text-lg font-semibold">Drawing & Guessing</h3>
              <p className="text-xs opacity-75">
                {gameState.drawerId === user.id || !currentSession
                  ? `Your secret word to draw: ${gameState.word || DRAWING_WORDS[0]}`
                  : `${partner?.display_name || 'Partner'} is drawing! Type your guess below.`}
              </p>
            </div>
            <button
              type="button"
              onClick={() =>
                startNewGame('drawing_guess', {
                  word: DRAWING_WORDS[Math.floor(Math.random() * DRAWING_WORDS.length)],
                  drawerId: user.id,
                  strokes: [],
                  guessedCorrectly: false,
                })
              }
              className="rounded-xl bg-pink-500 px-3.5 py-2 text-xs font-semibold text-white"
            >
              New Drawing Round
            </button>
          </div>

          <CoupleDrawingCanvas
            strokes={gameState.strokes || []}
            canDraw={!currentSession || gameState.drawerId === user.id}
            onAddStroke={(stroke) => {
              const nextStrokes = [...(gameState.strokes || []), stroke];
              if (!currentSession) {
                startNewGame('drawing_guess', { word: DRAWING_WORDS[0], drawerId: user.id, strokes: nextStrokes });
              } else {
                updateGame(currentSession.id, { state: { ...gameState, strokes: nextStrokes } });
              }
            }}
            onClear={() => {
              if (currentSession) updateGame(currentSession.id, { state: { ...gameState, strokes: [] } });
            }}
          />

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!currentSession || !guessText.trim()) return;
              const correct = guessText.trim().toLowerCase() === String(gameState.word || '').toLowerCase();
              updateGame(currentSession.id, {
                state: { ...gameState, lastGuess: guessText.trim(), guessedCorrectly: correct },
              });
              showToast(correct ? 'You guessed it right!' : 'Keep guessing!', correct ? 'success' : 'error');
              setGuessText('');
            }}
            className="flex gap-2"
          >
            <input
              value={guessText}
              onChange={(e) => setGuessText(e.target.value)}
              placeholder="Guess what your partner drew…"
              className="flex-1 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
            />
            <button type="submit" className="min-h-[42px] rounded-2xl bg-pink-500 px-5 text-xs font-semibold text-white">
              Guess
            </button>
          </form>
        </div>
      )}

      {/* Romantic & Fun Challenges */}
      {activeGameType === 'challenges' && (
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
          <h3 className="font-display text-lg font-semibold">Fun & Romantic Challenges</h3>
          <div className="space-y-2.5">
            {ROMANTIC_CHALLENGES.map((ch, idx) => {
              const doneMap = gameState.done || {};
              const isDone = Boolean(doneMap[idx]);
              return (
                <button
                  key={ch}
                  type="button"
                  onClick={() => {
                    const nextDone = { ...doneMap, [idx]: !isDone };
                    if (!currentSession) startNewGame('challenges', { done: nextDone });
                    else updateGame(currentSession.id, { state: { done: nextDone } });
                  }}
                  className="w-full min-h-[52px] rounded-2xl bg-pink-50/70 dark:bg-rose-950/40 p-4 text-left flex items-center gap-3 border border-pink-200/50 dark:border-pink-800/40"
                >
                  {isDone ? <CheckCircle2 className="h-5 w-5 text-pink-500 shrink-0" /> : <Circle className="h-5 w-5 text-pink-400 shrink-0" />}
                  <span className={`text-sm font-medium ${isDone ? 'line-through opacity-65' : ''}`}>{ch}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// --- 9. Our Plans ---
const OurPlansSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  plans: Array<Record<string, any>>;
  updates: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, plans, updates, onRefresh, showToast }) => {
  const [category, setCategory] = useState(PLAN_CATEGORIES[0]);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [targetDate, setTargetDate] = useState('');
  const [budget, setBudget] = useState('');
  const [checklistText, setChecklistText] = useState('');
  const [newCheckItem, setNewCheckItem] = useState<Record<string, string>>({});
  const [noteInput, setNoteInput] = useState<Record<string, string>>({});

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Our Plans</h2>
        <p className="text-sm opacity-75">Co-create life, travel, financial, and business plans together.</p>
      </div>

      <form
        onSubmit={async (e) => {
          e.preventDefault();
          const checklist = checklistText
            .split('\n')
            .map((l) => l.trim())
            .filter(Boolean)
            .map((text) => ({ id: crypto.randomUUID(), text, done: false }));
          await apiRequest('/api/plans', {
            method: 'POST',
            body: JSON.stringify({
              category,
              title,
              description,
              target_date: targetDate,
              budget: Number(budget || 0),
              assigned_to: user.id,
              checklist,
            }),
          });
          setTitle('');
          setDescription('');
          setTargetDate('');
          setBudget('');
          setChecklistText('');
          await onRefresh();
          showToast('Shared plan created!');
        }}
        className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3"
      >
        <div className="grid sm:grid-cols-2 gap-3">
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm font-medium"
          >
            {PLAN_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <input
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Plan title (e.g. Summer Amalfi Trip)"
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
          />
        </div>
        <div className="grid sm:grid-cols-2 gap-3">
          <input
            type="date"
            value={targetDate}
            onChange={(e) => setTargetDate(e.target.value)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2 text-xs"
          />
          <input
            type="number"
            min="0"
            step="0.01"
            value={budget}
            onChange={(e) => setBudget(e.target.value)}
            placeholder="Budget amount (optional)"
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2 text-xs"
          />
        </div>
        <textarea
          rows={2}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Description & vision…"
          className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-xs"
        />
        <textarea
          rows={2}
          value={checklistText}
          onChange={(e) => setChecklistText(e.target.value)}
          placeholder="Initial checklist steps (one per line)"
          className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-xs"
        />
        <button type="submit" className="min-h-[42px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-5 text-xs font-semibold text-white">
          Create Plan
        </button>
      </form>

      <div className="grid lg:grid-cols-2 gap-4">
        {plans.map((plan) => {
          const checklist = JSON.parse(plan.checklist_json || '[]') as Array<{ id: string; text: string; done: boolean }>;
          const planUpdates = updates.filter((u) => u.plan_id === plan.id);
          return (
            <div key={plan.id} className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs font-medium text-pink-600 dark:text-pink-300">
                    {plan.category}
                    {plan.target_date ? ` · Target ${plan.target_date}` : ''}
                    {plan.budget ? ` · Budget $${Number(plan.budget).toLocaleString()}` : ''}
                  </p>
                  <h3 className="font-display text-lg font-semibold mt-0.5">{plan.title}</h3>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    await apiRequest(`/api/plans/${plan.id}`, { method: 'DELETE' });
                    await onRefresh();
                  }}
                  className="text-rose-500 p-1"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
              {plan.description && <p className="text-xs opacity-80">{plan.description}</p>}

              <div>
                <div className="flex justify-between text-xs font-semibold mb-1">
                  <span>Progress</span>
                  <span className="font-mono-nums">{plan.progress}%</span>
                </div>
                <div className="h-2 rounded-full bg-pink-100 dark:bg-rose-950/60 overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-pink-500 to-purple-500" style={{ width: `${plan.progress}%` }} />
                </div>
              </div>

              <div className="space-y-1.5">
                {checklist.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={async () => {
                      const next = checklist.map((c) => (c.id === item.id ? { ...c, done: !c.done } : c));
                      await apiRequest(`/api/plans/${plan.id}`, { method: 'PATCH', body: JSON.stringify({ checklist: next }) });
                      await onRefresh();
                    }}
                    className="w-full flex items-center gap-2 text-left text-xs py-1"
                  >
                    {item.done ? <CheckCircle2 className="h-4 w-4 text-pink-500 shrink-0" /> : <Circle className="h-4 w-4 text-pink-300 shrink-0" />}
                    <span className={item.done ? 'line-through opacity-60' : ''}>{item.text}</span>
                  </button>
                ))}
              </div>

              <div className="flex gap-2">
                <input
                  value={newCheckItem[plan.id] || ''}
                  onChange={(e) => setNewCheckItem((prev) => ({ ...prev, [plan.id]: e.target.value }))}
                  placeholder="Add checklist step…"
                  className="flex-1 rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-1.5 text-xs"
                />
                <button
                  type="button"
                  onClick={async () => {
                    const txt = (newCheckItem[plan.id] || '').trim();
                    if (!txt) return;
                    const next = [...checklist, { id: crypto.randomUUID(), text: txt, done: false }];
                    await apiRequest(`/api/plans/${plan.id}`, { method: 'PATCH', body: JSON.stringify({ checklist: next }) });
                    setNewCheckItem((prev) => ({ ...prev, [plan.id]: '' }));
                    await onRefresh();
                  }}
                  className="rounded-xl bg-pink-500 px-3 py-1.5 text-xs font-semibold text-white"
                >
                  Add
                </button>
              </div>

              <div className="pt-2 border-t border-pink-100 dark:border-pink-900/40 space-y-1.5">
                <div className="flex gap-2">
                  <input
                    value={noteInput[plan.id] || ''}
                    onChange={(e) => setNoteInput((prev) => ({ ...prev, [plan.id]: e.target.value }))}
                    placeholder="Post a plan update…"
                    className="flex-1 rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-1.5 text-xs"
                  />
                  <button
                    type="button"
                    onClick={async () => {
                      const u = (noteInput[plan.id] || '').trim();
                      if (!u) return;
                      await apiRequest(`/api/plans/${plan.id}`, { method: 'PATCH', body: JSON.stringify({ updateNote: u }) });
                      setNoteInput((prev) => ({ ...prev, [plan.id]: '' }));
                      await onRefresh();
                    }}
                    className="rounded-xl bg-pink-100 dark:bg-rose-950/60 px-3 py-1.5 text-xs font-semibold"
                  >
                    Post
                  </button>
                </div>
                {planUpdates.slice(0, 3).map((u) => (
                  <p key={u.id} className="text-[11px] opacity-75">
                    {u.user_id === user.id ? user.display_name : partner?.display_name || 'Partner'}: {u.content}
                  </p>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// --- 10. Our Memories ---
const OurMemoriesSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  albums: Array<Record<string, any>>;
  memories: Array<Record<string, any>>;
  comments: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, albums, memories, comments, onRefresh, showToast }) => {
  const [search, setSearch] = useState('');
  const [filterFav, setFilterFav] = useState(false);
  const [selectedAlbum, setSelectedAlbum] = useState('');
  const [newAlbumTitle, setNewAlbumTitle] = useState('');
  const [caption, setCaption] = useState('');
  const [memoryDate, setMemoryDate] = useState(new Date().toISOString().slice(0, 10));
  const [locationLabel, setLocationLabel] = useState('');
  const [uploading, setUploading] = useState(false);
  const [showCamera, setShowCamera] = useState(false);
  const [commentText, setCommentText] = useState<Record<string, string>>({});

  const saveMemoryFile = async (f: File) => {
    setUploading(true);
    try {
      const up = await uploadPrivateFile(f, f.name);
      await apiRequest('/api/memories', {
        method: 'POST',
        body: JSON.stringify({
          album_id: selectedAlbum || null,
          media_url: up.url,
          media_type: f.type.startsWith('video/') ? 'video' : 'image',
          caption,
          memory_date: memoryDate,
          location_label: locationLabel,
        }),
      });
      setCaption('');
      setLocationLabel('');
      await onRefresh();
      showToast('Memory added to your private gallery!');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Upload failed', 'error');
    } finally {
      setUploading(false);
    }
  };

  const filtered = memories.filter((m) => {
    if (filterFav && !m.is_favorite) return false;
    if (selectedAlbum && m.album_id !== selectedAlbum) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (m.caption || '').toLowerCase().includes(q) || (m.location_label || '').toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Our Memories</h2>
        <p className="text-sm opacity-75">Private shared gallery & timeline exclusively for the two of you.</p>
      </div>

      {/* Upload / Camera Memory Card */}
      <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
        <div className="grid sm:grid-cols-3 gap-3">
          <input
            value={caption}
            onChange={(e) => setCaption(e.target.value)}
            placeholder="Write a caption for this memory…"
            className="sm:col-span-2 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
          />
          <input
            type="date"
            value={memoryDate}
            onChange={(e) => setMemoryDate(e.target.value)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-xs"
          />
        </div>
        <div className="grid sm:grid-cols-4 gap-3">
          <input
            value={locationLabel}
            onChange={(e) => setLocationLabel(e.target.value)}
            placeholder="Optional place (e.g. Botanical Gardens)"
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2 text-xs"
          />
          <select
            value={selectedAlbum}
            onChange={(e) => setSelectedAlbum(e.target.value)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2 text-xs"
          >
            <option value="">All Moments (No Album)</option>
            {albums.map((a) => (
              <option key={a.id} value={a.id}>
                {a.title}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={uploading}
            onClick={() => setShowCamera(true)}
            className="min-h-[42px] inline-flex items-center justify-center gap-2 rounded-2xl border border-pink-300 dark:border-pink-700 bg-pink-50 dark:bg-rose-950/60 px-4 text-xs font-semibold text-rose-900 dark:text-pink-100 shadow-xs"
          >
            <Camera className="h-4 w-4 text-pink-500" />
            <span>Use Camera</span>
          </button>
          <label className="min-h-[42px] inline-flex items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-4 text-xs font-semibold text-white cursor-pointer shadow-sm">
            <Upload className="h-4 w-4" />
            <span>{uploading ? 'Uploading…' : 'Upload Photo / Video'}</span>
            <input
              type="file"
              accept="image/*,video/*"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) saveMemoryFile(f);
              }}
            />
          </label>
        </div>
      </div>

      {showCamera && (
        <CameraCaptureModal
          title="Capture Couple Memory"
          allowVideo={true}
          defaultFacingMode="environment"
          onCapture={saveMemoryFile}
          onClose={() => setShowCamera(false)}
          showToast={showToast}
        />
      )}

      {/* Search, Favorites & Album Creation */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-[220px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search captions or places…"
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-white/80 dark:bg-[#281526] pl-9 pr-3 py-2 text-xs"
            />
          </div>
          <button
            type="button"
            onClick={() => setFilterFav((f) => !f)}
            className={`min-h-[38px] rounded-2xl px-3.5 text-xs font-semibold flex items-center gap-1.5 ${
              filterFav ? 'bg-pink-500 text-white' : 'bg-white/80 dark:bg-[#281526] border border-pink-200 dark:border-pink-800'
            }`}
          >
            <Star className="h-3.5 w-3.5" />
            Favourites
          </button>
        </div>

        <form
          onSubmit={async (e) => {
            e.preventDefault();
            if (!newAlbumTitle.trim()) return;
            await apiRequest('/api/memories/albums', { method: 'POST', body: JSON.stringify({ title: newAlbumTitle }) });
            setNewAlbumTitle('');
            await onRefresh();
          }}
          className="flex items-center gap-2"
        >
          <input
            value={newAlbumTitle}
            onChange={(e) => setNewAlbumTitle(e.target.value)}
            placeholder="New album name"
            className="rounded-xl border border-pink-200 dark:border-pink-800 bg-white/80 dark:bg-[#281526] px-3 py-2 text-xs"
          />
          <button type="submit" className="min-h-[38px] rounded-xl bg-pink-100 dark:bg-rose-950/60 px-3 text-xs font-semibold">
            + Album
          </button>
        </form>
      </div>

      {/* Memories Grid */}
      {filtered.length === 0 ? (
        <div className="rounded-3xl bg-white/70 dark:bg-[#281526]/60 p-10 text-center text-sm opacity-70">
          Upload your first photo or video to start building your timeline together.
        </div>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((mem) => {
            const memComments = comments.filter((c) => c.memory_id === mem.id);
            return (
              <div key={mem.id} className="rounded-3xl bg-white/85 dark:bg-[#281526] overflow-hidden border border-pink-200/60 dark:border-pink-900/40 shadow-sm flex flex-col">
                <div className="aspect-[4/3] w-full overflow-hidden bg-pink-50 dark:bg-black/30">
                  {mem.media_type === 'video' ? (
                    <PrivateVideo src={mem.media_url} className="h-full w-full object-cover" />
                  ) : (
                    <PrivateImage src={mem.media_url} alt={mem.caption || 'Couple memory'} className="h-full w-full object-cover" />
                  )}
                </div>
                <div className="p-4 flex-1 flex flex-col justify-between space-y-2.5">
                  <div>
                    <div className="flex items-center justify-between gap-2 text-[11px] opacity-70">
                      <span>
                        {mem.memory_date}
                        {mem.location_label ? ` · ${mem.location_label}` : ''}
                      </span>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          onClick={async () => {
                            await apiRequest(`/api/memories/${mem.id}`, {
                              method: 'PATCH',
                              body: JSON.stringify({ is_favorite: !mem.is_favorite }),
                            });
                            await onRefresh();
                          }}
                          className={mem.is_favorite ? 'text-amber-500' : 'opacity-50'}
                        >
                          <Star className={`h-4 w-4 ${mem.is_favorite ? 'fill-current' : ''}`} />
                        </button>
                        <button
                          type="button"
                          onClick={async () => {
                            await apiRequest(`/api/memories/${mem.id}`, { method: 'DELETE' });
                            await onRefresh();
                          }}
                          className="text-rose-500 opacity-70 hover:opacity-100"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                    {mem.caption && <p className="text-sm font-medium mt-1">{mem.caption}</p>}
                  </div>

                  <div className="space-y-1.5 pt-2 border-t border-pink-100 dark:border-pink-900/40">
                    {memComments.map((c) => (
                      <p key={c.id} className="text-xs opacity-80">
                        <span className="font-semibold">{c.user_id === user.id ? user.display_name : partner?.display_name || 'Partner'}:</span>{' '}
                        {c.content}
                      </p>
                    ))}
                    <div className="flex gap-1.5">
                      <input
                        value={commentText[mem.id] || ''}
                        onChange={(e) => setCommentText((prev) => ({ ...prev, [mem.id]: e.target.value }))}
                        placeholder="Add a comment…"
                        className="flex-1 rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-2.5 py-1 text-xs"
                      />
                      <button
                        type="button"
                        onClick={async () => {
                          const txt = (commentText[mem.id] || '').trim();
                          if (!txt) return;
                          await apiRequest(`/api/memories/${mem.id}/comments`, {
                            method: 'POST',
                            body: JSON.stringify({ content: txt }),
                          });
                          setCommentText((prev) => ({ ...prev, [mem.id]: '' }));
                          await onRefresh();
                        }}
                        className="rounded-xl bg-pink-500 px-2.5 py-1 text-xs font-semibold text-white"
                      >
                        Post
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// --- 11. Special Dates ---
const SpecialDatesSection: React.FC<{
  dates: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ dates, onRefresh, showToast }) => {
  const [title, setTitle] = useState('');
  const [dateValue, setDateValue] = useState('');
  const [category, setCategory] = useState('birthday');
  const [recurringYearly, setRecurringYearly] = useState(true);
  const [notes, setNotes] = useState('');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Special Dates & Countdowns</h2>
        <p className="text-sm opacity-75">Anniversaries, birthdays, family occasions, and milestones.</p>
      </div>

      <form
        onSubmit={async (e) => {
          e.preventDefault();
          await apiRequest('/api/special-dates', {
            method: 'POST',
            body: JSON.stringify({ title, date_value: dateValue, category, recurring_yearly: recurringYearly, notes }),
          });
          setTitle('');
          setDateValue('');
          setNotes('');
          await onRefresh();
          showToast('Special date added!');
        }}
        className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3"
      >
        <div className="grid sm:grid-cols-3 gap-3">
          <input
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Occasion (e.g. Vivi’s Birthday)"
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-4 py-2.5 text-sm"
          />
          <input
            type="date"
            required
            value={dateValue}
            onChange={(e) => setDateValue(e.target.value)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
          />
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
          >
            <option value="anniversary">Anniversary</option>
            <option value="birthday">Partner Birthday</option>
            <option value="family">Family Birthday</option>
            <option value="milestone">Milestone</option>
            <option value="custom">Custom Occasion</option>
          </select>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex items-center gap-2 text-xs font-medium">
            <input type="checkbox" checked={recurringYearly} onChange={(e) => setRecurringYearly(e.target.checked)} />
            Repeat countdown every year
          </label>
          <button type="submit" className="min-h-[42px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-5 text-xs font-semibold text-white">
            Add Special Date
          </button>
        </div>
      </form>

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {dates.map((d) => {
          const daysLeft = daysUntilDate(d.date_value, Boolean(d.recurring_yearly));
          return (
            <div
              key={d.id}
              className="rounded-3xl bg-gradient-to-br from-pink-100/90 via-white to-purple-100/80 dark:from-rose-950/60 dark:to-purple-950/60 p-5 border border-pink-200/70 dark:border-pink-800/40 flex flex-col justify-between"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs font-medium text-pink-600 dark:text-pink-300 capitalize">
                    {d.category} · {d.date_value}
                  </p>
                  <h3 className="font-display text-lg font-bold mt-1">{d.title}</h3>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    await apiRequest(`/api/special-dates/${d.id}`, { method: 'DELETE' });
                    await onRefresh();
                  }}
                  className="text-rose-500 p-1"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
              <div className="mt-4 pt-3 border-t border-pink-200/60 dark:border-pink-800/40 flex items-baseline justify-between">
                <span className="font-mono-nums text-2xl font-bold text-rose-950 dark:text-pink-100">
                  {daysLeft === 0 ? 'Today!' : `${daysLeft}d`}
                </span>
                <span className="text-xs opacity-75">{daysLeft === 0 ? 'Celebrate together' : 'until celebration'}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// --- 12. Our Screen — Wallpaper Studio ---
const WallpaperStudioSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  couple: CoupleInfo;
  daysTogether: number;
  specialDates: Array<Record<string, any>>;
  wallpapers: Array<Record<string, any>>;
  approvals: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  onReloadAuth: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, couple, daysTogether, specialDates, wallpapers, approvals, onRefresh, onReloadAuth, showToast }) => {
  const [title, setTitle] = useState('Our Lock Screen');
  const [bgUrl, setBgUrl] = useState(() => getSavedStarterWallpaper());
  const [showStudioCamera, setShowStudioCamera] = useState(false);
  const [templateId, setTemplateId] = useState<'romantic-clock' | 'polaroid-keepsake' | 'minimal-editorial'>('romantic-clock');
  const [config, setConfig] = useState<WallpaperConfig>({
    customText: 'Two lives. One shared journey.',
    showClock: true,
    showDuration: true,
    showSpecialCountdown: true,
    showHearts: true,
    fontFamily: 'Fraunces',
    textColor: '#ffffff',
    widgetPosition: 'center',
    overlayTint: 24,
  });

  const nextSpecialLabel = useMemo(() => {
    if (!specialDates.length) return '';
    const sorted = [...specialDates].sort((a, b) => daysUntilDate(a.date_value, true) - daysUntilDate(b.date_value, true));
    const first = sorted[0];
    return `${first.title} in ${daysUntilDate(first.date_value, true)} days`;
  }, [specialDates]);

  const coupleNames = partner ? `${user.display_name} & ${partner.display_name}` : user.display_name;
  const pendingProposals = wallpapers.filter((w) => w.status === 'proposed');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Our Screen — Wallpaper Studio</h2>
        <p className="text-sm opacity-75">
          Design your shared couples lock screen together. Both partners approve a design before it syncs as active.
        </p>
      </div>

      {/* Pending Approvals */}
      {pendingProposals.length > 0 && (
        <div className="space-y-3">
          {pendingProposals.map((wp) => {
            const myApproval = approvals.find((a) => a.wallpaper_id === wp.id && a.user_id === user.id);
            const wpConfig = JSON.parse(wp.config_json || '{}') as WallpaperConfig;
            return (
              <div
                key={wp.id}
                className="rounded-3xl bg-gradient-to-r from-pink-100 to-purple-100 dark:from-rose-950/70 dark:to-purple-950/70 p-5 border border-pink-300 dark:border-pink-700 flex flex-col sm:flex-row items-center justify-between gap-4"
              >
                <div className="flex items-center gap-4">
                  <WallpaperLockPreview
                    backgroundUrl={wp.background_url}
                    templateId={wp.template_id}
                    config={wpConfig}
                    coupleNames={coupleNames}
                    daysTogether={daysTogether}
                    nextSpecialLabel={nextSpecialLabel}
                    avatarA={user.avatar_url}
                    avatarB={partner?.avatar_url}
                    nameA={user.display_name}
                    nameB={partner?.display_name || 'Partner'}
                    compact
                  />
                  <div>
                    <p className="text-xs font-semibold text-pink-600 dark:text-pink-300">Proposed Shared Wallpaper</p>
                    <h3 className="font-display text-lg font-bold">{wp.title}</h3>
                    <p className="text-xs opacity-75 mt-1">
                      {myApproval ? 'Waiting for your partner to approve this design.' : 'Your partner proposed this screen for both of you!'}
                    </p>
                  </div>
                </div>
                {!myApproval && (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={async () => {
                        await apiRequest(`/api/wallpapers/${wp.id}/respond`, { method: 'POST', body: JSON.stringify({ approved: true }) });
                        await onRefresh();
                        await onReloadAuth();
                        showToast('Wallpaper approved & synced across both accounts!');
                      }}
                      className="min-h-[42px] rounded-2xl bg-pink-500 px-4 text-xs font-semibold text-white"
                    >
                      Approve & Activate
                    </button>
                    <button
                      type="button"
                      onClick={async () => {
                        await apiRequest(`/api/wallpapers/${wp.id}/respond`, { method: 'POST', body: JSON.stringify({ approved: false }) });
                        await onRefresh();
                      }}
                      className="min-h-[42px] rounded-2xl bg-white dark:bg-black/30 px-4 text-xs font-semibold"
                    >
                      Decline
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Designer Studio Split */}
      <div className="grid lg:grid-cols-2 gap-8 items-start">
        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-4">
          <div>
            <label className="block text-xs font-semibold mb-1.5">Choose Backdrop, Snap Camera Photo, or Upload</label>
            <div className="grid grid-cols-3 sm:grid-cols-7 gap-2">
              {WALLPAPER_TEMPLATES.map((tpl) => (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => {
                    setBgUrl(tpl.url);
                    saveStarterWallpaper(tpl.url);
                  }}
                  className={`aspect-[9/14] overflow-hidden rounded-2xl border-2 transition ${
                    bgUrl === tpl.url ? 'border-pink-500 scale-105' : 'border-transparent'
                  }`}
                >
                  <PrivateImage src={tpl.url} alt={tpl.name} className="h-full w-full object-cover" />
                </button>
              ))}
              <button
                type="button"
                onClick={() => setShowStudioCamera(true)}
                className="aspect-[9/14] rounded-2xl border-2 border-dashed border-purple-300 dark:border-purple-700 flex flex-col items-center justify-center text-center p-2 hover:bg-purple-50 dark:hover:bg-purple-950/40"
              >
                <Camera className="h-5 w-5 text-purple-500 mb-1" />
                <span className="text-[10px] font-semibold">Camera</span>
              </button>
              <label className="aspect-[9/14] rounded-2xl border-2 border-dashed border-pink-300 dark:border-pink-700 flex flex-col items-center justify-center text-center p-2 cursor-pointer hover:bg-pink-50 dark:hover:bg-rose-950/40">
                <Upload className="h-5 w-5 text-pink-500 mb-1" />
                <span className="text-[10px] font-semibold">Upload</span>
                <input
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={async (e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    const up = await uploadPrivateFile(f, f.name);
                    setBgUrl(up.url);
                    saveStarterWallpaper(up.url);
                    showToast('Couple photo loaded into studio!');
                  }}
                />
              </label>
            </div>
          </div>
          {showStudioCamera && (
            <CameraCaptureModal
              title="Snap Wallpaper Backdrop"
              allowVideo={false}
              defaultFacingMode="environment"
              onClose={() => setShowStudioCamera(false)}
              showToast={showToast}
              onCapture={async (file) => {
                const up = await uploadPrivateFile(file, file.name);
                setBgUrl(up.url);
                saveStarterWallpaper(up.url);
                showToast('Camera backdrop loaded into studio!');
              }}
            />
          )}

          <div className="grid sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold mb-1">Wallpaper Title</label>
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold mb-1">Layout Template</label>
              <select
                value={templateId}
                onChange={(e) => setTemplateId(e.target.value as any)}
                className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs"
              >
                <option value="romantic-clock">Romantic Lock Screen</option>
                <option value="polaroid-keepsake">Frosted Keepsake Card</option>
                <option value="minimal-editorial">Minimal Editorial</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold mb-1">Custom Love Quote / Text</label>
            <input
              value={config.customText}
              onChange={(e) => setConfig((c) => ({ ...c, customText: e.target.value }))}
              className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs"
            />
          </div>

          <div className="grid grid-cols-3 gap-2.5">
            <div>
              <label className="block text-xs font-semibold mb-1">Font</label>
              <select
                value={config.fontFamily}
                onChange={(e) => setConfig((c) => ({ ...c, fontFamily: e.target.value as any }))}
                className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-2 py-2 text-xs"
              >
                <option value="Fraunces">Fraunces</option>
                <option value="Plus Jakarta Sans">Jakarta Sans</option>
                <option value="JetBrains Mono">Mono</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold mb-1">Position</label>
              <select
                value={config.widgetPosition}
                onChange={(e) => setConfig((c) => ({ ...c, widgetPosition: e.target.value as any }))}
                className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-2 py-2 text-xs"
              >
                <option value="top">Top</option>
                <option value="center">Center</option>
                <option value="bottom">Bottom</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold mb-1">Text Color</label>
              <input
                type="color"
                value={config.textColor}
                onChange={(e) => setConfig((c) => ({ ...c, textColor: e.target.value }))}
                className="h-9 w-full rounded-xl border border-pink-200 cursor-pointer"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-3 text-xs">
            {[
              ['showClock', 'Live Clock & Date'],
              ['showDuration', 'Days Together'],
              ['showSpecialCountdown', 'Special Countdown'],
              ['showHearts', 'Heart Motifs'],
            ].map(([k, lbl]) => (
              <label key={k} className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={Boolean((config as any)[k])}
                  onChange={(e) => setConfig((c) => ({ ...c, [k]: e.target.checked }))}
                />
                <span>{lbl}</span>
              </label>
            ))}
          </div>

          <button
            type="button"
            onClick={async () => {
              await apiRequest('/api/wallpapers', {
                method: 'POST',
                body: JSON.stringify({ title, background_url: bgUrl, template_id: templateId, config }),
              });
              await onRefresh();
              await onReloadAuth();
              showToast(partner ? 'Wallpaper sent to your partner for mutual approval!' : 'Wallpaper saved!');
            }}
            className="w-full min-h-[46px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 text-xs font-semibold text-white shadow-md"
          >
            {partner ? 'Propose Shared Wallpaper to Partner' : 'Save Wallpaper Design'}
          </button>

          <p className="text-[11px] opacity-70 leading-relaxed">
            Android & iOS Tip: Tap “Save High-Res Lock Screen” below the preview to download your 1080×1920 image, then apply it
            from your Photos / Wallpaper settings (iOS protects lock screens via user-confirmed Photos application).
          </p>
        </div>

        {/* Live Interactive Lock Screen Preview */}
        <div className="flex flex-col items-center">
          <WallpaperLockPreview
            backgroundUrl={bgUrl}
            templateId={templateId}
            config={config}
            coupleNames={coupleNames}
            daysTogether={daysTogether}
            nextSpecialLabel={nextSpecialLabel}
            avatarA={user.avatar_url}
            avatarB={partner?.avatar_url}
            nameA={user.display_name}
            nameB={partner?.display_name || 'Partner'}
          />
        </div>
      </div>

      {/* Wallpaper History & Restore */}
      {wallpapers.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-pink-200/50 dark:border-pink-900/40">
          <h3 className="font-display text-lg font-semibold">Previous Wallpapers & History</h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3">
            {wallpapers.map((w) => {
              const cfg = JSON.parse(w.config_json || '{}') as WallpaperConfig;
              const isActive = couple.active_wallpaper_id === w.id;
              return (
                <div key={w.id} className="space-y-2 text-center">
                  <WallpaperLockPreview
                    backgroundUrl={w.background_url}
                    templateId={w.template_id}
                    config={cfg}
                    coupleNames={coupleNames}
                    daysTogether={daysTogether}
                    nextSpecialLabel={nextSpecialLabel}
                    avatarA={user.avatar_url}
                    avatarB={partner?.avatar_url}
                    nameA={user.display_name}
                    nameB={partner?.display_name || 'Partner'}
                    compact
                  />
                  <p className="text-xs font-semibold truncate">{w.title}</p>
                  <button
                    type="button"
                    onClick={() => {
                      setTitle(w.title);
                      setBgUrl(w.background_url);
                      setConfig(cfg);
                      showToast('Loaded design into Studio for editing/re-proposing!');
                    }}
                    className="rounded-xl bg-pink-100 dark:bg-rose-950/50 px-3 py-1 text-[11px] font-semibold"
                  >
                    {isActive ? 'Active Design' : 'Load to Restore'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// --- 13. Our Growth ---
const OurGrowthSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  goals: Array<Record<string, any>>;
  habits: Array<Record<string, any>>;
  onRefresh: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({ user, partner, goals, habits, onRefresh, showToast }) => {
  const [goalTitle, setGoalTitle] = useState('');
  const [goalScope, setGoalScope] = useState<'personal' | 'shared'>('shared');
  const [habitTitle, setHabitTitle] = useState('');
  const [habitFreq, setHabitFreq] = useState<'daily' | 'weekly'>('daily');
  const [encouragement, setEncouragement] = useState<Record<string, string>>({});

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-2xl font-bold">Our Growth</h2>
        <p className="text-sm opacity-75">Personal & shared goals, daily habits, streaks, and encouragement.</p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Goals */}
        <div className="space-y-4">
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              await apiRequest('/api/growth/goals', {
                method: 'POST',
                body: JSON.stringify({ title: goalTitle, scope: goalScope }),
              });
              setGoalTitle('');
              await onRefresh();
              showToast('Goal added!');
            }}
            className="rounded-3xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-200/60 dark:border-pink-900/40 flex flex-wrap gap-2"
          >
            <select
              value={goalScope}
              onChange={(e) => setGoalScope(e.target.value as any)}
              className="rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs font-semibold"
            >
              <option value="shared">Shared Goal</option>
              <option value="personal">Personal Goal</option>
            </select>
            <input
              required
              value={goalTitle}
              onChange={(e) => setGoalTitle(e.target.value)}
              placeholder="New goal (e.g. Read 12 books together)"
              className="flex-1 min-w-[160px] rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs"
            />
            <button type="submit" className="min-h-[38px] rounded-xl bg-pink-500 px-4 text-xs font-semibold text-white">
              Add Goal
            </button>
          </form>

          <div className="space-y-3">
            {goals.map((g) => (
              <div key={g.id} className="rounded-3xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-200/60 dark:border-pink-900/40 space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="capitalize font-semibold text-pink-600 dark:text-pink-300">
                    {g.scope} · {g.owner_id === user.id ? user.display_name : partner?.display_name || 'Partner'}
                  </span>
                  <span className="font-mono-nums font-bold">{g.progress}%</span>
                </div>
                <p className={`text-sm font-semibold ${g.is_completed ? 'line-through opacity-65' : ''}`}>{g.title}</p>
                <input
                  type="range"
                  min={0}
                  max={100}
                  step={10}
                  value={g.progress}
                  onChange={async (e) => {
                    await apiRequest(`/api/growth/goals/${g.id}`, {
                      method: 'PATCH',
                      body: JSON.stringify({ progress: Number(e.target.value) }),
                    });
                    await onRefresh();
                  }}
                  className="w-full accent-pink-500"
                />
                {g.encouragement_note && (
                  <p className="text-xs italic text-rose-700 dark:text-pink-200">Encouragement: “{g.encouragement_note}”</p>
                )}
                <div className="flex gap-2">
                  <input
                    value={encouragement[g.id] || ''}
                    onChange={(e) => setEncouragement((prev) => ({ ...prev, [g.id]: e.target.value }))}
                    placeholder="Leave an encouragement note…"
                    className="flex-1 rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-1.5 text-xs"
                  />
                  <button
                    type="button"
                    onClick={async () => {
                      const note = (encouragement[g.id] || '').trim();
                      if (!note) return;
                      await apiRequest(`/api/growth/goals/${g.id}`, {
                        method: 'PATCH',
                        body: JSON.stringify({ encouragement_note: note }),
                      });
                      setEncouragement((prev) => ({ ...prev, [g.id]: '' }));
                      await onRefresh();
                      showToast('Encouragement sent!');
                    }}
                    className="rounded-xl bg-pink-100 dark:bg-rose-950/60 px-3 py-1.5 text-xs font-semibold"
                  >
                    Cheer On
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Habits */}
        <div className="space-y-4">
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              await apiRequest('/api/growth/habits', {
                method: 'POST',
                body: JSON.stringify({ title: habitTitle, frequency: habitFreq }),
              });
              setHabitTitle('');
              await onRefresh();
              showToast('Habit tracker created!');
            }}
            className="rounded-3xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-200/60 dark:border-pink-900/40 flex flex-wrap gap-2"
          >
            <select
              value={habitFreq}
              onChange={(e) => setHabitFreq(e.target.value as any)}
              className="rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs font-semibold"
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
            <input
              required
              value={habitTitle}
              onChange={(e) => setHabitTitle(e.target.value)}
              placeholder="New habit (e.g. Evening prayer or Gratitude check-in)"
              className="flex-1 min-w-[160px] rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs"
            />
            <button type="submit" className="min-h-[38px] rounded-xl bg-purple-500 px-4 text-xs font-semibold text-white">
              Add Habit
            </button>
          </form>

          <div className="space-y-2.5">
            {habits.map((h) => {
              const today = new Date().toISOString().slice(0, 10);
              const checkedToday = h.last_completed_date === today;
              return (
                <div
                  key={h.id}
                  className="rounded-2xl bg-white/85 dark:bg-[#281526] p-4 border border-pink-200/60 dark:border-pink-900/40 flex items-center justify-between gap-3"
                >
                  <div>
                    <p className="text-sm font-semibold">{h.title}</p>
                    <p className="text-xs opacity-70 capitalize">
                      {h.frequency} · {h.owner_id === user.id ? user.display_name : partner?.display_name || 'Partner'} ·{' '}
                      <span className="font-mono-nums font-semibold text-pink-600 dark:text-pink-300">{h.streak} streak</span>
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={checkedToday}
                    onClick={async () => {
                      await apiRequest(`/api/growth/habits/${h.id}/check`, { method: 'POST' });
                      await onRefresh();
                      showToast('Habit streak updated!');
                    }}
                    className={`min-h-[40px] rounded-xl px-4 text-xs font-semibold ${
                      checkedToday ? 'bg-emerald-500 text-white' : 'bg-pink-500 text-white'
                    }`}
                  >
                    {checkedToday ? 'Done Today' : 'Check In'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

// --- 14. Settings, Profile, Security, Devices & Dark Mode ---
const SettingsSection: React.FC<{
  user: UserProfile;
  partner: UserProfile | null;
  couple: CoupleInfo;
  devices: Array<{ id: string; device_name: string; platform: string; last_active_at: string }>;
  currentDeviceId: string;
  notifPrefs: Record<string, number>;
  darkMode: boolean;
  safetyFingerprint: string;
  onToggleDarkMode: (next: boolean) => Promise<void>;
  onLockNow: () => void;
  onReload: () => Promise<void>;
  onLogout: () => Promise<void>;
  showToast: (t: string, type?: 'success' | 'error') => void;
}> = ({
  user,
  partner,
  couple,
  devices,
  currentDeviceId,
  notifPrefs,
  darkMode,
  safetyFingerprint,
  onToggleDarkMode,
  onLockNow,
  onReload,
  onLogout,
  showToast,
}) => {
  const [displayName, setDisplayName] = useState(user.display_name);
  const [nickname, setNickname] = useState(user.nickname || '');
  const [bio, setBio] = useState(user.bio || '');
  const [coupleName, setCoupleName] = useState(couple.name);
  const [startDate, setStartDate] = useState(couple.start_date);
  const [accountPassword, setAccountPassword] = useState('');
  const [newPin, setNewPin] = useState('');
  const [showAvatarCam, setShowAvatarCam] = useState(false);
  const [emailVerifyCode, setEmailVerifyCode] = useState('');
  const [emailOtpPreview, setEmailOtpPreview] = useState<string | null>(null);
  const [emailCodeSent, setEmailCodeSent] = useState(false);

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-display text-2xl font-bold">Profile & Settings</h2>
          <p className="text-sm opacity-75">Personalize your profile, email authentication, security, devices, and appearance.</p>
        </div>
        <div className="flex items-center gap-2">
          <PWAInstallButton />
          <button
            type="button"
            onClick={() => onToggleDarkMode(!darkMode)}
            className="min-h-[40px] inline-flex items-center gap-2 rounded-2xl border border-pink-200 dark:border-pink-800 bg-white/80 dark:bg-[#281526] px-4 text-xs font-semibold"
          >
            {darkMode ? <Sun className="h-4 w-4 text-amber-400" /> : <Moon className="h-4 w-4 text-purple-600" />}
            <span>{darkMode ? 'Light Mode' : 'Dark Mode'}</span>
          </button>
        </div>
      </div>

      {/* Individual Profile */}
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          await apiRequest('/api/profile', {
            method: 'PATCH',
            body: JSON.stringify({ display_name: displayName, nickname, bio }),
          });
          await apiRequest('/api/couple', {
            method: 'PATCH',
            body: JSON.stringify({ name: coupleName, start_date: startDate }),
          });
          await onReload();
          showToast('Profile & space settings saved!');
        }}
        className="rounded-3xl bg-white/85 dark:bg-[#281526] p-6 border border-pink-200/60 dark:border-pink-900/40 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <label className="relative cursor-pointer">
              <div className="h-16 w-16 overflow-hidden rounded-full border-2 border-pink-300 shadow">
                <PrivateImage src={user.avatar_url} alt={user.display_name} fallbackLabel={user.display_name} className="h-full w-full object-cover" />
              </div>
              <span className="absolute -bottom-1 -right-1 flex h-6 w-6 items-center justify-center rounded-full bg-pink-500 text-white">
                <Upload className="h-3 w-3" />
              </span>
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  const up = await uploadPrivateFile(f, f.name);
                  await apiRequest('/api/profile', { method: 'PATCH', body: JSON.stringify({ avatar_url: up.url }) });
                  await onReload();
                  showToast('Profile photo updated!');
                }}
              />
            </label>
            <div>
              <p className="font-display text-lg font-bold">{user.display_name}</p>
              <p className="text-xs opacity-70">{user.email} · Paired with {partner?.display_name || 'Pending partner'}</p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowAvatarCam(true)}
            className="min-h-[38px] inline-flex items-center gap-1.5 rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50 dark:bg-rose-950/60 px-3.5 text-xs font-semibold"
          >
            <Camera className="h-3.5 w-3.5 text-pink-500" />
            <span>Take Selfie</span>
          </button>
        </div>
        {showAvatarCam && (
          <CameraCaptureModal
            title="Take Profile Selfie"
            allowVideo={false}
            defaultFacingMode="user"
            onClose={() => setShowAvatarCam(false)}
            showToast={showToast}
            onCapture={async (file) => {
              const up = await uploadPrivateFile(file, file.name);
              await apiRequest('/api/profile', { method: 'PATCH', body: JSON.stringify({ avatar_url: up.url }) });
              await onReload();
              showToast('Profile selfie updated!');
            }}
          />
        )}

        <div className="grid sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-semibold mb-1">Display Name</label>
            <input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold mb-1">Nickname</label>
            <input
              value={nickname}
              onChange={(e) => setNickname(e.target.value)}
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold mb-1">Couple Space Name</label>
            <input
              value={coupleName}
              onChange={(e) => setCoupleName(e.target.value)}
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold mb-1">Relationship Start Date</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs font-semibold mb-1">Short Bio</label>
          <input
            value={bio}
            onChange={(e) => setBio(e.target.value)}
            placeholder="A little note for your partner…"
            className="w-full rounded-2xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3.5 py-2.5 text-sm"
          />
        </div>
        <button type="submit" className="min-h-[42px] rounded-2xl bg-gradient-to-r from-pink-500 to-rose-500 px-5 text-xs font-semibold text-white">
          Save Profile Changes
        </button>
      </form>

      {/* Email Authentication & 2FA */}
      <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-pink-500" />
            <h3 className="font-display text-base font-semibold">Email Authentication & 2FA</h3>
          </div>
          <span
            className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-semibold ${
              user.email_verified === 1
                ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300'
                : 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300'
            }`}
          >
            {user.email_verified === 1 ? 'Email Verified' : 'Verification Pending'}
          </span>
        </div>

        {user.email_verified !== 1 ? (
          <div className="space-y-2.5">
            <p className="text-xs opacity-75">
              Send a 6-digit authentication code to <strong>{user.email}</strong> to verify your email address.
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={async () => {
                  const res = await apiRequest<{ provider: string; previewCode?: string }>('/api/auth/email/send-code', {
                    method: 'POST',
                    body: JSON.stringify({ email: user.email, purpose: 'verify_email' }),
                  });
                  setEmailCodeSent(true);
                  setEmailOtpPreview(res.previewCode || null);
                  showToast(res.previewCode ? `Preview code: ${res.previewCode}` : 'Verification code emailed!');
                }}
                className="min-h-[38px] rounded-xl bg-pink-100 dark:bg-rose-950/60 px-4 text-xs font-semibold text-rose-900 dark:text-pink-100"
              >
                {emailCodeSent ? 'Resend Email Code' : 'Send Email Code'}
              </button>
              <input
                inputMode="numeric"
                maxLength={6}
                value={emailVerifyCode}
                onChange={(e) => setEmailVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="6-digit code"
                className="w-36 rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs font-mono-nums tracking-widest"
              />
              <button
                type="button"
                onClick={async () => {
                  try {
                    await apiRequest('/api/auth/email/verify', {
                      method: 'POST',
                      body: JSON.stringify({ code: emailVerifyCode }),
                    });
                    setEmailVerifyCode('');
                    await onReload();
                    showToast('Email address verified!');
                  } catch (err) {
                    showToast(err instanceof Error ? err.message : 'Invalid code', 'error');
                  }
                }}
                className="min-h-[38px] rounded-xl bg-pink-500 px-4 text-xs font-semibold text-white"
              >
                Confirm Code
              </button>
            </div>
            {emailOtpPreview && (
              <p className="text-xs text-pink-600 dark:text-pink-300 font-mono-nums">
                Preview verification code (set RESEND_API_KEY in .env for real inbox delivery): {emailOtpPreview}
              </p>
            )}
          </div>
        ) : (
          <label className="flex items-center justify-between rounded-2xl bg-pink-50/70 dark:bg-black/20 px-4 py-3 text-xs font-semibold">
            <div>
              <p>Require 6-Digit Email Authentication Code on Sign-In (2FA)</p>
              <p className="text-[11px] font-normal opacity-70">Protects {user.email} whenever you sign in from a device</p>
            </div>
            <input
              type="checkbox"
              checked={user.email_2fa_enabled === 1}
              onChange={async (e) => {
                try {
                  await apiRequest('/api/auth/email/2fa-toggle', {
                    method: 'POST',
                    body: JSON.stringify({ enabled: e.target.checked }),
                  });
                  await onReload();
                  showToast(e.target.checked ? 'Email 2FA enabled!' : 'Email 2FA disabled');
                } catch (err) {
                  showToast(err instanceof Error ? err.message : 'Failed to update 2FA', 'error');
                }
              }}
            />
          </label>
        )}
      </div>

      {/* Shared PIN & E2EE Security */}
      <div className="grid sm:grid-cols-2 gap-4">
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await apiRequest('/api/couple/pin/update', {
                method: 'POST',
                body: JSON.stringify({ accountPassword, newPin }),
              });
              setAccountPassword('');
              setNewPin('');
              showToast('Shared EverUs PIN updated securely!');
            } catch (err) {
              showToast(err instanceof Error ? err.message : 'Failed to update PIN', 'error');
            }
          }}
          className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3"
        >
          <h3 className="font-display text-base font-semibold">Shared App-Lock PIN</h3>
          <input
            type="password"
            required
            value={accountPassword}
            onChange={(e) => setAccountPassword(e.target.value)}
            placeholder="Verify your account password"
            className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs"
          />
          <input
            type="password"
            inputMode="numeric"
            pattern="\d{4,6}"
            required
            value={newPin}
            onChange={(e) => setNewPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
            placeholder="New 4–6 digit shared PIN"
            className="w-full rounded-xl border border-pink-200 dark:border-pink-800 bg-pink-50/40 dark:bg-black/20 px-3 py-2 text-xs font-mono-nums"
          />
          <div className="flex gap-2">
            <button type="submit" className="flex-1 min-h-[40px] rounded-xl bg-pink-500 text-xs font-semibold text-white">
              Update PIN
            </button>
            <button
              type="button"
              onClick={onLockNow}
              className="min-h-[40px] rounded-xl border border-pink-200 dark:border-pink-800 px-3.5 text-xs font-semibold"
            >
              Lock Now
            </button>
          </div>
        </form>

        <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-2.5">
          <h3 className="font-display text-base font-semibold">End-to-End Encryption</h3>
          <p className="text-xs opacity-75">
            Compare this safety fingerprint with your partner to verify your ECDH P-256 + AES-256-GCM chat keys:
          </p>
          <div className="rounded-2xl bg-pink-50 dark:bg-black/25 p-3 font-mono-nums text-sm font-bold tracking-wider text-center">
            {safetyFingerprint}
          </div>
        </div>
      </div>

      {/* Notification Preferences */}
      <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
        <h3 className="font-display text-base font-semibold">Notification Preferences</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
          {['messages', 'love', 'tasks', 'memories', 'dates', 'plans', 'games', 'location', 'wallpapers'].map((key) => {
            const enabled = notifPrefs[key] !== 0;
            return (
              <label key={key} className="flex items-center justify-between rounded-2xl bg-pink-50/70 dark:bg-black/20 px-3.5 py-2.5 text-xs font-semibold capitalize">
                <span>{key}</span>
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={async (e) => {
                    await apiRequest('/api/notifications/preferences', {
                      method: 'PATCH',
                      body: JSON.stringify({ [key]: e.target.checked }),
                    });
                    await onReload();
                  }}
                />
              </label>
            );
          })}
        </div>
      </div>

      {/* Device Management & Sign Out */}
      <div className="rounded-3xl bg-white/85 dark:bg-[#281526] p-5 border border-pink-200/60 dark:border-pink-900/40 space-y-3">
        <h3 className="font-display text-base font-semibold">Your Active Devices</h3>
        <div className="divide-y divide-pink-100 dark:divide-pink-900/40">
          {devices.map((d) => (
            <div key={d.id} className="py-2.5 flex items-center justify-between text-xs">
              <div>
                <p className="font-semibold">
                  {d.device_name} · {d.platform} {d.id === currentDeviceId ? '(This device)' : ''}
                </p>
                <p className="opacity-65">Last active {formatRelativeTime(d.last_active_at)}</p>
              </div>
              {d.id !== currentDeviceId && (
                <button
                  type="button"
                  onClick={async () => {
                    await apiRequest(`/api/devices/${d.id}`, { method: 'DELETE' });
                    await onReload();
                    showToast('Device session revoked.');
                  }}
                  className="text-rose-600 font-semibold"
                >
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
        <div className="pt-2">
          <button
            type="button"
            onClick={onLogout}
            className="inline-flex min-h-[44px] items-center gap-2 rounded-2xl bg-rose-600 px-5 text-xs font-semibold text-white"
          >
            <LogOut className="h-4 w-4" />
            <span>Sign Out of This Device</span>
          </button>
        </div>
      </div>
    </div>
  );
};
