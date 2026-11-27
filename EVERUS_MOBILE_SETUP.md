# EverUs — VS Code Setup, Testing & Mobile Publishing Guide

## Architecture Choice Note
In this live workspace, EverUs runs as an **installable Cross-Platform PWA (iOS Safari & Android Chrome) + Capacitor-ready React/TypeScript app** backed by a **real Express + SQLite + WebSocket server** with genuine **Web Crypto API (ECDH P-256 + HKDF + AES-256-GCM)** end-to-end encryption. This lets every feature—including two-device realtime sync, encrypted media uploads, couple pairing, and shared PIN locking—run live immediately without external cloud keys, while `supabase/migrations/001_everus_schema.sql` and `capacitor.config.ts` provide the exact PostgreSQL + Row Level Security + iOS/Android native wrapper definitions for publishing.

## 1. Local Development in VS Code
1. Install dependencies: `npm install`
2. Copy `.env.example` to `.env` (optionally set `SESSION_SECRET`).
3. Start the full-stack server + Vite frontend: `npm run dev`
4. Open `http://localhost:3000` on two browser windows or devices on your LAN to pair Partner A and Partner B in real time.

## 2. Installing on iOS & Android
- **iPhone / iPad (iOS Safari)**: Open the app URL in Safari -> Tap **Share** -> **Add to Home Screen**.
- **Android (Chrome)**: Tap the in-app **Install App** button or browser **Add to Home Screen** prompt.
- **App Store & Google Play via Capacitor**:
  ```bash
  npm install @capacitor/core @capacitor/cli @capacitor/ios @capacitor/android
  npm run build
  npx cap add ios
  npx cap add android
  npx cap sync
  npx cap open ios      # Opens Xcode for Apple signing & App Store Connect
  npx cap open android  # Opens Android Studio for AAB signing & Google Play
  ```

## 3. Supabase Production Database Migration
Run `supabase/migrations/001_everus_schema.sql` inside your Supabase SQL Editor to provision all tables, the 2-member backend trigger, Row Level Security policies, and the private `everus-private` storage bucket.
