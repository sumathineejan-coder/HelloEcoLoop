const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

// Firebase Admin: ใช้ service account จาก environment
let firestore = null;
function initFirebase() {
  try {
    let serviceAccount;
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
      serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    } else if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH && fs.existsSync(process.env.FIREBASE_SERVICE_ACCOUNT_PATH)) {
      serviceAccount = require(path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT_PATH));
    } else if (fs.existsSync(path.join(__dirname, 'serviceAccountKey.json'))) {
      serviceAccount = require(path.join(__dirname, 'serviceAccountKey.json'));
    }
    if (!serviceAccount) { 
      console.warn('Firebase profile sync disabled: configure FIREBASE_SERVICE_ACCOUNT_PATH or FIREBASE_SERVICE_ACCOUNT_JSON'); 
      return; 
    }
    if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    firestore = admin.firestore();
    console.log('Firebase Firestore profile connection ready');
  } catch (error) {
    console.error('Firebase initialization failed:', error.message);
  }
}

async function getFirebaseProfile(role, publicId) {
  if (!firestore) return null;
  const candidates = [
    firestore.collection('users').doc(`${role}_${publicId}`),
    firestore.collection('users').doc(String(publicId))
  ];
  for (const ref of candidates) {
    const snap = await ref.get();
    if (snap.exists) {
      const data = snap.data() || {};
      if (data.role && data.role !== role) continue;
      const name = role === 'merchant'
        ? (data.shopName || data.storeName || data.displayName || data.name || data.fullName)
        : (data.fullName || data.displayName || data.name || data.studentName);
      return { name: typeof name === 'string' ? name.trim() : '', role };
    }
  }
  return null;
}

async function saveFirebaseProfile(role, publicId, name) {
  if (!firestore) throw new Error('ยังไม่ได้เชื่อมต่อ Firebase กรุณาตั้งค่า FIREBASE_SERVICE_ACCOUNT_PATH ก่อน');
  const field = role === 'merchant' ? 'shopName' : 'fullName';
  await firestore.collection('users').doc(`${role}_${publicId}`).set({
    publicId: String(publicId), role, [field]: String(name).trim(), updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });
  return String(name).trim();
}

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

// 1. เชื่อมต่อฐานข้อมูล SQLite ผ่าน better-sqlite3
initFirebase();
const db = new Database(path.join(DATA_DIR, 'ecoloop.sqlite'));

// ตั้งค่า PRAGMA และสร้างตาราง
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','merchant')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(public_id, role)
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
  CREATE TABLE IF NOT EXISTS verification_codes (
    code TEXT PRIMARY KEY,
    student_user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS codes_student_idx ON verification_codes(student_user_id);
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_user_id INTEGER NOT NULL REFERENCES users(id),
    merchant_user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS tx_student_idx ON transactions(student_user_id, id DESC);