const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const db = new sqlite3.Database('./aadhaar_lite_v2.db');

db.serialize(() => {
  // Enhanced User Table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      aadhaar_hash TEXT PRIMARY KEY,
      full_name TEXT,
      date_of_birth TEXT,
      village_code TEXT,
      pin_hash TEXT,
      qr_token TEXT UNIQUE,
      trusted_witness_id TEXT,
      last_sync_ts DATETIME,
      is_active INTEGER DEFAULT 1
    )
  `);

  // Transaction / Verification Logs
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_hash TEXT,
      service_type TEXT,
      quantity REAL,
      unit TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      prev_hash TEXT,
      block_hash TEXT,
      synced INTEGER DEFAULT 0
    )
  `);
});

module.exports = db;
