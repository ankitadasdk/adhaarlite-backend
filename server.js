const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;


// Middleware
app.use(express.json());

// Database
const db = new sqlite3.Database("./aadhaar_lite_v2.db");

// =====================
// Helper Functions
// =====================

// Hash helper (SHA-256)
function hashValue(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

// Block hash for transaction chain
function createBlockHash(data) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(data))
    .digest("hex");
}

// =====================
// REGISTER USER
// =====================
app.post("/register", (req, res) => {
  const {
    full_name,
    date_of_birth,
    village_code,
    aadhaar_number,
    pin
  } = req.body;

  if (!full_name || !aadhaar_number || !pin) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const aadhaar_hash = hashValue(aadhaar_number);
  const pin_hash = hashValue(pin);
  const qr_token = crypto.randomUUID();

  db.run(
    `INSERT INTO users 
     (aadhaar_hash, full_name, date_of_birth, village_code, pin_hash, qr_token)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      aadhaar_hash,
      full_name,
      date_of_birth || null,
      village_code || null,
      pin_hash,
      qr_token
    ],
    function (err) {
      if (err) {
        return res.status(500).json({ error: "User already exists or DB error" });
      }

      res.json({
        message: "User registered successfully",
        qr_token
      });
    }
  );
});

// =====================
// VERIFY USER (QR + PIN)
// =====================
app.post("/verify", (req, res) => {
  const { qr_token, pin } = req.body;

  if (!qr_token || !pin) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const pin_hash = hashValue(pin);

  db.get(
    `SELECT full_name, village_code 
     FROM users 
     WHERE qr_token = ? AND pin_hash = ? AND is_active = 1`,
    [qr_token, pin_hash],
    (err, user) => {
      if (!user) {
        return res.status(401).json({ status: "VERIFICATION_FAILED" });
      }

      res.json({
        status: "VERIFIED",
        user
      });
    }
  );
});

// =====================
// TRANSACTION / SERVICE LOG
// =====================
app.post("/transact", (req, res) => {
  const { qr_token, service_type, quantity, unit } = req.body;

  if (!qr_token || !service_type) {
    return res.status(400).json({ error: "Missing fields" });
  }

  db.get(
    "SELECT aadhaar_hash FROM users WHERE qr_token = ? AND is_active = 1",
    [qr_token],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ error: "User not found" });
      }

      const user_hash = user.aadhaar_hash;

      db.get(
        "SELECT block_hash FROM logs ORDER BY id DESC LIMIT 1",
        [],
        (err, lastLog) => {
          const prev_hash = lastLog ? lastLog.block_hash : "GENESIS";

          const blockData = {
            user_hash,
            service_type,
            quantity,
            unit,
            prev_hash,
            timestamp: new Date().toISOString()
          };

          const block_hash = createBlockHash(blockData);

          db.run(
            `INSERT INTO logs 
             (user_hash, service_type, quantity, unit, prev_hash, block_hash)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
              user_hash,
              service_type,
              quantity || null,
              unit || null,
              prev_hash,
              block_hash
            ],
            function () {
              res.json({
                message: "Transaction recorded successfully",
                block_hash
              });
            }
          );
        }
      );
    }
  );
});

// =====================
// VIEW USER LOGS
// =====================
app.get("/logs/:qr_token", (req, res) => {
  const { qr_token } = req.params;

  db.get(
    "SELECT aadhaar_hash FROM users WHERE qr_token = ?",
    [qr_token],
    (err, user) => {
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      db.all(
        "SELECT service_type, quantity, unit, timestamp FROM logs WHERE user_hash = ?",
        [user.aadhaar_hash],
        (err, rows) => {
          res.json(rows);
        }
      );
    }
  );
});

// =====================
// SERVER START
// =====================
// =====================
// DEV ONLY: RESET DATABASE
// =====================
app.post("/dev/reset", (req, res) => {
  db.run("DELETE FROM users", () => {
    db.run("DELETE FROM logs", () => {
      res.json({ message: "Database reset successful" });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Aadhaar Lite backend running on http://localhost:${PORT}`);
});
