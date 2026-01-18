const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const db = require("../database");

const router = express.Router();

/**
 * REGISTER USER
 */
router.post("/", (req, res) => {
  console.log("REGISTER BODY RECEIVED 👉", req.body);

  const { full_name, aadhaar_number, pin, date_of_birth, village_code } = req.body;

  if (!full_name || !aadhaar_number || !pin) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const aadhaar_hash = crypto
    .createHash("sha256")
    .update(aadhaar_number)
    .digest("hex");

  const pin_hash = crypto
    .createHash("sha256")
    .update(pin)
    .digest("hex");

  const qr_token = uuidv4();

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
        console.error("DB ERROR:", err.message);
        return res.status(400).json({ error: "User already exists" });
      }

      res.json({
        message: "User registered successfully",
        qr_token
      });
    }
  );
});

module.exports = router;
