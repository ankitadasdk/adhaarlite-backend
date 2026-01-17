const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const db = require("../database");

const router = express.Router();

router.post("/", (req, res) => {
  const { name, aadhaar_number } = req.body;

  if (!name || !aadhaar_number) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // Hash Aadhaar (never store raw number)
  const aadhaar_hash = crypto
    .createHash("sha256")
    .update(aadhaar_number)
    .digest("hex");

  const qr_token = uuidv4();

  db.run(
    `INSERT INTO users (name, aadhaar_hash, qr_token)
     VALUES (?, ?, ?)`,
    [name, aadhaar_hash, qr_token],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "User already exists" });
      }

      res.json({
        message: "User registered successfully",
        qr_token: qr_token
      });
    }
  );
});

module.exports = router;
