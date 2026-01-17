const express = require("express");
const db = require("../database");

const router = express.Router();

router.post("/", (req, res) => {
  const { qr_token, verifier_id } = req.body;

  if (!qr_token || !verifier_id) {
    return res.status(400).json({ error: "Missing fields" });
  }

  db.get(
    "SELECT * FROM users WHERE qr_token = ?",
    [qr_token],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ status: "VERIFICATION_FAILED" });
      }

      // Log verification attempt
      db.run(
        `INSERT INTO verification_logs (user_id, verifier_id, method_used, status)
         VALUES (?, ?, ?, ?)`,
        [user.id, verifier_id, "QR_TOKEN", "SUCCESS"]
      );

      res.json({
        status: "VERIFIED",
        user: {
          id: user.id,
          name: user.name
        }
      });
    }
  );
});

module.exports = router;
