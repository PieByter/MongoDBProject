const express = require("express");
const Report = require("../models/Report");
const authenticateToken = require("../middlewares/authenticateToken");

const router = express.Router();

router.post("/", authenticateToken, async (req, res) => {
  try {
    const { titles, lat, lng, diameter, depth } = req.body;

    if (!titles || !lat || !lng || !diameter || !depth) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const report = new Report({
      userId: req.user.userId,
      username: req.user.username,
      titles,
      location: { lat, lng },
      diameter,
      depth,
    });

    await report.save();
    res.status(201).json({ message: "Report created", report });
  } catch (error) {
    console.error("Error creating report:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;