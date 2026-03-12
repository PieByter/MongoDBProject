const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { upload, uploadToCloudinary } = require("../config/cloudinary");
const authenticateToken = require("../middlewares/authenticateToken");

const router = express.Router();

// POST /register
router.post("/register", upload.single("profileImage"), async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
      return res
        .status(400)
        .json({ error: "Harap isi semua kolom dengan lengkap!" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Kata sandi tidak sesuai!" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email sudah terdaftar!" });
    }

    let profileImageUrl = null;
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer);
      profileImageUrl = result.secure_url;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
      profileImage: profileImageUrl,
      createdAt: Date.now(),
      role: "user",
    });

    await user.save();

    res.status(201).json({ message: "Pengguna berhasil terdaftar!", user });
  } catch (error) {
    console.error("Kesalahan registrasi: ", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

// POST /login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Harap isikan email dan kata sandi!" });
    }

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res
        .status(401)
        .json({ error: "Email atau kata sandi tidak valid!" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
        createdAt: user.createdAt,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Kesalahan login:", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

// GET /validate-token
router.get("/validate-token", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Token valid!" });
});

module.exports = router;