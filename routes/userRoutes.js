const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const authenticateToken = require("../middlewares/authenticateToken");
const authorizeAdmin = require("../middlewares/authorizeAdmin");

const router = express.Router();

// Endpoint untuk memperbarui data pengguna berdasarkan email
router.put("/update/:email", authenticateToken, async (req, res) => {
  try {
    const { username, password, profileImage } = req.body;
    const { email } = req.params;

    if (!username && !password && !profileImage) {
      return res.status(400).json({ error: "No data to update" });
    }

    // Mencari pengguna berdasarkan email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Update data pengguna
    if (username) user.username = username;
    if (password) user.password = await bcrypt.hash(password, 10); // Hash password baru
    if (profileImage) user.profileImage = profileImage;

    // Menyimpan perubahan ke database
    await user.save();

    res.json({
      message: "User updated successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profileImage: user.profileImage,
      },
    });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint untuk memperbarui role pengguna berdasarkan ID (hanya admin)
router.put("/:id/role", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role || !["user", "admin"].includes(role)) {
      return res
        .status(400)
        .json({ error: "Invalid role. Allowed values: 'user', 'admin'" });
    }

    // Cari pengguna berdasarkan ID
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Perbarui role pengguna
    user.role = role;
    await user.save();

    res.json({ message: "User role updated successfully", user });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
