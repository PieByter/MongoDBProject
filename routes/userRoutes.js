const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Report = require("../models/Report");
const authenticateToken = require("../middlewares/authenticateToken");
const { upload, cloudinary } = require("../config/cloudinary");

const router = express.Router();

// GET /users
router.get("/", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error("Kesalahan mengambil data pengguna:", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

// GET /users/me
router.get("/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: "Pengguna tidak ditemukan!" });
    }

    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      profileImage: user.profileImage,
      createdAt: user.createdAt,
      role: user.role,
    });
  } catch (error) {
    console.error("Kesalahan mengambil data pengguna:", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

// PUT /users/update
router.put(
  "/update",
  authenticateToken,
  upload.single("profileImage"),
  async (req, res) => {
    try {
      const { username, password, currentPassword } = req.body;

      if (!username && !password && !req.file) {
        return res
          .status(400)
          .json({ error: "Tidak ada data yang perlu diperbarui!" });
      }

      const user = await User.findById(req.user.userId);

      if (!user) {
        return res.status(404).json({ error: "Pengguna tidak ditemukan!" });
      }

      // Lacak perubahan apa saja yang terjadi
      const changes = [];

      if (password) {
        if (!currentPassword) {
          return res.status(400).json({
            error: "Kata sandi saat ini diperlukan untuk mengubah kata sandi!",
          });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
          return res.status(401).json({ error: "Kata sandi saat ini salah!" });
        }

        const isSamePassword = await bcrypt.compare(password, user.password);
        if (isSamePassword) {
          return res.status(400).json({
            error: "Password baru tidak boleh sama dengan yang lama!",
          });
        }

        user.password = await bcrypt.hash(password, 10);
        changes.push("password");
      }

      let usernameChanged = false;
      if (username && username !== user.username) {
        user.username = username;
        usernameChanged = true;
        changes.push("username");
      }

      if (req.file) {
        if (user.profileImage) {
          const regex = /\/uploads\/([^\.\\/]+)\./;
          const match = user.profileImage.match(regex);
          if (match && match[1]) {
            const publicId = `uploads/${match[1]}`;
            try {
              await cloudinary.uploader.destroy(publicId);
            } catch (err) {
              console.error(
                "Kegagalan menghapus gambar lama dari Cloudinary:",
                err
              );
            }
          }
        }
        user.profileImage = req.file.path;
        changes.push("profileImage");
      }

      await user.save();

      if (usernameChanged) {
        await Report.updateMany(
          { userId: user._id },
          { $set: { username: user.username } }
        );
      }

      // Generate pesan berdasarkan perubahan yang terjadi
      let message = "";
      if (changes.length === 1) {
        // Hanya satu hal yang diubah
        if (changes[0] === "password") {
          message = "Password berhasil diperbaharui!";
        } else if (changes[0] === "username") {
          message = "Username berhasil diupdate!";
        } else if (changes[0] === "profileImage") {
          message = "Gambar profil berhasil diupdate!";
        }
      } else {
        message = "Akun berhasil diperbarui!";
      }

      res.json({
        message,
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
      console.error("Kesalahan memperbarui akun:", error);
      res.status(500).json({ error: "Kesalahan server internal!" });
    }
  }
);

// PUT /users/:id/role
router.put("/:id/role", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role || !["user", "admin"].includes(role)) {
      return res.status(400).json({
        error: "Peran tidak valid. Nilai yang diizinkan: 'user', 'admin'",
      });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: "Pengguna tidak ditemukan!" });
    }

    user.role = role;
    await user.save();

    res.json({ message: "Peran pengguna berhasil diperbarui!", user });
  } catch (error) {
    console.error("Kesalahan memperbarui peran pengguna:", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

// DELETE /users/:id
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByIdAndDelete(id);

    if (!user) {
      return res.status(404).json({ error: "Pengguna tidak ditemukan!" });
    }

    res.json({ message: "Akun berhasil dihapus!" });
  } catch (error) {
    console.error("Kesalahan menghapus akun:", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

module.exports = router;
