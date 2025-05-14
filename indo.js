require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { create } = require("./models/Report");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "uploads",
    allowed_formats: ["jpg", "png", "jpeg"],
  },
});
const upload = multer({ storage });

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((error) => console.error("Error connecting to MongoDB Atlas:", error));

const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
  profileImage: String,
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const ReportSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  username: {
    type: String,
    required: true,
  },
  titles: String,
  imageUrl: String,
  location: {
    lat: Number,
    lng: Number,
  },
  holesCount: {
    type: Number,
    required: true,
    min: 0,
  },
  diameter: {
    type: Number,
    required: true,
    min: 0,
  },
  depth: {
    type: Number,
    required: true,
    min: 0,
  },
  severity: String,
  segmentationPercentage: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: null,
  },
});

delete mongoose.connection.models["Report"];
const Report = mongoose.model("Report", ReportSchema);

function classifySeverity(diameter, depth) {
  let row = 0;
  let col = 0;

  if (depth < 25) row = 1;
  else if (depth >= 25 && depth < 50) row = 2;
  else if (depth >= 50) row = 3;

  if (diameter < 200) col = 1;
  else if (diameter >= 200 && diameter < 450) col = 2;
  else if (diameter >= 450) col = 3;

  const matrix = {
    "1,1": "Rendah",
    "1,2": "Rendah",
    "1,3": "Sedang",
    "2,1": "Rendah",
    "2,2": "Sedang",
    "2,3": "Tinggi",
    "3,1": "Sedang",
    "3,2": "Sedang",
    "3,3": "Tinggi",
  };

  const key = `${row},${col}`;
  return matrix[key] || "Tidak diketahui";
}

app.post("/register", upload.single("profileImage"), async (req, res) => {
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

    const profileImageUrl = req.file ? req.file.path : null;

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

app.post("/login", async (req, res) => {
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

app.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error("Kesalahan mengambil data pengguna:", error);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

app.delete("/users/:id", async (req, res) => {
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

app.get("/validate-token", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Token valid!" });
});

app.get("/users/me", authenticateToken, async (req, res) => {
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

app.put(
  "/users/update",
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
      }

      let usernameChanged = false;
      if (username && username !== user.username) {
        user.username = username;
        usernameChanged = true;
      }

      if (req.file) {
        if (user.profileImage) {
          const regex = /\/uploads\/([^\.\/]+)\./;
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
      }

      await user.save();

      if (usernameChanged) {
        await Report.updateMany(
          { userId: user._id },
          { $set: { username: user.username } }
        );
      }

      res.json({
        message: "Akun berhasil diperbarui!",
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

app.put("/users/:id/role", authenticateToken, async (req, res) => {
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

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Forbidden" });
    req.user = user;
    next();
  });
}

app.post(
  "/reports",
  authenticateToken,
  upload.single("imageUrl"),
  async (req, res) => {
    try {
      const {
        titles,
        lat,
        lng,
        diameter,
        depth,
        holesCount,
        segmentationPercentage,
      } = req.body;

      if (!titles || typeof titles !== "string") {
        return res
          .status(400)
          .json({ error: "Judul tidak valid atau kosong!" });
      }
      if (!req.file) {
        return res.status(400).json({ error: "File gambar diperlukan!" });
      }
      if (!lat || !lng || !diameter || !depth || !holesCount) {
        return res
          .status(400)
          .json({ error: "Semua kolom harus terisi lengkap!" });
      }

      const parsedDiameter = parseFloat(diameter);
      const parsedDepth = parseFloat(depth);
      const parsedHolesCount = parseInt(holesCount, 10);
      const parsedSegmentation =
        segmentationPercentage !== undefined &&
        segmentationPercentage !== "" &&
        !isNaN(parseFloat(segmentationPercentage))
          ? Math.max(0, Math.min(100, parseFloat(segmentationPercentage)))
          : 0;

      const severity = classifySeverity(parsedDiameter, parsedDepth);

      const fullImageUrl = req.file ? req.file.path : null;

      const report = new Report({
        id: req.body.id,
        userId: req.user.userId,
        username: req.user.username,
        titles,
        imageUrl: fullImageUrl,
        location: { lat: parseFloat(lat), lng: parseFloat(lng) },
        holesCount: parsedHolesCount,
        diameter: parsedDiameter,
        depth: parsedDepth,
        severity,
        segmentationPercentage: parsedSegmentation,
        createdAt: req.body.createdAt || Date.now(),
        updatedAt: null,
      });

      await report.save();
      res.status(201).json({ message: "Laporan telah dibuat!", report });
    } catch (err) {
      console.error("Kesalahan membuat laporan:", err);
      res.status(500).json({ error: "Kesalahan server internal!" });
    }
  }
);

app.get("/reports", authenticateToken, async (req, res) => {
  try {
    const reports = await Report.find();

    const reportsWithFullUrl = reports.map((report) => ({
      id: report._id,
      userId: report.userId,
      username: report.username,
      titles: report.titles,
      imageUrl: report.imageUrl,
      location: report.location,
      holesCount: report.holesCount,
      diameter: report.diameter,
      depth: report.depth,
      severity: report.severity,
      segmentationPercentage: report.segmentationPercentage,
      createdAt: report.createdAt,
      updatedAt: report.updatedAt,
    }));

    res.json(reportsWithFullUrl);
  } catch (err) {
    console.error("Laporan pengambilan kesalahan:", err);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

app.put(
  "/reports/:id",
  authenticateToken,
  upload.single("imageUrl"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        titles,
        lat,
        lng,
        holesCount,
        diameter,
        depth,
        segmentationPercentage,
      } = req.body;

      const report = await Report.findById(id);
      if (!report)
        return res.status(404).json({ error: "Laporan tidak ditemukan!" });

      if (
        report.userId.toString() !== req.user.userId &&
        req.user.role !== "admin"
      ) {
        return res.status(403).json({ error: "Akses ditolak!" });
      }

      if (titles) report.titles = titles;
      if (holesCount) report.holesCount = parseInt(holesCount, 10);
      if (lat && lng)
        report.location = { lat: parseFloat(lat), lng: parseFloat(lng) };

      if (req.file) {
        if (report.imageUrl) {
          const regex = /\/uploads\/([^\.\/]+)\./;
          const match = report.imageUrl.match(regex);
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
        report.imageUrl = req.file.path;
      }

      if (diameter || depth) {
        report.diameter = diameter ? parseFloat(diameter) : report.diameter;
        report.depth = depth ? parseFloat(depth) : report.depth;
        report.severity = classifySeverity(report.diameter, report.depth);
      }

      if (segmentationPercentage !== undefined) {
        report.segmentationPercentage = Math.max(
          0,
          Math.min(100, parseFloat(segmentationPercentage))
        );
      }

      report.updatedAt = Date.now();

      await report.save();
      res.json({
        message: "Laporan berhasil diperbarui!",
        report: {
          id: report._id,
          userId: report.userId,
          username: report.username,
          titles: report.titles,
          imageUrl: report.imageUrl,
          location: report.location,
          holesCount: report.holesCount,
          diameter: report.diameter,
          depth: report.depth,
          severity: report.severity,
          segmentationPercentage: report.segmentationPercentage,
          createdAt: report.createdAt,
          updatedAt: report.updatedAt,
        },
      });
    } catch (err) {
      console.error("Gagal memperbarui laporan:", err);
      res.status(500).json({ error: "Kesalahan server internal!" });
    }
  }
);

app.delete("/reports/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const report = await Report.findById(id);

    if (!report)
      return res.status(404).json({ error: "Laporan tidak ditemukan!" });

    if (
      report.userId.toString() !== req.user.userId &&
      req.user.role !== "admin"
    ) {
      return res.status(403).json({ error: "Akses ditolak!" });
    }

    await report.deleteOne();
    res.json({ message: "Laporan berhasil dihapus!" });
  } catch (err) {
    console.error("Gagal menghapus laporan:", err);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

app.get("/reports/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const report = await Report.findById(id);

    if (!report) {
      return res.status(404).json({ error: "Laporan tidak ditemukan!" });
    }

    res.json({
      id: report._id,
      userId: report.userId,
      username: report.username,
      titles: report.titles,
      imageUrl: report.imageUrl,
      location: report.location,
      holesCount: report.holesCount,
      diameter: report.diameter,
      depth: report.depth,
      severity: report.severity,
      segmentationPercentage: report.segmentationPercentage,
      createdAt: report.createdAt,
      updatedAt: report.updatedAt,
    });
  } catch (err) {
    console.error("Gagal mengambil data laporan:", err);
    res.status(500).json({ error: "Kesalahan server internal!" });
  }
});

const PORT = 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`Server running on port ${PORT}`)
);
