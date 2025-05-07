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
const multer = require("multer");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// app.use("/uploads", express.static("uploads"));

// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET,
// });

// const storage = new CloudinaryStorage({
//   cloudinary: cloudinary,
//   params: {
//     folder: "uploads",
//     allowed_formats: ["jpg", "png", "jpeg"],
//   },
// });
// const upload = multer({ storage });

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Connect ke MongoDB lokal
// mongoose
//   .connect("mongodb://localhost:27017/user_auth")
//   .then(() => console.log("Connected to MongoDB"))
//   .catch((error) => console.error("Error connecting to MongoDB:", error));

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch((error) => console.error("Error connecting to MongoDB Atlas:", error));

// Schema dan model user
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
// const Report = mongoose.models.Report || mongoose.model("Report", ReportSchema);

function classifySeverity(diameter, depth) {
  let row = 0;
  let col = 0;

  if (depth < 25) row = 1;
  else if (depth >= 25 && depth < 50) row = 2;
  else if (depth >= 50) row = 3;

  if (diameter < 200) col = 1;
  else if (diameter >= 200 && diameter < 450) col = 2;
  else if (diameter >= 450) col = 3;

  // Matriks keparahan
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
  return matrix[key] || "Tidak diketahui"; // fallback
}

const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: (req, file, cb) => {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});
const upload = multer({ storage });

app.post("/register", upload.single("profileImage"), async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: "Please fill in all fields" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // let baseUrl = `${req.protocol}://${req.get("host")}`; // misal http://localhost:3000
    // if (baseUrl.includes("localhost")) {
    //   baseUrl = "https://parakeet-faithful-kangaroo.ngrok-free.app ";
    // }

    const baseUrl = "https://parakeet-faithful-kangaroo.ngrok-free.app";
    const profileImageUrl = req.file
      ? `${baseUrl}/uploads/${req.file.filename}`
      : null;

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

    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Please provide email and password" });
    }

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
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
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findByIdAndDelete(id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/validate-token", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Token is valid" });
});

app.get("/users/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
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
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal server error" });
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
        return res.status(400).json({ error: "No data to update" });
      }
      const user = await User.findById(req.user.userId);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (password) {
        if (!currentPassword) {
          return res
            .status(400)
            .json({ error: "Current password is required to change password" });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
          return res
            .status(401)
            .json({ error: "Current password is incorrect" });
        }

        const isSamePassword = await bcrypt.compare(password, user.password);
        if (isSamePassword) {
          return res.status(400).json({
            error: "New password cannot be the same as the current password",
          });
        }

        user.password = await bcrypt.hash(password, 10);
      }

      if (username) user.username = username;
      if (req.file) {
        if (user.profileImage) {
          const oldPath = path.join(
            __dirname,
            "uploads",
            path.basename(user.profileImage)
          );
          if (fs.existsSync(oldPath)) {
            try {
              fs.unlinkSync(oldPath);
            } catch (err) {
              console.error("Error deleting old image:", err);
            }
          }
        }
        let baseUrl = `${req.protocol}://${req.get("host")}`;
        user.profileImage = `${baseUrl}/uploads/${req.file.filename}`;
      }

      await user.save();

      res.json({
        message: "Account updated successfully",
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
      console.error("Error updating account:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.put("/users/:id/role", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role || !["user", "admin"].includes(role)) {
      return res
        .status(400)
        .json({ error: "Invalid role. Allowed values: 'user', 'admin'" });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.role = role;
    await user.save();

    res.json({ message: "User role updated successfully", user });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).json({ error: "Internal server error" });
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

// // Middleware untuk otorisasi admin
// function authorizeAdmin(req, res, next) {
//   if (req.user.role !== "admin") {
//     return res.status(403).json({ error: "Access denied" });
//   }
//   next();
// }

app.post(
  "/reports",
  authenticateToken,
  upload.single("imageUrl"),
  async (req, res) => {
    try {
      const { titles, lat, lng, diameter, depth, holesCount } = req.body;

      if (!titles || typeof titles !== "string") {
        return res.status(400).json({ error: "Invalid or missing titles" });
      }
      if (!req.file) {
        return res.status(400).json({ error: "File is required" });
      }
      if (!lat || !lng || !diameter || !depth || !holesCount) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      // Parsing nilai numerik
      const parsedDiameter = parseFloat(diameter);
      const parsedDepth = parseFloat(depth);
      const parsedHolesCount = parseInt(holesCount, 10);

      // Hitung severity berdasarkan diameter dan depth
      const severity = classifySeverity(parsedDiameter, parsedDepth);

      // Gabungkan base URL dengan path file
      // let baseUrl = `${req.protocol}://${req.get("host")}`;
      // if (baseUrl.includes("localhost")) {
      //   baseUrl = "https://parakeet-faithful-kangaroo.ngrok-free.app ";
      // }

      const baseUrl = "https://parakeet-faithful-kangaroo.ngrok-free.app";
      const fullImageUrl = req.file
        ? `${baseUrl}/uploads/${req.file.filename}`
        : null;

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
        createdAt: req.body.createdAt || Date.now(),
        updatedAt: null,
      });
      await report.save();
      res.status(201).json({ message: "Report created", report });
    } catch (err) {
      console.error("Error creating report:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get("/reports", authenticateToken, async (req, res) => {
  try {
    // let baseUrl = `${req.protocol}://${req.get("host")}`;
    // if (baseUrl.includes("localhost")) {
    //   baseUrl = "https://parakeet-faithful-kangaroo.ngrok-free.app ";
    // }
    const baseUrl = "https://parakeet-faithful-kangaroo.ngrok-free.app";

    const reports = await Report.find();

    // Gabungkan base URL dengan path file untuk setiap report
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
      createdAt: report.createdAt,
      updatedAt: report.updatedAt,
    }));

    res.json(reportsWithFullUrl);
  } catch (err) {
    console.error("Error fetching reports:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put(
  "/reports/:id",
  authenticateToken,
  upload.single("imageUrl"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { titles, lat, lng, holesCount, diameter, depth } = req.body;

      const report = await Report.findById(id);
      if (!report) return res.status(404).json({ error: "Report not found" });

      if (
        report.userId.toString() !== req.user.userId &&
        req.user.role !== "admin"
      ) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (titles) report.titles = titles;
      if (holesCount) report.holesCount = parseInt(holesCount, 10);
      if (lat && lng)
        report.location = { lat: parseFloat(lat), lng: parseFloat(lng) };

      if (req.file) {
        if (report.imageUrl) {
          const oldPath = path.join(
            __dirname,
            "uploads",
            path.basename(report.imageUrl)
          );
          if (fs.existsSync(oldPath)) {
            try {
              fs.unlinkSync(oldPath);
            } catch (err) {
              console.error("Error deleting old report image:", err);
            }
          }
        }
        let baseUrl = `${req.protocol}://${req.get("host")}`;
        report.imageUrl = `${baseUrl}/uploads/${req.file.filename}`;
      }

      if (diameter || depth) {
        report.diameter = diameter ? parseFloat(diameter) : report.diameter;
        report.depth = depth ? parseFloat(depth) : report.depth;
        report.severity = classifySeverity(report.diameter, report.depth);
      }

      report.updatedAt = Date.now();

      await report.save();
      res.json({
        message: "Report updated",
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
          createdAt: report.createdAt,
          updatedAt: report.updatedAt,
        },
      });
    } catch (err) {
      console.error("Error updating report:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete("/reports/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const report = await Report.findById(id);

    if (!report) return res.status(404).json({ error: "Report not found" });

    if (
      report.userId.toString() !== req.user.userId &&
      req.user.role !== "admin"
    ) {
      return res.status(403).json({ error: "Access denied" });
    }

    // Opsional: Hapus gambar dari file system
    if (fs.existsSync(report.imageUrl)) fs.unlinkSync(report.imageUrl);

    await report.deleteOne();
    res.json({ message: "Report deleted successfully" });
  } catch (err) {
    console.error("Error deleting report:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/reports/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const report = await Report.findById(id);

    if (!report) {
      return res.status(404).json({ error: "Report not found" });
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
      createdAt: report.createdAt,
      updatedAt: report.updatedAt,
    });
  } catch (err) {
    console.error("Error fetching report:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

const PORT = 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`Server running on port ${PORT}`)
);
