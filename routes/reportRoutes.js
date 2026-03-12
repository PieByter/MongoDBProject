const express = require("express");
const Report = require("../models/Report");
const authenticateToken = require("../middlewares/authenticateToken");
const { upload, cloudinary, uploadToCloudinary } = require("../config/cloudinary");
const classifySeverity = require("../utils/classifySeverity");

const router = express.Router();

// Helper untuk extract public_id dari cloudinary URL
function getPublicId(imageUrl) {
  const regex = /\/uploads\/([^\./]+)\./;
  const match = imageUrl.match(regex);
  return match && match[1] ? `uploads/${match[1]}` : null;
}

// POST /reports
router.post(
  "/",
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
        return res.status(400).json({ error: "Judul tidak valid atau kosong!" });
      }
      if (!req.file) {
        return res.status(400).json({ error: "File gambar diperlukan!" });
      }
      if (!lat || !lng || !diameter || !depth || !holesCount) {
        return res.status(400).json({ error: "Semua kolom harus terisi lengkap!" });
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

      const severity = classifySeverity(parsedDiameter, parsedSegmentation);

      // Upload ke Cloudinary dari buffer
      const uploadResult = await uploadToCloudinary(req.file.buffer);
      const fullImageUrl = uploadResult.secure_url;

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

// GET /reports
router.get("/", authenticateToken, async (req, res) => {
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

// GET /reports/:id
router.get("/:id", authenticateToken, async (req, res) => {
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

// PUT /reports/:id
router.put(
  "/:id",
  authenticateToken,
  upload.single("imageUrl"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { titles, lat, lng, holesCount, diameter, depth, segmentationPercentage } = req.body;

      const report = await Report.findById(id);
      if (!report) {
        return res.status(404).json({ error: "Laporan tidak ditemukan!" });
      }

      if (
        report.userId.toString() !== req.user.userId &&
        req.user.role !== "admin"
      ) {
        return res.status(403).json({ error: "Akses ditolak!" });
      }

      if (titles) report.titles = titles;
      if (holesCount) report.holesCount = parseInt(holesCount, 10);
      if (lat && lng) report.location = { lat: parseFloat(lat), lng: parseFloat(lng) };

      if (req.file) {
        if (report.imageUrl) {
          const publicId = getPublicId(report.imageUrl);
          if (publicId) {
            try {
              await cloudinary.uploader.destroy(publicId);
            } catch (err) {
              console.error("Kegagalan menghapus gambar lama dari Cloudinary:", err);
            }
          }
        }
        const uploadResult = await uploadToCloudinary(req.file.buffer);
        report.imageUrl = uploadResult.secure_url;
      }

      if (diameter || depth) {
        report.diameter = diameter ? parseFloat(diameter) : report.diameter;
        report.depth = depth ? parseFloat(depth) : report.depth;
        report.severity = classifySeverity(report.diameter, report.segmentationPercentage);
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

// DELETE /reports/:id
router.delete("/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const report = await Report.findById(id);

    if (!report) {
      return res.status(404).json({ error: "Laporan tidak ditemukan!" });
    }

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

module.exports = router;