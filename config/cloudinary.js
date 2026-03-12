const cloudinary = require("cloudinary").v2;
const multer = require("multer");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Gunakan memoryStorage — file disimpan di buffer, lalu di-upload manual ke Cloudinary
const upload = multer({ storage: multer.memoryStorage() });

/**
 * Upload buffer ke Cloudinary dan kembalikan hasilnya.
 * @param {Buffer} buffer - File buffer dari multer memoryStorage
 * @param {string} folder - Nama folder di Cloudinary
 * @returns {Promise<object>} - Hasil upload dari Cloudinary
 */
function uploadToCloudinary(buffer, folder = "uploads") {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, allowed_formats: ["jpg", "png", "jpeg"] },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    stream.end(buffer);
  });
}

module.exports = { cloudinary, upload, uploadToCloudinary };
