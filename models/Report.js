const mongoose = require("mongoose");

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

module.exports = mongoose.model("Report", ReportSchema);