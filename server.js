require("dotenv").config();
const express = require("express");
const cors = require("cors");
const connectDB = require("./config/database");

// Routes
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");
const reportRoutes = require("./routes/reportRoutes");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
connectDB();

// Route mounting
app.use("/", authRoutes);
app.use("/users", userRoutes);
app.use("/reports", reportRoutes);

// Start server
if (process.env.NODE_ENV !== "production") {
  const PORT = 3000;
  app.listen(PORT, "0.0.0.0", () =>
    console.log(`Server running on port ${PORT}`)
  );
}

// Penting untuk Vercel!
module.exports = app;
