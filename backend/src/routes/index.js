import express from "express";
import authRoutes from "./auth.routes.js";

const router = express.Router();

router.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "OAuth learning API is running",
  });
});

router.use("/auth", authRoutes);

export default router;
