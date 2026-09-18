import express from "express";
import { googleAuthorization, googleCallback } from "../controllers/auth.controller.js";
import { asyncHandler } from "../utils/async-handler.js";

const router = express.Router();

router.get("/google", asyncHandler(googleAuthorization));
router.get("/google/callback", asyncHandler(googleCallback));

export default router;
