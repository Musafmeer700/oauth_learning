import express from "express";
import {
    googleAuthorization,
    googleCallback,
    getMe,
    refreshAccessToken,
    logout,
} from "../controllers/auth.controller.js";
import authMiddleware from "../middlewares/auth.middleware.js";
import { asyncHandler } from "../utils/async-handler.js";

const router = express.Router();

router.get("/google", asyncHandler(googleAuthorization));
router.get("/google/callback", asyncHandler(googleCallback));
router.get("/me", authMiddleware, asyncHandler(getMe));
router.post("/refresh", asyncHandler(refreshAccessToken));
router.post("/logout", asyncHandler(logout));

export default router;
