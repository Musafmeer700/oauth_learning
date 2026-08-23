import express from "express";
import { googleAuthorization } from "../controllers/auth.controller.js";
import { asyncHandler } from "../utils/async-handler.js";

const router = express.Router();

router.get("/google", asyncHandler(googleAuthorization));

export default router;
