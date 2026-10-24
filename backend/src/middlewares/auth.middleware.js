import mongoose from "mongoose";
import User from "../models/user.model.js";
import { verifyAccessToken } from "../services/token.service.js";
import AppError from "../utils/app-error.js";
import { asyncHandler } from "../utils/async-handler.js";

const ACCESS_TOKEN_COOKIE = "access_token";

async function authMiddleware(req, _res, next) {
	const accessToken = req.cookies?.[ACCESS_TOKEN_COOKIE];

	if (!accessToken) {
		throw new AppError("Access token is missing", 401);
	}

	const decoded = await verifyAccessToken(accessToken);
	const userId = decoded.sub;

	if (!userId || !mongoose.isValidObjectId(userId)) {
		throw new AppError("Access token is invalid", 401);
	}

	const user = await User.findById(userId);

	if (!user) {
		throw new AppError("User was not found", 401);
	}

	req.user = user;
	next();
}

export default asyncHandler(authMiddleware);
